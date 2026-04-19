#ifndef _NTAG424_READER_H
#define _NTAG424_READER_H

/*
 * ntag424_reader.h — NFC Forum Type 4 / NDEF reader layer for NTAG424 DNA.
 *
 * This module handles everything from "card is on the reader" to "we have
 * the raw NDEF bytes".  It is deliberately kept free of:
 *   - cryptographic verification  (that is ntag424_verifier)
 *   - user policy and config      (Milestone 3)
 *   - PAM integration             (Milestone 4)
 *   - replay state                (Milestone 3)
 *
 * The transport abstraction (ntag424_transport_t) lets any transmit
 * implementation be plugged in, including the mock transport used in unit
 * tests, so all APDU-parsing logic can be exercised without real hardware.
 *
 * Hardware-backed (PC/SC) helpers follow at the bottom of this header.
 */

#include <stddef.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

/*
 * NFC Forum Type 4 Capability Container (CC) minimum size for V2.0.
 * A V2.0 CC that contains exactly one NDEF File Control TLV is 15 bytes:
 *   CCLen(2) + Version(1) + MLe(2) + MLc(2) + TLV_Tag(1) + TLV_Len(1) + TLV_Val(6)
 */
#define NTAG424_CC_MIN_LEN   15

/*
 * NFC Forum NDEF application AID (NFC Forum Type 4 Tag, version 2.0).
 * Used in the SELECT APPLICATION APDU.
 */
#define NTAG424_NDEF_AID_LEN 7

/*
 * Maximum bytes read per READ BINARY APDU.
 * 240 is a conservative limit well within ISO 7816 short-APDU capacity
 * and typical reader buffer sizes, and safely below NTAG424's 502-byte
 * NDEF capacity.
 */
#define NTAG424_READER_CHUNK_MAX  240

/*
 * Maximum NDEF buffer we allocate on the stack or accept as output.
 * NTAG424 DNA max NDEF is 256 bytes; 512 gives headroom for larger tags.
 */
#define NTAG424_READER_NDEF_MAX   512

/* -------------------------------------------------------------------------
 * Status codes
 * ---------------------------------------------------------------------- */

typedef enum {
	NTAG424_READER_OK = 0,
	NTAG424_READER_ERR_INVALID_ARGUMENT,
	NTAG424_READER_ERR_NO_READERS,
	NTAG424_READER_ERR_NO_CARD,
	NTAG424_READER_ERR_CONNECT,
	NTAG424_READER_ERR_TRANSMIT,    /* transport-level failure */
	NTAG424_READER_ERR_SW,          /* unexpected APDU status word */
	NTAG424_READER_ERR_CC_PARSE,    /* Capability Container malformed */
	NTAG424_READER_ERR_NDEF_TOO_LONG, /* NDEF does not fit in caller buffer */
	NTAG424_READER_ERR_NDEF_READ,   /* partial or otherwise failed read */
	NTAG424_READER_ERR_NOMEM
} ntag424_reader_status_t;

const char *ntag424_reader_status_string(ntag424_reader_status_t status);

/* -------------------------------------------------------------------------
 * Capability Container (CC) parsed representation
 *
 * Reference: NFC Forum Type 4 Tag Technical Specification v2.0, §5.1.
 * ---------------------------------------------------------------------- */

struct ntag424_cc_info {
	uint16_t cc_len;            /* CCLen field (total CC size in bytes) */
	uint8_t  mapping_version;   /* e.g. 0x20 for v2.0 */
	uint16_t max_rapdu;         /* MLe: max R-APDU data bytes */
	uint16_t max_capdu;         /* MLc: max C-APDU data bytes */
	/* From NDEF File Control TLV (tag 0x04): */
	uint16_t ndef_file_id;      /* NDEF file identifier */
	uint16_t ndef_max_size;     /* maximum NDEF file size */
	uint8_t  ndef_read_access;  /* 0x00 = open read access */
	uint8_t  ndef_write_access; /* 0x00 = open, 0x80 = read-only */
};

/*
 * Parse a Capability Container byte blob into ntag424_cc_info.
 * cc must be at least NTAG424_CC_MIN_LEN bytes.
 * Returns NTAG424_READER_ERR_CC_PARSE if no NDEF File Control TLV is found.
 */
ntag424_reader_status_t ntag424_parse_cc(const uint8_t *cc, size_t cc_len,
					 struct ntag424_cc_info *out);

/* -------------------------------------------------------------------------
 * Transport abstraction
 *
 * The transmit function must:
 *   - send cmd_len bytes from cmd to the tag
 *   - store the response (including SW1 SW2) into resp
 *   - update *resp_len to the actual response length
 *   - return 0 on a successful APDU exchange (status words are checked
 *     by the caller, not by the transport)
 *   - return non-zero on transport-level failure
 * ---------------------------------------------------------------------- */

typedef struct {
	int (*transmit)(void *user_data,
			const uint8_t *cmd, size_t cmd_len,
			uint8_t *resp, size_t *resp_len);
	void *user_data;
} ntag424_transport_t;

/* -------------------------------------------------------------------------
 * NDEF read flow (transport-agnostic)
 * ---------------------------------------------------------------------- */

/*
 * Execute the full NFC Forum Type 4 NDEF read sequence:
 *   1. SELECT NDEF application (AID D276000085 0101)
 *   2. SELECT Capability Container file (FID E103)
 *   3. READ BINARY: retrieve CC bytes
 *   4. Parse CC to obtain the NDEF file ID and maximum size
 *   5. SELECT NDEF file (FID from CC)
 *   6. READ BINARY: read the 2-byte NLEN prefix
 *   7. READ BINARY: read the NDEF message content (chunked if necessary)
 *
 * On success:
 *   - ndef_buf[0..*ndef_len_out - 1] contains the NDEF message bytes
 *     (without the 2-byte NLEN prefix)
 *   - *ndef_len_out is set to the NDEF message length in bytes
 *
 * ndef_buf_size must be at least the NDEF content size; if the card
 * reports a larger NDEF than ndef_buf_size, returns
 * NTAG424_READER_ERR_NDEF_TOO_LONG.
 *
 * Note: this implementation reads exactly NTAG424_CC_MIN_LEN (15) bytes
 * of CC, which is correct for NFC Forum T4T V2.0 / NTAG424.  Tags with
 * longer CCs (V3.0 extended records) are not fully supported yet.
 */
ntag424_reader_status_t ntag424_read_ndef(const ntag424_transport_t *transport,
					  uint8_t *ndef_buf,
					  size_t ndef_buf_size,
					  size_t *ndef_len_out);

/* -------------------------------------------------------------------------
 * PC/SC backend
 *
 * These functions wrap pcsc-lite to provide a concrete ntag424_transport_t.
 * They are compiled unconditionally (pcsc-lite is a required build
 * dependency), but require a live pcscd daemon and hardware at runtime.
 * ---------------------------------------------------------------------- */

/* Opaque PC/SC context.  Allocate with ntag424_pcsc_open(). */
struct ntag424_pcsc_ctx;

/*
 * Create a PC/SC context and establish a SCARD_SCOPE_SYSTEM connection.
 * Returns NTAG424_READER_ERR_CONNECT on failure.
 */
ntag424_reader_status_t ntag424_pcsc_open(struct ntag424_pcsc_ctx **ctx_out);

/*
 * Choose the reader whose name contains name_substr (simple substring
 * match, case-sensitive).  Pass NULL to select the first available reader.
 * Returns NTAG424_READER_ERR_NO_READERS if no matching reader is found.
 *
 * The name_substr match is intentionally simple; callers may use a short
 * distinguishing prefix such as "ACR122" or "ACS" rather than the full
 * system name.
 */
ntag424_reader_status_t ntag424_pcsc_select_reader(
	struct ntag424_pcsc_ctx *ctx, const char *name_substr);

/*
 * Connect to the card currently in the selected reader using the
 * negotiated protocol (T=0 or T=1).
 * Returns NTAG424_READER_ERR_NO_CARD if no card is present.
 */
ntag424_reader_status_t ntag424_pcsc_connect(struct ntag424_pcsc_ctx *ctx);

/*
 * Wait up to timeout_ms milliseconds for a card to appear in the
 * selected reader, then connect.  Uses SCardGetStatusChange().
 * timeout_ms = 0 means return immediately (same as ntag424_pcsc_connect).
 * Returns NTAG424_READER_ERR_NO_CARD on timeout.
 */
ntag424_reader_status_t ntag424_pcsc_wait_and_connect(
	struct ntag424_pcsc_ctx *ctx, unsigned int timeout_ms);

/*
 * Retrieve the selected reader name (for display / logging).
 * Returns NULL if no reader has been selected.
 * The returned pointer is valid until the context is closed.
 */
const char *ntag424_pcsc_reader_name(const struct ntag424_pcsc_ctx *ctx);

/*
 * Fill in a transport struct backed by this PC/SC context.
 * Must be called after a successful ntag424_pcsc_connect().
 */
ntag424_reader_status_t ntag424_pcsc_get_transport(
	struct ntag424_pcsc_ctx *ctx, ntag424_transport_t *transport_out);

/*
 * Disconnect from the card (if connected), free all resources, and
 * nullify *ctx_out if provided.  Safe to call with NULL ctx.
 */
void ntag424_pcsc_close(struct ntag424_pcsc_ctx *ctx);

#endif /* _NTAG424_READER_H */
