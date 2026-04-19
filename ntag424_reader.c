/*
 * ntag424_reader.c — NFC Forum Type 4 / NDEF reader for NTAG424 DNA.
 *
 * Provides:
 *   1. Pure transport-agnostic helpers:
 *        ntag424_parse_cc        — parse a CC byte blob
 *        ntag424_read_ndef       — full T4T NDEF read via any transport
 *        ntag424_reader_status_string
 *
 *   2. PC/SC backend (ntag424_pcsc_*) backed by pcsc-lite.
 *
 * Keep this file free of: verification keys, user policy, replay state.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_WINSCARD_H
# include <winscard.h>
#endif

#include "ntag424_reader.h"

/* =========================================================================
 * Internal APDU constants
 * ====================================================================== */

#define CLA_ISO      0x00
#define INS_SELECT   0xA4
#define INS_READ_BIN 0xB0

/* SELECT P1 values */
#define P1_SELECT_BY_AID  0x04
#define P1_SELECT_BY_FID  0x00

/* SELECT P2 values */
#define P2_SELECT_FIRST   0x00   /* return FCI */
#define P2_SELECT_NONE    0x0C   /* no response data */

/* Capability Container file identifier (NFC Forum T4T, always E103) */
#define CC_FID_HI  0xE1
#define CC_FID_LO  0x03

/* NFC Forum NDEF application AID */
static const uint8_t NDEF_AID[NTAG424_NDEF_AID_LEN] = {
	0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01
};

/* Successful status words */
#define SW1_OK  0x90
#define SW2_OK  0x00

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

static int sw_ok(const uint8_t *resp, size_t resp_len)
{
	return resp_len >= 2 &&
	       resp[resp_len - 2] == SW1_OK &&
	       resp[resp_len - 1] == SW2_OK;
}

static int do_transmit(const ntag424_transport_t *t,
		       const uint8_t *cmd, size_t cmd_len,
		       uint8_t *resp, size_t *resp_len)
{
	return t->transmit(t->user_data, cmd, cmd_len, resp, resp_len);
}

/* =========================================================================
 * Status string
 * ====================================================================== */

const char *ntag424_reader_status_string(ntag424_reader_status_t status)
{
	switch (status) {
	case NTAG424_READER_OK:
		return "ok";
	case NTAG424_READER_ERR_INVALID_ARGUMENT:
		return "invalid argument";
	case NTAG424_READER_ERR_NO_READERS:
		return "no readers found";
	case NTAG424_READER_ERR_NO_CARD:
		return "no card present";
	case NTAG424_READER_ERR_CONNECT:
		return "PC/SC connect failed";
	case NTAG424_READER_ERR_TRANSMIT:
		return "APDU transmit failed";
	case NTAG424_READER_ERR_SW:
		return "unexpected APDU status word";
	case NTAG424_READER_ERR_CC_PARSE:
		return "Capability Container parse error";
	case NTAG424_READER_ERR_NDEF_TOO_LONG:
		return "NDEF too long for provided buffer";
	case NTAG424_READER_ERR_NDEF_READ:
		return "NDEF read failed";
	case NTAG424_READER_ERR_NOMEM:
		return "memory allocation failed";
	default:
		return "unknown error";
	}
}

/* =========================================================================
 * CC parsing
 * ====================================================================== */

ntag424_reader_status_t ntag424_parse_cc(const uint8_t *cc, size_t cc_len,
					 struct ntag424_cc_info *out)
{
	size_t offset;
	size_t scan_limit;

	if (!cc || !out)
		return NTAG424_READER_ERR_INVALID_ARGUMENT;
	if (cc_len < NTAG424_CC_MIN_LEN)
		return NTAG424_READER_ERR_CC_PARSE;

	memset(out, 0, sizeof(*out));

	out->cc_len          = ((uint16_t)cc[0] << 8) | cc[1];
	out->mapping_version = cc[2];
	out->max_rapdu       = ((uint16_t)cc[3] << 8) | cc[4];
	out->max_capdu       = ((uint16_t)cc[5] << 8) | cc[6];

	/*
	 * The mapping version byte: the upper nibble is the major version
	 * and must be at least 2 (0x20).  We accept any minor revision.
	 */
	if ((out->mapping_version & 0xF0) < 0x20)
		return NTAG424_READER_ERR_CC_PARSE;

	/*
	 * Scan TLV structures starting at byte 7.
	 * We scan up to min(cc_len, out->cc_len) to respect both the
	 * declared CC length and the actual buffer we were given.
	 */
	scan_limit = cc_len;
	if (out->cc_len < (uint16_t)scan_limit)
		scan_limit = out->cc_len;

	offset = 7;
	while (offset < scan_limit) {
		uint8_t tag, len;

		tag = cc[offset++];

		if (tag == 0xFE)   /* Terminator TLV — no length, no value */
			break;

		if (offset >= scan_limit)
			return NTAG424_READER_ERR_CC_PARSE;

		len = cc[offset++];

		if (offset + len > scan_limit)
			return NTAG424_READER_ERR_CC_PARSE;

		if (tag == 0x04 && len >= 6) {
			/* NDEF File Control TLV */
			out->ndef_file_id    = ((uint16_t)cc[offset]     << 8)
					     | (uint16_t)cc[offset + 1];
			out->ndef_max_size   = ((uint16_t)cc[offset + 2] << 8)
					     | (uint16_t)cc[offset + 3];
			out->ndef_read_access  = cc[offset + 4];
			out->ndef_write_access = cc[offset + 5];
			return NTAG424_READER_OK;
		}

		offset += len;   /* skip unknown TLV value */
	}

	/* No NDEF File Control TLV found */
	return NTAG424_READER_ERR_CC_PARSE;
}

/* =========================================================================
 * NDEF read flow
 * ====================================================================== */

ntag424_reader_status_t ntag424_read_ndef(const ntag424_transport_t *transport,
					  uint8_t *ndef_buf,
					  size_t ndef_buf_size,
					  size_t *ndef_len_out)
{
	/*
	 * Response buffer: must hold the largest expected APDU response.
	 * Largest is one full chunk (NTAG424_READER_CHUNK_MAX bytes) + 2 SW
	 * bytes.  Use 16 extra bytes of headroom.
	 */
	uint8_t resp[NTAG424_READER_CHUNK_MAX + 16];
	size_t resp_len;

	/* SELECT NDEF Application */
	uint8_t sel_app[5 + NTAG424_NDEF_AID_LEN + 1];
	/* SELECT file / CC / NDEF */
	uint8_t sel_file[7];
	/* READ BINARY */
	uint8_t rd_bin[5];

	uint8_t cc_buf[NTAG424_CC_MIN_LEN];
	struct ntag424_cc_info cc;
	ntag424_reader_status_t rc;
	uint16_t ndef_content_len;
	size_t offset, chunk;

	if (!transport || !ndef_buf || !ndef_len_out)
		return NTAG424_READER_ERR_INVALID_ARGUMENT;

	/* ----------------------------------------------------------------
	 * Step 1: SELECT NDEF Application
	 * CLA=00 INS=A4 P1=04 P2=00 Lc=07 AID Le=00
	 * -------------------------------------------------------------- */
	sel_app[0] = CLA_ISO;
	sel_app[1] = INS_SELECT;
	sel_app[2] = P1_SELECT_BY_AID;
	sel_app[3] = P2_SELECT_FIRST;
	sel_app[4] = NTAG424_NDEF_AID_LEN;
	memcpy(sel_app + 5, NDEF_AID, NTAG424_NDEF_AID_LEN);
	sel_app[5 + NTAG424_NDEF_AID_LEN] = 0x00; /* Le */

	resp_len = sizeof(resp);
	if (do_transmit(transport, sel_app, sizeof(sel_app), resp, &resp_len))
		return NTAG424_READER_ERR_TRANSMIT;
	if (!sw_ok(resp, resp_len))
		return NTAG424_READER_ERR_SW;

	/* ----------------------------------------------------------------
	 * Step 2: SELECT Capability Container (FID = E103)
	 * CLA=00 INS=A4 P1=00 P2=0C Lc=02 E1 03
	 * -------------------------------------------------------------- */
	sel_file[0] = CLA_ISO;
	sel_file[1] = INS_SELECT;
	sel_file[2] = P1_SELECT_BY_FID;
	sel_file[3] = P2_SELECT_NONE;
	sel_file[4] = 0x02;
	sel_file[5] = CC_FID_HI;
	sel_file[6] = CC_FID_LO;

	resp_len = sizeof(resp);
	if (do_transmit(transport, sel_file, sizeof(sel_file), resp, &resp_len))
		return NTAG424_READER_ERR_TRANSMIT;
	if (!sw_ok(resp, resp_len))
		return NTAG424_READER_ERR_SW;

	/* ----------------------------------------------------------------
	 * Step 3: READ BINARY — CC (offset 0, length NTAG424_CC_MIN_LEN)
	 * CLA=00 INS=B0 P1=00 P2=00 Le=0F
	 *
	 * Note: we read exactly NTAG424_CC_MIN_LEN (15) bytes, which is
	 * the full V2.0 CC.  Tags with a longer CC (V3.0 extended records)
	 * would need a two-pass read; that is not implemented here.
	 * -------------------------------------------------------------- */
	rd_bin[0] = CLA_ISO;
	rd_bin[1] = INS_READ_BIN;
	rd_bin[2] = 0x00; /* offset high byte */
	rd_bin[3] = 0x00; /* offset low byte  */
	rd_bin[4] = NTAG424_CC_MIN_LEN; /* Le */

	resp_len = sizeof(resp);
	if (do_transmit(transport, rd_bin, sizeof(rd_bin), resp, &resp_len))
		return NTAG424_READER_ERR_TRANSMIT;
	if (!sw_ok(resp, resp_len) || resp_len < (size_t)(NTAG424_CC_MIN_LEN + 2))
		return NTAG424_READER_ERR_SW;

	memcpy(cc_buf, resp, NTAG424_CC_MIN_LEN);

	/* ----------------------------------------------------------------
	 * Step 4: Parse CC
	 * -------------------------------------------------------------- */
	rc = ntag424_parse_cc(cc_buf, NTAG424_CC_MIN_LEN, &cc);
	if (rc != NTAG424_READER_OK)
		return rc;

	/* ----------------------------------------------------------------
	 * Step 5: SELECT NDEF File (FID from CC)
	 * CLA=00 INS=A4 P1=00 P2=0C Lc=02 FID_HI FID_LO
	 * -------------------------------------------------------------- */
	sel_file[5] = (uint8_t)(cc.ndef_file_id >> 8);
	sel_file[6] = (uint8_t)(cc.ndef_file_id & 0xFF);

	resp_len = sizeof(resp);
	if (do_transmit(transport, sel_file, sizeof(sel_file), resp, &resp_len))
		return NTAG424_READER_ERR_TRANSMIT;
	if (!sw_ok(resp, resp_len))
		return NTAG424_READER_ERR_SW;

	/* ----------------------------------------------------------------
	 * Step 6: READ BINARY — NLEN (first 2 bytes of NDEF file)
	 * CLA=00 INS=B0 P1=00 P2=00 Le=02
	 * -------------------------------------------------------------- */
	rd_bin[2] = 0x00;
	rd_bin[3] = 0x00;
	rd_bin[4] = 0x02;

	resp_len = sizeof(resp);
	if (do_transmit(transport, rd_bin, sizeof(rd_bin), resp, &resp_len))
		return NTAG424_READER_ERR_TRANSMIT;
	/* need at least 2 data bytes + 2 SW */
	if (!sw_ok(resp, resp_len) || resp_len < 4)
		return NTAG424_READER_ERR_SW;

	ndef_content_len = ((uint16_t)resp[0] << 8) | resp[1];

	if (ndef_content_len == 0) {
		*ndef_len_out = 0;
		return NTAG424_READER_OK;
	}

	if ((size_t)ndef_content_len > ndef_buf_size)
		return NTAG424_READER_ERR_NDEF_TOO_LONG;

	/* ----------------------------------------------------------------
	 * Step 7: READ BINARY — NDEF content (chunked)
	 *
	 * The NDEF message occupies bytes [2 .. 2+ndef_content_len-1] of
	 * the NDEF file (offset 0 = NLEN_HI, offset 1 = NLEN_LO).
	 * -------------------------------------------------------------- */
	offset = 0;
	while (offset < (size_t)ndef_content_len) {
		uint16_t file_offset;
		size_t remaining = (size_t)ndef_content_len - offset;

		chunk = remaining;
		if (chunk > NTAG424_READER_CHUNK_MAX)
			chunk = NTAG424_READER_CHUNK_MAX;

		/* file offset = NLEN(2) + content_offset */
		file_offset = (uint16_t)(2U + offset);

		rd_bin[2] = (uint8_t)(file_offset >> 8);
		rd_bin[3] = (uint8_t)(file_offset & 0xFF);
		rd_bin[4] = (uint8_t)chunk;

		resp_len = sizeof(resp);
		if (do_transmit(transport, rd_bin, sizeof(rd_bin),
				resp, &resp_len))
			return NTAG424_READER_ERR_TRANSMIT;
		if (!sw_ok(resp, resp_len) || resp_len < chunk + 2)
			return NTAG424_READER_ERR_SW;

		memcpy(ndef_buf + offset, resp, chunk);
		offset += chunk;
	}

	*ndef_len_out = ndef_content_len;
	return NTAG424_READER_OK;
}

/* =========================================================================
 * PC/SC backend
 * ====================================================================== */

#ifdef HAVE_WINSCARD_H

struct ntag424_pcsc_ctx {
	SCARDCONTEXT  hctx;
	LPTSTR        readers_buf;   /* allocated by SCardListReaders */
	char         *selected;      /* points into readers_buf; NULL if none */
	SCARDHANDLE   hcard;
	DWORD         active_proto;
	int           connected;
};

/* PC/SC transmit callback used as ntag424_transport_t.transmit */
static int pcsc_transmit(void *user_data,
			 const uint8_t *cmd, size_t cmd_len,
			 uint8_t *resp, size_t *resp_len)
{
	struct ntag424_pcsc_ctx *ctx = (struct ntag424_pcsc_ctx *)user_data;
	SCARD_IO_REQUEST send_pci;
	DWORD rlen = (DWORD)*resp_len;
	LONG rc;

	switch (ctx->active_proto) {
	case SCARD_PROTOCOL_T0:
		send_pci = *SCARD_PCI_T0;
		break;
	case SCARD_PROTOCOL_T1:
		send_pci = *SCARD_PCI_T1;
		break;
	default:
		return -1;
	}

	rc = SCardTransmit(ctx->hcard, &send_pci,
			   cmd, (DWORD)cmd_len,
			   NULL, resp, &rlen);
	if (rc != SCARD_S_SUCCESS)
		return (int)rc;

	*resp_len = (size_t)rlen;
	return 0;
}

ntag424_reader_status_t ntag424_pcsc_open(struct ntag424_pcsc_ctx **ctx_out)
{
	struct ntag424_pcsc_ctx *ctx;
	LONG rc;

	if (!ctx_out)
		return NTAG424_READER_ERR_INVALID_ARGUMENT;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NTAG424_READER_ERR_NOMEM;

	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx->hctx);
	if (rc != SCARD_S_SUCCESS) {
		free(ctx);
		return NTAG424_READER_ERR_CONNECT;
	}

	*ctx_out = ctx;
	return NTAG424_READER_OK;
}

ntag424_reader_status_t ntag424_pcsc_select_reader(
	struct ntag424_pcsc_ctx *ctx, const char *name_substr)
{
	DWORD nrdrs = SCARD_AUTOALLOCATE;
	LPTSTR rdrs;
	LONG rc;
	char *r;

	if (!ctx)
		return NTAG424_READER_ERR_INVALID_ARGUMENT;

	if (ctx->readers_buf) {
		SCardFreeMemory(ctx->hctx, ctx->readers_buf);
		ctx->readers_buf = NULL;
		ctx->selected = NULL;
	}

	rc = SCardListReaders(ctx->hctx, NULL, (LPTSTR)&rdrs, &nrdrs);
	if (rc != SCARD_S_SUCCESS || nrdrs == 0)
		return NTAG424_READER_ERR_NO_READERS;

	ctx->readers_buf = rdrs;

	/* Walk the double-NUL-terminated multi-string */
	for (r = (char *)ctx->readers_buf; *r; r += strlen(r) + 1) {
		if (!name_substr) {
			ctx->selected = r;
			break;
		}
		if (strstr(r, name_substr)) {
			ctx->selected = r;
			break;
		}
	}

	if (!ctx->selected)
		return NTAG424_READER_ERR_NO_READERS;

	return NTAG424_READER_OK;
}

ntag424_reader_status_t ntag424_pcsc_connect(struct ntag424_pcsc_ctx *ctx)
{
	LONG rc;

	if (!ctx || !ctx->selected)
		return NTAG424_READER_ERR_INVALID_ARGUMENT;

	if (ctx->connected) {
		SCardDisconnect(ctx->hcard, SCARD_LEAVE_CARD);
		ctx->connected = 0;
	}

	rc = SCardConnect(ctx->hctx, ctx->selected,
			  SCARD_SHARE_SHARED,
			  SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
			  &ctx->hcard, &ctx->active_proto);
	if (rc != SCARD_S_SUCCESS)
		return NTAG424_READER_ERR_NO_CARD;

	ctx->connected = 1;
	return NTAG424_READER_OK;
}

const char *ntag424_pcsc_reader_name(const struct ntag424_pcsc_ctx *ctx)
{
	if (!ctx)
		return NULL;
	return ctx->selected;
}

ntag424_reader_status_t ntag424_pcsc_get_transport(
	struct ntag424_pcsc_ctx *ctx, ntag424_transport_t *transport_out)
{
	if (!ctx || !transport_out || !ctx->connected)
		return NTAG424_READER_ERR_INVALID_ARGUMENT;

	transport_out->transmit  = pcsc_transmit;
	transport_out->user_data = ctx;
	return NTAG424_READER_OK;
}

void ntag424_pcsc_close(struct ntag424_pcsc_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->connected)
		SCardDisconnect(ctx->hcard, SCARD_LEAVE_CARD);
	if (ctx->readers_buf)
		SCardFreeMemory(ctx->hctx, ctx->readers_buf);
	SCardReleaseContext(ctx->hctx);
	free(ctx);
}

#endif /* HAVE_WINSCARD_H */
