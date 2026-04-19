#ifndef _NTAG424_VERIFIER_H
#define _NTAG424_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#define NTAG424_KEY_BYTES     16  /* AES-128 key length */
#define NTAG424_UID_BYTES      7  /* NTAG424 UID length */
#define NTAG424_COUNTER_BYTES  3  /* SDMReadCtr length */
#define NTAG424_CT_BYTES       8  /* truncated CMAC (c param) length */
#define NTAG424_P_HEX_LEN     32  /* p param hex string: 16 bytes = 32 chars */
#define NTAG424_C_HEX_LEN     16  /* c param hex string:  8 bytes = 16 chars */
#define NTAG424_MAX_URL      256  /* maximum URL length extracted from NDEF */

typedef enum {
	NTAG424_VERIFY_OK = 0,
	NTAG424_VERIFY_ERR_INVALID_ARGUMENT,
	NTAG424_VERIFY_ERR_PARAM_PARSE,
	NTAG424_VERIFY_ERR_P_HEX,
	NTAG424_VERIFY_ERR_C_HEX,
	NTAG424_VERIFY_ERR_CRYPTO,
	NTAG424_VERIFY_ERR_PICC_TAG,
	NTAG424_VERIFY_ERR_CMAC_MISMATCH,
	NTAG424_VERIFY_ERR_NDEF_TOO_SHORT,
	NTAG424_VERIFY_ERR_NDEF_NOT_URL,
	NTAG424_VERIFY_ERR_URL_TOO_LONG
} ntag424_verify_status_t;

/* Populated by ntag424_verify_p_c / ntag424_verify_from_ndef */
struct ntag424_verify_result {
	ntag424_verify_status_t status;
	uint8_t uid[NTAG424_UID_BYTES];
	/* counter_be[0] = MSB, counter_be[2] = LSB */
	uint8_t counter_be[NTAG424_COUNTER_BYTES];
	uint32_t counter_value;
};

/*
 * Extract p= and c= query parameters from a URL or bare query string.
 * Accepts "https://host/path?...&p=<32hex>&c=<16hex>&..." as well as
 * bare "p=<32hex>&c=<16hex>" (without a leading '?').
 */
ntag424_verify_status_t ntag424_extract_p_c(const char *input,
	char *p_hex, size_t p_hex_size,
	char *c_hex, size_t c_hex_size);

/*
 * Decrypt p with k1 to recover UID + counter, then verify the truncated
 * CMAC c against the expected value derived from k2.
 * On NTAG424_VERIFY_OK the result struct is fully populated.
 */
ntag424_verify_status_t ntag424_verify_p_c(
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	const char *p_hex,
	const char *c_hex,
	struct ntag424_verify_result *out);

/*
 * Convenience: combine ntag424_extract_p_c + ntag424_verify_p_c.
 * url may be a full URL or a bare query string.
 */
ntag424_verify_status_t ntag424_verify_from_url(
	const char *url,
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	struct ntag424_verify_result *out);

/*
 * Parse a raw NFC Forum NDEF message (starting at the record header byte,
 * without any 2-byte file-length prefix) and reconstruct the URL text.
 * Supports NFC Forum Well Known URI records (TNF=0x01, Type='U').
 * Handles both short-record (SR=1) and standard-record (SR=0) formats.
 */
ntag424_verify_status_t ntag424_extract_url_from_ndef(
	const uint8_t *ndef, size_t ndef_len,
	char *url, size_t url_size);

/*
 * Full pipeline: NDEF bytes -> extract URL -> extract p/c -> verify.
 * Equivalent to ntag424_extract_url_from_ndef + ntag424_verify_from_url.
 */
ntag424_verify_status_t ntag424_verify_from_ndef(
	const uint8_t *ndef, size_t ndef_len,
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	struct ntag424_verify_result *out);

/*
 * Compute a single-block AES-128 CMAC (RFC 4493, msg_len <= 16).
 * Exposed for unit testing of the CMAC primitive.
 */
ntag424_verify_status_t ntag424_cmac_compute(
	const uint8_t key[NTAG424_KEY_BYTES],
	const uint8_t *msg, size_t msg_len,
	uint8_t mac[NTAG424_KEY_BYTES]);

/*
 * Build the SV2 session derivation value and compute the full CMAC chain:
 *   ks = CMAC(k2, sv2)
 *   cm = CMAC(ks, empty)
 *   ct = cm[1,3,5,7,9,11,13,15]  (odd-indexed bytes, BoltCard truncation)
 * counter_be[0] is MSB, counter_be[2] is LSB.
 * All output pointers must point to buffers of the declared sizes.
 * Exposed for unit testing of intermediate values.
 */
ntag424_verify_status_t ntag424_sv2_and_ct(
	const uint8_t uid[NTAG424_UID_BYTES],
	const uint8_t counter_be[NTAG424_COUNTER_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	uint8_t sv2[NTAG424_KEY_BYTES],
	uint8_t ks[NTAG424_KEY_BYTES],
	uint8_t cm[NTAG424_KEY_BYTES],
	uint8_t ct[NTAG424_CT_BYTES]);

const char *ntag424_verify_status_string(ntag424_verify_status_t status);

/*
 * Derive K1 and K2 from an IssuerKey using the Bolt Card deterministic
 * key derivation algorithm:
 *   K1       = AES-CMAC(IssuerKey, 0x2d003f77)
 *   CardKey  = AES-CMAC(IssuerKey, 0x2d003f75 || UID(7) || Version(4 LE))
 *   K2       = AES-CMAC(CardKey, 0x2d003f78)
 *
 * uid must be 7 bytes, version is a 32-bit LE integer (typically 0 or 1).
 * k1_out and k2_out must each be 16-byte buffers.
 */
ntag424_verify_status_t ntag424_derive_keys(
	const uint8_t issuer_key[NTAG424_KEY_BYTES],
	const uint8_t uid[NTAG424_UID_BYTES],
	uint32_t version,
	uint8_t k1_out[NTAG424_KEY_BYTES],
	uint8_t k2_out[NTAG424_KEY_BYTES]);

#endif
