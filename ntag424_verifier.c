#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "ntag424_verifier.h"

#define NTAG424_BLOCK_BYTES 16
#define NTAG424_TRUNCATED_C_BYTES 8

static int ntag424_hex_nibble(const char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int ntag424_hex_to_bytes(const char *hex, uint8_t *out, size_t bytes)
{
	size_t i;

	if (!hex || !out) return -1;
	if (strlen(hex) != bytes * 2) return -1;
	for (i = 0; i < bytes; i++) {
		int hi = ntag424_hex_nibble(hex[i * 2]);
		int lo = ntag424_hex_nibble(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static void ntag424_shift_left_1(const uint8_t in[NTAG424_BLOCK_BYTES],
				 uint8_t out[NTAG424_BLOCK_BYTES])
{
	int i;
	uint8_t carry = 0;

	for (i = NTAG424_BLOCK_BYTES - 1; i >= 0; i--) {
		out[i] = (uint8_t)((in[i] << 1) | carry);
		carry = (uint8_t)(in[i] >> 7);
	}
}

static void ntag424_generate_subkey(const uint8_t in[NTAG424_BLOCK_BYTES],
				    uint8_t out[NTAG424_BLOCK_BYTES])
{
	uint8_t shifted[NTAG424_BLOCK_BYTES];
	uint8_t carry = (uint8_t)(in[0] >> 7);

	ntag424_shift_left_1(in, shifted);
	memcpy(out, shifted, sizeof(shifted));
	if (carry) out[NTAG424_BLOCK_BYTES - 1] ^= 0x87;
}

static int ntag424_aes_block_encrypt(const uint8_t key[NTAG424_KEY_BYTES],
				     const uint8_t in[NTAG424_BLOCK_BYTES],
				     uint8_t out[NTAG424_BLOCK_BYTES])
{
	unsigned long rc = encrypt(key, NTAG424_KEY_BYTES, in, out,
				   NTAG424_BLOCK_BYTES);
	return rc ? -1 : 0;
}

static int ntag424_aes_block_decrypt(const uint8_t key[NTAG424_KEY_BYTES],
				     const uint8_t in[NTAG424_BLOCK_BYTES],
				     uint8_t out[NTAG424_BLOCK_BYTES])
{
	unsigned long rc = decrypt(key, NTAG424_KEY_BYTES, in, out,
				   NTAG424_BLOCK_BYTES);
	return rc ? -1 : 0;
}

static int ntag424_cmac(const uint8_t key[NTAG424_KEY_BYTES],
			const uint8_t *msg,
			size_t msg_len,
			uint8_t mac[NTAG424_BLOCK_BYTES])
{
	uint8_t zero[NTAG424_BLOCK_BYTES] = {0};
	uint8_t l[NTAG424_BLOCK_BYTES];
	uint8_t k1[NTAG424_BLOCK_BYTES];
	uint8_t k2[NTAG424_BLOCK_BYTES];
	uint8_t m_last[NTAG424_BLOCK_BYTES];
	size_t i;

	if (msg_len > NTAG424_BLOCK_BYTES) return -1;
	if (ntag424_aes_block_encrypt(key, zero, l)) return -1;
	ntag424_generate_subkey(l, k1);
	ntag424_generate_subkey(k1, k2);

	if (msg_len == NTAG424_BLOCK_BYTES) {
		for (i = 0; i < NTAG424_BLOCK_BYTES; i++) {
			m_last[i] = msg[i] ^ k1[i];
		}
	} else {
		uint8_t padded[NTAG424_BLOCK_BYTES] = {0};
		if (msg_len > 0 && msg) memcpy(padded, msg, msg_len);
		padded[msg_len] = 0x80;
		for (i = 0; i < NTAG424_BLOCK_BYTES; i++) {
			m_last[i] = padded[i] ^ k2[i];
		}
	}
	return ntag424_aes_block_encrypt(key, m_last, mac);
}

static int ntag424_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
	return diff == 0;
}

const char *ntag424_verify_status_string(ntag424_verify_status_t status)
{
	switch (status) {
	case NTAG424_VERIFY_OK: return "ok";
	case NTAG424_VERIFY_ERR_INVALID_ARGUMENT: return "invalid argument";
	case NTAG424_VERIFY_ERR_PARAM_PARSE: return "parameter parse failed";
	case NTAG424_VERIFY_ERR_P_HEX: return "invalid p parameter";
	case NTAG424_VERIFY_ERR_C_HEX: return "invalid c parameter";
	case NTAG424_VERIFY_ERR_CRYPTO: return "crypto operation failed";
	case NTAG424_VERIFY_ERR_PICC_TAG: return "invalid decrypted PICC data tag";
	case NTAG424_VERIFY_ERR_CMAC_MISMATCH: return "cmac mismatch";
	case NTAG424_VERIFY_ERR_NDEF_TOO_SHORT: return "NDEF message too short";
	case NTAG424_VERIFY_ERR_NDEF_NOT_URL: return "NDEF record is not a URL";
	case NTAG424_VERIFY_ERR_URL_TOO_LONG: return "URL exceeds maximum length";
	default: return "unknown error";
	}
}

ntag424_verify_status_t ntag424_derive_keys(
	const uint8_t issuer_key[NTAG424_KEY_BYTES],
	const uint8_t uid[NTAG424_UID_BYTES],
	uint32_t version,
	uint8_t k1_out[NTAG424_KEY_BYTES],
	uint8_t k2_out[NTAG424_KEY_BYTES])
{
	uint8_t card_key[NTAG424_KEY_BYTES];
	uint8_t msg[15];
	ntag424_verify_status_t rc;

	if (!issuer_key || !uid || !k1_out || !k2_out)
		return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;

	/* K1 = CMAC(IssuerKey, 0x2d003f77) */
	rc = ntag424_cmac_compute(issuer_key,
				  (const uint8_t *)"\x2d\x00\x3f\x77", 4,
				  k1_out);
	if (rc != NTAG424_VERIFY_OK)
		return rc;

	/* CardKey = CMAC(IssuerKey, 0x2d003f75 || UID(7) || Version(4 LE)) */
	msg[0] = 0x2d; msg[1] = 0x00; msg[2] = 0x3f; msg[3] = 0x75;
	memcpy(msg + 4, uid, NTAG424_UID_BYTES);
	msg[11] = (uint8_t)(version);
	msg[12] = (uint8_t)(version >> 8);
	msg[13] = (uint8_t)(version >> 16);
	msg[14] = (uint8_t)(version >> 24);

	rc = ntag424_cmac_compute(issuer_key, msg, sizeof(msg), card_key);
	if (rc != NTAG424_VERIFY_OK)
		return rc;

	/* K2 = CMAC(CardKey, 0x2d003f78) */
	rc = ntag424_cmac_compute(card_key,
				  (const uint8_t *)"\x2d\x00\x3f\x78", 4,
				  k2_out);
	return rc;
}

ntag424_verify_status_t ntag424_extract_p_c(const char *input,
	char *p_hex, size_t p_hex_size,
	char *c_hex, size_t c_hex_size)
{
	const char *query;
	const char *cur;
	int p_found = 0;
	int c_found = 0;

	if (!input || !p_hex || !c_hex) return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	if (p_hex_size < NTAG424_P_HEX_LEN + 1) return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	if (c_hex_size < NTAG424_C_HEX_LEN + 1) return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;

	p_hex[0] = '\0';
	c_hex[0] = '\0';
	query = strchr(input, '?');
	cur = query ? query + 1 : input;

	while (*cur) {
		const char *tok_end = strchr(cur, '&');
		const char *eq = strchr(cur, '=');
		size_t tok_len = tok_end ? (size_t)(tok_end - cur) : strlen(cur);
		size_t key_len;
		size_t val_len;
		const char *val;

		if (!eq || eq >= cur + tok_len) return NTAG424_VERIFY_ERR_PARAM_PARSE;
		key_len = (size_t)(eq - cur);
		val = eq + 1;
		val_len = (size_t)((cur + tok_len) - val);

		if (key_len == 1 && cur[0] == 'p') {
			if (val_len != NTAG424_P_HEX_LEN) return NTAG424_VERIFY_ERR_P_HEX;
			memcpy(p_hex, val, val_len);
			p_hex[val_len] = '\0';
			p_found = 1;
		} else if (key_len == 1 && cur[0] == 'c') {
			if (val_len != NTAG424_C_HEX_LEN) return NTAG424_VERIFY_ERR_C_HEX;
			memcpy(c_hex, val, val_len);
			c_hex[val_len] = '\0';
			c_found = 1;
		}
		if (!tok_end) break;
		cur = tok_end + 1;
	}
	if (!p_found || !c_found) return NTAG424_VERIFY_ERR_PARAM_PARSE;
	return NTAG424_VERIFY_OK;
}

ntag424_verify_status_t ntag424_verify_p_c(
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	const char *p_hex,
	const char *c_hex,
	struct ntag424_verify_result *out)
{
	uint8_t p_bytes[NTAG424_BLOCK_BYTES];
	uint8_t plain[NTAG424_BLOCK_BYTES];
	uint8_t provided_c[NTAG424_TRUNCATED_C_BYTES];
	uint8_t sv2[NTAG424_BLOCK_BYTES];
	uint8_t ks[NTAG424_BLOCK_BYTES];
	uint8_t cm[NTAG424_BLOCK_BYTES];
	uint8_t expected_c[NTAG424_TRUNCATED_C_BYTES];
	size_t i;
	const char *crypto_name;
	ntag424_verify_status_t status = NTAG424_VERIFY_OK;

	if (!k1 || !k2 || !p_hex || !c_hex || !out) {
		return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	}

	memset(out, 0, sizeof(*out));
	out->status = NTAG424_VERIFY_ERR_INVALID_ARGUMENT;

	crypto_name = crypto_init(0);
	if (!crypto_name) return NTAG424_VERIFY_ERR_CRYPTO;

	if (ntag424_hex_to_bytes(p_hex, p_bytes, sizeof(p_bytes))) {
		status = NTAG424_VERIFY_ERR_P_HEX;
		goto done;
	}
	if (ntag424_hex_to_bytes(c_hex, provided_c, sizeof(provided_c))) {
		status = NTAG424_VERIFY_ERR_C_HEX;
		goto done;
	}
	if (ntag424_aes_block_decrypt(k1, p_bytes, plain)) {
		status = NTAG424_VERIFY_ERR_CRYPTO;
		goto done;
	}
	if (plain[0] != 0xC7) {
		status = NTAG424_VERIFY_ERR_PICC_TAG;
		goto done;
	}

	memcpy(out->uid, plain + 1, NTAG424_UID_BYTES);
	out->counter_be[0] = plain[10];
	out->counter_be[1] = plain[9];
	out->counter_be[2] = plain[8];
	out->counter_value = ((uint32_t)out->counter_be[0] << 16) |
			     ((uint32_t)out->counter_be[1] << 8) |
			     (uint32_t)out->counter_be[2];

	sv2[0] = 0x3C;
	sv2[1] = 0xC3;
	sv2[2] = 0x00;
	sv2[3] = 0x01;
	sv2[4] = 0x00;
	sv2[5] = 0x80;
	memcpy(sv2 + 6, out->uid, NTAG424_UID_BYTES);
	sv2[13] = out->counter_be[2];
	sv2[14] = out->counter_be[1];
	sv2[15] = out->counter_be[0];

	if (ntag424_cmac(k2, sv2, sizeof(sv2), ks)) {
		status = NTAG424_VERIFY_ERR_CRYPTO;
		goto done;
	}
	if (ntag424_cmac(ks, NULL, 0, cm)) {
		status = NTAG424_VERIFY_ERR_CRYPTO;
		goto done;
	}
	for (i = 0; i < sizeof(expected_c); i++) {
		expected_c[i] = cm[1 + (i * 2)];
	}
	if (!ntag424_constant_time_eq(expected_c, provided_c, sizeof(expected_c))) {
		status = NTAG424_VERIFY_ERR_CMAC_MISMATCH;
		goto done;
	}

	status = NTAG424_VERIFY_OK;
done:
	out->status = status;
	memset(plain, 0, sizeof(plain));
	memset(ks, 0, sizeof(ks));
	memset(cm, 0, sizeof(cm));
	memset(expected_c, 0, sizeof(expected_c));
	return status;
}

ntag424_verify_status_t ntag424_cmac_compute(
	const uint8_t key[NTAG424_KEY_BYTES],
	const uint8_t *msg, size_t msg_len,
	uint8_t mac[NTAG424_KEY_BYTES])
{
	const char *cname;

	if (!key || !mac) return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	cname = crypto_init(0);
	if (!cname) return NTAG424_VERIFY_ERR_CRYPTO;
	return ntag424_cmac(key, msg, msg_len, mac) ?
		NTAG424_VERIFY_ERR_CRYPTO : NTAG424_VERIFY_OK;
}

ntag424_verify_status_t ntag424_sv2_and_ct(
	const uint8_t uid[NTAG424_UID_BYTES],
	const uint8_t counter_be[NTAG424_COUNTER_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	uint8_t sv2[NTAG424_KEY_BYTES],
	uint8_t ks[NTAG424_KEY_BYTES],
	uint8_t cm[NTAG424_KEY_BYTES],
	uint8_t ct[NTAG424_CT_BYTES])
{
	size_t i;
	const char *cname;

	if (!uid || !counter_be || !k2 || !sv2 || !ks || !cm || !ct)
		return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	cname = crypto_init(0);
	if (!cname) return NTAG424_VERIFY_ERR_CRYPTO;

	sv2[0]  = 0x3C; sv2[1]  = 0xC3; sv2[2]  = 0x00;
	sv2[3]  = 0x01; sv2[4]  = 0x00; sv2[5]  = 0x80;
	memcpy(sv2 + 6, uid, NTAG424_UID_BYTES);
	/* counter_be[2] is LSB; SV2 places counter LSB at byte 13 */
	sv2[13] = counter_be[2];
	sv2[14] = counter_be[1];
	sv2[15] = counter_be[0];

	if (ntag424_cmac(k2, sv2, NTAG424_KEY_BYTES, ks)) return NTAG424_VERIFY_ERR_CRYPTO;
	if (ntag424_cmac(ks, NULL, 0, cm)) return NTAG424_VERIFY_ERR_CRYPTO;
	for (i = 0; i < NTAG424_CT_BYTES; i++) ct[i] = cm[1 + i * 2];
	return NTAG424_VERIFY_OK;
}

/*
 * NFC Forum URI Identifier Codes (subset used for BoltCard / NTAG424).
 * Ref: NFC Forum URI Record Type Definition (RTD) 1.0, Section 3.2.2.
 */
static const char * const ntag424_uri_prefixes[] = {
	"",              /* 0x00 – no prefix */
	"http://www.",   /* 0x01 */
	"https://www.",  /* 0x02 */
	"http://",       /* 0x03 */
	"https://",      /* 0x04 */
	"tel:",          /* 0x05 */
	"mailto:",       /* 0x06 */
	"ftp://anonymous:anonymous@", /* 0x07 */
	"ftp://ftp.",    /* 0x08 */
	"ftps://",       /* 0x09 */
	"sftp://",       /* 0x0A */
	"smb://",        /* 0x0B */
	"nfs://",        /* 0x0C */
	"ftp://",        /* 0x0D */
	"dav://",        /* 0x0E */
	"news:",         /* 0x0F */
	"telnet://",     /* 0x10 */
	"imap:",         /* 0x11 */
	"rtsp://",       /* 0x12 */
	"urn:",          /* 0x13 */
	"pop:",          /* 0x14 */
	"sip:",          /* 0x15 */
	"sips:",         /* 0x16 */
	"tftp:",         /* 0x17 */
	"btspp://",      /* 0x18 */
	"btl2cap://",    /* 0x19 */
	"btgoep://",     /* 0x1A */
	"tcpobex://",    /* 0x1B */
	"irdaobex://",   /* 0x1C */
	"file://",       /* 0x1D */
	"urn:epc:id:",   /* 0x1E */
	"urn:epc:tag:",  /* 0x1F */
	"urn:epc:pat:",  /* 0x20 */
	"urn:epc:raw:",  /* 0x21 */
	"urn:epc:",      /* 0x22 */
	"urn:nfc:",      /* 0x23 */
};

#define NTAG424_URI_PREFIX_COUNT \
	(sizeof(ntag424_uri_prefixes) / sizeof(ntag424_uri_prefixes[0]))

ntag424_verify_status_t ntag424_extract_url_from_ndef(
	const uint8_t *ndef, size_t ndef_len,
	char *url, size_t url_size)
{
	uint8_t hdr, tnf, sr, il;
	uint8_t type_len, id_len;
	uint32_t payload_len;
	size_t offset;
	uint8_t prefix_code;
	const char *prefix_str;
	size_t prefix_slen, suffix_len, total_len;

	if (!ndef || !url || url_size == 0)
		return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;

	/* Need at least: header + type_len + payload_len(1 or 4) + type(1) + payload_prefix(1) */
	if (ndef_len < 5) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;

	hdr      = ndef[0];
	tnf      = (uint8_t)(hdr & 0x07);
	sr       = (uint8_t)((hdr >> 4) & 0x01);
	il       = (uint8_t)((hdr >> 3) & 0x01);
	type_len = ndef[1];
	offset   = 2;

	/* Payload length: 1 byte when SR=1, 4 bytes (big-endian) when SR=0 */
	if (sr) {
		if (ndef_len < offset + 1) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;
		payload_len = ndef[offset++];
	} else {
		if (ndef_len < offset + 4) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;
		payload_len = ((uint32_t)ndef[offset]     << 24) |
			      ((uint32_t)ndef[offset + 1] << 16) |
			      ((uint32_t)ndef[offset + 2] <<  8) |
			       (uint32_t)ndef[offset + 3];
		offset += 4;
	}

	/* Optional ID Length field */
	if (il) {
		if (ndef_len < offset + 1) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;
		id_len = ndef[offset++];
	} else {
		id_len = 0;
	}

	/* Type bytes */
	if (ndef_len < offset + type_len) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;

	/* Check: Well Known type (TNF=0x01), single-byte type, type byte = 'U' (0x55) */
	if (tnf != 0x01 || type_len != 1 || ndef[offset] != 0x55)
		return NTAG424_VERIFY_ERR_NDEF_NOT_URL;
	offset += type_len;

	/* Skip optional ID field */
	if (id_len > 0) {
		if (ndef_len < offset + id_len) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;
		offset += id_len;
	}

	/* Payload: at least 1 byte (the URI prefix code) */
	if (ndef_len < offset + payload_len) return NTAG424_VERIFY_ERR_NDEF_TOO_SHORT;
	if (payload_len < 1) return NTAG424_VERIFY_ERR_NDEF_NOT_URL;

	prefix_code = ndef[offset];
	if (prefix_code < (uint8_t)NTAG424_URI_PREFIX_COUNT)
		prefix_str = ntag424_uri_prefixes[prefix_code];
	else
		prefix_str = "";

	prefix_slen = strlen(prefix_str);
	suffix_len  = payload_len - 1;
	total_len   = prefix_slen + suffix_len;

	if (total_len + 1 > url_size) return NTAG424_VERIFY_ERR_URL_TOO_LONG;

	memcpy(url, prefix_str, prefix_slen);
	memcpy(url + prefix_slen, ndef + offset + 1, suffix_len);
	url[total_len] = '\0';
	return NTAG424_VERIFY_OK;
}

ntag424_verify_status_t ntag424_verify_from_url(
	const char *url,
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	struct ntag424_verify_result *out)
{
	char p_hex[NTAG424_P_HEX_LEN + 1];
	char c_hex[NTAG424_C_HEX_LEN + 1];
	ntag424_verify_status_t rc;

	if (!url || !k1 || !k2 || !out) return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	rc = ntag424_extract_p_c(url, p_hex, sizeof(p_hex), c_hex, sizeof(c_hex));
	if (rc != NTAG424_VERIFY_OK) return rc;
	return ntag424_verify_p_c(k1, k2, p_hex, c_hex, out);
}

ntag424_verify_status_t ntag424_verify_from_ndef(
	const uint8_t *ndef, size_t ndef_len,
	const uint8_t k1[NTAG424_KEY_BYTES],
	const uint8_t k2[NTAG424_KEY_BYTES],
	struct ntag424_verify_result *out)
{
	char url[NTAG424_MAX_URL];
	ntag424_verify_status_t rc;

	if (!ndef || !k1 || !k2 || !out) return NTAG424_VERIFY_ERR_INVALID_ARGUMENT;
	rc = ntag424_extract_url_from_ndef(ndef, ndef_len, url, sizeof(url));
	if (rc != NTAG424_VERIFY_OK) return rc;
	return ntag424_verify_from_url(url, k1, k2, out);
}
