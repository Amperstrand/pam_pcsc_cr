/*
 * test_ntag424_verifier.c — comprehensive unit tests for the ntag424_verifier
 * module.
 *
 * Tests are organised into groups:
 *  A. ntag424_extract_p_c          — URL / query string parameter extraction
 *  B. ntag424_cmac_compute         — RFC 4493 AES-CMAC primitive
 *  C. ntag424_sv2_and_ct           — intermediate CMAC chain values
 *  D. ntag424_verify_p_c           — core p/c decryption + CMAC verification
 *  E. ntag424_extract_url_from_ndef — NDEF message → URL string
 *  F. ntag424_verify_from_ndef /
 *     ntag424_verify_from_url      — full pipeline tests
 *
 * All test vectors (BoltCard and RFC 4493) are drawn from:
 *  - tests/cryptoutils.test.js in the boltcard-cloudflareworker compare branch
 *  - RFC 4493 §4 (AES-CMAC test vectors)
 *  - NXP AN12196 (SDM/SUN verification background)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ntag424_verifier.h"

/* ── test harness ────────────────────────────────────────────────────────── */

static int tests_run    = 0;
static int tests_passed = 0;

#define ASSERT(label, cond) do { \
	tests_run++; \
	if (cond) { \
		tests_passed++; \
	} else { \
		printf("FAIL: %s (line %d)\n", label, __LINE__); \
	} \
} while (0)

/* helpers */
static int parse_hex(const char *hex, uint8_t *out, size_t bytes)
{
	size_t i;
	for (i = 0; i < bytes; i++) {
		unsigned int b;
		if (sscanf(hex + (i * 2), "%2x", &b) != 1) return -1;
		out[i] = (uint8_t)b;
	}
	return 0;
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

/*
 * Build an NFC Forum short-record URI NDEF message in buf[].
 * Returns the number of bytes written.
 * prefix_code: NFC URI Identifier Code (e.g. 0x04 for "https://")
 * suffix: the URL text after the prefix (not NUL-terminated for the NDEF,
 *         but must be a C string for strlen()).
 */
static size_t build_ndef_url(uint8_t *buf, size_t bufsz,
			     uint8_t prefix_code, const char *suffix,
			     int short_record)
{
	size_t suffix_len = strlen(suffix);
	uint32_t payload_len = (uint32_t)(suffix_len + 1); /* +1 for prefix byte */
	size_t offset = 0;

	if (short_record) {
		/* SR=1: header 0xD1, type_len 0x01, payload_len 1 byte */
		if (offset + 4 + suffix_len > bufsz) return 0;
		buf[offset++] = 0xD1;                    /* MB ME SR TNF=WellKnown */
		buf[offset++] = 0x01;                    /* type length */
		buf[offset++] = (uint8_t)payload_len;    /* payload length (1 byte) */
		buf[offset++] = 0x55;                    /* type 'U' */
	} else {
		/* SR=0: header 0xC1, type_len 0x01, payload_len 4 bytes BE */
		if (offset + 7 + suffix_len > bufsz) return 0;
		buf[offset++] = 0xC1;                    /* MB ME ~SR TNF=WellKnown */
		buf[offset++] = 0x01;                    /* type length */
		buf[offset++] = (uint8_t)((payload_len >> 24) & 0xFF);
		buf[offset++] = (uint8_t)((payload_len >> 16) & 0xFF);
		buf[offset++] = (uint8_t)((payload_len >>  8) & 0xFF);
		buf[offset++] = (uint8_t)( payload_len        & 0xFF);
		buf[offset++] = 0x55;                    /* type 'U' */
	}
	buf[offset++] = prefix_code;
	memcpy(buf + offset, suffix, suffix_len);
	offset += suffix_len;
	return offset;
}

/* ── A. ntag424_extract_p_c ─────────────────────────────────────────────── */

static void test_extract_full_url(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	const char *url =
		"https://localhost/path?x=1&p=4E2E289D945A66BB13377A728884E867"
		"&c=E19CCB1FED8892CE";
	ntag424_verify_status_t rc =
		ntag424_extract_p_c(url, p, sizeof(p), c, sizeof(c));
	ASSERT("extract_full_url_status", rc == NTAG424_VERIFY_OK);
	ASSERT("extract_full_url_p",
	       strcmp(p, "4E2E289D945A66BB13377A728884E867") == 0);
	ASSERT("extract_full_url_c",
	       strcmp(c, "E19CCB1FED8892CE") == 0);
}

static void test_extract_c_before_p(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	/* c appears before p — parser must handle any order */
	const char *url =
		"https://localhost/?c=E19CCB1FED8892CE"
		"&p=4E2E289D945A66BB13377A728884E867";
	ntag424_verify_status_t rc =
		ntag424_extract_p_c(url, p, sizeof(p), c, sizeof(c));
	ASSERT("extract_c_before_p_status", rc == NTAG424_VERIFY_OK);
	ASSERT("extract_c_before_p_p",
	       strcmp(p, "4E2E289D945A66BB13377A728884E867") == 0);
	ASSERT("extract_c_before_p_c",
	       strcmp(c, "E19CCB1FED8892CE") == 0);
}

static void test_extract_extra_params(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	/* extra params before and after p/c must be ignored */
	const char *url =
		"https://host/?a=1&b=2"
		"&p=4E2E289D945A66BB13377A728884E867"
		"&q=xyz"
		"&c=E19CCB1FED8892CE"
		"&z=end";
	ntag424_verify_status_t rc =
		ntag424_extract_p_c(url, p, sizeof(p), c, sizeof(c));
	ASSERT("extract_extra_status", rc == NTAG424_VERIFY_OK);
	ASSERT("extract_extra_p",
	       strcmp(p, "4E2E289D945A66BB13377A728884E867") == 0);
	ASSERT("extract_extra_c",
	       strcmp(c, "E19CCB1FED8892CE") == 0);
}

static void test_extract_bare_query(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	/* bare query string without a leading '?' must also work */
	const char *bare =
		"p=4E2E289D945A66BB13377A728884E867&c=E19CCB1FED8892CE";
	ntag424_verify_status_t rc =
		ntag424_extract_p_c(bare, p, sizeof(p), c, sizeof(c));
	ASSERT("extract_bare_status", rc == NTAG424_VERIFY_OK);
	ASSERT("extract_bare_p",
	       strcmp(p, "4E2E289D945A66BB13377A728884E867") == 0);
	ASSERT("extract_bare_c",
	       strcmp(c, "E19CCB1FED8892CE") == 0);
}

static void test_extract_missing_c(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	ntag424_verify_status_t rc =
		ntag424_extract_p_c("p=4E2E289D945A66BB13377A728884E867",
				    p, sizeof(p), c, sizeof(c));
	ASSERT("extract_missing_c", rc == NTAG424_VERIFY_ERR_PARAM_PARSE);
}

static void test_extract_missing_p(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	ntag424_verify_status_t rc =
		ntag424_extract_p_c("?c=E19CCB1FED8892CE",
				    p, sizeof(p), c, sizeof(c));
	ASSERT("extract_missing_p", rc == NTAG424_VERIFY_ERR_PARAM_PARSE);
}

static void test_extract_p_wrong_len(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	/* p too short — 30 hex chars instead of 32 */
	ntag424_verify_status_t rc =
		ntag424_extract_p_c(
			"?p=4E2E289D945A66BB13377A728884&c=E19CCB1FED8892CE",
			p, sizeof(p), c, sizeof(c));
	ASSERT("extract_p_short", rc == NTAG424_VERIFY_ERR_P_HEX);
}

static void test_extract_c_wrong_len(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	/* c too short — 14 hex chars instead of 16 */
	ntag424_verify_status_t rc =
		ntag424_extract_p_c(
			"?p=4E2E289D945A66BB13377A728884E867&c=E19CCB1FED889",
			p, sizeof(p), c, sizeof(c));
	ASSERT("extract_c_short", rc == NTAG424_VERIFY_ERR_C_HEX);
}

static void test_extract_null_args(void)
{
	char p[NTAG424_P_HEX_LEN + 1], c[NTAG424_C_HEX_LEN + 1];
	ASSERT("extract_null_input",
	       ntag424_extract_p_c(NULL, p, sizeof(p), c, sizeof(c))
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("extract_null_p_buf",
	       ntag424_extract_p_c("?p=x&c=y", NULL, sizeof(p), c, sizeof(c))
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("extract_null_c_buf",
	       ntag424_extract_p_c("?p=x&c=y", p, sizeof(p), NULL, sizeof(c))
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	/* buffer too small for p */
	ASSERT("extract_p_buf_small",
	       ntag424_extract_p_c("?p=x&c=y", p, 5, c, sizeof(c))
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
}

/* ── B. ntag424_cmac_compute — RFC 4493 §4 test vectors ─────────────────── */

/*
 * RFC 4493 §4 Example 1 — empty message
 * Key  = 2b7e151628aed2a6abf7158809cf4f3c
 * CMAC = bb1d6929e95937287fa37d129b756746
 */
static void test_rfc4493_cmac_empty(void)
{
	uint8_t key[16], mac[16];
	const uint8_t expected[] = {
		0xbb,0x1d,0x69,0x29, 0xe9,0x59,0x37,0x28,
		0x7f,0xa3,0x7d,0x12, 0x9b,0x75,0x67,0x46
	};
	ASSERT("rfc4493_empty_parse_key",
	       parse_hex("2b7e151628aed2a6abf7158809cf4f3c", key, 16) == 0);
	ASSERT("rfc4493_empty_rc",
	       ntag424_cmac_compute(key, NULL, 0, mac) == NTAG424_VERIFY_OK);
	ASSERT("rfc4493_empty_mac", bytes_eq(mac, expected, 16));
}

/*
 * RFC 4493 §4 Example 2 — 16-byte (one full block) message
 * Key  = 2b7e151628aed2a6abf7158809cf4f3c
 * Msg  = 6bc1bee22e409f96e93d7e117393172a
 * CMAC = 070a16b46b4d4144f79bdd9dd04a287c
 */
static void test_rfc4493_cmac_oneblock(void)
{
	uint8_t key[16], msg[16], mac[16];
	const uint8_t expected[] = {
		0x07,0x0a,0x16,0xb4, 0x6b,0x4d,0x41,0x44,
		0xf7,0x9b,0xdd,0x9d, 0xd0,0x4a,0x28,0x7c
	};
	ASSERT("rfc4493_1block_parse_key",
	       parse_hex("2b7e151628aed2a6abf7158809cf4f3c", key, 16) == 0);
	ASSERT("rfc4493_1block_parse_msg",
	       parse_hex("6bc1bee22e409f96e93d7e117393172a", msg, 16) == 0);
	ASSERT("rfc4493_1block_rc",
	       ntag424_cmac_compute(key, msg, 16, mac) == NTAG424_VERIFY_OK);
	ASSERT("rfc4493_1block_mac", bytes_eq(mac, expected, 16));
}

static void test_cmac_null_args(void)
{
	uint8_t key[16] = {0}, mac[16];
	ASSERT("cmac_null_key",
	       ntag424_cmac_compute(NULL, NULL, 0, mac)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("cmac_null_mac",
	       ntag424_cmac_compute(key, NULL, 0, NULL)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
}

/* ── C. ntag424_sv2_and_ct — intermediate values ────────────────────────── */

/*
 * BoltCard test vector 1: UID = 04996c6a926980, counter = 3
 * k2 = b45775776cb224c75bcde7ca3704e933
 *
 * Expected values from tests/cryptoutils.test.js TEST_VECTORS[0]:
 *   sv2 = 3cc3000100800499 6c6a926980030000
 *   ks  = f25c4b5ce6ab3ff4 05f287afac4e4d1a
 *   cm  = 76e1e99ceecb401f a3ed6e887092 7cce
 *   ct  = e19ccb1fed8892ce
 */
static void test_sv2_vector1(void)
{
	uint8_t uid[7], counter_be[3], k2[16];
	uint8_t sv2[16], ks[16], cm[16], ct[8];
	const uint8_t exp_sv2[] = {
		0x3c,0xc3,0x00,0x01,0x00,0x80,
		0x04,0x99,0x6c,0x6a,0x92,0x69,0x80,
		0x03,0x00,0x00
	};
	const uint8_t exp_ks[] = {
		0xf2,0x5c,0x4b,0x5c,0xe6,0xab,0x3f,0xf4,
		0x05,0xf2,0x87,0xaf,0xac,0x4e,0x4d,0x1a
	};
	const uint8_t exp_cm[] = {
		0x76,0xe1,0xe9,0x9c,0xee,0xcb,0x40,0x1f,
		0xa3,0xed,0x6e,0x88,0x70,0x92,0x7c,0xce
	};
	const uint8_t exp_ct[] = {
		0xe1,0x9c,0xcb,0x1f,0xed,0x88,0x92,0xce
	};
	ntag424_verify_status_t rc;

	ASSERT("sv2v1_parse_uid",
	       parse_hex("04996c6a926980", uid, 7) == 0);
	ASSERT("sv2v1_parse_k2",
	       parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);
	/* counter=3 in big-endian MSB-first */
	counter_be[0] = 0x00; counter_be[1] = 0x00; counter_be[2] = 0x03;

	rc = ntag424_sv2_and_ct(uid, counter_be, k2, sv2, ks, cm, ct);
	ASSERT("sv2v1_rc",  rc == NTAG424_VERIFY_OK);
	ASSERT("sv2v1_sv2", bytes_eq(sv2, exp_sv2, 16));
	ASSERT("sv2v1_ks",  bytes_eq(ks,  exp_ks,  16));
	ASSERT("sv2v1_cm",  bytes_eq(cm,  exp_cm,  16));
	ASSERT("sv2v1_ct",  bytes_eq(ct,  exp_ct,   8));
}

/*
 * BoltCard test vector 2: UID = 04996c6a926980, counter = 5
 * k2 = b45775776cb224c75bcde7ca3704e933
 *
 * Expected values from tests/cryptoutils.test.js TEST_VECTORS[1]:
 *   sv2 = 3cc3000100800499 6c6a926980050000
 *   ks  = 4946276974187e98 60658bbd8210c8be
 *   cm  = 5e66f3b45d82026e c6a4f1c14355 70b4
 *   ct  = 66b4826ea4c155b4
 */
static void test_sv2_vector2(void)
{
	uint8_t uid[7], counter_be[3], k2[16];
	uint8_t sv2[16], ks[16], cm[16], ct[8];
	const uint8_t exp_sv2[] = {
		0x3c,0xc3,0x00,0x01,0x00,0x80,
		0x04,0x99,0x6c,0x6a,0x92,0x69,0x80,
		0x05,0x00,0x00
	};
	const uint8_t exp_ks[] = {
		0x49,0x46,0x27,0x69,0x74,0x18,0x7e,0x98,
		0x60,0x65,0x8b,0xbd,0x82,0x10,0xc8,0xbe
	};
	const uint8_t exp_cm[] = {
		0x5e,0x66,0xf3,0xb4,0x5d,0x82,0x02,0x6e,
		0xc6,0xa4,0xf1,0xc1,0x43,0x55,0x70,0xb4
	};
	const uint8_t exp_ct[] = {
		0x66,0xb4,0x82,0x6e,0xa4,0xc1,0x55,0xb4
	};
	ntag424_verify_status_t rc;

	ASSERT("sv2v2_parse_uid",
	       parse_hex("04996c6a926980", uid, 7) == 0);
	ASSERT("sv2v2_parse_k2",
	       parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);
	counter_be[0] = 0x00; counter_be[1] = 0x00; counter_be[2] = 0x05;

	rc = ntag424_sv2_and_ct(uid, counter_be, k2, sv2, ks, cm, ct);
	ASSERT("sv2v2_rc",  rc == NTAG424_VERIFY_OK);
	ASSERT("sv2v2_sv2", bytes_eq(sv2, exp_sv2, 16));
	ASSERT("sv2v2_ks",  bytes_eq(ks,  exp_ks,  16));
	ASSERT("sv2v2_cm",  bytes_eq(cm,  exp_cm,  16));
	ASSERT("sv2v2_ct",  bytes_eq(ct,  exp_ct,   8));
}

/*
 * BoltCard test vector 3: UID = 04996c6a926980, counter = 7
 * k2 = b45775776cb224c75bcde7ca3704e933
 *
 * Expected values from tests/cryptoutils.test.js TEST_VECTORS[2]:
 *   sv2 = 3cc3000100800499 6c6a926980070000
 *   ks  = 61bdb1510f4fd905 665fa23ac0c72661
 *   cm  = 28ccca61576606 0c6502fa0bc74d4996
 *   ct  = cc61660c020b4d96
 */
static void test_sv2_vector3(void)
{
	uint8_t uid[7], counter_be[3], k2[16];
	uint8_t sv2[16], ks[16], cm[16], ct[8];
	const uint8_t exp_sv2[] = {
		0x3c,0xc3,0x00,0x01,0x00,0x80,
		0x04,0x99,0x6c,0x6a,0x92,0x69,0x80,
		0x07,0x00,0x00
	};
	const uint8_t exp_ks[] = {
		0x61,0xbd,0xb1,0x51,0x0f,0x4f,0xd9,0x05,
		0x66,0x5f,0xa2,0x3a,0xc0,0xc7,0x26,0x61
	};
	const uint8_t exp_cm[] = {
		0x28,0xcc,0xca,0x61,0x57,0x66,0x06,0x0c,
		0x65,0x02,0xfa,0x0b,0xc7,0x4d,0x49,0x96
	};
	const uint8_t exp_ct[] = {
		0xcc,0x61,0x66,0x0c,0x02,0x0b,0x4d,0x96
	};
	ntag424_verify_status_t rc;

	ASSERT("sv2v3_parse_uid",
	       parse_hex("04996c6a926980", uid, 7) == 0);
	ASSERT("sv2v3_parse_k2",
	       parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);
	counter_be[0] = 0x00; counter_be[1] = 0x00; counter_be[2] = 0x07;

	rc = ntag424_sv2_and_ct(uid, counter_be, k2, sv2, ks, cm, ct);
	ASSERT("sv2v3_rc",  rc == NTAG424_VERIFY_OK);
	ASSERT("sv2v3_sv2", bytes_eq(sv2, exp_sv2, 16));
	ASSERT("sv2v3_ks",  bytes_eq(ks,  exp_ks,  16));
	ASSERT("sv2v3_cm",  bytes_eq(cm,  exp_cm,  16));
	ASSERT("sv2v3_ct",  bytes_eq(ct,  exp_ct,   8));
}

static void test_sv2_null_args(void)
{
	uint8_t uid[7] = {0}, ctr[3] = {0}, k2[16] = {0};
	uint8_t sv2[16], ks[16], cm[16], ct[8];
	ASSERT("sv2_null_uid",
	       ntag424_sv2_and_ct(NULL, ctr, k2, sv2, ks, cm, ct)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("sv2_null_k2",
	       ntag424_sv2_and_ct(uid, ctr, NULL, sv2, ks, cm, ct)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("sv2_null_ct",
	       ntag424_sv2_and_ct(uid, ctr, k2, sv2, ks, cm, NULL)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
}

/* ── D. ntag424_verify_p_c ───────────────────────────────────────────────── */

/*
 * All three BoltCard test vectors:
 *   k1 = 0c3b25d92b38ae443229dd59ad34b85d
 *   k2 = b45775776cb224c75bcde7ca3704e933
 *   UID = 04996c6a926980 for all three
 */
static void test_verify_vector1(void)
{
	uint8_t k1[16], k2[16];
	struct ntag424_verify_result out;
	const uint8_t exp_uid[] = {
		0x04,0x99,0x6c,0x6a,0x92,0x69,0x80
	};
	ntag424_verify_status_t rc;

	ASSERT("v1_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("v1_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	rc = ntag424_verify_p_c(k1, k2,
				"4E2E289D945A66BB13377A728884E867",
				"E19CCB1FED8892CE", &out);
	ASSERT("v1_status",  rc == NTAG424_VERIFY_OK);
	ASSERT("v1_uid",     bytes_eq(out.uid, exp_uid, 7));
	ASSERT("v1_counter", out.counter_value == 3U);
}

static void test_verify_vector2(void)
{
	uint8_t k1[16], k2[16];
	struct ntag424_verify_result out;
	const uint8_t exp_uid[] = {
		0x04,0x99,0x6c,0x6a,0x92,0x69,0x80
	};
	ntag424_verify_status_t rc;

	ASSERT("v2_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("v2_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	rc = ntag424_verify_p_c(k1, k2,
				"00F48C4F8E386DED06BCDC78FA92E2FE",
				"66B4826EA4C155B4", &out);
	ASSERT("v2_status",  rc == NTAG424_VERIFY_OK);
	ASSERT("v2_uid",     bytes_eq(out.uid, exp_uid, 7));
	ASSERT("v2_counter", out.counter_value == 5U);
}

static void test_verify_vector3(void)
{
	uint8_t k1[16], k2[16];
	struct ntag424_verify_result out;
	const uint8_t exp_uid[] = {
		0x04,0x99,0x6c,0x6a,0x92,0x69,0x80
	};
	ntag424_verify_status_t rc;

	ASSERT("v3_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("v3_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	rc = ntag424_verify_p_c(k1, k2,
				"0DBF3C59B59B0638D60B5842A997D4D1",
				"CC61660C020B4D96", &out);
	ASSERT("v3_status",  rc == NTAG424_VERIFY_OK);
	ASSERT("v3_uid",     bytes_eq(out.uid, exp_uid, 7));
	ASSERT("v3_counter", out.counter_value == 7U);
}

static void test_verify_bad_cmac(void)
{
	uint8_t k1[16], k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("badcmac_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("badcmac_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	rc = ntag424_verify_p_c(k1, k2,
				"4E2E289D945A66BB13377A728884E867",
				"0000000000000000", &out);
	ASSERT("badcmac_status", rc == NTAG424_VERIFY_ERR_CMAC_MISMATCH);
}

static void test_verify_wrong_k1(void)
{
	uint8_t k1_wrong[16], k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	/* wrong K1 → plaintext[0] != 0xC7 */
	ASSERT("wrongk1_parse_k1", parse_hex("00000000000000000000000000000000", k1_wrong, 16) == 0);
	ASSERT("wrongk1_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	rc = ntag424_verify_p_c(k1_wrong, k2,
				"4E2E289D945A66BB13377A728884E867",
				"E19CCB1FED8892CE", &out);
	ASSERT("wrongk1_picc_tag", rc == NTAG424_VERIFY_ERR_PICC_TAG);
}

static void test_verify_bad_p_hex(void)
{
	uint8_t k1[16], k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("badhex_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("badhex_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	/* non-hex chars in p */
	rc = ntag424_verify_p_c(k1, k2,
				"ZZZZ289D945A66BB13377A728884E867",
				"E19CCB1FED8892CE", &out);
	ASSERT("bad_p_hex", rc == NTAG424_VERIFY_ERR_P_HEX);

	/* non-hex chars in c */
	rc = ntag424_verify_p_c(k1, k2,
				"4E2E289D945A66BB13377A728884E867",
				"XYZCCB1FED8892CE", &out);
	ASSERT("bad_c_hex", rc == NTAG424_VERIFY_ERR_C_HEX);
}

static void test_verify_null_args(void)
{
	uint8_t k1[16] = {0}, k2[16] = {0};
	struct ntag424_verify_result out;
	const char *p = "4E2E289D945A66BB13377A728884E867";
	const char *c = "E19CCB1FED8892CE";

	ASSERT("verify_null_k1",
	       ntag424_verify_p_c(NULL, k2, p, c, &out)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("verify_null_k2",
	       ntag424_verify_p_c(k1, NULL, p, c, &out)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("verify_null_p",
	       ntag424_verify_p_c(k1, k2, NULL, c, &out)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("verify_null_out",
	       ntag424_verify_p_c(k1, k2, p, c, NULL)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
}

/* ── E. ntag424_extract_url_from_ndef ────────────────────────────────────── */

static void test_ndef_short_record_https(void)
{
	/* https:// (prefix code 0x04) */
	const char *suffix =
		"localhost/?p=4E2E289D945A66BB13377A728884E867"
		"&c=E19CCB1FED8892CE";
	const char *expected_url =
		"https://localhost/?p=4E2E289D945A66BB13377A728884E867"
		"&c=E19CCB1FED8892CE";
	uint8_t ndef[256];
	char url[NTAG424_MAX_URL];
	size_t ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x04, suffix, 1);
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, ndef_len, url, sizeof(url));
	ASSERT("ndef_short_https_rc",  rc == NTAG424_VERIFY_OK);
	ASSERT("ndef_short_https_url", strcmp(url, expected_url) == 0);
}

static void test_ndef_standard_record(void)
{
	/* SR=0 (non-short record), prefix 0x04 = https:// */
	const char *suffix = "example.com/?p=0DBF3C59B59B0638D60B5842A997D4D1"
			     "&c=CC61660C020B4D96";
	const char *expected_url = "https://example.com/?p=0DBF3C59B59B0638"
				   "D60B5842A997D4D1&c=CC61660C020B4D96";
	uint8_t ndef[256];
	char url[NTAG424_MAX_URL];
	size_t ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x04, suffix, 0);
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, ndef_len, url, sizeof(url));
	ASSERT("ndef_standard_rc",  rc == NTAG424_VERIFY_OK);
	ASSERT("ndef_standard_url", strcmp(url, expected_url) == 0);
}

static void test_ndef_http_prefix(void)
{
	/* http:// (prefix code 0x03) */
	const char *suffix = "example.org/path?foo=bar";
	const char *expected_url = "http://example.org/path?foo=bar";
	uint8_t ndef[128];
	char url[NTAG424_MAX_URL];
	size_t ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x03, suffix, 1);
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, ndef_len, url, sizeof(url));
	ASSERT("ndef_http_rc",  rc == NTAG424_VERIFY_OK);
	ASSERT("ndef_http_url", strcmp(url, expected_url) == 0);
}

static void test_ndef_no_prefix(void)
{
	/* no prefix (code 0x00) — full URL in suffix */
	const char *suffix = "https://full.example.com/?x=1";
	uint8_t ndef[128];
	char url[NTAG424_MAX_URL];
	size_t ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x00, suffix, 1);
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, ndef_len, url, sizeof(url));
	ASSERT("ndef_noprefix_rc",  rc == NTAG424_VERIFY_OK);
	/* prefix "" + suffix → same as suffix */
	ASSERT("ndef_noprefix_url", strcmp(url, suffix) == 0);
}

static void test_ndef_too_short(void)
{
	uint8_t ndef[4] = {0xD1, 0x01, 0x08, 0x55};
	char url[NTAG424_MAX_URL];
	/* 4 bytes but claims 8-byte payload → too short */
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, sizeof(ndef), url, sizeof(url));
	ASSERT("ndef_tooshort", rc == NTAG424_VERIFY_ERR_NDEF_TOO_SHORT);
}

static void test_ndef_too_short_header_only(void)
{
	uint8_t ndef[2] = {0xD1, 0x01};
	char url[NTAG424_MAX_URL];
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, sizeof(ndef), url, sizeof(url));
	ASSERT("ndef_tooshort_hdr", rc == NTAG424_VERIFY_ERR_NDEF_TOO_SHORT);
}

static void test_ndef_not_url_wrong_tnf(void)
{
	/* TNF = 0x02 (Media) instead of 0x01 (Well Known) */
	uint8_t ndef[] = {0xD2, 0x01, 0x03, 0x55, 0x04, 'a', 'b'};
	char url[NTAG424_MAX_URL];
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, sizeof(ndef), url, sizeof(url));
	ASSERT("ndef_wrong_tnf", rc == NTAG424_VERIFY_ERR_NDEF_NOT_URL);
}

static void test_ndef_not_url_wrong_type_byte(void)
{
	/* type byte 0x54 ('T') instead of 0x55 ('U') */
	uint8_t ndef[] = {0xD1, 0x01, 0x03, 0x54, 0x04, 'a', 'b'};
	char url[NTAG424_MAX_URL];
	ntag424_verify_status_t rc =
		ntag424_extract_url_from_ndef(ndef, sizeof(ndef), url, sizeof(url));
	ASSERT("ndef_wrong_type", rc == NTAG424_VERIFY_ERR_NDEF_NOT_URL);
}

static void test_ndef_url_too_long(void)
{
	/* Suffix of 300 bytes → after adding prefix exceeds NTAG424_MAX_URL */
	char long_suffix[305];
	uint8_t ndef[400];
	char url[NTAG424_MAX_URL]; /* only 256 bytes */
	size_t ndef_len;
	ntag424_verify_status_t rc;

	memset(long_suffix, 'x', 300);
	long_suffix[300] = '\0';
	ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x04, long_suffix, 0);
	rc = ntag424_extract_url_from_ndef(ndef, ndef_len, url, sizeof(url));
	ASSERT("ndef_url_too_long", rc == NTAG424_VERIFY_ERR_URL_TOO_LONG);
}

static void test_ndef_null_args(void)
{
	uint8_t ndef[8] = {0xD1, 0x01, 0x01, 0x55, 0x04, 0, 0, 0};
	char url[NTAG424_MAX_URL];
	ASSERT("ndef_null_ndef",
	       ntag424_extract_url_from_ndef(NULL, 8, url, sizeof(url))
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("ndef_null_url",
	       ntag424_extract_url_from_ndef(ndef, 8, NULL, sizeof(url))
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
}

/* ── F. ntag424_verify_from_ndef / ntag424_verify_from_url ──────────────── */

/*
 * Full pipeline test using BoltCard vector 1:
 * Build an NDEF record containing the URL with p/c from vector 1,
 * then run the complete pipeline to verify UID and counter.
 */
static void test_verify_from_ndef_vector1(void)
{
	uint8_t k1[16], k2[16];
	const uint8_t exp_uid[] = {0x04,0x99,0x6c,0x6a,0x92,0x69,0x80};
	const char *suffix =
		"localhost/?p=4E2E289D945A66BB13377A728884E867&c=E19CCB1FED8892CE";
	uint8_t ndef[256];
	size_t ndef_len;
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("fndef_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("fndef_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x04, suffix, 1);
	ASSERT("fndef_build",  ndef_len > 0);

	rc = ntag424_verify_from_ndef(ndef, ndef_len, k1, k2, &out);
	ASSERT("fndef_status",  rc == NTAG424_VERIFY_OK);
	ASSERT("fndef_uid",     bytes_eq(out.uid, exp_uid, 7));
	ASSERT("fndef_counter", out.counter_value == 3U);
}

/* Pipeline test with vector 3 (counter=7) using standard (non-SR) record */
static void test_verify_from_ndef_vector3(void)
{
	uint8_t k1[16], k2[16];
	const uint8_t exp_uid[] = {0x04,0x99,0x6c,0x6a,0x92,0x69,0x80};
	const char *suffix =
		"localhost/?p=0DBF3C59B59B0638D60B5842A997D4D1&c=CC61660C020B4D96";
	uint8_t ndef[256];
	size_t ndef_len;
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("fndef3_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("fndef3_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x04, suffix, 0); /* SR=0 */
	ASSERT("fndef3_build",  ndef_len > 0);

	rc = ntag424_verify_from_ndef(ndef, ndef_len, k1, k2, &out);
	ASSERT("fndef3_status",  rc == NTAG424_VERIFY_OK);
	ASSERT("fndef3_uid",     bytes_eq(out.uid, exp_uid, 7));
	ASSERT("fndef3_counter", out.counter_value == 7U);
}

static void test_verify_from_url_vector2(void)
{
	uint8_t k1[16], k2[16];
	const uint8_t exp_uid[] = {0x04,0x99,0x6c,0x6a,0x92,0x69,0x80};
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("furl2_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("furl2_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);

	rc = ntag424_verify_from_url(
		"https://localhost/?p=00F48C4F8E386DED06BCDC78FA92E2FE"
		"&c=66B4826EA4C155B4",
		k1, k2, &out);
	ASSERT("furl2_status",  rc == NTAG424_VERIFY_OK);
	ASSERT("furl2_uid",     bytes_eq(out.uid, exp_uid, 7));
	ASSERT("furl2_counter", out.counter_value == 5U);
}

static void test_verify_from_ndef_bad_cmac(void)
{
	uint8_t k1[16], k2[16];
	/* c parameter is all-zeros → CMAC mismatch */
	const char *suffix =
		"localhost/?p=4E2E289D945A66BB13377A728884E867&c=0000000000000000";
	uint8_t ndef[256];
	size_t ndef_len;
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("fndef_bad_parse_k1", parse_hex("0c3b25d92b38ae443229dd59ad34b85d", k1, 16) == 0);
	ASSERT("fndef_bad_parse_k2", parse_hex("b45775776cb224c75bcde7ca3704e933", k2, 16) == 0);
	ndef_len = build_ndef_url(ndef, sizeof(ndef), 0x04, suffix, 1);
	rc = ntag424_verify_from_ndef(ndef, ndef_len, k1, k2, &out);
	ASSERT("fndef_bad_cmac", rc == NTAG424_VERIFY_ERR_CMAC_MISMATCH);
}

static void test_verify_from_ndef_null_args(void)
{
	uint8_t k1[16] = {0}, k2[16] = {0};
	uint8_t ndef[8] = {0xD1, 0x01, 0x01, 0x55, 0x04, 'x', 0, 0};
	struct ntag424_verify_result out;

	ASSERT("fndef_null_ndef",
	       ntag424_verify_from_ndef(NULL, 8, k1, k2, &out)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("fndef_null_k1",
	       ntag424_verify_from_ndef(ndef, 8, NULL, k2, &out)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
	ASSERT("fndef_null_out",
	       ntag424_verify_from_ndef(ndef, 8, k1, k2, NULL)
	       == NTAG424_VERIFY_ERR_INVALID_ARGUMENT);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
	/* A: extract_p_c */
	test_extract_full_url();
	test_extract_c_before_p();
	test_extract_extra_params();
	test_extract_bare_query();
	test_extract_missing_c();
	test_extract_missing_p();
	test_extract_p_wrong_len();
	test_extract_c_wrong_len();
	test_extract_null_args();

	/* B: cmac_compute (RFC 4493) */
	test_rfc4493_cmac_empty();
	test_rfc4493_cmac_oneblock();
	test_cmac_null_args();

	/* C: sv2_and_ct intermediate values */
	test_sv2_vector1();
	test_sv2_vector2();
	test_sv2_vector3();
	test_sv2_null_args();

	/* D: verify_p_c */
	test_verify_vector1();
	test_verify_vector2();
	test_verify_vector3();
	test_verify_bad_cmac();
	test_verify_wrong_k1();
	test_verify_bad_p_hex();
	test_verify_null_args();

	/* E: extract_url_from_ndef */
	test_ndef_short_record_https();
	test_ndef_standard_record();
	test_ndef_http_prefix();
	test_ndef_no_prefix();
	test_ndef_too_short();
	test_ndef_too_short_header_only();
	test_ndef_not_url_wrong_tnf();
	test_ndef_not_url_wrong_type_byte();
	test_ndef_url_too_long();
	test_ndef_null_args();

	/* F: verify_from_ndef / verify_from_url */
	test_verify_from_ndef_vector1();
	test_verify_from_ndef_vector3();
	test_verify_from_url_vector2();
	test_verify_from_ndef_bad_cmac();
	test_verify_from_ndef_null_args();

	if (tests_run == tests_passed) {
		printf("PASS: %d/%d tests\n", tests_passed, tests_run);
		return 0;
	}
	printf("FAIL: %d/%d tests\n", tests_passed, tests_run);
	return 1;
}
