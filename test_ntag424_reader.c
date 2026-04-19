/*
 * test_ntag424_reader.c — unit tests for the ntag424_reader module.
 *
 * All tests run without real hardware by using a mock transport that
 * returns pre-programmed APDU responses.
 *
 * Test groups:
 *   A. ntag424_parse_cc        — Capability Container parsing
 *   B. ntag424_read_ndef       — full Type 4 NDEF read flow
 *   C. status string smoke-test
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ntag424_reader.h"
#include "ntag424_verifier.h"   /* ntag424_extract_p_c, ntag424_extract_url_from_ndef */

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

/* ── mock transport ──────────────────────────────────────────────────────── */

/*
 * Each exchange entry pre-programs one APDU response.
 * Set fail != 0 to make the transmit function return an error instead
 * of delivering the response bytes (simulates a reader disconnect etc.)
 */
struct mock_exchange {
	const uint8_t *resp;
	size_t         resp_len;
	int            fail;
};

struct mock_ctx {
	const struct mock_exchange *exchanges;
	size_t count;
	size_t next_idx;
};

static int mock_transmit(void *user_data,
			 const uint8_t *cmd, size_t cmd_len,
			 uint8_t *resp, size_t *resp_len)
{
	struct mock_ctx *ctx = (struct mock_ctx *)user_data;
	const struct mock_exchange *ex;

	(void)cmd;
	(void)cmd_len;

	if (ctx->next_idx >= ctx->count)
		return -1;   /* ran out of pre-programmed responses */

	ex = &ctx->exchanges[ctx->next_idx++];
	if (ex->fail)
		return -1;

	if (ex->resp_len > *resp_len)
		return -1;   /* response too large for caller buffer */

	memcpy(resp, ex->resp, ex->resp_len);
	*resp_len = ex->resp_len;
	return 0;
}

/* Convenience: build a transport struct from a mock_ctx */
static ntag424_transport_t make_transport(struct mock_ctx *ctx)
{
	ntag424_transport_t t;
	t.transmit  = mock_transmit;
	t.user_data = ctx;
	return t;
}

/* ── shared test data ────────────────────────────────────────────────────── */

/*
 * Standard NTAG424 Capability Container (15 bytes, V2.0):
 *   CCLen=0x000F  Version=0x20  MLe=0x007F  MLc=0x007F
 *   TLV 04 06: FileID=E104  MaxNDEF=0x01F6  ReadAcc=0x00  WriteAcc=0x00
 */
static const uint8_t GOOD_CC[15] = {
	0x00, 0x0F,              /* CCLen = 15 */
	0x20,                    /* Mapping Version 2.0 */
	0x00, 0x7F,              /* MLe */
	0x00, 0x7F,              /* MLc */
	0x04, 0x06,              /* NDEF File Control TLV: tag=0x04, len=6 */
	0xE1, 0x04,              /* NDEF File ID = 0xE104 */
	0x01, 0xF6,              /* NDEF Max Size = 502 */
	0x00,                    /* Read Access: open */
	0x00                     /* Write Access: open */
};

/* GOOD_CC followed by SW 9000 — the READ BINARY response for the CC */
static const uint8_t CC_RESP[17] = {
	0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x7F,
	0x04, 0x06, 0xE1, 0x04, 0x01, 0xF6, 0x00, 0x00,
	0x90, 0x00
};

/* Bare "OK" status word */
static const uint8_t SW_OK[2]   = { 0x90, 0x00 };
/* Generic "file not found" status word */
static const uint8_t SW_6A82[2] = { 0x6A, 0x82 };

/*
 * Test NDEF: an NFC Forum short-record URL record.
 *   https://x.test?p=4E2E289D945A66BB13377A728884E867&c=E19CCB1FED8892CE
 * (BoltCard test-vector 1 — verifies correctly against known K1/K2)
 *
 * Encoded as:
 *   Header  Type_Len  Payload_Len  Type  URI_Prefix  Suffix
 *   D1      01        3D           55    04           x.test?p=...&c=...
 *
 * Payload length = 1 (prefix) + 60 (suffix) = 61 = 0x3D.
 * Total NDEF record = 1+1+1+1+61 = 65 bytes.
 */
static const uint8_t TEST_NDEF[65] = {
	0xD1, 0x01, 0x3D, 0x55, 0x04,
	'x', '.', 't', 'e', 's', 't', '?', 'p', '=',
	'4','E','2','E','2','8','9','D','9','4','5','A','6','6','B','B',
	'1','3','3','7','7','A','7','2','8','8','8','4','E','8','6','7',
	'&', 'c', '=',
	'E','1','9','C','C','B','1','F','E','D','8','8','9','2','C','E'
};
#define TEST_NDEF_LEN 65

/* NLEN response: 00 41 = 65, then SW 9000 */
static const uint8_t NLEN_RESP[4] = { 0x00, 0x41, 0x90, 0x00 };

/* Full TEST_NDEF followed by SW 9000 */
static uint8_t NDEF_RESP[TEST_NDEF_LEN + 2];

/* Initialise NDEF_RESP once */
static void init_test_data(void)
{
	memcpy(NDEF_RESP, TEST_NDEF, TEST_NDEF_LEN);
	NDEF_RESP[TEST_NDEF_LEN]     = 0x90;
	NDEF_RESP[TEST_NDEF_LEN + 1] = 0x00;
}

/* ============================================================
 * A. CC parsing
 * ========================================================== */

static void test_cc_valid(void)
{
	struct ntag424_cc_info info;
	ntag424_reader_status_t rc =
		ntag424_parse_cc(GOOD_CC, sizeof(GOOD_CC), &info);

	ASSERT("cc_valid_rc",           rc == NTAG424_READER_OK);
	ASSERT("cc_valid_cc_len",       info.cc_len          == 0x000F);
	ASSERT("cc_valid_version",      info.mapping_version == 0x20);
	ASSERT("cc_valid_mle",          info.max_rapdu       == 0x007F);
	ASSERT("cc_valid_mlc",          info.max_capdu       == 0x007F);
	ASSERT("cc_valid_file_id",      info.ndef_file_id    == 0xE104);
	ASSERT("cc_valid_max_size",     info.ndef_max_size   == 0x01F6);
	ASSERT("cc_valid_read_acc",     info.ndef_read_access  == 0x00);
	ASSERT("cc_valid_write_acc",    info.ndef_write_access == 0x00);
}

static void test_cc_too_short(void)
{
	struct ntag424_cc_info info;
	/* Only 14 bytes — one short of NTAG424_CC_MIN_LEN */
	ntag424_reader_status_t rc =
		ntag424_parse_cc(GOOD_CC, NTAG424_CC_MIN_LEN - 1, &info);
	ASSERT("cc_too_short", rc == NTAG424_READER_ERR_CC_PARSE);
}

static void test_cc_null_args(void)
{
	struct ntag424_cc_info info;
	uint8_t buf[15] = {0};
	ASSERT("cc_null_cc",
	       ntag424_parse_cc(NULL, 15, &info)
	       == NTAG424_READER_ERR_INVALID_ARGUMENT);
	ASSERT("cc_null_out",
	       ntag424_parse_cc(buf, 15, NULL)
	       == NTAG424_READER_ERR_INVALID_ARGUMENT);
}

static void test_cc_bad_version(void)
{
	uint8_t cc[15];
	struct ntag424_cc_info info;

	memcpy(cc, GOOD_CC, 15);
	cc[2] = 0x10; /* version 1.0 — below minimum 0x20 */
	ASSERT("cc_bad_version",
	       ntag424_parse_cc(cc, 15, &info)
	       == NTAG424_READER_ERR_CC_PARSE);
}

static void test_cc_version_minor_accepted(void)
{
	/* Version 0x25 = major 2, minor 5 — should be accepted */
	uint8_t cc[15];
	struct ntag424_cc_info info;

	memcpy(cc, GOOD_CC, 15);
	cc[2] = 0x25;
	ASSERT("cc_version_minor",
	       ntag424_parse_cc(cc, 15, &info) == NTAG424_READER_OK);
}

static void test_cc_terminator_only(void)
{
	/*
	 * CC with only a Terminator TLV (0xFE) at offset 7.
	 * No NDEF File Control TLV → expect CC_PARSE error.
	 */
	static const uint8_t cc[15] = {
		0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x7F,
		0xFE,   /* Terminator */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	struct ntag424_cc_info info;
	ASSERT("cc_terminator_only",
	       ntag424_parse_cc(cc, 15, &info)
	       == NTAG424_READER_ERR_CC_PARSE);
}

static void test_cc_extra_tlv_before_ndef(void)
{
	/*
	 * CC with a proprietary (unknown) TLV before the NDEF TLV.
	 * The parser must skip it and still find the NDEF TLV.
	 *
	 * Layout (19 bytes):
	 *   00 13 20 00 7F 00 7F  — header
	 *   77 04 01 02 03 04     — proprietary TLV: tag=0x77, len=4, value
	 *   04 06 E1 04 01 F6 00 00 — NDEF File Control TLV
	 */
	static const uint8_t cc[19] = {
		0x00, 0x13, 0x20, 0x00, 0x7F, 0x00, 0x7F,
		0x77, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x04, 0x06, 0xE1, 0x04, 0x01, 0xF6
		/* note: read/write access bytes cut off — but len says 6 */
	};
	/* The TLV value is truncated — expect CC_PARSE */
	struct ntag424_cc_info info;
	ASSERT("cc_truncated_extra",
	       ntag424_parse_cc(cc, 19, &info)
	       == NTAG424_READER_ERR_CC_PARSE);
}

static void test_cc_extra_tlv_full(void)
{
	/*
	 * Complete CC (21 bytes) with extra TLV before NDEF TLV.
	 * Parser should skip it and return the correct NDEF info.
	 *
	 *   00 15 20 00 7F 00 7F     — header
	 *   77 04 01 02 03 04        — proprietary TLV (4 bytes value)
	 *   04 06 E1 04 01 F6 00 00  — NDEF File Control TLV
	 */
	static const uint8_t cc[21] = {
		0x00, 0x15, 0x20, 0x00, 0x7F, 0x00, 0x7F,
		0x77, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x04, 0x06, 0xE1, 0x04, 0x01, 0xF6, 0x00, 0x00
	};
	struct ntag424_cc_info info;
	ntag424_reader_status_t rc = ntag424_parse_cc(cc, 21, &info);
	ASSERT("cc_extra_tlv_rc",      rc == NTAG424_READER_OK);
	ASSERT("cc_extra_tlv_file_id", info.ndef_file_id == 0xE104);
}

static void test_cc_truncated_tlv_value(void)
{
	/*
	 * NDEF File Control TLV claims len=6 but only 2 value bytes follow
	 * before the buffer ends.
	 */
	static const uint8_t cc[11] = {
		0x00, 0x0B, 0x20, 0x00, 0x7F, 0x00, 0x7F,
		0x04, 0x06,
		0xE1, 0x04  /* only 2 bytes of 6 */
	};
	struct ntag424_cc_info info;
	ASSERT("cc_truncated_value",
	       ntag424_parse_cc(cc, 11, &info)
	       == NTAG424_READER_ERR_CC_PARSE);
}

static void test_cc_file_id_e104(void)
{
	/* Sanity: standard NTAG424 NDEF file ID must be 0xE104 */
	struct ntag424_cc_info info;
	ntag424_parse_cc(GOOD_CC, sizeof(GOOD_CC), &info);
	ASSERT("cc_file_id_e104", info.ndef_file_id == 0xE104);
}

/* ============================================================
 * B. NDEF read flow with mock transport
 * ========================================================== */

/*
 * Happy path: full NDEF read succeeds.
 * Exchange sequence:
 *   [0] SELECT NDEF App → 9000
 *   [1] SELECT CC       → 9000
 *   [2] READ CC         → [CC bytes] 9000
 *   [3] SELECT NDEF     → 9000
 *   [4] READ NLEN       → 00 41 9000  (NLEN=65)
 *   [5] READ NDEF       → [65 bytes] 9000
 */
static void test_ndef_read_success(void)
{
	const struct mock_exchange exchanges[] = {
		{ SW_OK,    2,                  0 },   /* SELECT App */
		{ SW_OK,    2,                  0 },   /* SELECT CC  */
		{ CC_RESP,  sizeof(CC_RESP),    0 },   /* READ CC    */
		{ SW_OK,    2,                  0 },   /* SELECT NDEF */
		{ NLEN_RESP, sizeof(NLEN_RESP), 0 },   /* READ NLEN  */
		{ NDEF_RESP, TEST_NDEF_LEN + 2, 0 }    /* READ NDEF  */
	};
	struct mock_ctx mctx = { exchanges, 6, 0 };
	ntag424_transport_t t = make_transport(&mctx);

	uint8_t buf[512];
	size_t  ndef_len;
	ntag424_reader_status_t rc =
		ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len);

	ASSERT("success_rc",    rc == NTAG424_READER_OK);
	ASSERT("success_len",   ndef_len == TEST_NDEF_LEN);
	ASSERT("success_bytes", memcmp(buf, TEST_NDEF, TEST_NDEF_LEN) == 0);
	ASSERT("success_all_used", mctx.next_idx == mctx.count);
}

/*
 * Verify that the NDEF bytes returned by the reader can be used directly
 * by ntag424_extract_url_from_ndef (end-to-end integration without hardware).
 */
static void test_ndef_read_then_extract_url(void)
{
	const struct mock_exchange exchanges[] = {
		{ SW_OK,    2,                  0 },
		{ SW_OK,    2,                  0 },
		{ CC_RESP,  sizeof(CC_RESP),    0 },
		{ SW_OK,    2,                  0 },
		{ NLEN_RESP, sizeof(NLEN_RESP), 0 },
		{ NDEF_RESP, TEST_NDEF_LEN + 2, 0 }
	};
	struct mock_ctx mctx = { exchanges, 6, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t ndef_buf[512];
	size_t  ndef_len;
	char    url[NTAG424_MAX_URL];
	char    p_hex[NTAG424_P_HEX_LEN + 1];
	char    c_hex[NTAG424_C_HEX_LEN + 1];
	ntag424_reader_status_t rrc;
	ntag424_verify_status_t vrc;

	rrc = ntag424_read_ndef(&t, ndef_buf, sizeof(ndef_buf), &ndef_len);
	ASSERT("e2e_ndef_rc",   rrc == NTAG424_READER_OK);

	vrc = ntag424_extract_url_from_ndef(ndef_buf, ndef_len,
					    url, sizeof(url));
	ASSERT("e2e_url_rc",    vrc == NTAG424_VERIFY_OK);
	ASSERT("e2e_url_https", strncmp(url, "https://", 8) == 0);

	vrc = ntag424_extract_p_c(url, p_hex, sizeof(p_hex),
				  c_hex, sizeof(c_hex));
	ASSERT("e2e_pc_rc",     vrc == NTAG424_VERIFY_OK);
	ASSERT("e2e_p_present", p_hex[0] != '\0');
	ASSERT("e2e_c_present", c_hex[0] != '\0');
}

/* SELECT NDEF Application returns non-9000 status word */
static void test_ndef_read_select_app_fails(void)
{
	const struct mock_exchange exchanges[] = {
		{ SW_6A82, 2, 0 }   /* SELECT App fails */
	};
	struct mock_ctx mctx = { exchanges, 1, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;
	ASSERT("sel_app_fails",
	       ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_SW);
}

/* SELECT CC returns non-9000 status word */
static void test_ndef_read_select_cc_fails(void)
{
	const struct mock_exchange exchanges[] = {
		{ SW_OK,   2, 0 },   /* SELECT App OK */
		{ SW_6A82, 2, 0 }    /* SELECT CC fails */
	};
	struct mock_ctx mctx = { exchanges, 2, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;
	ASSERT("sel_cc_fails",
	       ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_SW);
}

/* READ BINARY for CC returns bad data (version byte 0x10 = too low) */
static void test_ndef_read_bad_cc_content(void)
{
	static const uint8_t bad_cc_resp[17] = {
		0x00, 0x0F, 0x10, 0x00, 0x7F, 0x00, 0x7F,
		0x04, 0x06, 0xE1, 0x04, 0x01, 0xF6, 0x00, 0x00,
		0x90, 0x00
	};
	const struct mock_exchange exchanges[] = {
		{ SW_OK,         2,               0 },
		{ SW_OK,         2,               0 },
		{ bad_cc_resp,   sizeof(bad_cc_resp), 0 }
	};
	struct mock_ctx mctx = { exchanges, 3, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;
	ASSERT("bad_cc_content",
	       ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_CC_PARSE);
}

/* SELECT NDEF file returns non-9000 status word */
static void test_ndef_read_select_ndef_fails(void)
{
	const struct mock_exchange exchanges[] = {
		{ SW_OK,   2,                0 },
		{ SW_OK,   2,                0 },
		{ CC_RESP, sizeof(CC_RESP),  0 },
		{ SW_6A82, 2,                0 }  /* SELECT NDEF fails */
	};
	struct mock_ctx mctx = { exchanges, 4, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;
	ASSERT("sel_ndef_fails",
	       ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_SW);
}

/* READ BINARY for NLEN returns non-9000 status word */
static void test_ndef_read_nlen_fails(void)
{
	const struct mock_exchange exchanges[] = {
		{ SW_OK,   2,                0 },
		{ SW_OK,   2,                0 },
		{ CC_RESP, sizeof(CC_RESP),  0 },
		{ SW_OK,   2,                0 },
		{ SW_6A82, 2,                0 }  /* READ NLEN fails */
	};
	struct mock_ctx mctx = { exchanges, 5, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;
	ASSERT("nlen_fails",
	       ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_SW);
}

/* NLEN == 0 → success, ndef_len = 0 */
static void test_ndef_read_empty_ndef(void)
{
	static const uint8_t empty_nlen[4] = { 0x00, 0x00, 0x90, 0x00 };
	const struct mock_exchange exchanges[] = {
		{ SW_OK,       2,                   0 },
		{ SW_OK,       2,                   0 },
		{ CC_RESP,     sizeof(CC_RESP),      0 },
		{ SW_OK,       2,                   0 },
		{ empty_nlen,  4,                   0 }
	};
	struct mock_ctx mctx = { exchanges, 5, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len = 99;
	ntag424_reader_status_t rc =
		ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len);
	ASSERT("empty_ndef_rc",  rc == NTAG424_READER_OK);
	ASSERT("empty_ndef_len", ndef_len == 0);
}

/* NLEN > buffer → NTAG424_READER_ERR_NDEF_TOO_LONG */
static void test_ndef_read_too_long(void)
{
	/* NLEN = 0x01F6 = 502 bytes */
	static const uint8_t big_nlen[4] = { 0x01, 0xF6, 0x90, 0x00 };
	const struct mock_exchange exchanges[] = {
		{ SW_OK,     2,                0 },
		{ SW_OK,     2,                0 },
		{ CC_RESP,   sizeof(CC_RESP),  0 },
		{ SW_OK,     2,                0 },
		{ big_nlen,  4,                0 }
	};
	struct mock_ctx mctx = { exchanges, 5, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t small_buf[32]; /* deliberately too small */
	size_t  ndef_len;
	ASSERT("too_long",
	       ntag424_read_ndef(&t, small_buf, sizeof(small_buf), &ndef_len)
	       == NTAG424_READER_ERR_NDEF_TOO_LONG);
}

/* Transport returns error on first APDU */
static void test_ndef_read_transport_error(void)
{
	static const uint8_t dummy[2] = { 0x90, 0x00 };
	const struct mock_exchange exchanges[] = {
		{ dummy, 2, 1 }   /* fail=1 → transmit returns error */
	};
	struct mock_ctx mctx = { exchanges, 1, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;
	ASSERT("transport_err",
	       ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_TRANSMIT);
}

/* NULL argument checks */
static void test_ndef_read_null_args(void)
{
	struct mock_ctx mctx = { NULL, 0, 0 };
	ntag424_transport_t t = make_transport(&mctx);
	uint8_t buf[512];
	size_t  ndef_len;

	ASSERT("null_transport",
	       ntag424_read_ndef(NULL, buf, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_INVALID_ARGUMENT);
	ASSERT("null_buf",
	       ntag424_read_ndef(&t, NULL, sizeof(buf), &ndef_len)
	       == NTAG424_READER_ERR_INVALID_ARGUMENT);
	ASSERT("null_len_out",
	       ntag424_read_ndef(&t, buf, sizeof(buf), NULL)
	       == NTAG424_READER_ERR_INVALID_ARGUMENT);
}

/*
 * Chunked read test: NDEF content = 250 bytes (> NTAG424_READER_CHUNK_MAX=240).
 * Expects 7 APDU exchanges:
 *   [0] SELECT App  → 9000
 *   [1] SELECT CC   → 9000
 *   [2] READ CC     → CC_RESP
 *   [3] SELECT NDEF → 9000
 *   [4] READ NLEN   → 00 FA 9000  (NLEN = 250)
 *   [5] READ chunk1 → 240 bytes + 9000
 *   [6] READ chunk2 → 10 bytes + 9000
 */
static void test_ndef_read_chunked(void)
{
	/* Build canned chunk responses */
	static uint8_t chunk1_resp[NTAG424_READER_CHUNK_MAX + 2];
	static uint8_t chunk2_resp[10 + 2];
	static const uint8_t chunked_nlen[4] = { 0x00, 0xFA, 0x90, 0x00 };
	size_t i;

	/* Fill with a recognisable pattern */
	for (i = 0; i < NTAG424_READER_CHUNK_MAX; i++)
		chunk1_resp[i] = (uint8_t)(i & 0xFF);
	chunk1_resp[NTAG424_READER_CHUNK_MAX]     = 0x90;
	chunk1_resp[NTAG424_READER_CHUNK_MAX + 1] = 0x00;

	for (i = 0; i < 10; i++)
		chunk2_resp[i] = (uint8_t)((NTAG424_READER_CHUNK_MAX + i) & 0xFF);
	chunk2_resp[10] = 0x90;
	chunk2_resp[11] = 0x00;

	const struct mock_exchange exchanges[] = {
		{ SW_OK,         2,                              0 },
		{ SW_OK,         2,                              0 },
		{ CC_RESP,       sizeof(CC_RESP),                0 },
		{ SW_OK,         2,                              0 },
		{ chunked_nlen,  4,                              0 },
		{ chunk1_resp,   NTAG424_READER_CHUNK_MAX + 2,   0 },
		{ chunk2_resp,   12,                             0 }
	};
	struct mock_ctx mctx = { exchanges, 7, 0 };
	ntag424_transport_t t = make_transport(&mctx);

	uint8_t buf[512];
	size_t  ndef_len;
	ntag424_reader_status_t rc =
		ntag424_read_ndef(&t, buf, sizeof(buf), &ndef_len);

	ASSERT("chunked_rc",        rc == NTAG424_READER_OK);
	ASSERT("chunked_len",       ndef_len == 250);
	ASSERT("chunked_all_used",  mctx.next_idx == mctx.count);

	/* Verify first chunk bytes */
	ASSERT("chunked_byte0",     buf[0] == 0x00);
	ASSERT("chunked_byte1",     buf[1] == 0x01);
	/* Verify second chunk bytes (starting at offset 240) */
	ASSERT("chunked_byte240",   buf[240] == (uint8_t)(240 & 0xFF));
	ASSERT("chunked_byte249",   buf[249] == (uint8_t)(249 & 0xFF));
}

/* ============================================================
 * C. Status string smoke test
 * ========================================================== */

static void test_status_strings(void)
{
	ASSERT("str_ok",       strcmp(ntag424_reader_status_string(
				       NTAG424_READER_OK), "ok") == 0);
	ASSERT("str_no_card",  ntag424_reader_status_string(
				       NTAG424_READER_ERR_NO_CARD) != NULL);
	ASSERT("str_cc_parse", ntag424_reader_status_string(
				       NTAG424_READER_ERR_CC_PARSE) != NULL);
	ASSERT("str_unknown",  ntag424_reader_status_string(
				       (ntag424_reader_status_t)999) != NULL);
}

/* ============================================================
 * main
 * ========================================================== */

int main(void)
{
	init_test_data();

	/* A: CC parsing */
	test_cc_valid();
	test_cc_too_short();
	test_cc_null_args();
	test_cc_bad_version();
	test_cc_version_minor_accepted();
	test_cc_terminator_only();
	test_cc_extra_tlv_before_ndef();
	test_cc_extra_tlv_full();
	test_cc_truncated_tlv_value();
	test_cc_file_id_e104();

	/* B: NDEF read flow */
	test_ndef_read_success();
	test_ndef_read_then_extract_url();
	test_ndef_read_select_app_fails();
	test_ndef_read_select_cc_fails();
	test_ndef_read_bad_cc_content();
	test_ndef_read_select_ndef_fails();
	test_ndef_read_nlen_fails();
	test_ndef_read_empty_ndef();
	test_ndef_read_too_long();
	test_ndef_read_transport_error();
	test_ndef_read_null_args();
	test_ndef_read_chunked();

	/* C: status strings */
	test_status_strings();

	if (tests_run == tests_passed) {
		printf("PASS: %d/%d tests\n", tests_passed, tests_run);
		return 0;
	}
	printf("FAIL: %d/%d tests\n", tests_passed, tests_run);
	return 1;
}
