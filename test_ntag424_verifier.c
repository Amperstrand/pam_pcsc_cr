#include <stdio.h>
#include <string.h>
#include "ntag424_verifier.h"

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(label, cond) do { \
	tests_run++; \
	if (cond) { \
		tests_passed++; \
	} else { \
		printf("FAIL: %s (line %d)\n", label, __LINE__); \
	} \
} while (0)

static int parse_hex16(const char *hex, unsigned char out[16])
{
	int i;
	for (i = 0; i < 16; i++) {
		unsigned int b;
		if (sscanf(hex + (i * 2), "%2x", &b) != 1) return -1;
		out[i] = (unsigned char)b;
	}
	return 0;
}

static void test_extract_query_ok(void)
{
	char p[NTAG424_P_HEX_LEN + 1];
	char c[NTAG424_C_HEX_LEN + 1];
	const char *url =
		"https://localhost/path?x=1&p=4E2E289D945A66BB13377A728884E867&c=E19CCB1FED8892CE";
	ntag424_verify_status_t rc = ntag424_extract_p_c(url, p, sizeof(p), c, sizeof(c));
	ASSERT("extract_query_ok_status", rc == NTAG424_VERIFY_OK);
	ASSERT("extract_query_ok_p", strcmp(p, "4E2E289D945A66BB13377A728884E867") == 0);
	ASSERT("extract_query_ok_c", strcmp(c, "E19CCB1FED8892CE") == 0);
}

static void test_extract_query_missing(void)
{
	char p[NTAG424_P_HEX_LEN + 1];
	char c[NTAG424_C_HEX_LEN + 1];
	ntag424_verify_status_t rc = ntag424_extract_p_c("p=4E2E289D945A66BB13377A728884E867",
							 p, sizeof(p), c, sizeof(c));
	ASSERT("extract_query_missing", rc == NTAG424_VERIFY_ERR_PARAM_PARSE);
}

static void test_verify_ok_vector_1(void)
{
	unsigned char k1[16];
	unsigned char k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("parse_k1_1", parse_hex16("0c3b25d92b38ae443229dd59ad34b85d", k1) == 0);
	ASSERT("parse_k2_1", parse_hex16("b45775776cb224c75bcde7ca3704e933", k2) == 0);

	rc = ntag424_verify_p_c(k1, k2, "4E2E289D945A66BB13377A728884E867", "E19CCB1FED8892CE", &out);
	ASSERT("verify_vector1_status", rc == NTAG424_VERIFY_OK);
	ASSERT("verify_vector1_uid0", out.uid[0] == 0x04);
	ASSERT("verify_vector1_uid1", out.uid[1] == 0x99);
	ASSERT("verify_vector1_uid2", out.uid[2] == 0x6c);
	ASSERT("verify_vector1_uid3", out.uid[3] == 0x6a);
	ASSERT("verify_vector1_uid4", out.uid[4] == 0x92);
	ASSERT("verify_vector1_uid5", out.uid[5] == 0x69);
	ASSERT("verify_vector1_uid6", out.uid[6] == 0x80);
	ASSERT("verify_vector1_counter", out.counter_value == 3U);
}

static void test_verify_ok_vector_2(void)
{
	unsigned char k1[16];
	unsigned char k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("parse_k1_2", parse_hex16("0c3b25d92b38ae443229dd59ad34b85d", k1) == 0);
	ASSERT("parse_k2_2", parse_hex16("b45775776cb224c75bcde7ca3704e933", k2) == 0);

	rc = ntag424_verify_p_c(k1, k2, "00F48C4F8E386DED06BCDC78FA92E2FE", "66B4826EA4C155B4", &out);
	ASSERT("verify_vector2_status", rc == NTAG424_VERIFY_OK);
	ASSERT("verify_vector2_counter", out.counter_value == 5U);
}

static void test_verify_bad_cmac(void)
{
	unsigned char k1[16];
	unsigned char k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("parse_k1_bad_cmac", parse_hex16("0c3b25d92b38ae443229dd59ad34b85d", k1) == 0);
	ASSERT("parse_k2_bad_cmac", parse_hex16("b45775776cb224c75bcde7ca3704e933", k2) == 0);
	rc = ntag424_verify_p_c(k1, k2, "4E2E289D945A66BB13377A728884E867", "0000000000000000", &out);
	ASSERT("verify_bad_cmac_status", rc == NTAG424_VERIFY_ERR_CMAC_MISMATCH);
}

static void test_verify_bad_inputs(void)
{
	unsigned char k1[16];
	unsigned char k2[16];
	struct ntag424_verify_result out;
	ntag424_verify_status_t rc;

	ASSERT("parse_k1_bad_inputs", parse_hex16("0c3b25d92b38ae443229dd59ad34b85d", k1) == 0);
	ASSERT("parse_k2_bad_inputs", parse_hex16("b45775776cb224c75bcde7ca3704e933", k2) == 0);

	rc = ntag424_verify_p_c(k1, k2, "ZZZZ289D945A66BB13377A728884E867", "E19CCB1FED8892CE", &out);
	ASSERT("verify_bad_p_hex", rc == NTAG424_VERIFY_ERR_P_HEX);

	rc = ntag424_verify_p_c(k1, k2, "4E2E289D945A66BB13377A728884E867", "XYZCCB1FED8892CE", &out);
	ASSERT("verify_bad_c_hex", rc == NTAG424_VERIFY_ERR_C_HEX);
}

int main(void)
{
	test_extract_query_ok();
	test_extract_query_missing();
	test_verify_ok_vector_1();
	test_verify_ok_vector_2();
	test_verify_bad_cmac();
	test_verify_bad_inputs();

	if (tests_run == tests_passed) {
		printf("PASS: %d/%d tests\n", tests_passed, tests_run);
		return 0;
	}
	printf("FAIL: %d/%d tests\n", tests_passed, tests_run);
	return 1;
}
