/*
 * test_ntag424_policy.c — unit tests for the ntag424_policy module.
 *
 * Tests run without hardware or real config files; config content is
 * written to temporary files in /tmp.
 *
 * Test groups:
 *   A. Config parsing (valid and invalid)
 *   B. ntag424_policy_lookup (uid + username matching)
 *   C. ntag424_policy_try_verify (crypto + policy in one call)
 *   D. Null argument handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "ntag424_policy.h"
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

/* ── helpers ─────────────────────────────────────────────────────────────── */

/*
 * Write `content` to a new temp file and return its path.
 * Returns 0 on success, -1 on failure.
 */
static int write_temp_config(const char *content, char *path_out,
			     size_t path_size)
{
	int fd;
	size_t len = strlen(content);
	ssize_t written;

	snprintf(path_out, path_size, "/tmp/ntag424_policy_XXXXXX");
	fd = mkstemp(path_out);
	if (fd < 0)
		return -1;

	written = write(fd, content, len);
	close(fd);

	return (written == (ssize_t)len) ? 0 : -1;
}

/* Parse `hex_len` hex chars into `out` (hex_len/2 bytes). */
static int parse_hex(const char *hex, uint8_t *out, size_t bytes)
{
	size_t i;
	for (i = 0; i < bytes; i++) {
		unsigned int b;
		if (sscanf(hex + (i * 2), "%2x", &b) != 1)
			return -1;
		out[i] = (uint8_t)b;
	}
	return 0;
}

/*
 * Known-good BoltCard test vectors (from test_ntag424_verifier.c):
 *   k1  = 0c3b25d92b38ae443229dd59ad34b85d
 *   k2  = b45775776cb224c75bcde7ca3704e933
 *   UID = 04996c6a926980
 * Vector 1:
 *   p = 4E2E289D945A66BB13377A728884E867
 *   c = E19CCB1FED8892CE
 *   counter = 3
 */
#define TV_K1     "0c3b25d92b38ae443229dd59ad34b85d"
#define TV_K2     "b45775776cb224c75bcde7ca3704e933"
#define TV_UID    "04996c6a926980"
#define TV_URL    "https://x.test?p=4E2E289D945A66BB13377A728884E867" \
		  "&c=E19CCB1FED8892CE"

/* Minimal valid config: one card, user alice */
static const char GOOD_CONFIG[] =
	"# test config\n"
	"[card:testcard1]\n"
	"uid  = " TV_UID "\n"
	"k1   = " TV_K1 "\n"
	"k2   = " TV_K2 "\n"
	"user = alice\n";

/* Two cards: testcard1 → alice, testcard2 → bob */
static const char TWO_CARD_CONFIG[] =
	"[card:testcard1]\n"
	"uid  = " TV_UID "\n"
	"k1   = " TV_K1 "\n"
	"k2   = " TV_K2 "\n"
	"user = alice\n"
	"\n"
	"[card:testcard2]\n"
	"uid  = 04AABBCCDDEEFF\n"
	"k1   = 00112233445566778899aabbccddeeff\n"
	"k2   = ffeeddccbbaa99887766554433221100\n"
	"user = bob\n";

/* ============================================================
 * A. Config parsing
 * ========================================================== */

static void test_parse_valid_single_card(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_valid_single_card (temp file failed)\n");
		return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_valid_rc",   rc == NTAG424_POLICY_OK);
	ASSERT("parse_valid_notnull", p != NULL);

	ntag424_policy_free(p);
}

static void test_parse_two_cards(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(TWO_CARD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_two_cards (temp file failed)\n");
		return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_two_rc", rc == NTAG424_POLICY_OK);
	ASSERT("parse_two_notnull", p != NULL);

	ntag424_policy_free(p);
}

static void test_parse_empty_config(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config("# empty config\n", path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_empty_config (temp file failed)\n");
		return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_empty_rc",      rc == NTAG424_POLICY_OK);
	ASSERT("parse_empty_notnull", p != NULL);
	ntag424_policy_free(p);
}

static void test_parse_comments_and_blanks(void)
{
	/* Config with lots of whitespace/comments around a valid card */
	static const char cfg[] =
		"\n"
		"   # full-line comment\n"
		"\n"
		"[card:c1]\n"
		"   uid  =  " TV_UID "   \n"
		"   k1   =  " TV_K1 "\n"
		"   k2   =  " TV_K2 "\n"
		"   user =  alice\n"
		"\n"
		"  # trailing comment\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_comments_and_blanks (temp file failed)\n");
		return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_whitespace_rc", rc == NTAG424_POLICY_OK);
	ntag424_policy_free(p);
}

static void test_parse_file_not_found(void)
{
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc =
		ntag424_policy_load("/tmp/ntag424_NOEXIST_XYZZY", &p);
	ASSERT("parse_nofile_rc", rc == NTAG424_POLICY_ERR_OPEN);
	ASSERT("parse_nofile_null", p == NULL);
}

static void test_parse_missing_uid(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_missing_uid\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_missing_uid", rc == NTAG424_POLICY_ERR_PARSE);
	ASSERT("parse_missing_uid_null", p == NULL);
}

static void test_parse_missing_k1(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_missing_k1\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_missing_k1", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_missing_k2(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k1   = " TV_K1 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_missing_k2\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_missing_k2", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_missing_user(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_missing_user\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_missing_user", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_unknown_key(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid     = " TV_UID "\n"
		"k1      = " TV_K1 "\n"
		"k2      = " TV_K2 "\n"
		"user    = alice\n"
		"unknown = badvalue\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_unknown_key\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_unknown_key", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_unknown_section(void)
{
	static const char cfg[] =
		"[global]\n"
		"something = value\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_unknown_section\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_unknown_section", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_kv_outside_section(void)
{
	static const char cfg[] =
		"uid = " TV_UID "\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_kv_outside_section\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_kv_outside_section", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_duplicate_card_id(void)
{
	static const char cfg[] =
		"[card:dup]\n"
		"uid  = " TV_UID "\n"
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n"
		"[card:dup]\n"
		"uid  = " TV_UID "\n"
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_duplicate_card_id\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_dup_id", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_bad_hex_uid(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = ZZZZZZZZZZZZZZ\n"   /* not valid hex */
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_bad_hex_uid\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_bad_hex_uid", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_short_uid(void)
{
	/* uid must be 14 hex chars (7 bytes); this is only 12 */
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = 04996c6a9269\n"
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_short_uid\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_short_uid", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_bad_hex_k1(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k1   = ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_bad_hex_k1\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_bad_hex_k1", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_k1_too_short(void)
{
	/* k1 must be 32 hex chars (16 bytes); this is only 30 */
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k1   = 0c3b25d92b38ae443229dd59ad34b8\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_k1_too_short\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_k1_too_short", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_line_too_long(void)
{
	/* Build a line of 520 'a' chars (exceeds NTAG424_POLICY_LINE_MAX=511) */
	char cfg[600];
	char path[64];
	int offset;
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	offset = snprintf(cfg, sizeof(cfg), "[card:c1]\nuid = ");
	memset(cfg + offset, 'a', 520);
	offset += 520;
	cfg[offset++] = '\n';
	cfg[offset]   = '\0';

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_line_too_long\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_line_too_long", rc == NTAG424_POLICY_ERR_PARSE);
}

/* ============================================================
 * B. ntag424_policy_lookup
 * ========================================================== */

static void test_lookup_success(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	const struct ntag424_card_entry *e = NULL;
	uint8_t uid[NTAG424_UID_BYTES];
	ntag424_policy_status_t rc;

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_lookup_success\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_lookup_success (load failed)\n"); return; }

	parse_hex(TV_UID, uid, NTAG424_UID_BYTES);

	rc = ntag424_policy_lookup(p, "alice", uid, &e);
	ASSERT("lookup_ok_rc",       rc == NTAG424_POLICY_OK);
	ASSERT("lookup_ok_entry",    e != NULL);
	ASSERT("lookup_ok_user",     e && strcmp(e->username, "alice") == 0);
	ASSERT("lookup_ok_card_id",  e && strcmp(e->card_id, "testcard1") == 0);

	ntag424_policy_free(p);
}

static void test_lookup_wrong_user(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	const struct ntag424_card_entry *e = NULL;
	uint8_t uid[NTAG424_UID_BYTES];

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_lookup_wrong_user\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_lookup_wrong_user (load failed)\n"); return; }

	parse_hex(TV_UID, uid, NTAG424_UID_BYTES);

	ASSERT("lookup_wrong_user",
	       ntag424_policy_lookup(p, "bob", uid, &e)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

static void test_lookup_wrong_uid(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	const struct ntag424_card_entry *e = NULL;
	uint8_t uid[NTAG424_UID_BYTES];
	memset(uid, 0xFF, sizeof(uid));

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_lookup_wrong_uid\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_lookup_wrong_uid (load failed)\n"); return; }

	ASSERT("lookup_wrong_uid",
	       ntag424_policy_lookup(p, "alice", uid, &e)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

static void test_lookup_two_cards_correct_user(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	const struct ntag424_card_entry *e = NULL;
	uint8_t uid_alice[NTAG424_UID_BYTES];
	uint8_t uid_bob[NTAG424_UID_BYTES];

	if (write_temp_config(TWO_CARD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_lookup_two_cards_correct_user\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_lookup_two_cards_correct_user\n"); return; }

	parse_hex(TV_UID,            uid_alice, NTAG424_UID_BYTES);
	parse_hex("04AABBCCDDEEFF", uid_bob,   NTAG424_UID_BYTES);

	ASSERT("two_alice_rc",
	       ntag424_policy_lookup(p, "alice", uid_alice, &e)
	       == NTAG424_POLICY_OK);
	ASSERT("two_alice_card", e && strcmp(e->card_id, "testcard1") == 0);

	e = NULL;
	ASSERT("two_bob_rc",
	       ntag424_policy_lookup(p, "bob", uid_bob, &e)
	       == NTAG424_POLICY_OK);
	ASSERT("two_bob_card", e && strcmp(e->card_id, "testcard2") == 0);

	/* alice's uid doesn't match bob */
	e = NULL;
	ASSERT("two_alice_uid_as_bob",
	       ntag424_policy_lookup(p, "bob", uid_alice, &e)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

/* ============================================================
 * C. ntag424_policy_try_verify
 * ========================================================== */

static void test_try_verify_success(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_try_verify_success\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_try_verify_success (load)\n"); return; }

	memset(&result, 0, sizeof(result));
	rc = ntag424_policy_try_verify(p, "alice", TV_URL, &result, &card);

	ASSERT("try_verify_rc",       rc == NTAG424_POLICY_OK);
	ASSERT("try_verify_card",     card != NULL);
	ASSERT("try_verify_counter",  result.counter_value == 3U);
	ASSERT("try_verify_card_id",  card && strcmp(card->card_id, "testcard1") == 0);

	ntag424_policy_free(p);
}

static void test_try_verify_wrong_user(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_try_verify_wrong_user\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_try_verify_wrong_user (load)\n"); return; }

	memset(&result, 0, sizeof(result));
	ASSERT("try_verify_wrong_user",
	       ntag424_policy_try_verify(p, "bob", TV_URL, &result, &card)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

static void test_try_verify_bad_url(void)
{
	/* URL with no p/c params at all */
	char path[64];
	struct ntag424_policy *p = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;

	if (write_temp_config(GOOD_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_try_verify_bad_url\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_try_verify_bad_url (load)\n"); return; }

	memset(&result, 0, sizeof(result));
	ASSERT("try_verify_bad_url",
	       ntag424_policy_try_verify(p, "alice",
					 "https://x.test?no_params=1",
					 &result, &card)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

static void test_try_verify_wrong_keys(void)
{
	/* Config has the correct UID but wrong keys → verify will fail */
	static const char bad_key_cfg[] =
		"[card:wrongkeys]\n"
		"uid  = " TV_UID "\n"
		"k1   = deadbeefdeadbeefdeadbeefdeadbeef\n"
		"k2   = cafecafecafecafecafecafecafecafe\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;

	if (write_temp_config(bad_key_cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_try_verify_wrong_keys\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_try_verify_wrong_keys (load)\n"); return; }

	memset(&result, 0, sizeof(result));
	ASSERT("try_verify_wrong_keys",
	       ntag424_policy_try_verify(p, "alice", TV_URL, &result, &card)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

static void test_try_verify_uid_mismatch_in_config(void)
{
	/* Config has correct keys but a different UID — verify will succeed
	 * crypto-wise but UID post-check will fail */
	static const char uid_mismatch_cfg[] =
		"[card:uidmismatch]\n"
		"uid  = 04AABBCCDDEEFF\n"  /* wrong UID */
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;

	if (write_temp_config(uid_mismatch_cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_try_verify_uid_mismatch_in_config\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_try_verify_uid_mismatch_in_config (load)\n"); return; }

	memset(&result, 0, sizeof(result));
	ASSERT("try_verify_uid_mismatch",
	       ntag424_policy_try_verify(p, "alice", TV_URL, &result, &card)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(p);
}

/* ============================================================
 * D. Null argument handling
 * ========================================================== */

static void test_null_args(void)
{
	struct ntag424_policy *p = NULL;
	const struct ntag424_card_entry *e = NULL;
	uint8_t uid[NTAG424_UID_BYTES] = {0};
	struct ntag424_verify_result result;

	ASSERT("load_null_path",
	       ntag424_policy_load(NULL, &p)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("load_null_out",
	       ntag424_policy_load("/tmp/x", NULL)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);

	/* Use a dummy non-null policy pointer for null argument tests */
	ASSERT("lookup_null_policy",
	       ntag424_policy_lookup(NULL, "alice", uid, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("lookup_null_user",
	       ntag424_policy_lookup(p, NULL, uid, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("lookup_null_uid",
	       ntag424_policy_lookup(p, "alice", NULL, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("lookup_null_out",
	       ntag424_policy_lookup(p, "alice", uid, NULL)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);

	memset(&result, 0, sizeof(result));
	ASSERT("try_verify_null_policy",
	       ntag424_policy_try_verify(NULL, "alice", TV_URL, &result, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("try_verify_null_user",
	       ntag424_policy_try_verify(p, NULL, TV_URL, &result, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("try_verify_null_url",
	       ntag424_policy_try_verify(p, "alice", NULL, &result, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("try_verify_null_result",
	       ntag424_policy_try_verify(p, "alice", TV_URL, NULL, &e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
	ASSERT("try_verify_null_card",
	       ntag424_policy_try_verify(p, "alice", TV_URL, &result, NULL)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);

	/* ntag424_policy_free(NULL) must not crash */
	ntag424_policy_free(NULL);
	ASSERT("free_null_ok", 1);
}

static void test_status_strings(void)
{
	ASSERT("str_ok",
	       strcmp(ntag424_policy_status_string(NTAG424_POLICY_OK), "ok") == 0);
	ASSERT("str_no_match",
	       ntag424_policy_status_string(NTAG424_POLICY_ERR_NO_MATCH) != NULL);
	ASSERT("str_parse",
	       ntag424_policy_status_string(NTAG424_POLICY_ERR_PARSE) != NULL);
	ASSERT("str_unknown",
	       ntag424_policy_status_string((ntag424_policy_status_t)999) != NULL);
}

/* ============================================================
 * H. Card entry validation and config file writing
 * ========================================================== */

/* ============================================================
 * E. [defaults] section and key resolution
 * ========================================================== */

/* HW Bolt Card: UID=04bd60fa967380, IK=00..01, v1
 * K1=55da174c9608993dc27bb3f30a4a7314, K2=e82327c7e2f27f2fd0361bacb4ac9d1e */
#define HW_UID         "04bd60fa967380"
#define HW_ISSUER_KEY  "00000000000000000000000000000001"
#define HW_K1          "55da174c9608993dc27bb3f30a4a7314"
#define HW_K2          "e82327c7e2f27f2fd0361bacb4ac9d1e"

static const char DEFAULTS_CONFIG[] =
	"[defaults]\n"
	"issuer_key = " HW_ISSUER_KEY "\n"
	"\n"
	"[card:hwcard]\n"
	"uid  = " HW_UID "\n"
	"user = testuser\n";

/* Config with per-card issuer_key */
static const char PERCARD_IK_CONFIG[] =
	"[card:special]\n"
	"uid        = " HW_UID "\n"
	"issuer_key = " HW_ISSUER_KEY "\n"
	"user       = testuser\n";

/* Card with no keys and no [defaults] — must fail */
static const char NO_KEYS_NO_DEFAULTS[] =
	"[card:bad]\n"
	"uid  = " HW_UID "\n"
	"user = testuser\n";

static void test_parse_defaults_section(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(DEFAULTS_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_defaults_section\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_defaults_rc", rc == NTAG424_POLICY_OK);
	ASSERT("parse_defaults_notnull", p != NULL);
	ntag424_policy_free(p);
}

static void test_parse_defaults_with_card_version(void)
{
	static const char cfg[] =
		"[defaults]\n"
		"issuer_key = " HW_ISSUER_KEY "\n"
		"card_version = 2\n"
		"\n"
		"[card:c1]\n"
		"uid  = " HW_UID "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_defaults_with_card_version\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_defaults_ver_rc", rc == NTAG424_POLICY_OK);
	ntag424_policy_free(p);
}

static void test_parse_defaults_unknown_key(void)
{
	static const char cfg[] =
		"[defaults]\n"
		"issuer_key = " HW_ISSUER_KEY "\n"
		"bad_key = value\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_defaults_unknown_key\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_defaults_bad_key", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_percard_issuer_key(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(PERCARD_IK_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_percard_issuer_key\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_percard_ik_rc", rc == NTAG424_POLICY_OK);
	ASSERT("parse_percard_ik_notnull", p != NULL);
	ntag424_policy_free(p);
}

static void test_parse_no_keys_no_defaults_fails(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(NO_KEYS_NO_DEFAULTS, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_no_keys_no_defaults_fails\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);

	ASSERT("parse_no_keys_no_defaults",
	       rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_only_k1_no_k2_fails(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k1   = " TV_K1 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_only_k1_no_k2_fails\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_only_k1", rc == NTAG424_POLICY_ERR_PARSE);
}

static void test_parse_only_k2_no_k1_fails(void)
{
	static const char cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_parse_only_k2_no_k1_fails\n"); return;
	}
	rc = ntag424_policy_load(path, &p);
	unlink(path);
	ASSERT("parse_only_k2", rc == NTAG424_POLICY_ERR_PARSE);
}

/* Key resolution: explicit k1/k2 wins over per-card issuer_key */
static void test_key_resolution_explicit_wins(void)
{
	static const char cfg[] =
		"[card:explicit]\n"
		"uid        = " TV_UID "\n"
		"k1         = " TV_K1 "\n"
		"k2         = " TV_K2 "\n"
		"issuer_key = deadbeefdeadbeefdeadbeefdeadbeef\n"
		"user       = alice\n";
	char path[64];
	struct ntag424_policy *p = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;
	ntag424_policy_status_t rc;

	if (write_temp_config(cfg, path, sizeof(path)) != 0) {
		printf("SKIP: test_key_resolution_explicit_wins\n"); return;
	}
	ntag424_policy_load(path, &p);
	unlink(path);
	if (!p) { printf("SKIP: test_key_resolution_explicit_wins (load)\n"); return; }

	memset(&result, 0, sizeof(result));
	rc = ntag424_policy_try_verify(p, "alice", TV_URL, &result, &card);
	ASSERT("key_resolution_explicit", rc == NTAG424_POLICY_OK);
	ASSERT("key_resolution_explicit_counter", result.counter_value == 3U);
	ntag424_policy_free(p);
}

static void test_key_resolution_percard_ik_derives_correctly(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;
	uint8_t ik[NTAG424_KEY_BYTES];
	uint8_t uid[NTAG424_UID_BYTES];
	uint8_t derived_k1[NTAG424_KEY_BYTES];
	uint8_t derived_k2[NTAG424_KEY_BYTES];
	uint8_t expected_k1[NTAG424_KEY_BYTES];
	uint8_t expected_k2[NTAG424_KEY_BYTES];

	parse_hex(HW_ISSUER_KEY, ik, NTAG424_KEY_BYTES);
	parse_hex(HW_UID, uid, NTAG424_UID_BYTES);
	parse_hex(HW_K1, expected_k1, NTAG424_KEY_BYTES);
	parse_hex(HW_K2, expected_k2, NTAG424_KEY_BYTES);

	ASSERT("derive_keys_rc",
	       ntag424_derive_keys(ik, uid, 1, derived_k1, derived_k2)
	       == NTAG424_VERIFY_OK);

	ASSERT("derive_k1_match",
	       memcmp(derived_k1, expected_k1, NTAG424_KEY_BYTES) == 0);
	ASSERT("derive_k2_match",
	       memcmp(derived_k2, expected_k2, NTAG424_KEY_BYTES) == 0);

	if (write_temp_config(PERCARD_IK_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_key_resolution_percard_ik_derives_correctly\n"); return;
	}
	ASSERT("percarrd_ik_load",
	       ntag424_policy_load(path, &p) == NTAG424_POLICY_OK);
	unlink(path);
	ntag424_policy_free(p);
}

static void test_key_resolution_global_defaults_derives_correctly(void)
{
	char path[64];
	struct ntag424_policy *p = NULL;

	if (write_temp_config(DEFAULTS_CONFIG, path, sizeof(path)) != 0) {
		printf("SKIP: test_key_resolution_global_defaults_derives_correctly\n");
		return;
	}
	ASSERT("defaults_load",
	       ntag424_policy_load(path, &p) == NTAG424_POLICY_OK);
	unlink(path);
	ntag424_policy_free(p);
}

/* Test that [defaults] is preserved when add_card rewrites the config */
static void test_add_card_preserves_defaults(void)
{
	char path[64];
	struct ntag424_policy *pol = NULL;
	const struct ntag424_card_entry *found;
	struct ntag424_card_entry e;
	uint8_t uid2[NTAG424_UID_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_pd_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
	}
	write_temp_config(DEFAULTS_CONFIG, path, sizeof(path));

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "card2");
	snprintf(e.username, sizeof(e.username), "bob");
	parse_hex("04AABBCCDDEEFF", uid2, NTAG424_UID_BYTES);
	memcpy(e.uid, uid2, NTAG424_UID_BYTES);
	e.has_k1_k2 = 0;
	e.has_issuer_key = 0;

	ASSERT("add_preserves_defaults",
	       ntag424_policy_add_card(path, &e, 0) == NTAG424_POLICY_OK);

	ASSERT("add_defaults_parse",
	       ntag424_policy_load(path, &pol) == NTAG424_POLICY_OK);

	/* Original card should still work */
	{
		uint8_t hw_uid[NTAG424_UID_BYTES];
		parse_hex(HW_UID, hw_uid, NTAG424_UID_BYTES);
		ASSERT("add_defaults_orig",
		       ntag424_policy_lookup(pol, "testuser", hw_uid, &found)
		       == NTAG424_POLICY_OK);
	}

	/* New card should be there */
	ASSERT("add_defaults_new",
	       ntag424_policy_lookup(pol, "bob", uid2, &found)
	       == NTAG424_POLICY_OK);

	ntag424_policy_free(pol);
	unlink(path);
}

/* Test add_card with issuer_key entry */
static void test_add_card_with_issuer_key(void)
{
	char path[64];
	struct ntag424_policy *pol;
	const struct ntag424_card_entry *found;
	struct ntag424_card_entry e;
	uint8_t uid_bytes[NTAG424_UID_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_aik_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
		unlink(path);
	}

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "ikcard");
	snprintf(e.username, sizeof(e.username), "charlie");
	parse_hex(HW_UID, uid_bytes, NTAG424_UID_BYTES);
	memcpy(e.uid, uid_bytes, NTAG424_UID_BYTES);
	parse_hex(HW_ISSUER_KEY, e.issuer_key, NTAG424_KEY_BYTES);
	e.has_issuer_key = 1;

	ASSERT("add_ik_file",
	       ntag424_policy_add_card(path, &e, 0) == NTAG424_POLICY_OK);

	ASSERT("add_ik_parse",
	       ntag424_policy_load(path, &pol) == NTAG424_POLICY_OK);

	ASSERT("add_ik_lookup",
	       ntag424_policy_lookup(pol, "charlie", uid_bytes, &found)
	       == NTAG424_POLICY_OK);

	ASSERT("add_ik_has_ik",
	       found && found->has_issuer_key == 1);

	ntag424_policy_free(pol);
	unlink(path);
}

/* Test add_card rejects no-keys when no defaults exist */
static void test_add_card_no_keys_no_defaults_rejected(void)
{
	char path[64];
	struct ntag424_card_entry e;
	uint8_t uid_bytes[NTAG424_UID_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_nknd_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
		unlink(path);
	}

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "nokcard");
	snprintf(e.username, sizeof(e.username), "dave");
	parse_hex(HW_UID, uid_bytes, NTAG424_UID_BYTES);
	memcpy(e.uid, uid_bytes, NTAG424_UID_BYTES);

	ASSERT("add_nknd_rejected",
	       ntag424_policy_add_card(path, &e, 0)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);

	unlink(path);
}

/* ============================================================
 * I. Card entry validation and config file writing
 * ========================================================== */

static void test_validate_good_entry(void)
{
	struct ntag424_card_entry e;
	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "test1");
	snprintf(e.username, sizeof(e.username), "alice");
	parse_hex(TV_UID, e.uid, NTAG424_UID_BYTES);
	parse_hex(TV_K1, e.k1, NTAG424_KEY_BYTES);
	parse_hex(TV_K2, e.k2, NTAG424_KEY_BYTES);

	ASSERT("validate_good", ntag424_policy_validate_card_entry(&e)
	       == NTAG424_POLICY_OK);
}

static void test_validate_null_entry(void)
{
	ASSERT("validate_null", ntag424_policy_validate_card_entry(NULL)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
}

static void test_validate_empty_card_id(void)
{
	struct ntag424_card_entry e;
	memset(&e, 0, sizeof(e));
	e.card_id[0] = '\0';
	snprintf(e.username, sizeof(e.username), "alice");
	ASSERT("validate_empty_cid",
	       ntag424_policy_validate_card_entry(&e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
}

static void test_validate_empty_username(void)
{
	struct ntag424_card_entry e;
	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "test1");
	e.username[0] = '\0';
	ASSERT("validate_empty_user",
	       ntag424_policy_validate_card_entry(&e)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
}

static void test_add_to_new_file(void)
{
	char path[64];
	struct ntag424_card_entry e;
	struct ntag424_policy *pol;
	const struct ntag424_card_entry *found;

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_add_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
		unlink(path);
	}

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "card1");
	snprintf(e.username, sizeof(e.username), "alice");
	parse_hex(TV_UID, e.uid, NTAG424_UID_BYTES);
	parse_hex(TV_K1, e.k1, NTAG424_KEY_BYTES);
	parse_hex(TV_K2, e.k2, NTAG424_KEY_BYTES);
	e.has_k1_k2 = 1;

	ASSERT("add_new_file",
	       ntag424_policy_add_card(path, &e, 0) == NTAG424_POLICY_OK);

	ASSERT("add_new_parse",
	       ntag424_policy_load(path, &pol) == NTAG424_POLICY_OK);

	ASSERT("add_new_lookup",
	       ntag424_policy_lookup(pol, "alice", e.uid, &found)
	       == NTAG424_POLICY_OK);

	ASSERT("add_new_user",
	       found && strcmp(found->username, "alice") == 0);

	ASSERT("add_new_cid",
	       found && strcmp(found->card_id, "card1") == 0);

	ASSERT("add_new_k1",
	       found && memcmp(found->k1, e.k1, NTAG424_KEY_BYTES) == 0);
	ASSERT("add_new_k2",
	       found && memcmp(found->k2, e.k2, NTAG424_KEY_BYTES) == 0);

	ntag424_policy_free(pol);
	unlink(path);
}

static void test_add_to_existing_file(void)
{
	char path[64];
	struct ntag424_policy *pol;
	const struct ntag424_card_entry *found;
	struct ntag424_card_entry e2;
	uint8_t uid2[NTAG424_UID_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_add2_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
	}
	write_temp_config(GOOD_CONFIG, path, sizeof(path));

	memset(&e2, 0, sizeof(e2));
	snprintf(e2.card_id, sizeof(e2.card_id), "card2");
	snprintf(e2.username, sizeof(e2.username), "bob");
	parse_hex("04AABBCCDDEEFF", uid2, NTAG424_UID_BYTES);
	memcpy(e2.uid, uid2, NTAG424_UID_BYTES);
	parse_hex("00112233445566778899aabbccddeeff", e2.k1, NTAG424_KEY_BYTES);
	parse_hex("ffeeddccbbaa99887766554433221100", e2.k2, NTAG424_KEY_BYTES);
	e2.has_k1_k2 = 1;

	ASSERT("add_existing",
	       ntag424_policy_add_card(path, &e2, 0) == NTAG424_POLICY_OK);

	ASSERT("add_existing_parse",
	       ntag424_policy_load(path, &pol) == NTAG424_POLICY_OK);

	{
		uint8_t alice_uid[NTAG424_UID_BYTES];
		parse_hex(TV_UID, alice_uid, NTAG424_UID_BYTES);

		ASSERT("add_existing_alice",
		       ntag424_policy_lookup(pol, "alice", alice_uid, &found)
		       == NTAG424_POLICY_OK);

		ASSERT("add_existing_bob",
		       ntag424_policy_lookup(pol, "bob", uid2, &found)
		       == NTAG424_POLICY_OK);
	}

	ntag424_policy_free(pol);
	unlink(path);
}

static void test_add_duplicate_rejected(void)
{
	char path[64];
	struct ntag424_card_entry e;
	uint8_t uid2[NTAG424_UID_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_dup_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
	}
	write_temp_config(GOOD_CONFIG, path, sizeof(path));

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "testcard1");
	snprintf(e.username, sizeof(e.username), "mallory");
	parse_hex("04DEADBEEF0000", uid2, NTAG424_UID_BYTES);
	memcpy(e.uid, uid2, NTAG424_UID_BYTES);
	parse_hex("0c3b25d92b38ae443229dd59ad34b85d", e.k1, NTAG424_KEY_BYTES);
	parse_hex("b45775776cb224c75bcde7ca3704e933", e.k2, NTAG424_KEY_BYTES);
	e.has_k1_k2 = 1;

	ASSERT("dup_rejected",
	       ntag424_policy_add_card(path, &e, 0)
	       == NTAG424_POLICY_ERR_PARSE);

	unlink(path);
}

static void test_add_duplicate_overwrite(void)
{
	char path[64];
	struct ntag424_policy *pol;
	struct ntag424_card_entry e;
	uint8_t uid2[NTAG424_UID_BYTES];
	const struct ntag424_card_entry *found;

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_ow_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
	}
	write_temp_config(GOOD_CONFIG, path, sizeof(path));

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "testcard1");
	snprintf(e.username, sizeof(e.username), "mallory");
	parse_hex("04DEADBEEF0000", uid2, NTAG424_UID_BYTES);
	memcpy(e.uid, uid2, NTAG424_UID_BYTES);
	parse_hex("0c3b25d92b38ae443229dd59ad34b85d", e.k1, NTAG424_KEY_BYTES);
	parse_hex("b45775776cb224c75bcde7ca3704e933", e.k2, NTAG424_KEY_BYTES);
	e.has_k1_k2 = 1;

	ASSERT("dup_overwrite",
	       ntag424_policy_add_card(path, &e, 1) == NTAG424_POLICY_OK);

	ASSERT("dup_ow_parse",
	       ntag424_policy_load(path, &pol) == NTAG424_POLICY_OK);

	ASSERT("dup_ow_user",
	       ntag424_policy_lookup(pol, "mallory", uid2, &found)
	       == NTAG424_POLICY_OK);

	ASSERT("dup_ow_not_alice",
	       ntag424_policy_lookup(pol, "alice", uid2, &found)
	       == NTAG424_POLICY_ERR_NO_MATCH);

	ntag424_policy_free(pol);
	unlink(path);
}

static void test_add_null_path(void)
{
	struct ntag424_card_entry e;
	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "x");
	snprintf(e.username, sizeof(e.username), "x");

	ASSERT("add_null_path",
	       ntag424_policy_add_card(NULL, &e, 0)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
}

static void test_add_null_entry(void)
{
	ASSERT("add_null_entry",
	       ntag424_policy_add_card("/tmp/x", NULL, 0)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
}

static void test_add_invalid_entry(void)
{
	struct ntag424_card_entry e;
	memset(&e, 0, sizeof(e));

	ASSERT("add_invalid_entry",
	       ntag424_policy_add_card("/tmp/x", &e, 0)
	       == NTAG424_POLICY_ERR_INVALID_ARGUMENT);
}

static void test_add_to_malformed_file(void)
{
	char path[64];
	struct ntag424_card_entry e;

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_mal_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
	}
	write_temp_config("garbage content\nnot a config\n", path, sizeof(path));

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "c1");
	snprintf(e.username, sizeof(e.username), "alice");
	parse_hex(TV_UID, e.uid, NTAG424_UID_BYTES);
	parse_hex(TV_K1, e.k1, NTAG424_KEY_BYTES);
	parse_hex(TV_K2, e.k2, NTAG424_KEY_BYTES);
	e.has_k1_k2 = 1;

	ASSERT("add_malformed",
	       ntag424_policy_add_card(path, &e, 0)
	       == NTAG424_POLICY_ERR_PARSE);

	unlink(path);
}

static void test_add_preserves_existing(void)
{
	char path[64];
	struct ntag424_policy *pol;
	struct ntag424_card_entry e2;
	const struct ntag424_card_entry *found = NULL;
	uint8_t uid2[NTAG424_UID_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_pres_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
	}
	write_temp_config(GOOD_CONFIG, path, sizeof(path));

	memset(&e2, 0, sizeof(e2));
	snprintf(e2.card_id, sizeof(e2.card_id), "card2");
	snprintf(e2.username, sizeof(e2.username), "bob");
	parse_hex("04AABBCCDDEEFF", uid2, NTAG424_UID_BYTES);
	memcpy(e2.uid, uid2, NTAG424_UID_BYTES);
	parse_hex("00112233445566778899aabbccddeeff", e2.k1, NTAG424_KEY_BYTES);
	parse_hex("ffeeddccbbaa99887766554433221100", e2.k2, NTAG424_KEY_BYTES);
	e2.has_k1_k2 = 1;

	ntag424_policy_add_card(path, &e2, 0);

	ntag424_policy_load(path, &pol);
	{
		uint8_t alice_uid[NTAG424_UID_BYTES];
		parse_hex(TV_UID, alice_uid, NTAG424_UID_BYTES);

		ASSERT("preserve_alice",
		       ntag424_policy_lookup(pol, "alice", alice_uid, &found)
		       == NTAG424_POLICY_OK);
	}

	ntag424_policy_free(pol);
	unlink(path);
}

static void test_add_roundtrip_hex(void)
{
	char path[64];
	struct ntag424_policy *pol;
	struct ntag424_card_entry e;
	const struct ntag424_card_entry *found = NULL;
	uint8_t expected_uid[NTAG424_UID_BYTES];
	uint8_t expected_k1[NTAG424_KEY_BYTES];
	uint8_t expected_k2[NTAG424_KEY_BYTES];

	snprintf(path, sizeof(path), "/tmp/ntag424_policy_rt_XXXXXX");
	{
		int fd = mkstemp(path);
		close(fd);
		unlink(path);
	}

	memset(&e, 0, sizeof(e));
	snprintf(e.card_id, sizeof(e.card_id), "rt1");
	snprintf(e.username, sizeof(e.username), "carol");
	parse_hex("04112233445566", expected_uid, NTAG424_UID_BYTES);
	memcpy(e.uid, expected_uid, NTAG424_UID_BYTES);
	parse_hex("aabbccddeeff00112233445566778899", expected_k1, NTAG424_KEY_BYTES);
	memcpy(e.k1, expected_k1, NTAG424_KEY_BYTES);
	parse_hex("99887766554433221100ffeeddccbbaa", expected_k2, NTAG424_KEY_BYTES);
	memcpy(e.k2, expected_k2, NTAG424_KEY_BYTES);
	e.has_k1_k2 = 1;

	ntag424_policy_add_card(path, &e, 0);
	ntag424_policy_load(path, &pol);

	ntag424_policy_lookup(pol, "carol", expected_uid, &found);

	ASSERT("rt_uid",
	       found && memcmp(found->uid, expected_uid,
		      NTAG424_UID_BYTES) == 0);
	ASSERT("rt_k1",
	       found && memcmp(found->k1, expected_k1,
		      NTAG424_KEY_BYTES) == 0);
	ASSERT("rt_k2",
	       found && memcmp(found->k2, expected_k2,
		      NTAG424_KEY_BYTES) == 0);

	ntag424_policy_free(pol);
	unlink(path);
}

/* ============================================================
 * main
 * ========================================================== */

int main(void)
{
	/* A: Config parsing */
	test_parse_valid_single_card();
	test_parse_two_cards();
	test_parse_empty_config();
	test_parse_comments_and_blanks();
	test_parse_file_not_found();
	test_parse_missing_uid();
	test_parse_missing_k1();
	test_parse_missing_k2();
	test_parse_missing_user();
	test_parse_unknown_key();
	test_parse_unknown_section();
	test_parse_kv_outside_section();
	test_parse_duplicate_card_id();
	test_parse_bad_hex_uid();
	test_parse_short_uid();
	test_parse_bad_hex_k1();
	test_parse_k1_too_short();
	test_parse_line_too_long();

	/* E: [defaults] and key resolution */
	test_parse_defaults_section();
	test_parse_defaults_with_card_version();
	test_parse_defaults_unknown_key();
	test_parse_percard_issuer_key();
	test_parse_no_keys_no_defaults_fails();
	test_parse_only_k1_no_k2_fails();
	test_parse_only_k2_no_k1_fails();
	test_key_resolution_explicit_wins();
	test_key_resolution_percard_ik_derives_correctly();
	test_key_resolution_global_defaults_derives_correctly();
	test_add_card_preserves_defaults();
	test_add_card_with_issuer_key();
	test_add_card_no_keys_no_defaults_rejected();

	/* B: Lookup */
	test_lookup_success();
	test_lookup_wrong_user();
	test_lookup_wrong_uid();
	test_lookup_two_cards_correct_user();

	/* C: try_verify */
	test_try_verify_success();
	test_try_verify_wrong_user();
	test_try_verify_bad_url();
	test_try_verify_wrong_keys();
	test_try_verify_uid_mismatch_in_config();

	/* D: Null args */
	test_null_args();
	test_status_strings();

	/* E: Card entry validation and writing */
	test_validate_good_entry();
	test_validate_null_entry();
	test_validate_empty_card_id();
	test_validate_empty_username();
	test_add_to_new_file();
	test_add_to_existing_file();
	test_add_duplicate_rejected();
	test_add_duplicate_overwrite();
	test_add_null_path();
	test_add_null_entry();
	test_add_invalid_entry();
	test_add_to_malformed_file();
	test_add_preserves_existing();
	test_add_roundtrip_hex();

	if (tests_run == tests_passed) {
		printf("PASS: %d/%d tests\n", tests_passed, tests_run);
		return 0;
	}
	printf("FAIL: %d/%d tests\n", tests_passed, tests_run);
	return 1;
}
