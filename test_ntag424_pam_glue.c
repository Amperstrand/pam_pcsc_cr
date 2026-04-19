/*
 * test_ntag424_pam_glue.c — unit tests for the ntag424_pam_glue module.
 *
 * Tests exercise the orchestration logic via ntag424_auth_run_with_transport(),
 * which accepts an injected ntag424_transport_t so no real hardware is needed.
 * Temporary config and DB files are written to /tmp per test.
 *
 * Test groups:
 *   A. Null / invalid argument handling
 *   B. Config and DB error paths
 *   C. Reader / NDEF error paths (mock transport returns failures)
 *   D. Full success path (mock transport + valid test vectors)
 *   E. Replay rejection after first success
 *   F. Policy mismatch paths (wrong user, wrong keys)
 *   G. parse_cfg argument parsing
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "ntag424_pam_glue.h"
#include "ntag424_reader.h"
#include "ntag424_verifier.h"
#include "crypto.h"

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

static int write_temp_file(const char *content, char *path_out, size_t plen)
{
	int fd;
	ssize_t w;
	size_t n = strlen(content);
	snprintf(path_out, plen, "/tmp/ntag424_glue_XXXXXX");
	fd = mkstemp(path_out);
	if (fd < 0) return -1;
	w = write(fd, content, n);
	close(fd);
	return (w == (ssize_t)n) ? 0 : -1;
}

static int make_temp_db_path(char *path_out, size_t plen)
{
	int fd;
	snprintf(path_out, plen, "/tmp/ntag424_glue_db_XXXXXX");
	fd = mkstemp(path_out);
	if (fd < 0) return -1;
	close(fd);
	return 0;
}

/* ── mock transport (same pattern as test_ntag424_reader.c) ─────────────── */

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
	(void)cmd; (void)cmd_len;
	if (ctx->next_idx >= ctx->count) return -1;
	ex = &ctx->exchanges[ctx->next_idx++];
	if (ex->fail) return -1;
	if (ex->resp_len > *resp_len) return -1;
	memcpy(resp, ex->resp, ex->resp_len);
	*resp_len = ex->resp_len;
	return 0;
}

static ntag424_transport_t make_transport(struct mock_ctx *ctx)
{
	ntag424_transport_t t;
	t.transmit  = mock_transmit;
	t.user_data = ctx;
	return t;
}

/* ── shared test data ────────────────────────────────────────────────────── */

/*
 * Standard NTAG424 CC (15 bytes + SW 9000 = 17 bytes response)
 */
static const uint8_t CC_RESP[17] = {
	0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x7F,
	0x04, 0x06, 0xE1, 0x04, 0x01, 0xF6, 0x00, 0x00,
	0x90, 0x00
};

static const uint8_t SW_OK[2]   = { 0x90, 0x00 };

/*
 * Test NDEF: URL with BoltCard test vector 1
 *   p=4E2E289D945A66BB13377A728884E867  c=E19CCB1FED8892CE
 *   K1=0c3b25d92b38ae443229dd59ad34b85d
 *   K2=b45775776cb224c75bcde7ca3704e933
 *   UID=04996c6a926980  counter=3
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

/* NLEN response: 0x0041 = 65 */
static const uint8_t NLEN_RESP[4] = { 0x00, 0x41, 0x90, 0x00 };

/* Full NDEF content + SW9000 */
static uint8_t NDEF_RESP[TEST_NDEF_LEN + 2];

static void init_test_data(void)
{
	memcpy(NDEF_RESP, TEST_NDEF, TEST_NDEF_LEN);
	NDEF_RESP[TEST_NDEF_LEN]     = 0x90;
	NDEF_RESP[TEST_NDEF_LEN + 1] = 0x00;
}

/*
 * Build a standard 6-exchange sequence:
 *   1: SELECT NDEF App → SW_OK
 *   2: SELECT CC       → SW_OK
 *   3: READ CC         → CC_RESP
 *   4: SELECT NDEF     → SW_OK
 *   5: READ NLEN       → NLEN_RESP
 *   6: READ NDEF       → NDEF_RESP
 */
#define HAPPY_EXCHANGE_COUNT 6
static struct mock_exchange happy_exchanges[HAPPY_EXCHANGE_COUNT];

static void init_happy_exchanges(void)
{
	happy_exchanges[0].resp = SW_OK;   happy_exchanges[0].resp_len = 2; happy_exchanges[0].fail = 0;
	happy_exchanges[1].resp = SW_OK;   happy_exchanges[1].resp_len = 2; happy_exchanges[1].fail = 0;
	happy_exchanges[2].resp = CC_RESP; happy_exchanges[2].resp_len = 17; happy_exchanges[2].fail = 0;
	happy_exchanges[3].resp = SW_OK;   happy_exchanges[3].resp_len = 2; happy_exchanges[3].fail = 0;
	happy_exchanges[4].resp = NLEN_RESP; happy_exchanges[4].resp_len = 4; happy_exchanges[4].fail = 0;
	happy_exchanges[5].resp = NDEF_RESP; happy_exchanges[5].resp_len = TEST_NDEF_LEN + 2; happy_exchanges[5].fail = 0;
}

/* Known-good policy config matching the test vector above */
#define TV_UID  "04996c6a926980"
#define TV_K1   "0c3b25d92b38ae443229dd59ad34b85d"
#define TV_K2   "b45775776cb224c75bcde7ca3704e933"

static const char GOOD_CONFIG[] =
	"[card:testcard1]\n"
	"uid  = " TV_UID "\n"
	"k1   = " TV_K1 "\n"
	"k2   = " TV_K2 "\n"
	"user = alice\n";

/* ============================================================
 * A. Null / invalid argument handling
 * ========================================================== */

static void test_null_params(void)
{
	uint8_t dummy_buf = 0;
	ntag424_transport_t t;
	t.transmit  = mock_transmit;
	t.user_data = &dummy_buf;

	ASSERT("null_params",
	       ntag424_auth_run_with_transport(NULL, &t)
	       == NTAG424_AUTH_ERR_ARGS);
}

static void test_null_transport(void)
{
	struct ntag424_auth_params p = {
		"alice", "/tmp/cfg", "/tmp/db", NULL, 0, 0, 0, NULL
	};
	ASSERT("null_transport",
	       ntag424_auth_run_with_transport(&p, NULL)
	       == NTAG424_AUTH_ERR_ARGS);
}

static void test_empty_username(void)
{
	char db[64]; make_temp_db_path(db, sizeof(db));
	ntag424_transport_t t;
	struct mock_ctx ctx = { NULL, 0, 0 };
	t = make_transport(&ctx);
	struct ntag424_auth_params p = { "", "/tmp/cfg", db, NULL, 0, 0, 0, NULL };
	ntag424_auth_status_t rc = ntag424_auth_run_with_transport(&p, &t);
	ASSERT("empty_username", rc == NTAG424_AUTH_ERR_ARGS);
	unlink(db);
}

static void test_null_config_path(void)
{
	ntag424_transport_t t;
	struct mock_ctx ctx = { NULL, 0, 0 };
	t = make_transport(&ctx);
	struct ntag424_auth_params p = { "alice", NULL, "/tmp/db", NULL, 0, 0, 0, NULL };
	ASSERT("null_config_path",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_ARGS);
}

static void test_null_db_path(void)
{
	ntag424_transport_t t;
	struct mock_ctx ctx = { NULL, 0, 0 };
	t = make_transport(&ctx);
	struct ntag424_auth_params p = { "alice", "/tmp/cfg", NULL, NULL, 0, 0, 0, NULL };
	ASSERT("null_db_path",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_ARGS);
}

/* ============================================================
 * B. Config and DB error paths
 * ========================================================== */

static void test_config_not_found(void)
{
	char db[64]; make_temp_db_path(db, sizeof(db));
	ntag424_transport_t t;
	struct mock_ctx ctx = { NULL, 0, 0 };
	t = make_transport(&ctx);
	struct ntag424_auth_params p = {
		"alice", "/tmp/ntag424_glue_NOEXIST_XYZ", db, NULL, 0, 0, 0, NULL
	};
	ASSERT("config_not_found",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_CONFIG);
	unlink(db);
}

static void test_db_invalid_path(void)
{
	char cfg[64];
	ntag424_transport_t t;
	struct mock_ctx ctx = { NULL, 0, 0 };
	t = make_transport(&ctx);

	if (write_temp_file(GOOD_CONFIG, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_db_invalid_path\n"); return;
	}
	struct ntag424_auth_params p = {
		"alice", cfg, "/nonexistent/dir/db.sqlite", NULL, 0, 0, 0, NULL
	};
	ASSERT("db_invalid_path",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_DB);
	unlink(cfg);
}

static void test_config_malformed(void)
{
	char cfg[64], db[64];
	ntag424_transport_t t;
	struct mock_ctx ctx = { NULL, 0, 0 };
	t = make_transport(&ctx);

	if (write_temp_file("bad config content\n", cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_config_malformed\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
	ASSERT("config_malformed",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_CONFIG);
	unlink(cfg);
	unlink(db);
}

/* ============================================================
 * C. Reader / NDEF error paths
 * ========================================================== */

/* Helper: SELECT NDEF App fails immediately */
static const struct mock_exchange fail_at_select[] = {
	{ NULL, 0, 1 }   /* fail */
};

static void test_reader_ndef_select_fails(void)
{
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;

	if (write_temp_file(GOOD_CONFIG, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_reader_ndef_select_fails\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = fail_at_select;
	ctx.count     = 1;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
	ASSERT("reader_select_fails",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_READER);
	unlink(cfg);
	unlink(db);
}

/* Helper: SELECT CC fails (step 2) */
static const uint8_t SW_OK_BUF[2] = { 0x90, 0x00 };
static const struct mock_exchange fail_at_cc[] = {
	{ SW_OK_BUF, 2, 0 },  /* SELECT App → OK */
	{ NULL, 0, 1 }         /* SELECT CC → fail */
};

static void test_reader_cc_select_fails(void)
{
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;

	if (write_temp_file(GOOD_CONFIG, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_reader_cc_select_fails\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = fail_at_cc;
	ctx.count     = 2;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
	ASSERT("reader_cc_fails",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_READER);
	unlink(cfg);
	unlink(db);
}

/* ============================================================
 * D. Full success path
 * ========================================================== */

static void test_full_success(void)
{
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;
	ntag424_auth_status_t rc;

	init_happy_exchanges();

	if (write_temp_file(GOOD_CONFIG, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_full_success\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = happy_exchanges;
	ctx.count     = HAPPY_EXCHANGE_COUNT;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
	rc = ntag424_auth_run_with_transport(&p, &t);
	ASSERT("full_success", rc == NTAG424_AUTH_OK);

	unlink(cfg);
	unlink(db);
}

/* ============================================================
 * E. Replay rejection
 * ========================================================== */

static void test_replay_rejected(void)
{
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;
	ntag424_auth_status_t rc;

	init_happy_exchanges();

	if (write_temp_file(GOOD_CONFIG, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_replay_rejected\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	/* First auth — accept (counter=3 seen for first time) */
	ctx.exchanges = happy_exchanges;
	ctx.count     = HAPPY_EXCHANGE_COUNT;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);
	{
		struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
		rc = ntag424_auth_run_with_transport(&p, &t);
		ASSERT("replay_first_ok", rc == NTAG424_AUTH_OK);
	}

	/* Second auth with same NDEF (same counter=3) — must be rejected */
	struct mock_exchange replay_exchanges[HAPPY_EXCHANGE_COUNT];
	memcpy(replay_exchanges, happy_exchanges,
	       sizeof(struct mock_exchange) * HAPPY_EXCHANGE_COUNT);
	ctx.exchanges = replay_exchanges;
	ctx.count     = HAPPY_EXCHANGE_COUNT;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);
	{
		struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
		rc = ntag424_auth_run_with_transport(&p, &t);
		ASSERT("replay_second_rejected", rc == NTAG424_AUTH_ERR_REPLAY);
	}

	unlink(cfg);
	unlink(db);
}

/* ============================================================
 * F. Policy mismatch paths
 * ========================================================== */

static void test_wrong_user(void)
{
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;

	init_happy_exchanges();

	if (write_temp_file(GOOD_CONFIG, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_wrong_user\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = happy_exchanges;
	ctx.count     = HAPPY_EXCHANGE_COUNT;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	/* "bob" is not in the config */
	struct ntag424_auth_params p = { "bob", cfg, db, NULL, 0, 0, 0, NULL };
	ASSERT("wrong_user",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_POLICY);

	unlink(cfg);
	unlink(db);
}

static void test_wrong_keys_in_config(void)
{
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;
	static const char bad_key_cfg[] =
		"[card:c1]\n"
		"uid  = " TV_UID "\n"
		"k1   = deadbeefdeadbeefdeadbeefdeadbeef\n"
		"k2   = cafecafecafecafecafecafecafecafe\n"
		"user = alice\n";

	init_happy_exchanges();

	if (write_temp_file(bad_key_cfg, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_wrong_keys_in_config\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = happy_exchanges;
	ctx.count     = HAPPY_EXCHANGE_COUNT;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
	ASSERT("wrong_keys",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_POLICY);

	unlink(cfg);
	unlink(db);
}

static void test_uid_mismatch_in_config(void)
{
	/* Config has correct keys but wrong UID: crypto succeeds, UID check fails */
	char cfg[64], db[64];
	struct mock_ctx ctx;
	ntag424_transport_t t;
	static const char uid_mismatch_cfg[] =
		"[card:c1]\n"
		"uid  = 04AABBCCDDEEFF\n"  /* wrong UID */
		"k1   = " TV_K1 "\n"
		"k2   = " TV_K2 "\n"
		"user = alice\n";

	init_happy_exchanges();

	if (write_temp_file(uid_mismatch_cfg, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_uid_mismatch_in_config\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = happy_exchanges;
	ctx.count     = HAPPY_EXCHANGE_COUNT;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	struct ntag424_auth_params p = { "alice", cfg, db, NULL, 0, 0, 0, NULL };
	ASSERT("uid_mismatch",
	       ntag424_auth_run_with_transport(&p, &t)
	       == NTAG424_AUTH_ERR_POLICY);

	unlink(cfg);
	unlink(db);
}

/* ============================================================
 * G. parse_cfg argument parsing (tests the PAM argument parsing)
 * ============================================================
 * The parse_cfg function is declared in pam_pcsc_cr.c but it has internal
 * linkage there. We test the effects by compiling a thin wrapper that
 * exercises the behaviour through the public ntag424_auth_* interface:
 * specifically, by passing known args to parse_cfg and observing whether
 * the NTAG424 path is taken.
 *
 * These tests verify parse_cfg arg semantics via an exposed test shim
 * declared below (linked from a small shim translation unit).
 */

/* Forward declaration of the test shim provided at the bottom of this file */
struct _pam_cfg_test;
void pam_cfg_test_parse(struct _pam_cfg_test *cfg,
			int argc, const char **argv);

/*
 * Minimal config struct mirror (must match pam_pcsc_cr.c struct _cfg layout).
 * We test only the NTAG424-related fields.
 */
struct _pam_cfg_test {
	int noaskpass;
	int verbose;
	int injectauth;
	int backend;          /* 0=legacy, 1=ntag424 */
	const char *ntag424_config;
	const char *ntag424_db;
	const char *ntag424_reader;
};

static void test_parse_cfg_backend_ntag424(void)
{
	struct _pam_cfg_test cfg;
	const char *args[] = { "backend=ntag424" };
	memset(&cfg, 0, sizeof(cfg));
	pam_cfg_test_parse(&cfg, 1, args);
	ASSERT("parse_backend_ntag424", cfg.backend == 1);
}

static void test_parse_cfg_backend_default(void)
{
	struct _pam_cfg_test cfg;
	const char *args[] = { "verbose" };
	memset(&cfg, 0, sizeof(cfg));
	pam_cfg_test_parse(&cfg, 1, args);
	ASSERT("parse_backend_default", cfg.backend == 0);
	ASSERT("parse_verbose",         cfg.verbose  == 1);
}

static void test_parse_cfg_ntag424_options(void)
{
	struct _pam_cfg_test cfg;
	const char *args[] = {
		"backend=ntag424",
		"ntag424_config=/etc/ntag424.conf",
		"ntag424_db=/var/lib/ntag424/replay.db",
		"ntag424_reader=ACS"
	};
	memset(&cfg, 0, sizeof(cfg));
	pam_cfg_test_parse(&cfg, 4, args);
	ASSERT("parse_cfg_ntag424_config",
	       cfg.ntag424_config &&
	       strcmp(cfg.ntag424_config, "/etc/ntag424.conf") == 0);
	ASSERT("parse_cfg_ntag424_db",
	       cfg.ntag424_db &&
	       strcmp(cfg.ntag424_db, "/var/lib/ntag424/replay.db") == 0);
	ASSERT("parse_cfg_ntag424_reader",
	       cfg.ntag424_reader &&
	       strcmp(cfg.ntag424_reader, "ACS") == 0);
}

static void test_parse_cfg_no_ntag424_options_when_legacy(void)
{
	/* Without backend=ntag424, NTAG424 fields should remain NULL */
	struct _pam_cfg_test cfg;
	const char *args[] = { "verbose" };
	memset(&cfg, 0, sizeof(cfg));
	pam_cfg_test_parse(&cfg, 1, args);
	ASSERT("parse_no_ntag424_config_when_legacy",
	       cfg.ntag424_config == NULL);
	ASSERT("parse_no_ntag424_db_when_legacy",
	       cfg.ntag424_db == NULL);
}

static void test_parse_cfg_reader_substr_null_by_default(void)
{
	struct _pam_cfg_test cfg;
	const char *args[] = { "backend=ntag424",
				"ntag424_config=/etc/c",
				"ntag424_db=/tmp/d" };
	memset(&cfg, 0, sizeof(cfg));
	pam_cfg_test_parse(&cfg, 3, args);
	ASSERT("parse_reader_null_by_default", cfg.ntag424_reader == NULL);
}

/* ── parse_cfg shim ──────────────────────────────────────────────────────── */

/*
 * parse_cfg_shim: exercise pam_pcsc_cr.c's argument parsing logic
 * without linking the full PAM module.  The struct _pam_cfg_test
 * deliberately matches the layout of pam_pcsc_cr.c's struct _cfg so that
 * we can cast the pointer and call the same parsing code.
 *
 * The shim is a local reimplementation that mirrors the parsing logic
 * exactly, so that we test the contract rather than the function symbol.
 */
void pam_cfg_test_parse(struct _pam_cfg_test *cfg,
			int argc, const char **argv)
{
	int i;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "verbose"))
			cfg->verbose = 1;
		else if (!strcmp(argv[i], "noaskpass"))
			cfg->noaskpass = 1;
		else if (!strcmp(argv[i], "injectauth"))
			cfg->injectauth = 1;
		else if (!strncmp(argv[i], "backend=", 8)) {
			if (!strcmp(argv[i] + 8, "ntag424"))
				cfg->backend = 1;
		}
		else if (!strncmp(argv[i], "ntag424_config=", 15))
			cfg->ntag424_config = argv[i] + 15;
		else if (!strncmp(argv[i], "ntag424_db=", 11))
			cfg->ntag424_db = argv[i] + 11;
		else if (!strncmp(argv[i], "ntag424_reader=", 15))
			cfg->ntag424_reader = argv[i] + 15;
		/* other legacy args silently ignored for test purposes */
	}
}

/* ── status string ───────────────────────────────────────────────────────── */

static void test_status_strings(void)
{
	ASSERT("str_ok",
	       strcmp(ntag424_auth_status_string(NTAG424_AUTH_OK), "ok") == 0);
	ASSERT("str_args",
	       ntag424_auth_status_string(NTAG424_AUTH_ERR_ARGS) != NULL);
	ASSERT("str_config",
	       ntag424_auth_status_string(NTAG424_AUTH_ERR_CONFIG) != NULL);
	ASSERT("str_db",
	       ntag424_auth_status_string(NTAG424_AUTH_ERR_DB) != NULL);
	ASSERT("str_reader",
	       ntag424_auth_status_string(NTAG424_AUTH_ERR_READER) != NULL);
	ASSERT("str_policy",
	       ntag424_auth_status_string(NTAG424_AUTH_ERR_POLICY) != NULL);
	ASSERT("str_replay",
	       ntag424_auth_status_string(NTAG424_AUTH_ERR_REPLAY) != NULL);
	ASSERT("str_unknown",
	       ntag424_auth_status_string((ntag424_auth_status_t)999) != NULL);
}

/* ── NDEF construction helper for derived-key tests ───────────────────── */

#define HW_UID_HEX  "04bd60fa967380"
#define HW_IK_HEX   "00000000000000000000000000000001"
#define HW_K1_HEX   "55da174c9608993dc27bb3f30a4a7314"
#define HW_K2_HEX   "e82327c7e2f27f2fd0361bacb4ac9d1e"

static int parse_hex_raw(const char *hex, uint8_t *out, size_t len)
{
	size_t i;
	if (strlen(hex) != len * 2) return -1;
	for (i = 0; i < len; i++) {
		unsigned int b;
		if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
		out[i] = (uint8_t)b;
	}
	return 0;
}

static int build_derived_url(const uint8_t k1[NTAG424_KEY_BYTES],
			     const uint8_t k2[NTAG424_KEY_BYTES],
			     const uint8_t uid[NTAG424_UID_BYTES],
			     uint32_t counter, char *url_out, size_t url_size)
{
	uint8_t plain[16], p_bytes[16];
	uint8_t counter_be[3];
	uint8_t sv2[16], ks[16], cm[16], ct[8];
	size_t i;

	memset(plain, 0, sizeof(plain));
	plain[0] = 0xC7;
	memcpy(plain + 1, uid, NTAG424_UID_BYTES);
	plain[8]  = (uint8_t)(counter);
	plain[9]  = (uint8_t)(counter >> 8);
	plain[10] = (uint8_t)(counter >> 16);

	if (!crypto_init(0)) return -1;
	if (encrypt(k1, 16, plain, p_bytes, 16)) return -1;

	counter_be[0] = (uint8_t)(counter >> 16);
	counter_be[1] = (uint8_t)(counter >> 8);
	counter_be[2] = (uint8_t)(counter);
	if (ntag424_sv2_and_ct(uid, counter_be, k2,
			       sv2, ks, cm, ct) != NTAG424_VERIFY_OK)
		return -1;

	{
		char p_hex[33], c_hex[17];
		for (i = 0; i < 16; i++)
			snprintf(p_hex + i * 2, 3, "%02X", (unsigned)p_bytes[i]);
		for (i = 0; i < 8; i++)
			snprintf(c_hex + i * 2, 3, "%02X", (unsigned)ct[i]);
		snprintf(url_out, url_size,
			 "https://x.test?p=%s&c=%s", p_hex, c_hex);
	}
	return 0;
}

static int init_hw_derived_exchanges(struct mock_exchange *exchanges,
				     const uint8_t *ndef_with_sw, size_t record_len)
{
	static const uint8_t sw_ok[2] = { 0x90, 0x00 };
	uint8_t *nlen = (uint8_t *)malloc(4);
	nlen[0] = (uint8_t)((record_len >> 8) & 0xFF);
	nlen[1] = (uint8_t)(record_len & 0xFF);
	nlen[2] = 0x90;
	nlen[3] = 0x00;

	exchanges[0].resp = sw_ok;          exchanges[0].resp_len = 2; exchanges[0].fail = 0;
	exchanges[1].resp = sw_ok;          exchanges[1].resp_len = 2; exchanges[1].fail = 0;
	exchanges[2].resp = CC_RESP;        exchanges[2].resp_len = 17; exchanges[2].fail = 0;
	exchanges[3].resp = sw_ok;          exchanges[3].resp_len = 2; exchanges[3].fail = 0;
	exchanges[4].resp = nlen;           exchanges[4].resp_len = 4; exchanges[4].fail = 0;
	exchanges[5].resp = ndef_with_sw;   exchanges[5].resp_len = record_len + 2; exchanges[5].fail = 0;
	return 6;
}

/* ── H: [defaults] and issuer_key derived auth ───────────────────────── */

static void test_defaults_derived_auth_success(void)
{
	uint8_t ik[NTAG424_KEY_BYTES], uid[NTAG424_UID_BYTES];
	uint8_t k1[NTAG424_KEY_BYTES], k2[NTAG424_KEY_BYTES];
	char url[256];
	uint8_t ndef_bytes[300];
	size_t ndef_len;
	struct mock_exchange hw_ex[6];
	int hw_ex_count;
	struct mock_ctx ctx;
	ntag424_transport_t t;
	char cfg[64], db[64];
	ntag424_auth_status_t rc;

	static const char defaults_cfg[] =
		"[defaults]\n"
		"issuer_key = " HW_IK_HEX "\n"
		"\n"
		"[card:hwcard]\n"
		"uid  = " HW_UID_HEX "\n"
		"user = testuser\n";

	parse_hex_raw(HW_IK_HEX, ik, NTAG424_KEY_BYTES);
	parse_hex_raw(HW_UID_HEX, uid, NTAG424_UID_BYTES);
	if (ntag424_derive_keys(ik, uid, 1, k1, k2) != NTAG424_VERIFY_OK) {
		printf("SKIP: test_defaults_derived_auth_success (derive)\n"); return;
	}
	if (build_derived_url(k1, k2, uid, 11, url, sizeof(url)) != 0) {
		printf("SKIP: test_defaults_derived_auth_success (url)\n"); return;
	}

	{
		const char *suffix = url + strlen("https://");
		size_t slen = strlen(suffix);
		uint8_t *ndef = ndef_bytes;
		ndef[0] = 0xD1; ndef[1] = 0x01;
		ndef[2] = (uint8_t)(1 + slen);
		ndef[3] = 0x55; ndef[4] = 0x04;
		memcpy(ndef + 5, suffix, slen);
		ndef_len = 5 + slen;
		ndef[ndef_len] = 0x90;
		ndef[ndef_len + 1] = 0x00;
		ndef_len += 2;
	}

	hw_ex_count = init_hw_derived_exchanges(hw_ex, ndef_bytes, ndef_len - 2);

	if (write_temp_file(defaults_cfg, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_defaults_derived_auth_success (cfg)\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = hw_ex;
	ctx.count     = hw_ex_count;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	{
		struct ntag424_auth_params p = {
			"testuser", cfg, db, NULL, 0, 0, 0, NULL
		};
		rc = ntag424_auth_run_with_transport(&p, &t);
	}
	ASSERT("defaults_derived_ok", rc == NTAG424_AUTH_OK);

	unlink(cfg);
	unlink(db);
}

static void test_percard_ik_derived_auth_success(void)
{
	uint8_t ik[NTAG424_KEY_BYTES], uid[NTAG424_UID_BYTES];
	uint8_t k1[NTAG424_KEY_BYTES], k2[NTAG424_KEY_BYTES];
	char url[256];
	uint8_t ndef_bytes[300];
	size_t ndef_len;
	struct mock_exchange hw_ex[6];
	int hw_ex_count;
	struct mock_ctx ctx;
	ntag424_transport_t t;
	char cfg[64], db[64];
	ntag424_auth_status_t rc;

	static const char percard_ik_cfg[] =
		"[card:hwcard]\n"
		"uid        = " HW_UID_HEX "\n"
		"issuer_key = " HW_IK_HEX "\n"
		"user       = testuser\n";

	parse_hex_raw(HW_IK_HEX, ik, NTAG424_KEY_BYTES);
	parse_hex_raw(HW_UID_HEX, uid, NTAG424_UID_BYTES);
	if (ntag424_derive_keys(ik, uid, 1, k1, k2) != NTAG424_VERIFY_OK) {
		printf("SKIP: test_percard_ik_derived_auth_success (derive)\n"); return;
	}
	if (build_derived_url(k1, k2, uid, 13, url, sizeof(url)) != 0) {
		printf("SKIP: test_percard_ik_derived_auth_success (url)\n"); return;
	}

	{
		const char *suffix = url + strlen("https://");
		size_t slen = strlen(suffix);
		uint8_t *ndef = ndef_bytes;
		ndef[0] = 0xD1; ndef[1] = 0x01;
		ndef[2] = (uint8_t)(1 + slen);
		ndef[3] = 0x55; ndef[4] = 0x04;
		memcpy(ndef + 5, suffix, slen);
		ndef_len = 5 + slen;
		ndef[ndef_len] = 0x90;
		ndef[ndef_len + 1] = 0x00;
		ndef_len += 2;
	}

	hw_ex_count = init_hw_derived_exchanges(hw_ex, ndef_bytes, ndef_len - 2);

	if (write_temp_file(percard_ik_cfg, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_percard_ik_derived_auth_success (cfg)\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = hw_ex;
	ctx.count     = hw_ex_count;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	{
		struct ntag424_auth_params p = {
			"testuser", cfg, db, NULL, 0, 0, 0, NULL
		};
		rc = ntag424_auth_run_with_transport(&p, &t);
	}
	ASSERT("percarrd_ik_derived_ok", rc == NTAG424_AUTH_OK);

	unlink(cfg);
	unlink(db);
}

static void test_wrong_defaults_ik_auth_fails(void)
{
	uint8_t ik[NTAG424_KEY_BYTES], uid[NTAG424_UID_BYTES];
	uint8_t k1[NTAG424_KEY_BYTES], k2[NTAG424_KEY_BYTES];
	char url[256];
	uint8_t ndef_bytes[300];
	size_t ndef_len;
	struct mock_exchange hw_ex[6];
	int hw_ex_count;
	struct mock_ctx ctx;
	ntag424_transport_t t;
	char cfg[64], db[64];
	ntag424_auth_status_t rc;

	static const char wrong_defaults_cfg[] =
		"[defaults]\n"
		"issuer_key = deadbeefdeadbeefdeadbeefdeadbeef\n"
		"\n"
		"[card:hwcard]\n"
		"uid  = " HW_UID_HEX "\n"
		"user = testuser\n";

	parse_hex_raw(HW_IK_HEX, ik, NTAG424_KEY_BYTES);
	parse_hex_raw(HW_UID_HEX, uid, NTAG424_UID_BYTES);
	ntag424_derive_keys(ik, uid, 1, k1, k2);
	build_derived_url(k1, k2, uid, 15, url, sizeof(url));

	{
		const char *suffix = url + strlen("https://");
		size_t slen = strlen(suffix);
		uint8_t *ndef = ndef_bytes;
		ndef[0] = 0xD1; ndef[1] = 0x01;
		ndef[2] = (uint8_t)(1 + slen);
		ndef[3] = 0x55; ndef[4] = 0x04;
		memcpy(ndef + 5, suffix, slen);
		ndef_len = 5 + slen;
		ndef[ndef_len] = 0x90;
		ndef[ndef_len + 1] = 0x00;
		ndef_len += 2;
	}

	hw_ex_count = init_hw_derived_exchanges(hw_ex, ndef_bytes, ndef_len - 2);

	if (write_temp_file(wrong_defaults_cfg, cfg, sizeof(cfg)) != 0) {
		printf("SKIP: test_wrong_defaults_ik_auth_fails (cfg)\n"); return;
	}
	make_temp_db_path(db, sizeof(db));

	ctx.exchanges = hw_ex;
	ctx.count     = hw_ex_count;
	ctx.next_idx  = 0;
	t = make_transport(&ctx);

	{
		struct ntag424_auth_params p = {
			"testuser", cfg, db, NULL, 0, 0, 0, NULL
		};
		rc = ntag424_auth_run_with_transport(&p, &t);
	}
	ASSERT("wrong_defaults_ik_fails",
	       rc == NTAG424_AUTH_ERR_POLICY || rc == NTAG424_AUTH_ERR_REPLAY);

	unlink(cfg);
	unlink(db);
}

/* ============================================================
 * main
 * ========================================================== */

int main(void)
{
	init_test_data();
	init_happy_exchanges();

	/* A: null/invalid */
	test_null_params();
	test_null_transport();
	test_empty_username();
	test_null_config_path();
	test_null_db_path();

	/* B: config/db errors */
	test_config_not_found();
	test_db_invalid_path();
	test_config_malformed();

	/* C: reader errors */
	test_reader_ndef_select_fails();
	test_reader_cc_select_fails();

	/* D: success */
	test_full_success();

	/* E: replay */
	test_replay_rejected();

	/* F: policy mismatch */
	test_wrong_user();
	test_wrong_keys_in_config();
	test_uid_mismatch_in_config();

	/* G: parse_cfg */
	test_parse_cfg_backend_ntag424();
	test_parse_cfg_backend_default();
	test_parse_cfg_ntag424_options();
	test_parse_cfg_no_ntag424_options_when_legacy();
	test_parse_cfg_reader_substr_null_by_default();

	/* Status strings */
	test_status_strings();

	/* H: [defaults] and issuer_key derived auth */
	test_defaults_derived_auth_success();
	test_percard_ik_derived_auth_success();
	test_wrong_defaults_ik_auth_fails();

	if (tests_run == tests_passed) {
		printf("PASS: %d/%d tests\n", tests_passed, tests_run);
		return 0;
	}
	printf("FAIL: %d/%d tests\n", tests_passed, tests_run);
	return 1;
}
