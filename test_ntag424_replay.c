/*
 * test_ntag424_replay.c — unit tests for the ntag424_replay module.
 *
 * All tests use temporary SQLite databases in /tmp (created and removed
 * per test).  No hardware is required.
 *
 * Test groups:
 *   A. Basic open / close
 *   B. First-seen card accepted
 *   C. Monotonic counter enforcement
 *   D. State persistence across reopen
 *   E. Null / invalid argument handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "ntag424_replay.h"

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

/* Create a temp path for a SQLite database. */
static int make_temp_db_path(char *path_out, size_t path_size)
{
	int fd;
	snprintf(path_out, path_size, "/tmp/ntag424_replay_XXXXXX");
	fd = mkstemp(path_out);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

/* ============================================================
 * A. Open / close
 * ========================================================== */

static void test_open_close(void)
{
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_open_close (temp path failed)\n"); return;
	}

	rc = ntag424_replay_open(path, &db);
	ASSERT("open_rc",    rc == NTAG424_REPLAY_OK);
	ASSERT("open_notnull", db != NULL);

	ntag424_replay_close(db);
	unlink(path);
	ASSERT("close_ok", 1);
}

static void test_open_creates_db(void)
{
	/* Open a path that does not yet exist; should create it. */
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	snprintf(path, sizeof(path), "/tmp/ntag424_replay_new_XXXXXX");
	{
		int fd = mkstemp(path);
		if (fd < 0) {
			printf("SKIP: test_open_creates_db\n"); return;
		}
		close(fd);
		unlink(path); /* remove so we can test creation */
	}

	rc = ntag424_replay_open(path, &db);
	ASSERT("create_rc",    rc == NTAG424_REPLAY_OK);
	ASSERT("create_notnull", db != NULL);

	ntag424_replay_close(db);
	unlink(path);
}

/* ============================================================
 * B. First-seen card accepted
 * ========================================================== */

static void test_first_use_accepted(void)
{
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_first_use_accepted\n"); return;
	}
	ntag424_replay_open(path, &db);
	if (!db) { printf("SKIP: test_first_use_accepted (open)\n"); unlink(path); return; }

	rc = ntag424_replay_check_and_update(db, "04996C6A926980", 3U);
	ASSERT("first_use_rc", rc == NTAG424_REPLAY_OK);

	ntag424_replay_close(db);
	unlink(path);
}

static void test_first_use_counter_zero(void)
{
	/* Counter 0 on first use should be accepted */
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_first_use_counter_zero\n"); return;
	}
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }

	rc = ntag424_replay_check_and_update(db, "CARDID_ZERO", 0U);
	ASSERT("first_use_zero", rc == NTAG424_REPLAY_OK);

	ntag424_replay_close(db);
	unlink(path);
}

/* ============================================================
 * C. Monotonic counter enforcement
 * ========================================================== */

static void test_same_counter_rejected(void)
{
	char path[64];
	struct ntag424_replay_db *db = NULL;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_same_counter_rejected\n"); return;
	}
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }

	ntag424_replay_check_and_update(db, "CARD1", 10U);

	ASSERT("same_counter_rejected",
	       ntag424_replay_check_and_update(db, "CARD1", 10U)
	       == NTAG424_REPLAY_ERR_REPLAYED);

	ntag424_replay_close(db);
	unlink(path);
}

static void test_lower_counter_rejected(void)
{
	char path[64];
	struct ntag424_replay_db *db = NULL;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_lower_counter_rejected\n"); return;
	}
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }

	ntag424_replay_check_and_update(db, "CARD2", 10U);

	ASSERT("lower_counter_rejected",
	       ntag424_replay_check_and_update(db, "CARD2", 9U)
	       == NTAG424_REPLAY_ERR_REPLAYED);
	ASSERT("much_lower_counter_rejected",
	       ntag424_replay_check_and_update(db, "CARD2", 0U)
	       == NTAG424_REPLAY_ERR_REPLAYED);

	ntag424_replay_close(db);
	unlink(path);
}

static void test_increasing_counter_accepted(void)
{
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_increasing_counter_accepted\n"); return;
	}
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }

	rc = ntag424_replay_check_and_update(db, "CARD3", 1U);
	ASSERT("inc_step1", rc == NTAG424_REPLAY_OK);

	rc = ntag424_replay_check_and_update(db, "CARD3", 2U);
	ASSERT("inc_step2", rc == NTAG424_REPLAY_OK);

	rc = ntag424_replay_check_and_update(db, "CARD3", 100U);
	ASSERT("inc_step3", rc == NTAG424_REPLAY_OK);

	/* Now the stored value is 100; 99 must be rejected */
	ASSERT("inc_replay",
	       ntag424_replay_check_and_update(db, "CARD3", 99U)
	       == NTAG424_REPLAY_ERR_REPLAYED);

	/* 101 must still be accepted */
	rc = ntag424_replay_check_and_update(db, "CARD3", 101U);
	ASSERT("inc_step4", rc == NTAG424_REPLAY_OK);

	ntag424_replay_close(db);
	unlink(path);
}

static void test_independent_cards(void)
{
	/* Counters for different card_ids are independent */
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_independent_cards\n"); return;
	}
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }

	ntag424_replay_check_and_update(db, "CARD_A", 50U);
	ntag424_replay_check_and_update(db, "CARD_B", 10U);

	/* CARD_A at 50: new counter 51 should be OK */
	rc = ntag424_replay_check_and_update(db, "CARD_A", 51U);
	ASSERT("indep_A_ok", rc == NTAG424_REPLAY_OK);

	/* CARD_B at 10: re-use 10 must fail */
	ASSERT("indep_B_replay",
	       ntag424_replay_check_and_update(db, "CARD_B", 10U)
	       == NTAG424_REPLAY_ERR_REPLAYED);

	/* CARD_B: 11 must succeed */
	rc = ntag424_replay_check_and_update(db, "CARD_B", 11U);
	ASSERT("indep_B_ok", rc == NTAG424_REPLAY_OK);

	ntag424_replay_close(db);
	unlink(path);
}

/* ============================================================
 * D. State persistence across reopen
 * ========================================================== */

static void test_state_persists_across_reopen(void)
{
	char path[64];
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	if (make_temp_db_path(path, sizeof(path)) != 0) {
		printf("SKIP: test_state_persists_across_reopen\n"); return;
	}

	/* Session 1: record counter=42 */
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }
	ntag424_replay_check_and_update(db, "PERSIST_CARD", 42U);
	ntag424_replay_close(db);
	db = NULL;

	/* Session 2: reopen; counter=42 should be rejected */
	ntag424_replay_open(path, &db);
	if (!db) { unlink(path); return; }

	ASSERT("persist_same_rejected",
	       ntag424_replay_check_and_update(db, "PERSIST_CARD", 42U)
	       == NTAG424_REPLAY_ERR_REPLAYED);

	rc = ntag424_replay_check_and_update(db, "PERSIST_CARD", 43U);
	ASSERT("persist_higher_ok", rc == NTAG424_REPLAY_OK);

	ntag424_replay_close(db);
	unlink(path);
}

/* ============================================================
 * E. Null / invalid argument handling
 * ========================================================== */

static void test_null_args(void)
{
	struct ntag424_replay_db *db = NULL;

	ASSERT("open_null_path",
	       ntag424_replay_open(NULL, &db)
	       == NTAG424_REPLAY_ERR_INVALID_ARGUMENT);
	ASSERT("open_null_out",
	       ntag424_replay_open("/tmp/x", NULL)
	       == NTAG424_REPLAY_ERR_INVALID_ARGUMENT);

	ASSERT("check_null_db",
	       ntag424_replay_check_and_update(NULL, "CARD", 1U)
	       == NTAG424_REPLAY_ERR_INVALID_ARGUMENT);
	ASSERT("check_null_id",
	       ntag424_replay_check_and_update(db, NULL, 1U)
	       == NTAG424_REPLAY_ERR_INVALID_ARGUMENT);
	ASSERT("check_empty_id",
	       ntag424_replay_check_and_update(db, "", 1U)
	       == NTAG424_REPLAY_ERR_INVALID_ARGUMENT);

	/* ntag424_replay_close(NULL) must not crash */
	ntag424_replay_close(NULL);
	ASSERT("close_null_ok", 1);
}

static void test_open_invalid_path(void)
{
	struct ntag424_replay_db *db = NULL;
	ntag424_replay_status_t rc;

	/* /nonexistent/dir/db.sqlite — directory does not exist */
	rc = ntag424_replay_open("/nonexistent/dir/db.sqlite", &db);
	ASSERT("open_invalid_path", rc == NTAG424_REPLAY_ERR_OPEN);
	ASSERT("open_invalid_null", db == NULL);
}

static void test_status_strings(void)
{
	ASSERT("str_ok",
	       strcmp(ntag424_replay_status_string(NTAG424_REPLAY_OK), "ok") == 0);
	ASSERT("str_replayed",
	       ntag424_replay_status_string(NTAG424_REPLAY_ERR_REPLAYED) != NULL);
	ASSERT("str_db",
	       ntag424_replay_status_string(NTAG424_REPLAY_ERR_DB) != NULL);
	ASSERT("str_unknown",
	       ntag424_replay_status_string((ntag424_replay_status_t)999) != NULL);
}

/* ============================================================
 * main
 * ========================================================== */

int main(void)
{
	/* A: open/close */
	test_open_close();
	test_open_creates_db();

	/* B: first use */
	test_first_use_accepted();
	test_first_use_counter_zero();

	/* C: monotonic enforcement */
	test_same_counter_rejected();
	test_lower_counter_rejected();
	test_increasing_counter_accepted();
	test_independent_cards();

	/* D: persistence */
	test_state_persists_across_reopen();

	/* E: null/invalid args */
	test_null_args();
	test_open_invalid_path();
	test_status_strings();

	if (tests_run == tests_passed) {
		printf("PASS: %d/%d tests\n", tests_passed, tests_run);
		return 0;
	}
	printf("FAIL: %d/%d tests\n", tests_passed, tests_run);
	return 1;
}
