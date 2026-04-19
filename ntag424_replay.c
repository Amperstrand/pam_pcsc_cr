/*
 * ntag424_replay.c — SQLite-backed monotonic counter replay protection.
 *
 * All operations are fail-closed: any SQLite error or counter not strictly
 * increasing causes rejection.  The check and update are done inside a
 * single IMMEDIATE transaction so no two callers can race.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#include "ntag424_replay.h"

/* =========================================================================
 * Status string
 * ====================================================================== */

const char *ntag424_replay_status_string(ntag424_replay_status_t status)
{
	switch (status) {
	case NTAG424_REPLAY_OK:
		return "ok";
	case NTAG424_REPLAY_ERR_INVALID_ARGUMENT:
		return "invalid argument";
	case NTAG424_REPLAY_ERR_OPEN:
		return "could not open replay database";
	case NTAG424_REPLAY_ERR_DB:
		return "SQLite database error";
	case NTAG424_REPLAY_ERR_REPLAYED:
		return "counter not strictly increasing (replay detected)";
	default:
		return "unknown error";
	}
}

/* =========================================================================
 * Schema
 * ====================================================================== */

static const char SCHEMA_SQL[] =
	"CREATE TABLE IF NOT EXISTS ntag424_replay ("
	"    card_id      TEXT    PRIMARY KEY NOT NULL,"
	"    last_counter INTEGER NOT NULL,"
	"    updated_at   INTEGER NOT NULL"
	");";

static const char WAL_SQL[] = "PRAGMA journal_mode=WAL;";

/* =========================================================================
 * Opaque DB struct
 * ====================================================================== */

struct ntag424_replay_db {
	sqlite3 *db;
};

/* =========================================================================
 * Open / close
 * ====================================================================== */

ntag424_replay_status_t ntag424_replay_open(const char *db_path,
					    struct ntag424_replay_db **db_out)
{
	struct ntag424_replay_db *h;
	int rc;

	if (!db_path || !db_out)
		return NTAG424_REPLAY_ERR_INVALID_ARGUMENT;

	h = calloc(1, sizeof(*h));
	if (!h)
		return NTAG424_REPLAY_ERR_OPEN;

	rc = sqlite3_open(db_path, &h->db);
	if (rc != SQLITE_OK) {
		sqlite3_close(h->db);
		free(h);
		return NTAG424_REPLAY_ERR_OPEN;
	}

	/* Enable WAL mode for crash safety */
	rc = sqlite3_exec(h->db, WAL_SQL, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		sqlite3_close(h->db);
		free(h);
		return NTAG424_REPLAY_ERR_OPEN;
	}

	/* Create schema if absent */
	rc = sqlite3_exec(h->db, SCHEMA_SQL, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		sqlite3_close(h->db);
		free(h);
		return NTAG424_REPLAY_ERR_OPEN;
	}

	*db_out = h;
	return NTAG424_REPLAY_OK;
}

void ntag424_replay_close(struct ntag424_replay_db *db)
{
	if (!db)
		return;
	sqlite3_close(db->db);
	free(db);
}

/* =========================================================================
 * Check and update — single transaction
 * ====================================================================== */

ntag424_replay_status_t ntag424_replay_check_and_update(
	struct ntag424_replay_db *db,
	const char *card_id,
	uint32_t new_counter)
{
	sqlite3_stmt *stmt = NULL;
	int rc;
	ntag424_replay_status_t result = NTAG424_REPLAY_ERR_DB; /* fail-closed default */
	int64_t stored_counter;
	int row_exists;
	time_t now = time(NULL);

	if (!db || !card_id || card_id[0] == '\0')
		return NTAG424_REPLAY_ERR_INVALID_ARGUMENT;

	/* ── BEGIN IMMEDIATE ──────────────────────────────────────────── */
	rc = sqlite3_exec(db->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
	if (rc != SQLITE_OK)
		return NTAG424_REPLAY_ERR_DB;

	/* ── SELECT existing counter ──────────────────────────────────── */
	rc = sqlite3_prepare_v2(db->db,
				"SELECT last_counter FROM ntag424_replay"
				" WHERE card_id = ?;",
				-1, &stmt, NULL);
	if (rc != SQLITE_OK)
		goto rollback;

	rc = sqlite3_bind_text(stmt, 1, card_id, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK)
		goto rollback;

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		stored_counter = sqlite3_column_int64(stmt, 0);
		row_exists = 1;
	} else if (rc == SQLITE_DONE) {
		stored_counter = -1;  /* no existing row */
		row_exists = 0;
	} else {
		goto rollback;
	}
	sqlite3_finalize(stmt);
	stmt = NULL;

	/* ── Counter check ────────────────────────────────────────────── */
	if (row_exists && (int64_t)new_counter <= stored_counter) {
		result = NTAG424_REPLAY_ERR_REPLAYED;
		goto rollback_clean;
	}

	/* ── INSERT or UPDATE ─────────────────────────────────────────── */
	if (!row_exists) {
		rc = sqlite3_prepare_v2(db->db,
					"INSERT INTO ntag424_replay"
					" (card_id, last_counter, updated_at)"
					" VALUES (?, ?, ?);",
					-1, &stmt, NULL);
	} else {
		rc = sqlite3_prepare_v2(db->db,
					"UPDATE ntag424_replay"
					" SET last_counter = ?, updated_at = ?"
					" WHERE card_id = ?;",
					-1, &stmt, NULL);
	}
	if (rc != SQLITE_OK)
		goto rollback;

	if (!row_exists) {
		sqlite3_bind_text(stmt,  1, card_id, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 2, (int64_t)new_counter);
		sqlite3_bind_int64(stmt, 3, (int64_t)now);
	} else {
		sqlite3_bind_int64(stmt, 1, (int64_t)new_counter);
		sqlite3_bind_int64(stmt, 2, (int64_t)now);
		sqlite3_bind_text(stmt,  3, card_id, -1, SQLITE_STATIC);
	}

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE)
		goto rollback;

	sqlite3_finalize(stmt);
	stmt = NULL;

	/* ── COMMIT ───────────────────────────────────────────────────── */
	rc = sqlite3_exec(db->db, "COMMIT;", NULL, NULL, NULL);
	if (rc != SQLITE_OK)
		goto rollback;

	return NTAG424_REPLAY_OK;

rollback:
	result = NTAG424_REPLAY_ERR_DB;
rollback_clean:
	if (stmt) {
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	sqlite3_exec(db->db, "ROLLBACK;", NULL, NULL, NULL);
	return result;
}
