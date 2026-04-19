#ifndef _NTAG424_REPLAY_H
#define _NTAG424_REPLAY_H

/*
 * ntag424_replay.h — SQLite-backed monotonic counter replay protection.
 *
 * Maintains a per-card record of the last seen SDM read counter value.
 * An incoming counter is accepted only if it is strictly greater than
 * the stored value.  The check and update are performed atomically inside
 * a single SQLite IMMEDIATE transaction.
 *
 * Failure modes are all fail-closed:
 *   - DB file cannot be opened / created → rejected
 *   - Any SQLite error during check/update → rejected
 *   - Counter not strictly increasing → rejected
 *
 * The card identifier passed to ntag424_replay_check_and_update() should
 * be the UID formatted as a 14-character uppercase hex string (stable,
 * unique per card).  Use the uid field from ntag424_verify_result.
 *
 * Schema (created automatically if absent):
 *   CREATE TABLE IF NOT EXISTS ntag424_replay (
 *       card_id      TEXT    PRIMARY KEY NOT NULL,
 *       last_counter INTEGER NOT NULL,
 *       updated_at   INTEGER NOT NULL   -- Unix timestamp
 *   );
 */

#include <stdint.h>

/* -------------------------------------------------------------------------
 * Status codes
 * ---------------------------------------------------------------------- */

typedef enum {
	NTAG424_REPLAY_OK = 0,
	NTAG424_REPLAY_ERR_INVALID_ARGUMENT,
	NTAG424_REPLAY_ERR_OPEN,       /* could not open or create database */
	NTAG424_REPLAY_ERR_DB,         /* SQLite error during operation */
	NTAG424_REPLAY_ERR_REPLAYED    /* counter not strictly greater */
} ntag424_replay_status_t;

const char *ntag424_replay_status_string(ntag424_replay_status_t status);

/* -------------------------------------------------------------------------
 * Opaque database handle
 * ---------------------------------------------------------------------- */

struct ntag424_replay_db;

/*
 * Open (or create) the SQLite replay database at db_path.
 * Creates the schema if not already present.
 * Enables WAL journal mode for robustness under concurrent use.
 *
 * Returns NTAG424_REPLAY_ERR_OPEN if the file cannot be opened or the
 * schema cannot be created.
 */
ntag424_replay_status_t ntag424_replay_open(const char *db_path,
					    struct ntag424_replay_db **db_out);

/*
 * Atomically check and update the counter for card_id.
 *
 * Behaviour:
 *   - If no row exists for card_id: insert (new_counter, now) — accepted.
 *   - If new_counter > stored last_counter: update — accepted.
 *   - If new_counter <= stored last_counter: rejected (REPLAYED).
 *   - Any SQLite error: rejected (ERR_DB, fail-closed).
 *
 * card_id must be a non-empty, NUL-terminated string.
 * Typically the card UID formatted as a 14-char uppercase hex string.
 */
ntag424_replay_status_t ntag424_replay_check_and_update(
	struct ntag424_replay_db *db,
	const char *card_id,
	uint32_t new_counter);

/*
 * Close the database and free all resources.
 * Safe to call with NULL.
 */
void ntag424_replay_close(struct ntag424_replay_db *db);

#endif /* _NTAG424_REPLAY_H */
