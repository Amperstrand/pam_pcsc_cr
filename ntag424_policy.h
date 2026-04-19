#ifndef _NTAG424_POLICY_H
#define _NTAG424_POLICY_H

/*
 * ntag424_policy.h — local config / policy layer for NTAG424 DNA auth.
 *
 * Parses a small, strict, auditable config file that maps:
 *   card identity (UID) + PAM username → verifier key material (K1, K2)
 *
 * Deliberately kept free of:
 *   - network calls
 *   - cryptographic operations  (those are ntag424_verifier)
 *   - replay state              (that is ntag424_replay)
 *   - PAM integration           (Milestone 4)
 *
 * Config format (one file, INI-like):
 *
 *   # Lines beginning with '#' (after optional whitespace) are comments.
 *   # Empty lines are ignored.
 *
 *   # Optional global defaults for key derivation:
 *   [defaults]
 *   issuer_key   = <32 hex chars = 16 bytes>
 *   card_version = <integer, default 1>
 *
 *   # Each card is a section: [card:<id>]
 *   # where <id> is 1-63 characters of [A-Za-z0-9_-].
 *   # Required fields: uid, user
 *   # Key source (pick one, or inherit from [defaults]):
 *   #   k1 + k2           — explicit per-card keys
 *   #   issuer_key         — per-card derivation key
 *   #   (neither)          — derive from [defaults] issuer_key
 *   # Optional: card_version (overrides [defaults])
 *   #
 *   # Unknown keys are rejected (fail-closed).
 *   # Duplicate card IDs are rejected.
 *   # Lines longer than NTAG424_POLICY_LINE_MAX are rejected.
 *
 * Example (derived keys from global issuer_key):
 *   [defaults]
 *   issuer_key = 00000000000000000000000000000001
 *
 *   [card:boltcard-alice]
 *   uid  = 04996c6a926980
 *   user = alice
 *
 * Example (explicit per-card keys):
 *   [card:custom-card]
 *   uid  = 04996c6a926980
 *   k1   = 0c3b25d92b38ae443229dd59ad34b85d
 *   k2   = b45775776cb224c75bcde7ca3704e933
 *   user = alice
 *
 * Example (per-card issuer_key):
 *   [card:special]
 *   uid        = 04aaaaabbbbbb80
 *   issuer_key = deadbeefdeadbeefdeadbeefdeadbeef
 *   user       = charlie
 */

#include <stddef.h>
#include <stdint.h>
#include "ntag424_verifier.h"   /* NTAG424_KEY_BYTES, NTAG424_UID_BYTES */

/* -------------------------------------------------------------------------
 * Limits
 * ---------------------------------------------------------------------- */

/* Maximum identifier / username length in the config (including NUL) */
#define NTAG424_POLICY_ID_MAX    64

/* Maximum line length accepted by the parser (bytes, not including NUL) */
#define NTAG424_POLICY_LINE_MAX  511

/* -------------------------------------------------------------------------
 * Status codes
 * ---------------------------------------------------------------------- */

typedef enum {
	NTAG424_POLICY_OK = 0,
	NTAG424_POLICY_ERR_INVALID_ARGUMENT,
	NTAG424_POLICY_ERR_OPEN,        /* could not open config file */
	NTAG424_POLICY_ERR_PARSE,       /* malformed config (fail-closed) */
	NTAG424_POLICY_ERR_NO_MATCH,    /* no card entry matches user + uid */
	NTAG424_POLICY_ERR_NOMEM
} ntag424_policy_status_t;

const char *ntag424_policy_status_string(ntag424_policy_status_t status);

/* -------------------------------------------------------------------------
 * Card entry
 *
 * One entry is populated per [card:<id>] section in the config file.
 * Callers receive a const pointer into the policy's internal storage;
 * the pointer is valid until ntag424_policy_free() is called.
 * ---------------------------------------------------------------------- */

struct ntag424_card_entry {
	char    card_id[NTAG424_POLICY_ID_MAX]; /* identifier from [card:<id>] */
	uint8_t uid[NTAG424_UID_BYTES];         /* 7 bytes */
	uint8_t k1[NTAG424_KEY_BYTES];          /* 16 bytes (zero if derived) */
	uint8_t k2[NTAG424_KEY_BYTES];          /* 16 bytes (zero if derived) */
	char    username[NTAG424_POLICY_ID_MAX]; /* PAM username */
	uint8_t issuer_key[NTAG424_KEY_BYTES];  /* per-card issuer key (zero if none) */
	int     has_issuer_key;                 /* 1 if issuer_key is set in this card */
	int     has_k1_k2;                      /* 1 if k1/k2 are set in this card */
	uint32_t card_version;                  /* per-card version override (0 = use default) */
};

/* -------------------------------------------------------------------------
 * Policy object (opaque)
 * ---------------------------------------------------------------------- */

struct ntag424_policy;

/*
 * Parse the config file at `path` and return an allocated policy object.
 *
 * Returns NTAG424_POLICY_ERR_OPEN if the file cannot be opened.
 * Returns NTAG424_POLICY_ERR_PARSE on any malformed input (fail-closed):
 *   - line too long
 *   - unknown section type
 *   - unknown key within a [card:] section
 *   - missing required field
 *   - duplicate card_id
 *   - malformed hex, wrong hex length
 *   - empty username or card_id
 */
ntag424_policy_status_t ntag424_policy_load(const char *path,
					    struct ntag424_policy **out);

/*
 * Free all resources.  Safe to call with NULL.
 */
void ntag424_policy_free(struct ntag424_policy *policy);

/*
 * Find the unique card entry whose uid matches `uid` AND whose username
 * matches `username`.
 *
 * The UID comparison is performed in constant time.
 *
 * On success, *entry_out points into the policy's internal array; the
 * pointer is valid until ntag424_policy_free() is called.
 *
 * Returns NTAG424_POLICY_ERR_NO_MATCH if no entry satisfies both
 * conditions (unknown user, UID mismatch, etc.).
 */
ntag424_policy_status_t ntag424_policy_lookup(
	const struct ntag424_policy *policy,
	const char *username,
	const uint8_t uid[NTAG424_UID_BYTES],
	const struct ntag424_card_entry **entry_out);

/*
 * Convenience: iterate all card entries matching `username`, try
 * ntag424_verify_from_url() with each card's K1/K2, and for any
 * successful verify, check the recovered UID against the card config.
 *
 * url_or_query may be a full URL or a bare "p=...&c=..." query string.
 *
 * On success:
 *   - *result_out is populated with UID, counter, and verify status
 *   - *card_out points to the matching card entry (valid until free)
 *
 * Returns NTAG424_POLICY_ERR_NO_MATCH if no card in the policy
 * verifies and UID-matches for this user.
 */
ntag424_policy_status_t ntag424_policy_try_verify(
	const struct ntag424_policy *policy,
	const char *username,
	const char *url_or_query,
	struct ntag424_verify_result *result_out,
	const struct ntag424_card_entry **card_out);

/* -------------------------------------------------------------------------
 * Card entry validation and config file writing
 * ---------------------------------------------------------------------- */

/*
 * Validate a card entry's fields without writing anything.
 * Checks: non-empty card_id and username.
 * Returns NTAG424_POLICY_OK if valid, NTAG424_POLICY_ERR_INVALID_ARGUMENT
 * otherwise.
 */
ntag424_policy_status_t ntag424_policy_validate_card_entry(
	const struct ntag424_card_entry *entry);

/*
 * Add a card entry to the policy config file.
 *
 * If the file does not exist, creates it with the single entry.
 * If the file exists:
 *   - Parses it first to validate existing content (must be a valid config).
 *   - If a card with the same card_id already exists:
 *     - If overwrite != 0: rewrites the file with the updated entry.
 *     - If overwrite == 0: returns NTAG424_POLICY_ERR_PARSE (duplicate).
 *   - Appends the new [card:<id>] section otherwise.
 *
 * The entry is validated via ntag424_policy_validate_card_entry first.
 * UID is written as 14 lowercase hex chars; K1/K2 as 32 lowercase hex chars.
 *
 * Returns NTAG424_POLICY_OK on success.
 */
ntag424_policy_status_t ntag424_policy_add_card(
	const char *config_path,
	const struct ntag424_card_entry *entry,
	int overwrite);

#endif /* _NTAG424_POLICY_H */
