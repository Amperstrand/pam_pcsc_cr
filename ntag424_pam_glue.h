#ifndef _NTAG424_PAM_GLUE_H
#define _NTAG424_PAM_GLUE_H

/*
 * ntag424_pam_glue.h — thin orchestration layer for NTAG424 PAM authentication.
 *
 * This module composes:
 *   ntag424_reader  — NDEF acquisition from a Type 4 tag over PC/SC
 *   ntag424_verifier — cryptographic p/c validation
 *   ntag424_policy  — per-user card allowlist and key material
 *   ntag424_replay  — SQLite monotonic counter replay protection
 *
 * into a single call that can be invoked from pam_sm_authenticate.
 *
 * The split between ntag424_auth_run() (PC/SC backend) and
 * ntag424_auth_run_with_transport() (injected transport) exists solely to
 * allow the orchestration logic to be unit-tested without real hardware.
 *
 * Security constraints (all fail-closed):
 *   - malformed or missing config → ERR_CONFIG
 *   - replay DB cannot be opened   → ERR_DB
 *   - reader / NDEF error          → ERR_READER
 *   - no matching card for user    → ERR_POLICY
 *   - replay counter not strictly increasing → ERR_REPLAY
 *
 * Nothing in this module logs URLs, p/c parameter values, or key material.
 */

#include "ntag424_reader.h"   /* ntag424_transport_t */

/* -------------------------------------------------------------------------
 * Status codes
 * ---------------------------------------------------------------------- */

typedef enum {
	NTAG424_AUTH_OK = 0,
	NTAG424_AUTH_ERR_ARGS,    /* NULL required parameter */
	NTAG424_AUTH_ERR_CONFIG,  /* policy config load failed */
	NTAG424_AUTH_ERR_DB,      /* replay DB open failed */
	NTAG424_AUTH_ERR_READER,  /* NDEF read failed */
	NTAG424_AUTH_ERR_POLICY,  /* no matching card for user / crypto fail */
	NTAG424_AUTH_ERR_REPLAY   /* counter not strictly increasing */
} ntag424_auth_status_t;

const char *ntag424_auth_status_string(ntag424_auth_status_t status);

/* -------------------------------------------------------------------------
 * Parameters
 * ---------------------------------------------------------------------- */

/*
 * All pointers are borrowed references valid for the lifetime of the call.
 * The struct need not outlive ntag424_auth_run / ntag424_auth_run_with_transport.
 */
struct ntag424_auth_params {
	const char *username;       /* PAM username (required) */
	const char *config_path;    /* path to ntag424 policy config (required) */
	const char *db_path;        /* path to SQLite replay DB (required, created if absent) */
	const char *reader_substr;  /* reader name substring filter; NULL = first available */
	int         verbose;        /* if non-zero, emit syslog(LOG_DEBUG/ERR) lines */
	int         cue;            /* if non-zero, show PAM_TEXT_INFO prompt before card read */
	unsigned int timeout_ms;    /* milliseconds to wait for card; 0 = immediate (default) */
	void       *pamh;           /* pam_handle_t* (borrowed); only used for cue display */
};

/* -------------------------------------------------------------------------
 * Entry points
 * ---------------------------------------------------------------------- */

/*
 * Run the full NTAG424 auth flow using the PC/SC reader backend.
 *
 * Sequence:
 *   1. Validate params.
 *   2. Load policy config.
 *   3. Open replay DB.
 *   4. Open PC/SC context, select reader, connect to card.
 *   5. Read NDEF.
 *   6. Extract URL from NDEF.
 *   7. ntag424_policy_try_verify  (crypto + UID + username check).
 *   8. ntag424_replay_check_and_update (monotonic counter).
 *
 * Returns NTAG424_AUTH_OK on success; appropriate error code otherwise.
 * All resources are freed before returning.
 */
ntag424_auth_status_t ntag424_auth_run(
	const struct ntag424_auth_params *params);

/*
 * Same as ntag424_auth_run() but accepts a pre-built transport instead of
 * opening a PC/SC connection.  Intended for unit testing.
 *
 * transport must not be NULL; it must outlive this call.
 */
ntag424_auth_status_t ntag424_auth_run_with_transport(
	const struct ntag424_auth_params *params,
	const ntag424_transport_t *transport);

#endif /* _NTAG424_PAM_GLUE_H */
