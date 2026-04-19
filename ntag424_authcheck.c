/*
 * ntag424_authcheck.c — non-PAM end-to-end auth harness for NTAG424 DNA.
 *
 * Exercises the full Milestone 3 stack:
 *   URL → verifier → policy → replay → accept/reject
 *
 * This tool is used to prove the Milestone 3 components work together
 * before PAM integration (Milestone 4).
 *
 * Usage:
 *   ntag424_authcheck -u <username> -c <config_path> -d <replay_db_path>
 *                     --url <url_or_query_string>
 *
 *   -u <username>   PAM username to authenticate
 *   -c <path>       path to ntag424 policy config file
 *   -d <path>       path to SQLite replay database (created if absent)
 *   --url <url>     full URL or bare p=...&c=... query string from card
 *   -h              show help
 *
 * Output (stdout):
 *   AUTH OK        — all checks passed, counter updated
 *   AUTH FAILED: <reason>  — check failed
 *
 * Sensitive data (URL, p, c, keys) is NOT printed by default.
 * The exit code is 0 on success, 1 on failure, 2 on usage error.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ntag424_policy.h"
#include "ntag424_replay.h"
#include "ntag424_verifier.h"

#define EXIT_AUTH_OK     0
#define EXIT_AUTH_FAIL   1
#define EXIT_USAGE_ERROR 2

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -u <username> -c <config> -d <db> --url <url>\n"
		"\n"
		"  -u <username>  PAM username to authenticate\n"
		"  -c <config>    path to ntag424 policy config file\n"
		"  -d <db>        path to SQLite replay database\n"
		"  --url <url>    URL or bare p=...&c=... from card\n"
		"  -h             show this help\n"
		"\n"
		"Exit codes: 0=AUTH OK, 1=AUTH FAILED, 2=usage error\n"
		"Does NOT print sensitive URL/key values.\n",
		prog);
}

/*
 * Format a 7-byte UID as a 14-char uppercase hex string + NUL.
 * buf must be at least 15 bytes.
 */
static void uid_to_hex_upper(const uint8_t uid[NTAG424_UID_BYTES],
			     char buf[15])
{
	int i;
	for (i = 0; i < NTAG424_UID_BYTES; i++)
		snprintf(buf + i * 2, 3, "%02X", (unsigned)uid[i]);
}

int main(int argc, char *argv[])
{
	const char *username    = NULL;
	const char *config_path = NULL;
	const char *db_path     = NULL;
	const char *url         = NULL;

	struct ntag424_policy    *policy = NULL;
	struct ntag424_replay_db *db     = NULL;
	struct ntag424_verify_result result;
	const struct ntag424_card_entry *card = NULL;
	ntag424_policy_status_t prc;
	ntag424_replay_status_t rrc;
	char uid_hex[15];
	int i, ret = EXIT_AUTH_FAIL;

	/* ── Argument parsing ───────────────────────────────────────── */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
			username = argv[++i];
		} else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
			config_path = argv[++i];
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			db_path = argv[++i];
		} else if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
			url = argv[++i];
		} else if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return EXIT_AUTH_OK;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
			return EXIT_USAGE_ERROR;
		}
	}

	if (!username || !config_path || !db_path || !url) {
		fprintf(stderr, "All of -u, -c, -d, --url are required.\n");
		usage(argv[0]);
		return EXIT_USAGE_ERROR;
	}

	/* ── Load policy config ─────────────────────────────────────── */
	prc = ntag424_policy_load(config_path, &policy);
	if (prc != NTAG424_POLICY_OK) {
		fprintf(stderr, "AUTH FAILED: policy load: %s\n",
			ntag424_policy_status_string(prc));
		printf("AUTH FAILED: policy load error\n");
		return EXIT_AUTH_FAIL;
	}

	/* ── Open replay database ───────────────────────────────────── */
	rrc = ntag424_replay_open(db_path, &db);
	if (rrc != NTAG424_REPLAY_OK) {
		fprintf(stderr, "AUTH FAILED: replay db: %s\n",
			ntag424_replay_status_string(rrc));
		printf("AUTH FAILED: replay database error\n");
		ntag424_policy_free(policy);
		return EXIT_AUTH_FAIL;
	}

	/* ── Verify URL against policy (finds card + verifies crypto) ── */
	memset(&result, 0, sizeof(result));
	prc = ntag424_policy_try_verify(policy, username, url,
					&result, &card);
	if (prc != NTAG424_POLICY_OK) {
		printf("AUTH FAILED: %s\n",
		       ntag424_policy_status_string(prc));
		ret = EXIT_AUTH_FAIL;
		goto out;
	}

	/* ── Replay check and counter update ───────────────────────── */
	uid_to_hex_upper(result.uid, uid_hex);

	rrc = ntag424_replay_check_and_update(db, uid_hex,
					      result.counter_value);
	if (rrc != NTAG424_REPLAY_OK) {
		printf("AUTH FAILED: %s\n",
		       ntag424_replay_status_string(rrc));
		ret = EXIT_AUTH_FAIL;
		goto out;
	}

	/* ── All checks passed ─────────────────────────────────────── */
	printf("AUTH OK\n");
	ret = EXIT_AUTH_OK;

out:
	ntag424_replay_close(db);
	ntag424_policy_free(policy);
	return ret;
}
