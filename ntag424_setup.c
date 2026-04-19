/*
 * ntag424_setup.c — CLI tool for registering NTAG424 card entries.
 *
 * Creates or updates the NTAG424 policy config file with card identity
 * and key material.  Assumes the card is already deployed with known keys.
 *
 * Usage:
 *   ntag424_setup -u <user> --uid <hex> --k1 <hex> --k2 <hex> [options]
 *
 * Exit codes: 0=success, 1=operation failed, 2=usage error.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "ntag424_policy.h"
#include "ntag424_verifier.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -u <user> --uid <hex> (--issuer-key <hex> | --k1 <hex> --k2 <hex> | --use-defaults) "
		"[options]\n"
		"\n"
		"Required:\n"
		"  -u <username>         PAM username\n"
		"  --uid <hex>           Card UID (14 hex chars, 7 bytes)\n"
		"\n"
		"Key source (pick one):\n"
		"  --issuer-key <hex>    Per-card issuer key for deterministic derivation\n"
		"                        (32 hex). K1/K2 derived at auth time.\n"
		"                        Default card version is 1; use --card-version\n"
		"                        to override.\n"
		"  --k1 <hex>            SDM decryption key (32 hex chars)\n"
		"  --k2 <hex>            CMAC verification key (32 hex chars)\n"
		"  --use-defaults        No per-card keys; derive from [defaults] section\n"
		"\n"
		"Optional:\n"
		"  -c <path>             Config file path (default: /etc/ntag424.conf)\n"
		"  --id <label>          Card identifier (default: card-<user>-<uid>)\n"
		"  --card-version <int>  Card version for key derivation (default: 1)\n"
		"  --force               Overwrite existing card entry with same ID\n"
		"  -h                    Show this help\n"
		"\n"
		"The config file must be readable only by root (mode 0600).\n"
		"Exit codes: 0=ok, 1=failed, 2=usage error\n",
		prog);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes)
{
	size_t i;
	size_t hex_len = strlen(hex);

	if (hex_len != expected_bytes * 2)
		return -1;

	for (i = 0; i < hex_len; i++) {
		if (!isxdigit((unsigned char)hex[i]))
			return -1;
	}

	for (i = 0; i < expected_bytes; i++) {
		unsigned int b;
		if (sscanf(hex + i * 2, "%2x", &b) != 1)
			return -1;
		out[i] = (uint8_t)b;
	}

	return 0;
}

static void uid_hex_lower(const uint8_t *uid, char *out)
{
	int i;
	for (i = 0; i < NTAG424_UID_BYTES; i++)
		snprintf(out + i * 2, 3, "%02x", (unsigned)uid[i]);
}

int main(int argc, char *argv[])
{
	const char *username     = NULL;
	const char *uid_hex      = NULL;
	const char *k1_hex       = NULL;
	const char *k2_hex       = NULL;
	const char *issuer_key_hex = NULL;
	unsigned int card_version = 1;
	const char *config_path  = "/etc/ntag424.conf";
	const char *card_id      = NULL;
	int force = 0;
	int use_defaults = 0;
	int i;

	struct ntag424_card_entry entry;
	char uid_lower[NTAG424_UID_BYTES * 2 + 1];
	ntag424_policy_status_t rc;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
			username = argv[++i];
		} else if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
			uid_hex = argv[++i];
		} else if (strcmp(argv[i], "--k1") == 0 && i + 1 < argc) {
			k1_hex = argv[++i];
		} else if (strcmp(argv[i], "--k2") == 0 && i + 1 < argc) {
			k2_hex = argv[++i];
		} else if (strcmp(argv[i], "--issuer-key") == 0 && i + 1 < argc) {
			issuer_key_hex = argv[++i];
		} else if (strcmp(argv[i], "--card-version") == 0 && i + 1 < argc) {
			card_version = (unsigned int)atoi(argv[++i]);
		} else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
			config_path = argv[++i];
		} else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
			card_id = argv[++i];
	} else if (strcmp(argv[i], "--force") == 0) {
		force = 1;
	} else if (strcmp(argv[i], "--use-defaults") == 0) {
		use_defaults = 1;
		} else if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	if (!username || !uid_hex) {
		fprintf(stderr, "Error: -u and --uid are required.\n");
		usage(argv[0]);
		return 2;
	}

	if (issuer_key_hex && (k1_hex || k2_hex)) {
		fprintf(stderr, "Error: --issuer-key cannot be used with --k1/--k2.\n");
		return 2;
	}

	if (use_defaults && (issuer_key_hex || k1_hex || k2_hex)) {
		fprintf(stderr, "Error: --use-defaults cannot be used with key options.\n");
		return 2;
	}

	if (!use_defaults && !issuer_key_hex && (!k1_hex || !k2_hex)) {
		fprintf(stderr, "Error: provide --issuer-key, --k1/--k2, or --use-defaults.\n");
		usage(argv[0]);
		return 2;
	}

	/* Validate username */
	if (username[0] == '\0' || strlen(username) >= NTAG424_POLICY_ID_MAX) {
		fprintf(stderr, "Error: invalid username\n");
		return 2;
	}

	/* Parse hex inputs */
	memset(&entry, 0, sizeof(entry));

	if (hex_to_bytes(uid_hex, entry.uid, NTAG424_UID_BYTES) != 0) {
		fprintf(stderr, "Error: UID must be exactly 14 hex characters\n");
		return 2;
	}

	if (use_defaults) {
		/* No per-card keys; relies on [defaults] in config */
		if (card_version != 1)
			entry.card_version = card_version;
	} else if (issuer_key_hex) {
		if (hex_to_bytes(issuer_key_hex, entry.issuer_key,
				 NTAG424_KEY_BYTES) != 0) {
			fprintf(stderr, "Error: issuer key must be exactly 32 hex characters\n");
			return 2;
		}
		entry.has_issuer_key = 1;
		if (card_version != 1)
			entry.card_version = card_version;

		printf("Per-card issuer_key set (version %u).\n", card_version);
	} else {
		if (hex_to_bytes(k1_hex, entry.k1, NTAG424_KEY_BYTES) != 0) {
			fprintf(stderr, "Error: K1 must be exactly 32 hex characters\n");
			return 2;
		}

		if (hex_to_bytes(k2_hex, entry.k2, NTAG424_KEY_BYTES) != 0) {
			fprintf(stderr, "Error: K2 must be exactly 32 hex characters\n");
			return 2;
		}
		entry.has_k1_k2 = 1;
	}

	/* Set username */
	snprintf(entry.username, sizeof(entry.username), "%s", username);

	/* Set or generate card_id */
	if (card_id) {
		snprintf(entry.card_id, sizeof(entry.card_id), "%s", card_id);
	} else {
		uid_hex_lower(entry.uid, uid_lower);
		snprintf(entry.card_id, sizeof(entry.card_id),
			 "card-%s-%s", username, uid_lower);
	}

	/* Write to config */
	rc = ntag424_policy_add_card(config_path, &entry, force);
	if (rc != NTAG424_POLICY_OK) {
		fprintf(stderr, "Error: %s\n",
			ntag424_policy_status_string(rc));
		return 1;
	}

	printf("Added card [%s] for user [%s] to %s\n",
	       entry.card_id, username, config_path);
	return 0;
}
