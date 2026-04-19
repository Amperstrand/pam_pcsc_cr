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

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -u <user> --uid <hex> --k1 <hex> --k2 <hex> "
		"[options]\n"
		"\n"
		"Required:\n"
		"  -u <username>     PAM username\n"
		"  --uid <hex>       Card UID (14 hex chars, 7 bytes)\n"
		"  --k1 <hex>        SDM decryption key (32 hex chars, 16 bytes)\n"
		"  --k2 <hex>        CMAC verification key (32 hex chars, 16 bytes)\n"
		"\n"
		"Optional:\n"
		"  -c <path>         Config file path (default: /etc/ntag424.conf)\n"
		"  --id <label>      Card identifier (default: card-<user>-<uid>)\n"
		"  --force           Overwrite existing card entry with same ID\n"
		"  -h                Show this help\n"
		"\n"
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
	const char *username    = NULL;
	const char *uid_hex     = NULL;
	const char *k1_hex      = NULL;
	const char *k2_hex      = NULL;
	const char *config_path = "/etc/ntag424.conf";
	const char *card_id     = NULL;
	int force = 0;
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
		} else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
			config_path = argv[++i];
		} else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
			card_id = argv[++i];
		} else if (strcmp(argv[i], "--force") == 0) {
			force = 1;
		} else if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	if (!username || !uid_hex || !k1_hex || !k2_hex) {
		fprintf(stderr, "Error: -u, --uid, --k1, --k2 are all required.\n");
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

	if (hex_to_bytes(k1_hex, entry.k1, NTAG424_KEY_BYTES) != 0) {
		fprintf(stderr, "Error: K1 must be exactly 32 hex characters\n");
		return 2;
	}

	if (hex_to_bytes(k2_hex, entry.k2, NTAG424_KEY_BYTES) != 0) {
		fprintf(stderr, "Error: K2 must be exactly 32 hex characters\n");
		return 2;
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
