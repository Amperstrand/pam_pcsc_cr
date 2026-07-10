#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ntag424_policy.h"

#define EXIT_OK          0
#define EXIT_FAIL        1
#define EXIT_USAGE_ERROR 2

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -u <username> --uid <hex> --k1 <hex> --k2 <hex> [options]\n"
		"\n"
		"Required:\n"
		"  -u <username>     PAM username\n"
		"  --uid <hex>       Card UID as 14-character hex string (7 bytes)\n"
		"  --k1 <hex>        SDM decryption key as 32-character hex string (16 bytes)\n"
		"  --k2 <hex>        CMAC verification key as 32-character hex string (16 bytes)\n"
		"\n"
		"Optional:\n"
		"  -c <path>         Policy config file path (default: /etc/ntag424.conf)\n"
		"  --id <label>      Card identifier (default: card-<username>-<uid_hex_lowercase>)\n"
		"  --force           Overwrite existing card entry with same ID\n"
		"  -h                Show help and exit\n",
		prog);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes)
{
	size_t hex_len;
	size_t i;
	unsigned int hi;
	unsigned int lo;

	if (!hex || !out)
		return -1;

	hex_len = strlen(hex);
	if (hex_len != expected_bytes * 2)
		return -1;

	for (i = 0; i < hex_len; i++) {
		if (!isxdigit((unsigned char)hex[i]))
			return -1;
	}

	for (i = 0; i < expected_bytes; i++) {
		if (hex[i * 2] >= '0' && hex[i * 2] <= '9')
			hi = (unsigned int)(hex[i * 2] - '0');
		else if (hex[i * 2] >= 'a' && hex[i * 2] <= 'f')
			hi = (unsigned int)(hex[i * 2] - 'a' + 10);
		else
			hi = (unsigned int)(hex[i * 2] - 'A' + 10);

		if (hex[i * 2 + 1] >= '0' && hex[i * 2 + 1] <= '9')
			lo = (unsigned int)(hex[i * 2 + 1] - '0');
		else if (hex[i * 2 + 1] >= 'a' && hex[i * 2 + 1] <= 'f')
			lo = (unsigned int)(hex[i * 2 + 1] - 'a' + 10);
		else
			lo = (unsigned int)(hex[i * 2 + 1] - 'A' + 10);

		out[i] = (uint8_t)((hi << 4) | lo);
	}

	return 0;
}

static int username_is_valid(const char *username)
{
	size_t len;
	size_t i;

	if (!username)
		return 0;

	len = strlen(username);
	if (len == 0 || len >= NTAG424_POLICY_ID_MAX)
		return 0;

	for (i = 0; i < len; i++) {
		if (isspace((unsigned char)username[i]))
			return 0;
	}

	return 1;
}

static void uid_to_hex_lower(const uint8_t uid[NTAG424_UID_BYTES],
			     char buf[NTAG424_UID_BYTES * 2 + 1])
{
	int i;

	for (i = 0; i < NTAG424_UID_BYTES; i++)
		snprintf(buf + i * 2, 3, "%02x", (unsigned)uid[i]);
}

int main(int argc, char *argv[])
{
	const char *username;
	const char *uid_hex;
	const char *k1_hex;
	const char *k2_hex;
	const char *config_path;
	const char *card_id;
	char uid_hex_lower[NTAG424_UID_BYTES * 2 + 1];
	struct ntag424_card_entry entry;
	ntag424_policy_status_t rc;
	int force;
	int i;

	username = NULL;
	uid_hex = NULL;
	k1_hex = NULL;
	k2_hex = NULL;
	config_path = "/etc/ntag424.conf";
	card_id = NULL;
	force = 0;

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
			return EXIT_OK;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
			return EXIT_USAGE_ERROR;
		}
	}

	if (!username || !uid_hex || !k1_hex || !k2_hex) {
		fprintf(stderr, "Error: -u, --uid, --k1, and --k2 are required.\n");
		usage(argv[0]);
		return EXIT_USAGE_ERROR;
	}

	if (!username_is_valid(username)) {
		fprintf(stderr,
			"Error: username must be non-empty, at most 63 chars, and contain no whitespace.\n");
		return EXIT_USAGE_ERROR;
	}

	memset(&entry, 0, sizeof(entry));

	if (hex_to_bytes(uid_hex, entry.uid, NTAG424_UID_BYTES) != 0) {
		fprintf(stderr, "Error: UID must be exactly 14 hex characters.\n");
		return EXIT_USAGE_ERROR;
	}

	if (hex_to_bytes(k1_hex, entry.k1, NTAG424_KEY_BYTES) != 0) {
		fprintf(stderr, "Error: K1 must be exactly 32 hex characters.\n");
		return EXIT_USAGE_ERROR;
	}

	if (hex_to_bytes(k2_hex, entry.k2, NTAG424_KEY_BYTES) != 0) {
		fprintf(stderr, "Error: K2 must be exactly 32 hex characters.\n");
		return EXIT_USAGE_ERROR;
	}

	entry.has_k1_k2 = 1;
	entry.has_issuer_key = 0;
	entry.card_version = 0;

	snprintf(entry.username, sizeof(entry.username), "%s", username);

	if (card_id) {
		snprintf(entry.card_id, sizeof(entry.card_id), "%s", card_id);
	} else {
		uid_to_hex_lower(entry.uid, uid_hex_lower);
		snprintf(entry.card_id, sizeof(entry.card_id),
			 "card-%s-%s", username, uid_hex_lower);
	}

	rc = ntag424_policy_add_card(config_path, &entry, force);
	if (rc != NTAG424_POLICY_OK) {
		fprintf(stderr, "Error: %s\n", ntag424_policy_status_string(rc));
		return EXIT_FAIL;
	}

	printf("Added card [%s] for user [%s] to %s\n",
	       entry.card_id, username, config_path);
	return EXIT_OK;
}
