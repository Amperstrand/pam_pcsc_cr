/*
 * ntag424_policy.c — local config / policy parser for NTAG424 DNA auth.
 *
 * Parses an INI-like config file into an array of ntag424_card_entry structs.
 * All parsing is strict and fail-closed; any unexpected input causes
 * NTAG424_POLICY_ERR_PARSE to be returned.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>

#include "ntag424_policy.h"
#include "ntag424_verifier.h"

/* =========================================================================
 * Status string
 * ====================================================================== */

const char *ntag424_policy_status_string(ntag424_policy_status_t status)
{
	switch (status) {
	case NTAG424_POLICY_OK:
		return "ok";
	case NTAG424_POLICY_ERR_INVALID_ARGUMENT:
		return "invalid argument";
	case NTAG424_POLICY_ERR_OPEN:
		return "could not open config file";
	case NTAG424_POLICY_ERR_PARSE:
		return "config parse error";
	case NTAG424_POLICY_ERR_NO_MATCH:
		return "no matching card entry for user/uid";
	case NTAG424_POLICY_ERR_NOMEM:
		return "memory allocation failed";
	default:
		return "unknown error";
	}
}

/* =========================================================================
 * Policy struct (heap-allocated, opaque to callers)
 * ====================================================================== */

struct ntag424_policy {
	struct ntag424_card_entry *cards;
	size_t                     num_cards;
	size_t                     cap;       /* allocated capacity */
};

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

/* Parse `hex_len` hex characters from `hex` into `out` (hex_len/2 bytes).
 * Returns 0 on success, -1 on invalid characters or odd length.
 */
static int policy_parse_hex(const char *hex, size_t hex_len,
			    uint8_t *out, size_t out_len)
{
	size_t i;

	if (hex_len != out_len * 2)
		return -1;

	for (i = 0; i < out_len; i++) {
		unsigned int b;
		if (sscanf(hex + (i * 2), "%2x", &b) != 1)
			return -1;
		out[i] = (uint8_t)b;
	}
	return 0;
}

/* Trim leading and trailing ASCII whitespace in-place.
 * Returns pointer to first non-whitespace char; *len_out is updated.
 * The returned pointer is within the original buffer.
 */
static const char *policy_trim(const char *s, size_t *len_out)
{
	size_t len = *len_out;

	while (len > 0 && isspace((unsigned char)s[0])) { s++; len--; }
	while (len > 0 && isspace((unsigned char)s[len - 1])) { len--; }
	*len_out = len;
	return s;
}

/* Return 1 if s[0..len-1] consists only of alphanumeric, '-', '_'. */
static int policy_is_valid_id(const char *s, size_t len)
{
	size_t i;
	if (len == 0 || len >= NTAG424_POLICY_ID_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		char c = s[i];
		if (!isalnum((unsigned char)c) && c != '-' && c != '_')
			return 0;
	}
	return 1;
}

/* Return 1 if s[0..len-1] is a valid username (printable, no whitespace). */
static int policy_is_valid_username(const char *s, size_t len)
{
	size_t i;
	if (len == 0 || len >= NTAG424_POLICY_ID_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		if (isspace((unsigned char)s[i]) || !isprint((unsigned char)s[i]))
			return 0;
	}
	return 1;
}

/* Return 1 if card_id already exists in the policy. */
static int policy_has_duplicate(const struct ntag424_policy *p,
				const char *card_id)
{
	size_t i;
	for (i = 0; i < p->num_cards; i++) {
		if (strcmp(p->cards[i].card_id, card_id) == 0)
			return 1;
	}
	return 0;
}

/* Grow the cards array by doubling (or set initial capacity). */
static ntag424_policy_status_t policy_grow(struct ntag424_policy *p)
{
	size_t new_cap = (p->cap == 0) ? 4 : p->cap * 2;
	struct ntag424_card_entry *new_cards;

	new_cards = realloc(p->cards,
			    new_cap * sizeof(struct ntag424_card_entry));
	if (!new_cards)
		return NTAG424_POLICY_ERR_NOMEM;

	p->cards = new_cards;
	p->cap   = new_cap;
	return NTAG424_POLICY_OK;
}

/* =========================================================================
 * Parser state machine
 * ====================================================================== */

/* Bitmask of required fields within a [card:id] section */
#define FIELD_UID  0x01u
#define FIELD_K1   0x02u
#define FIELD_K2   0x04u
#define FIELD_USER 0x08u
#define FIELDS_ALL 0x0Fu

static ntag424_policy_status_t
finalise_entry(struct ntag424_policy *policy,
	       struct ntag424_card_entry *entry,
	       unsigned int fields_set,
	       int lineno)
{
	(void)lineno;

	if (fields_set == 0)
		return NTAG424_POLICY_OK;  /* empty (initial) state, nothing to finalise */

	if ((fields_set & FIELDS_ALL) != FIELDS_ALL)
		return NTAG424_POLICY_ERR_PARSE;  /* missing required field */

	if (policy_has_duplicate(policy, entry->card_id))
		return NTAG424_POLICY_ERR_PARSE;  /* duplicate card_id */

	if (policy->num_cards >= policy->cap) {
		ntag424_policy_status_t rc = policy_grow(policy);
		if (rc != NTAG424_POLICY_OK)
			return rc;
	}

	policy->cards[policy->num_cards++] = *entry;
	return NTAG424_POLICY_OK;
}

ntag424_policy_status_t ntag424_policy_load(const char *path,
					    struct ntag424_policy **out)
{
	FILE *f;
	struct ntag424_policy *policy;
	/* line buffer: NTAG424_POLICY_LINE_MAX chars + NUL + possible newline */
	char buf[NTAG424_POLICY_LINE_MAX + 2];
	int lineno = 0;
	int in_section = 0;                    /* currently inside [card:id] */
	struct ntag424_card_entry cur;
	unsigned int fields_set = 0;
	ntag424_policy_status_t rc = NTAG424_POLICY_OK;

	if (!path || !out)
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;

	policy = calloc(1, sizeof(*policy));
	if (!policy)
		return NTAG424_POLICY_ERR_NOMEM;

	f = fopen(path, "r");
	if (!f) {
		free(policy);
		return NTAG424_POLICY_ERR_OPEN;
	}

	memset(&cur, 0, sizeof(cur));

	while (fgets(buf, (int)sizeof(buf), f)) {
		size_t len;
		const char *line;
		size_t trimlen;

		lineno++;

		len = strlen(buf);

		/* Detect line too long: no NUL within NTAG424_POLICY_LINE_MAX+1 */
		if (len > NTAG424_POLICY_LINE_MAX &&
		    buf[NTAG424_POLICY_LINE_MAX] != '\n') {
			rc = NTAG424_POLICY_ERR_PARSE;
			goto done;
		}

		/* Strip trailing newline/CR */
		while (len > 0 &&
		       (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';

		/* Trim leading/trailing whitespace */
		line = buf;
		trimlen = len;
		line = policy_trim(line, &trimlen);

		/* Skip empty lines and comments */
		if (trimlen == 0 || line[0] == '#')
			continue;

		/* ── Section header ──────────────────────────────────── */
		if (line[0] == '[') {
			/* Finalise previous section before starting a new one */
			rc = finalise_entry(policy, &cur, fields_set, lineno);
			if (rc != NTAG424_POLICY_OK)
				goto done;

			/* Parse [card:<id>] */
			if (trimlen < 8 ||
			    strncmp(line, "[card:", 6) != 0 ||
			    line[trimlen - 1] != ']') {
				rc = NTAG424_POLICY_ERR_PARSE;
				goto done;
			}

			{
				const char *id_start = line + 6;
				size_t id_len = trimlen - 7; /* -6 for "[card:" and -1 for "]" */

				if (!policy_is_valid_id(id_start, id_len)) {
					rc = NTAG424_POLICY_ERR_PARSE;
					goto done;
				}

				memset(&cur, 0, sizeof(cur));
				memcpy(cur.card_id, id_start, id_len);
				cur.card_id[id_len] = '\0';
			}

			in_section = 1;
			fields_set = 0;
			continue;
		}

		/* ── Key = value ─────────────────────────────────────── */
		if (!in_section) {
			/* Key/value outside any section */
			rc = NTAG424_POLICY_ERR_PARSE;
			goto done;
		}

		{
			const char *eq = memchr(line, '=', trimlen);
			const char *key;
			size_t key_len;
			const char *val;
			size_t val_len;

			if (!eq) {
				rc = NTAG424_POLICY_ERR_PARSE;
				goto done;
			}

			key = line;
			key_len = (size_t)(eq - line);
			key = policy_trim(key, &key_len);

			val = eq + 1;
			val_len = trimlen - (size_t)(val - line);
			val = policy_trim(val, &val_len);

			if (key_len == 0) {
				rc = NTAG424_POLICY_ERR_PARSE;
				goto done;
			}

			if (key_len == 3 && strncmp(key, "uid", 3) == 0) {
				if (policy_parse_hex(val, val_len,
						     cur.uid,
						     NTAG424_UID_BYTES) != 0) {
					rc = NTAG424_POLICY_ERR_PARSE;
					goto done;
				}
				fields_set |= FIELD_UID;

			} else if (key_len == 2 && strncmp(key, "k1", 2) == 0) {
				if (policy_parse_hex(val, val_len,
						     cur.k1,
						     NTAG424_KEY_BYTES) != 0) {
					rc = NTAG424_POLICY_ERR_PARSE;
					goto done;
				}
				fields_set |= FIELD_K1;

			} else if (key_len == 2 && strncmp(key, "k2", 2) == 0) {
				if (policy_parse_hex(val, val_len,
						     cur.k2,
						     NTAG424_KEY_BYTES) != 0) {
					rc = NTAG424_POLICY_ERR_PARSE;
					goto done;
				}
				fields_set |= FIELD_K2;

			} else if (key_len == 4 && strncmp(key, "user", 4) == 0) {
				if (!policy_is_valid_username(val, val_len)) {
					rc = NTAG424_POLICY_ERR_PARSE;
					goto done;
				}
				memcpy(cur.username, val, val_len);
				cur.username[val_len] = '\0';
				fields_set |= FIELD_USER;

			} else {
				/* Unknown key — fail closed */
				rc = NTAG424_POLICY_ERR_PARSE;
				goto done;
			}
		}
	}

	/* Finalise the last section (or the initial state if file was empty) */
	rc = finalise_entry(policy, &cur, fields_set, lineno);

done:
	fclose(f);

	if (rc != NTAG424_POLICY_OK) {
		free(policy->cards);
		free(policy);
		return rc;
	}

	*out = policy;
	return NTAG424_POLICY_OK;
}

void ntag424_policy_free(struct ntag424_policy *policy)
{
	if (!policy)
		return;
	free(policy->cards);
	free(policy);
}

/* =========================================================================
 * Lookup
 * ====================================================================== */

/*
 * Constant-time comparison of two byte arrays of equal length.
 * Returns 1 if equal, 0 otherwise.
 */
static int ct_bytes_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0;
	size_t i;
	for (i = 0; i < len; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

ntag424_policy_status_t ntag424_policy_lookup(
	const struct ntag424_policy *policy,
	const char *username,
	const uint8_t uid[NTAG424_UID_BYTES],
	const struct ntag424_card_entry **entry_out)
{
	size_t i;

	if (!policy || !username || !uid || !entry_out)
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;

	for (i = 0; i < policy->num_cards; i++) {
		const struct ntag424_card_entry *e = &policy->cards[i];

		if (strcmp(e->username, username) != 0)
			continue;

		if (!ct_bytes_eq(e->uid, uid, NTAG424_UID_BYTES))
			continue;

		*entry_out = e;
		return NTAG424_POLICY_OK;
	}

	return NTAG424_POLICY_ERR_NO_MATCH;
}

/* =========================================================================
 * Convenience: try verify against all cards for a user
 * ====================================================================== */

ntag424_policy_status_t ntag424_policy_try_verify(
	const struct ntag424_policy *policy,
	const char *username,
	const char *url_or_query,
	struct ntag424_verify_result *result_out,
	const struct ntag424_card_entry **card_out)
{
	size_t i;

	if (!policy || !username || !url_or_query || !result_out || !card_out)
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;

	for (i = 0; i < policy->num_cards; i++) {
		const struct ntag424_card_entry *e = &policy->cards[i];
		ntag424_verify_status_t vrc;
		struct ntag424_verify_result result;

		if (strcmp(e->username, username) != 0)
			continue;

		memset(&result, 0, sizeof(result));
		vrc = ntag424_verify_from_url(url_or_query, e->k1, e->k2,
					      &result);
		if (vrc != NTAG424_VERIFY_OK)
			continue;

		if (!ct_bytes_eq(result.uid, e->uid, NTAG424_UID_BYTES))
			continue;

		*result_out = result;
		*card_out   = e;
		return NTAG424_POLICY_OK;
	}

	return NTAG424_POLICY_ERR_NO_MATCH;
}

/* =========================================================================
 * Card entry validation
 * ====================================================================== */

ntag424_policy_status_t ntag424_policy_validate_card_entry(
	const struct ntag424_card_entry *entry)
{
	if (!entry)
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;
	if (entry->card_id[0] == '\0')
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;
	if (entry->username[0] == '\0')
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;
	return NTAG424_POLICY_OK;
}

/* =========================================================================
 * Config file writing
 * ====================================================================== */

static void format_hex_lower(const uint8_t *src, size_t src_len,
			     char *dst)
{
	size_t i;
	for (i = 0; i < src_len; i++)
		snprintf(dst + i * 2, 3, "%02x", (unsigned)src[i]);
}

static ntag424_policy_status_t write_card_entry(FILE *f,
						const struct ntag424_card_entry *e)
{
	char uid_hex[NTAG424_UID_BYTES * 2 + 1];
	char k1_hex[NTAG424_KEY_BYTES * 2 + 1];
	char k2_hex[NTAG424_KEY_BYTES * 2 + 1];

	format_hex_lower(e->uid, NTAG424_UID_BYTES, uid_hex);
	format_hex_lower(e->k1, NTAG424_KEY_BYTES, k1_hex);
	format_hex_lower(e->k2, NTAG424_KEY_BYTES, k2_hex);

	uid_hex[NTAG424_UID_BYTES * 2] = '\0';
	k1_hex[NTAG424_KEY_BYTES * 2] = '\0';
	k2_hex[NTAG424_KEY_BYTES * 2] = '\0';

	if (fprintf(f, "[card:%s]\nuid  = %s\nk1   = %s\nk2   = %s\nuser = %s\n",
		    e->card_id, uid_hex, k1_hex, k2_hex,
		    e->username) < 0)
		return NTAG424_POLICY_ERR_OPEN;

	return NTAG424_POLICY_OK;
}

ntag424_policy_status_t ntag424_policy_add_card(
	const char *config_path,
	const struct ntag424_card_entry *entry,
	int overwrite)
{
	ntag424_policy_status_t rc;
	struct ntag424_policy *policy = NULL;
	FILE *f;
	int found_idx = -1;
	size_t i;
	char tmp_path[512];

	rc = ntag424_policy_validate_card_entry(entry);
	if (rc != NTAG424_POLICY_OK)
		return rc;

	if (!config_path)
		return NTAG424_POLICY_ERR_INVALID_ARGUMENT;

	/* Try to load existing config */
	rc = ntag424_policy_load(config_path, &policy);

	if (rc == NTAG424_POLICY_ERR_OPEN) {
		/* File doesn't exist — create new */
		f = fopen(config_path, "w");
		if (!f)
			return NTAG424_POLICY_ERR_OPEN;
		rc = write_card_entry(f, entry);
		fclose(f);
		return rc;
	}

	if (rc != NTAG424_POLICY_OK)
		return rc;  /* malformed existing config */

	/* Check for duplicate card_id */
	for (i = 0; i < policy->num_cards; i++) {
		if (strcmp(policy->cards[i].card_id, entry->card_id) == 0) {
			found_idx = (int)i;
			break;
		}
	}

	if (found_idx >= 0 && !overwrite) {
		ntag424_policy_free(policy);
		return NTAG424_POLICY_ERR_PARSE;
	}

	/* Write to temp file, then rename for atomicity */
	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d",
		 config_path, (int)getpid());

	f = fopen(tmp_path, "w");
	if (!f) {
		ntag424_policy_free(policy);
		return NTAG424_POLICY_ERR_OPEN;
	}

	for (i = 0; i < policy->num_cards; i++) {
		if ((int)i == found_idx) {
			rc = write_card_entry(f, entry);
		} else {
			rc = write_card_entry(f, &policy->cards[i]);
		}
		if (rc != NTAG424_POLICY_OK) {
			fclose(f);
			unlink(tmp_path);
			ntag424_policy_free(policy);
			return rc;
		}
	}

	if (found_idx < 0) {
		rc = write_card_entry(f, entry);
		if (rc != NTAG424_POLICY_OK) {
			fclose(f);
			unlink(tmp_path);
			ntag424_policy_free(policy);
			return rc;
		}
	}

	fclose(f);
	ntag424_policy_free(policy);

	if (rename(tmp_path, config_path) != 0) {
		unlink(tmp_path);
		return NTAG424_POLICY_ERR_OPEN;
	}

	return NTAG424_POLICY_OK;
}
