/*
 * ntag424_testread.c — manual hardware test utility for the NTAG424 reader layer.
 *
 * Connects to the first available PC/SC reader (or the one matching -r),
 * performs a full NFC Forum Type 4 NDEF read, and reports:
 *   - the selected reader name
 *   - NDEF length in bytes
 *   - whether p= and c= parameters are present in the extracted URL
 *
 * By default only summary info is printed.  Use -v to also print the full
 * URL and the p= / c= parameter values (these are single-use, counter-based
 * card outputs — not key material — and are safe to display for testing).
 *
 * It requires a live pcscd daemon and an NTAG424 (or compatible T4T) card.
 *
 * Usage:
 *   ntag424_testread [-r reader_substring] [-v] [-h]
 *
 *   -r reader_substring  substring match for reader name (default: first reader)
 *   -v                   verbose: print full URL and p=/c= values
 *   -h                   show this help
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ntag424_reader.h"
#include "ntag424_verifier.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-r reader_substring] [-v] [-h]\n"
		"\n"
		"  -r <substr>  select reader whose name contains <substr>\n"
		"               (default: first available reader)\n"
		"  -v           verbose: print full URL and p=/c= parameter values\n"
		"  -h           show this help\n"
		"\n"
		"Requires a live pcscd daemon and an NTAG424 (Type 4) card.\n",
		prog);
}

int main(int argc, char *argv[])
{
	const char *reader_substr = NULL;
	int verbose = 0;
	int opt;

	struct ntag424_pcsc_ctx *ctx = NULL;
	ntag424_transport_t transport;
	uint8_t ndef_buf[NTAG424_READER_NDEF_MAX];
	size_t  ndef_len;
	ntag424_reader_status_t rc;

	char url[NTAG424_MAX_URL];
	char p_hex[NTAG424_P_HEX_LEN + 1];
	char c_hex[NTAG424_C_HEX_LEN + 1];
	int p_found, c_found;

	while ((opt = getopt(argc, argv, "r:vh")) != -1) {
		switch (opt) {
		case 'r':
			reader_substr = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* ----------------------------------------------------------------
	 * Open PC/SC context
	 * -------------------------------------------------------------- */
	rc = ntag424_pcsc_open(&ctx);
	if (rc != NTAG424_READER_OK) {
		fprintf(stderr, "Error: ntag424_pcsc_open: %s\n",
			ntag424_reader_status_string(rc));
		fprintf(stderr, "Is pcscd running?\n");
		return 1;
	}

	/* ----------------------------------------------------------------
	 * Select reader
	 * -------------------------------------------------------------- */
	rc = ntag424_pcsc_select_reader(ctx, reader_substr);
	if (rc != NTAG424_READER_OK) {
		fprintf(stderr, "Error: no reader found (%s)%s\n",
			ntag424_reader_status_string(rc),
			reader_substr ? " matching substring" : "");
		ntag424_pcsc_close(ctx);
		return 1;
	}

	printf("Reader: %s\n", ntag424_pcsc_reader_name(ctx));

	/* ----------------------------------------------------------------
	 * Connect to card
	 * -------------------------------------------------------------- */
	rc = ntag424_pcsc_connect(ctx);
	if (rc != NTAG424_READER_OK) {
		fprintf(stderr, "Error: ntag424_pcsc_connect: %s\n",
			ntag424_reader_status_string(rc));
		fprintf(stderr, "Is a card on the reader?\n");
		ntag424_pcsc_close(ctx);
		return 1;
	}

	/* ----------------------------------------------------------------
	 * Obtain transport and read NDEF
	 * -------------------------------------------------------------- */
	rc = ntag424_pcsc_get_transport(ctx, &transport);
	if (rc != NTAG424_READER_OK) {
		fprintf(stderr, "Error: ntag424_pcsc_get_transport: %s\n",
			ntag424_reader_status_string(rc));
		ntag424_pcsc_close(ctx);
		return 1;
	}

	rc = ntag424_read_ndef(&transport, ndef_buf, sizeof(ndef_buf), &ndef_len);
	if (rc != NTAG424_READER_OK) {
		fprintf(stderr, "Error: ntag424_read_ndef: %s\n",
			ntag424_reader_status_string(rc));
		ntag424_pcsc_close(ctx);
		return 1;
	}

	printf("NDEF length: %zu bytes\n", ndef_len);

	/* ----------------------------------------------------------------
	 * Extract URL and check for p/c parameters (no values printed)
	 * -------------------------------------------------------------- */
	if (ndef_len == 0) {
		printf("NDEF message is empty.\n");
	} else {
		ntag424_verify_status_t vrc;

		vrc = ntag424_extract_url_from_ndef(ndef_buf, ndef_len,
						    url, sizeof(url));
		if (vrc != NTAG424_VERIFY_OK) {
			printf("URL extraction: failed (%s)\n",
			       ntag424_verify_status_string(vrc));
		} else {
			printf("URL extraction: ok\n");
			if (verbose)
				printf("URL:            %s\n", url);

			vrc = ntag424_extract_p_c(url,
						  p_hex, sizeof(p_hex),
						  c_hex, sizeof(c_hex));
			p_found = (vrc == NTAG424_VERIFY_OK);
			c_found = (vrc == NTAG424_VERIFY_OK);

			printf("p parameter:    %s\n", p_found ? "found" : "not found");
			if (p_found && verbose)
				printf("p value:        %s\n", p_hex);
			printf("c parameter:    %s\n", c_found ? "found" : "not found");
			if (c_found && verbose)
				printf("c value:        %s\n", c_hex);
		}
	}

	ntag424_pcsc_close(ctx);
	return 0;
}
