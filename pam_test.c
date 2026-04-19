/*
 * pam_test.c — minimal PAM test harness.
 *
 * Calls pam_authenticate() for a given service/user so we can test
 * the pam_pcsc_cr ntag424 backend without touching any system PAM config.
 *
 * Usage: ./pam_test <service> <username>
 *
 * Example:
 *   sudo ./pam_test boltcard-login boltcard
 *   (then tap the Bolt Card on the NFC reader)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

static int conv_cb(int num_msg, const struct pam_message **msg,
		   struct pam_response **resp, void *appdata_ptr)
{
	(void)appdata_ptr;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	*resp = calloc((size_t)num_msg, sizeof(struct pam_response));
	if (!*resp)
		return PAM_CONV_ERR;

	/* Just acknowledge any prompts — the NTAG424 backend doesn't
	   ask for input, but silence any PAM_TEXT_INFO / PAM_ERROR_MSG. */
	for (int i = 0; i < num_msg; i++) {
		(*resp)[i].resp = NULL;
		(*resp)[i].resp_retcode = 0;
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
		    msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
			(*resp)[i].resp = strdup("");
		}
	}
	return PAM_SUCCESS;
}

int main(int argc, char *argv[])
{
	pam_handle_t *pamh = NULL;
	struct pam_conv conv = { .conv = conv_cb, .appdata_ptr = NULL };
	int rc;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <service> <username>\n", argv[0]);
		return 1;
	}

	rc = pam_start(argv[1], argv[2], &conv, &pamh);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_start: %s\n", pam_strerror(pamh, rc));
		return 1;
	}

	printf("Authenticating [%s] via service [%s]...\n", argv[2], argv[1]);
	printf("Tap your Bolt Card now.\n");

	rc = pam_authenticate(pamh, 0);
	if (rc == PAM_SUCCESS) {
		printf("AUTH OK\n");
	} else {
		printf("AUTH FAILED: %s\n", pam_strerror(pamh, rc));
	}

	pam_end(pamh, rc);
	return (rc == PAM_SUCCESS) ? 0 : 1;
}
