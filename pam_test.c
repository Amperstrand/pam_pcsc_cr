/*
 * pam_test.c — PAM test harness with optional shell drop.
 *
 * Usage: ./pam_test [-s] <service> <username>
 *   -s    on success, drop to a shell as the target user
 *
 * Example:
 *   sudo ./pam_test boltcard-login boltcard       (auth-only)
 *   sudo ./pam_test -s boltcard-login boltcard    (auth + shell)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>

static int conv_cb(int num_msg, const struct pam_message **msg,
		   struct pam_response **resp, void *appdata_ptr)
{
	int i;

	(void)appdata_ptr;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	*resp = calloc((size_t)num_msg, sizeof(struct pam_response));
	if (!*resp)
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		if (msg[i]->msg_style == PAM_TEXT_INFO ||
		    msg[i]->msg_style == PAM_ERROR_MSG) {
			fprintf(stderr, "%s\n", msg[i]->msg);
		}
		(*resp)[i].resp = NULL;
		(*resp)[i].resp_retcode = 0;
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
		    msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
			(*resp)[i].resp = strdup("");
		}
	}
	return PAM_SUCCESS;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-s] <service> <username>\n", prog);
	fprintf(stderr, "  -s    drop to shell as user on success\n");
}

int main(int argc, char *argv[])
{
	pam_handle_t *pamh = NULL;
	struct pam_conv conv = { .conv = conv_cb, .appdata_ptr = NULL };
	int rc, opt, do_shell = 0;
	const char *service, *username;

	while ((opt = getopt(argc, argv, "sh")) != -1) {
		switch (opt) {
		case 's':
			do_shell = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (argc - optind != 2) {
		usage(argv[0]);
		return 1;
	}

	service = argv[optind];
	username = argv[optind + 1];

	rc = pam_start(service, username, &conv, &pamh);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_start: %s\n", pam_strerror(pamh, rc));
		return 1;
	}

	printf("Authenticating [%s] via service [%s]...\n", username, service);
	printf("Tap your Bolt Card now.\n");

	rc = pam_authenticate(pamh, 0);
	if (rc == PAM_SUCCESS) {
		printf("AUTH OK\n");
	} else {
		printf("AUTH FAILED: %s\n", pam_strerror(pamh, rc));
		pam_end(pamh, rc);
		return 1;
	}

	if (do_shell) {
		struct passwd *pw = getpwnam(username);
		if (!pw) {
			fprintf(stderr, "user '%s' not found\n", username);
			pam_end(pamh, PAM_SUCCESS);
			return 1;
		}

		pam_end(pamh, PAM_SUCCESS);

		printf("\nDropping to shell as %s. Type 'exit' to return.\n\n",
		       username);

		setgid(pw->pw_gid);
		setuid(pw->pw_uid);
		setenv("HOME", pw->pw_dir, 1);
		setenv("USER", pw->pw_name, 1);
		chdir(pw->pw_dir);

		execl(pw->pw_shell, pw->pw_shell, (char *)NULL);
		perror("execl");
		return 1;
	}

	pam_end(pamh, rc);
	return 0;
}
