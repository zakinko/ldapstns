/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Authenticate through PAM, for tests/pam.sh.
 *
 * A PAM module cannot be tested by calling its functions: what is worth
 * checking is that OpenPAM loads the thing, finds the entry points, runs the
 * stack, and turns what the module returns into the answer an application
 * sees.  So this is an ordinary PAM application - the same three calls sshd(8)
 * and su(1) make - and the module is reached the way they reach it.
 *
 * It prints one word, which is what the shell compares:
 *
 *	ok		PAM_SUCCESS
 *	denied		PAM_AUTH_ERR, a password that is not the user's
 *	unknown		PAM_USER_UNKNOWN, nobody of that name in the directory
 *	unavailable	PAM_AUTHINFO_UNAVAIL, the directory could not be asked
 *	error:<n>	anything else, with the code, so a surprise is visible
 */
#include <security/pam_appl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Hand back the password to every prompt that hides what is typed, and nothing
 * to anything else.  A real conversation would talk to a terminal; this one
 * has the answer in advance, which is exactly what a non-interactive caller
 * such as sshd's keyboard-interactive path does too.
 */
static int
converse(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
	const char *password = data;
	struct pam_response *r;
	int i;

	if (n <= 0)
		return PAM_CONV_ERR;
	if ((r = calloc((size_t)n, sizeof(*r))) == NULL)
		return PAM_BUF_ERR;

	for (i = 0; i < n; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			if ((r[i].resp = strdup(password)) == NULL) {
				while (i-- > 0)
					free(r[i].resp);
				free(r);
				return PAM_BUF_ERR;
			}
			break;
		default:
			/* An informational message; nothing to answer. */
			break;
		}
	}

	*resp = r;
	return PAM_SUCCESS;
}

int
main(int argc, char *argv[])
{
	struct pam_conv pc;
	pam_handle_t *pamh = NULL;
	int rv;

	if (argc != 4) {
		(void)fprintf(stderr, "usage: pam_client service user password\n");
		return 2;
	}

	pc.conv = converse;
	pc.appdata_ptr = argv[3];

	if ((rv = pam_start(argv[1], argv[2], &pc, &pamh)) != PAM_SUCCESS) {
		(void)printf("error:%d\n", rv);
		return 2;
	}

	rv = pam_authenticate(pamh, 0);
	(void)pam_end(pamh, rv);

	switch (rv) {
	case PAM_SUCCESS:
		(void)puts("ok");
		return 0;
	case PAM_AUTH_ERR:
		(void)puts("denied");
		return 1;
	case PAM_USER_UNKNOWN:
		(void)puts("unknown");
		return 1;
	case PAM_AUTHINFO_UNAVAIL:
		(void)puts("unavailable");
		return 1;
	default:
		(void)printf("error:%d\n", rv);
		return 1;
	}
}
