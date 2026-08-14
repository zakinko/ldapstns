/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * pam_stns - check a password against an STNS directory, for macOS.
 *
 * ldapstns answers who somebody is; this answers whether a password is theirs.
 * On macOS those are asked through two different systems and neither will do
 * the other's job:
 *
 *	who		opendirectoryd, which this daemon serves over LDAP
 *	whether		PAM, for sshd(8), su(1) and sudo(8) - or Open Directory
 *			authentication, for the login window
 *
 * This covers the first of those two and not the second, and the gap is real
 * rather than an oversight.  dsconfigldap(8) configures a node with the Open
 * Directory Server template, whose authentication modules are AppleODClientLDAP
 * and AppleODClientPWS - Password Server and Kerberos, neither of which this
 * daemon speaks and neither of which is a simple LDAP bind it could speak
 * instead.  So the login window authenticates a directory user against
 * something that is not here, and does not succeed.  sshd, su and sudo all go
 * through PAM and all work.
 *
 * That is worth stating plainly rather than discovering: a machine set up this
 * way lets a directory user in over ssh and not at the screen.  Where the
 * screen matters, the account wants to be local, with STNS supplying only the
 * keys - see stns-key-wrapper(8).
 *
 * The comparison itself is src/stns_crypt.c, which carries its own SHA-crypt
 * because
 * crypt(3) here understands traditional DES and nothing else - and does not
 * say so, which is the more dangerous half.  See src/stns_crypt.c.
 */
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/openpam.h>

#include <string.h>
#include <syslog.h>

#include "stns.h"

/*
 * Options, taken from the line in /etc/pam.d that named this module.
 *
 * Only one is understood.  "try_first_pass" and "use_first_pass" are handled
 * by pam_get_authtok(3) itself, which is why they are not listed here despite
 * being the two that everybody writes.
 */
static int
option_set(int argc, const char *argv[], const char *name)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], name) == 0)
			return 1;
	}
	return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	const char *user = NULL, *password = NULL;
	stns_conf_t sc;
	stns_user_t *u = NULL;
	int debug = option_set(argc, argv, "debug");
	int rv = PAM_AUTH_ERR;

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL)
		return PAM_AUTH_ERR;

	/*
	 * A name the API could not hold is refused before anything is asked,
	 * which is also what keeps it out of a query string.  PAM_USER_UNKNOWN
	 * rather than PAM_AUTH_ERR, so that a stack listing this module before
	 * pam_opendirectory carries on to it.
	 */
	if (!stns_is_valid_name(user))
		return PAM_USER_UNKNOWN;

	if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS || password == NULL)
		return PAM_AUTH_ERR;

	/*
	 * An empty password is refused before it is hashed.  The hash of an
	 * empty string is a perfectly good hash, and an account holding one
	 * would otherwise be open to anybody who pressed return.
	 */
	if (*password == '\0')
		return PAM_AUTH_ERR;

	if (stns_load_config(stns_config_path(), &sc) != STNS_OK) {
		syslog(LOG_ERR, "pam_stns: cannot load %s", stns_config_path());
		return PAM_AUTHINFO_UNAVAIL;
	}

	/*
	 * The same two settings the daemon turns off, for the same reasons.
	 * The on-disk cache would be written as whoever called PAM and read as
	 * somebody else; the circuit breaker would suppress the next minute of
	 * logins after one failed request, which is the right trade when every
	 * process on the machine is asking and the wrong one when the question
	 * is "may this person in".
	 */
	sc.cache = 0;
	sc.request_locktime = 0;

	switch (stns_user_by_name(&sc, user, &u)) {
	case STNS_LOOKUP_SUCCESS:
		break;
	case STNS_LOOKUP_NOTFOUND:
		/*
		 * Not logged.  This module is stacked alongside
		 * pam_opendirectory, so every local login on the machine
		 * reaches here for an account the directory never held.
		 */
		rv = PAM_USER_UNKNOWN;
		goto done;
	default:
		syslog(LOG_ERR, "pam_stns: cannot reach the API to authenticate \"%s\"", user);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}

	/*
	 * Two reasons a password can fail, and they are worth telling apart in
	 * the log even though the caller is told the same thing.  An
	 * administrator whose users cannot log in needs to know whether the
	 * hashes are wrong or merely of a kind this machine cannot read - and
	 * on macOS the second is the likely one, since crypt(3) here reads
	 * neither SHA-512 crypt nor bcrypt.
	 */
	if (!stns_crypt_supported(u->password)) {
		syslog(LOG_NOTICE, "pam_stns: no usable password hash for \"%s\"", user);
		rv = PAM_AUTH_ERR;
		goto done;
	}

	if (stns_crypt_check(password, u->password) == STNS_OK) {
		if (debug)
			syslog(LOG_DEBUG, "pam_stns: authenticated \"%s\"", user);
		rv = PAM_SUCCESS;
	} else {
		syslog(LOG_NOTICE, "pam_stns: failed password for \"%s\"", user);
		rv = PAM_AUTH_ERR;
	}

done:
	stns_free_users(u, (u != NULL) ? 1 : 0);
	stns_unload_config(&sc);
	return rv;
}

/*
 * Nothing to grant and nothing to take away.
 *
 * A module that implements pam_sm_authenticate must implement this too, or the
 * auth facility refuses to load it; the credentials a directory user has are
 * their uid and their groups, and opendirectoryd has already established those
 * through ldapstns(8) by the time anybody gets here.
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_MODULE_ENTRY("pam_stns");
