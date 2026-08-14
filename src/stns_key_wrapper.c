/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * stns-key-wrapper - print a user's SSH public keys, for use as sshd_config's
 * AuthorizedKeysCommand.
 *
 * This is the one piece of STNS support that needs nothing from the operating
 * system's directory machinery: sshd runs a command and reads its output, and
 * every system sshd runs on can do that.  So it lives in the library rather
 * than in nss_stns, ypstns and ldapstns three times over, and each of them
 * installs the very same program.
 */
#include <errno.h>

#include "stns.h"

static void
usage(void)
{
	(void)fprintf(stderr, "usage: stns-key-wrapper user\n");
	exit(1);
}

/*
 * Some sites keep a second source of keys (LDAP, a local file, ...).  When
 * chain_ssh_wrapper is configured its output is emitted as well, so the two
 * can be rolled out side by side.
 */
static void
chain(stns_conf_t *c, const char *user)
{
	stns_response_t r;

	if (c->chain_ssh_wrapper == NULL)
		return;
	memset(&r, 0, sizeof(r));
	if (stns_exec_cmd(c->chain_ssh_wrapper, user, &r) == STNS_OK && r.data != NULL)
		(void)fputs(r.data, stdout);
	free(r.data);
}

/*
 * sshd runs this once per authentication attempt, for local accounts as much
 * as directory ones, so a user we do not know is not an error: it is an empty
 * key list and a zero exit status.  Exiting non-zero would put a line in the
 * log for every local login on the machine.
 *
 * The same goes for a server that is down.  Refusing to answer would be no
 * more secure - sshd falls back to authorized_keys either way - and would turn
 * an unreachable API into an unreadable log.
 */
int
main(int argc, char *argv[])
{
	stns_conf_t c;
	stns_user_t *u;
	const char *user;
	size_t i;

	if (argc != 2)
		usage();
	user = argv[1];

	if (!stns_is_valid_name(user)) {
		(void)fprintf(stderr, "stns-key-wrapper: invalid user name\n");
		return 1;
	}

	if (stns_load_config(stns_config_path(), &c) != STNS_OK) {
		(void)fprintf(stderr, "stns-key-wrapper: cannot load %s\n", stns_config_path());
		return 1;
	}

	if (stns_user_by_name(&c, user, &u) == STNS_LOOKUP_SUCCESS) {
		for (i = 0; i < u->keys_size; i++)
			(void)printf("%s\n", u->keys[i]);
		stns_free_users(u, 1);
	}

	chain(&c, user);
	stns_unload_config(&c);
	return 0;
}
