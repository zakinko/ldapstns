/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * ldapstns.conf: the daemon's own settings.
 *
 * Everything about the API - where it is, how to authenticate to it, how long
 * to wait for it - lives in stns.conf and is read by src/stns_config.c.  What is here is
 * only what has no meaning outside this daemon: which address to listen on,
 * which suffix to serve, how often to refresh, and who may read the directory.
 *
 * It is TOML because stns.conf is, so an administrator has one syntax to learn
 * and the daemon has one parser to link.  A launchd job description is a
 * property list, and jp.stns.ldapstns.plist duly is one - but that file says
 * how to start the program, which is a different question from what the
 * program should do, and macOS keeps the two apart as well.
 */
#include <errno.h>
#include <string.h>

#include "ldapstns.h"

/*
 * Append one address to the listen list.
 */
static int
add_listen(ldapstns_conf *c, const char *addr)
{
	char **grown;
	char *copy;

	if ((copy = strdup(addr)) == NULL)
		return -1;
	if ((grown = realloc(c->listen, (c->nlisten + 1) * sizeof(*grown))) == NULL) {
		free(copy);
		return -1;
	}
	c->listen = grown;
	c->listen[c->nlisten++] = copy;
	return 0;
}

static void
free_listen(ldapstns_conf *c)
{
	size_t i;

	for (i = 0; i < c->nlisten; i++)
		free(c->listen[i]);
	free(c->listen);
	c->listen = NULL;
	c->nlisten = 0;
}

/*
 * "listen" is a string or an array of them.
 *
 * A string because one address is the ordinary case and an array because two
 * is the default - and having written the default as two, refusing to let an
 * administrator write two would be an odd thing to do.
 */
static int
conf_listen(toml_table_t *tab, ldapstns_conf *c, const char *filename)
{
	toml_array_t *arr;
	toml_datum_t d;
	int i;

	if (!toml_key_exists(tab, "listen"))
		return 0;

	free_listen(c);

	if ((arr = toml_array_in(tab, "listen")) != NULL) {
		for (i = 0;; i++) {
			d = toml_string_at(arr, i);
			if (!d.ok)
				break;
			if (add_listen(c, d.u.s) != 0) {
				free(d.u.s);
				return -1;
			}
			free(d.u.s);
		}
		if (c->nlisten == 0) {
			logit(LOG_ERR, "%s: listen is an empty list", filename);
			return -1;
		}
		return 0;
	}

	d = toml_string_in(tab, "listen");
	if (!d.ok) {
		logit(LOG_ERR, "%s: listen is not a string or a list of them", filename);
		return -1;
	}
	if (add_listen(c, d.u.s) != 0) {
		free(d.u.s);
		return -1;
	}
	free(d.u.s);
	return 0;
}

/* strdup(3) that turns NULL into NULL rather than crashing. */
static char *
dup_or_null(const char *s)
{
	return (s != NULL) ? strdup(s) : NULL;
}

/*
 * Every key this daemon reads.  A key that is present and not one of these is
 * a typo or a setting from some other program's configuration, and either way
 * it is doing nothing - which is worth saying out loud, because "absent" and
 * "misspelled" are otherwise indistinguishable and a misspelled suffix leaves
 * the daemon serving a tree nobody is looking at.
 */
static const char *const known_keys[] = { "listen", "port", "suffix", "user", "interval", "bind_dn", "bind_password",
	"expose_password", NULL };

static int
report_unknown(toml_table_t *tab, const char *filename)
{
	const char *key;
	int i, j, n = 0;

	for (i = 0; (key = toml_key_in(tab, i)) != NULL; i++) {
		for (j = 0; known_keys[j] != NULL; j++) {
			if (strcmp(known_keys[j], key) == 0)
				break;
		}
		if (known_keys[j] != NULL)
			continue;
		logit(LOG_NOTICE, "%s: unknown key '%s', ignored", filename, key);
		n++;
	}
	return n;
}

static void
conf_str(toml_table_t *tab, const char *key, char **dst, const char *def, const char *filename)
{
	toml_datum_t d = toml_string_in(tab, key);

	if (d.ok) {
		*dst = d.u.s;
		return;
	}
	if (toml_key_exists(tab, key))
		logit(LOG_ERR, "%s: key '%s' is not a string", filename, key);
	*dst = dup_or_null(def);
}

static void
conf_int(toml_table_t *tab, const char *key, int *dst, int def, const char *filename)
{
	toml_datum_t d = toml_int_in(tab, key);

	*dst = def;
	if (d.ok)
		*dst = (int)d.u.i;
	else if (toml_key_exists(tab, key))
		logit(LOG_ERR, "%s: key '%s' is not an integer", filename, key);
}

static void
conf_bool(toml_table_t *tab, const char *key, int *dst, int def, const char *filename)
{
	toml_datum_t d = toml_bool_in(tab, key);

	*dst = def;
	if (d.ok)
		*dst = d.u.b;
	else if (toml_key_exists(tab, key))
		logit(LOG_ERR, "%s: key '%s' is not a boolean", filename, key);
}

/* Fill in every default, for the case where there is no file at all. */
static int
conf_defaults(ldapstns_conf *c)
{
	memset(c, 0, sizeof(*c));
	c->suffix = strdup(LDAPSTNS_DEFAULT_SUFFIX);
	c->user = strdup(LDAPSTNS_DEFAULT_USER);
	c->port = LDAPSTNS_DEFAULT_PORT;
	c->interval = LDAPSTNS_DEFAULT_INTERVAL;
	if (add_listen(c, LDAPSTNS_DEFAULT_LISTEN_V4) != 0)
		return -1;
	if (add_listen(c, LDAPSTNS_DEFAULT_LISTEN_V6) != 0)
		return -1;
	return (c->suffix != NULL && c->user != NULL) ? 0 : -1;
}

/*
 * Check the settings against each other, rather than one at a time.
 *
 * The interesting rule is the last one.  expose_password puts crypt hashes on
 * a socket, and a socket on the loopback interface is reachable by every
 * process on the machine, so it is only allowed at all when there is a bind_dn
 * to keep anonymous clients away from it - and refusing to start is the right
 * response to being asked for it without one, because the alternative is
 * starting up in exactly the configuration the administrator did not mean.
 */
static int
conf_check(const ldapstns_conf *c, const char *filename)
{
	if (c->port < 1 || c->port > 65535) {
		logit(LOG_ERR, "%s: port %d is not a port number", filename, c->port);
		return -1;
	}
	if (c->interval < 10) {
		logit(LOG_ERR, "%s: interval %d is too short; ten seconds is the minimum", filename, c->interval);
		return -1;
	}
	if (strchr(c->suffix, '=') == NULL) {
		logit(LOG_ERR, "%s: suffix \"%s\" is not a distinguished name", filename, c->suffix);
		return -1;
	}
	if (c->bind_dn != NULL && c->bind_password == NULL) {
		logit(LOG_ERR, "%s: bind_dn is set but bind_password is not", filename);
		return -1;
	}
	if (c->expose_password && c->bind_dn == NULL) {
		logit(LOG_ERR, "%s: expose_password needs a bind_dn; refusing to serve password "
			       "hashes to anonymous clients on a loopback socket",
		    filename);
		return -1;
	}
	return 0;
}

int
conf_load(const char *filename, ldapstns_conf *c)
{
	char errbuf[200];
	toml_table_t *tab;
	FILE *fp;

	if (conf_defaults(c) != 0) {
		conf_free(c);
		return -1;
	}

	/*
	 * A missing file is not an error.  Every setting here has a working
	 * default, and on a machine whose stns.conf is already in place the
	 * daemon has everything it needs; saying so once is more useful than
	 * refusing to start over a file with nothing in it.
	 */
	if ((fp = fopen(filename, "r")) == NULL) {
		if (errno != ENOENT) {
			logit(LOG_ERR, "cannot open %s: %s", filename, strerror(errno));
			conf_free(c);
			return -1;
		}
		logit(LOG_NOTICE, "no %s; using the defaults", filename);
		return conf_check(c, filename);
	}

	tab = toml_parse_file(fp, errbuf, sizeof(errbuf));
	(void)fclose(fp);
	if (tab == NULL) {
		logit(LOG_ERR, "%s: %s", filename, errbuf);
		conf_free(c);
		return -1;
	}

	free(c->suffix);
	free(c->user);
	if (conf_listen(tab, c, filename) != 0) {
		toml_free(tab);
		conf_free(c);
		return -1;
	}
	conf_str(tab, "suffix", &c->suffix, LDAPSTNS_DEFAULT_SUFFIX, filename);
	conf_str(tab, "user", &c->user, LDAPSTNS_DEFAULT_USER, filename);
	conf_str(tab, "bind_dn", &c->bind_dn, NULL, filename);
	conf_str(tab, "bind_password", &c->bind_password, NULL, filename);
	conf_int(tab, "port", &c->port, LDAPSTNS_DEFAULT_PORT, filename);
	conf_int(tab, "interval", &c->interval, LDAPSTNS_DEFAULT_INTERVAL, filename);
	conf_bool(tab, "expose_password", &c->expose_password, 0, filename);
	c->unknown_keys = report_unknown(tab, filename);

	toml_free(tab);

	if (c->nlisten == 0 || c->suffix == NULL || c->user == NULL) {
		logit(LOG_ERR, "out of memory reading %s", filename);
		conf_free(c);
		return -1;
	}
	if (conf_check(c, filename) != 0) {
		conf_free(c);
		return -1;
	}
	return 0;
}

void
conf_free(ldapstns_conf *c)
{
	free_listen(c);
	free(c->suffix);
	free(c->user);
	free(c->bind_dn);
	free(c->bind_password);
	memset(c, 0, sizeof(*c));
}
