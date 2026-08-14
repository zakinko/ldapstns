/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Client configuration (stns.conf) loading.
 *
 * Portions are derived from libnss (https://github.com/STNS/libnss),
 * Copyright (c) 2026 pyama86, distributed under the MIT license.
 */
#include <errno.h>

#include "stns.h"

/*
 * strdup(3) that tolerates NULL, so that an absent key and an absent default
 * both come out as a NULL pointer rather than needing a check at every call.
 */
static char *
stns_strdup(const char *s)
{
	char *p;
	size_t len;

	if (s == NULL)
		return NULL;
	len = strlen(s) + 1;
	if ((p = malloc(len)) == NULL)
		return NULL;
	memcpy(p, s, len);
	return p;
}

/*
 * These three read one key each and leave the default in place whenever it is
 * absent or of the wrong type.  toml_*_in() reports both cases the same way,
 * through the ok flag, and hands over a string the caller then owns.
 *
 * A bad value is logged rather than fatal.  A typo in one line of stns.conf
 * must not take name resolution down with it.
 */
static void
conf_str(toml_table_t *tab, const char *key, char **dst, const char *def, const char *filename)
{
	toml_datum_t d;

	if (tab != NULL) {
		d = toml_string_in(tab, key);
		if (d.ok) {
			*dst = d.u.s;
			return;
		}
		if (toml_key_exists(tab, key))
			syslog(LOG_ERR, STNS_PRODUCT ": %s: key '%s' is not a string", filename, key);
	}
	*dst = stns_strdup(def);
}

static void
conf_int(toml_table_t *tab, const char *key, int *dst, int def, const char *filename)
{
	toml_datum_t d;

	*dst = def;
	if (tab == NULL)
		return;
	d = toml_int_in(tab, key);
	if (d.ok)
		*dst = (int)d.u.i;
	else if (toml_key_exists(tab, key))
		syslog(LOG_ERR, STNS_PRODUCT ": %s: key '%s' is not an integer", filename, key);
}

static void
conf_bool(toml_table_t *tab, const char *key, int *dst, int def, const char *filename)
{
	toml_datum_t d;

	*dst = def;
	if (tab == NULL)
		return;
	d = toml_bool_in(tab, key);
	if (d.ok)
		*dst = d.u.b;
	else if (toml_key_exists(tab, key))
		syslog(LOG_ERR, STNS_PRODUCT ": %s: key '%s' is not a boolean", filename, key);
}

/* Drop a single trailing slash so that endpoint + "/" + path stays sane. */
static void
trim_slash(char *s)
{
	size_t len;

	if (s == NULL)
		return;
	len = strlen(s);
	if (len > 0 && s[len - 1] == '/')
		s[len - 1] = '\0';
}

/*
 * [http_headers] is an open ended table - the keys are whatever header names
 * the site needs - so it is read by index rather than by name.
 */
static void
load_http_headers(toml_table_t *tab, stns_conf_t *c, const char *filename)
{
	toml_table_t *in_tab;
	stns_http_header_t *headers = NULL, *grown;
	const char *key;
	size_t n = 0;
	char *value;

	c->http_headers = NULL;
	c->http_headers_size = 0;

	if ((in_tab = toml_table_in(tab, "http_headers")) == NULL)
		return;

	while (n < STNS_MAXBUF) {
		toml_datum_t d;

		if ((key = toml_key_in(in_tab, (int)n)) == NULL)
			break;
		d = toml_string_in(in_tab, key);
		if (!d.ok) {
			syslog(LOG_ERR, STNS_PRODUCT ": %s: http_headers.%s is not a string", filename, key);
			break;
		}
		value = d.u.s;
		if ((grown = realloc(headers, sizeof(*headers) * (n + 1))) == NULL) {
			free(value);
			break;
		}
		headers = grown;
		headers[n].key = stns_strdup(key);
		headers[n].value = value;
		n++;
	}

	c->http_headers = headers;
	c->http_headers_size = n;
}

/*
 * Create the leading directories of path, as mkdir -p would.
 *
 * A single mkdir(2) is not enough: cache_dir is configurable and an
 * administrator may point it somewhere several levels deep, and even the
 * default sits under a directory that not every system ships.
 */
static void
mkdir_parents(const char *path, mode_t mode)
{
	char buf[STNS_MAXBUF];
	struct stat sb;
	char *p;

	if (strlen(path) >= sizeof(buf))
		return;
	(void)snprintf(buf, sizeof(buf), "%s", path);

	for (p = buf + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (stat(buf, &sb) != 0)
			(void)mkdir(buf, mode);
		*p = '/';
	}
}

/*
 * The cache directory is shared by every user on the box, so it is created
 * sticky (like /tmp): each euid owns its own subdirectory underneath and
 * cannot clobber another user's entries.
 */
static void
force_create_cache_dir(stns_conf_t *c)
{
	struct stat sb;
	mode_t um;

	if (!c->cache || c->cached_enable || geteuid() != 0 || c->cache_dir == NULL)
		return;

	um = umask(0);
	if (stat(c->cache_dir, &sb) != 0) {
		mkdir_parents(c->cache_dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		(void)mkdir(c->cache_dir, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);
	} else if ((sb.st_mode & S_ISVTX) == 0) {
		(void)chmod(c->cache_dir, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);
	}
	(void)umask(um);
}

/*
 * Every key this module reads.  A key in stns.conf that is not one of these is
 * worth complaining about, because "absent" and "misspelled" are otherwise the
 * same thing: write api_endpont and the module silently talks to localhost and
 * every lookup fails for no visible reason.
 *
 * An absent key, by contrast, is normal and is not reported.  Almost all of
 * these are optional and documented defaults, and a line per lookup per
 * process would drown syslog in noise about a working configuration.
 */
static const char *const known_keys[] = {
	"api_endpoint", "auth_token", "user", "password",
	"query_wrapper", "chain_ssh_wrapper", "http_proxy", "http_location",
	"ssl_verify", "use_cached",
	"uid_shift", "gid_shift",
	"cache", "cache_dir", "cache_ttl", "negative_cache_ttl",
	"request_timeout", "request_retry", "request_locktime",
	/* tables, walked separately below */
	"tls", "cached", "http_headers",
	NULL
};
static const char *const known_tls[] = { "ca", "cert", "key", NULL };
static const char *const known_cached[] = { "enable", "unix_socket", NULL };

static int
is_known(const char *const *list, const char *key)
{
	size_t i;

	for (i = 0; list[i] != NULL; i++) {
		if (strcmp(list[i], key) == 0)
			return 1;
	}
	return 0;
}

/*
 * Count, and report once, the keys we do not recognise.
 *
 * Reported once per process rather than once per lookup: this file is re-read
 * every time a name is resolved, and a typo would otherwise produce a line for
 * every getent(1) in a loop.  The flag is written without a lock, so a
 * multithreaded caller may see two lines instead of one, which is harmless.
 */
static int
count_unknown(toml_table_t *tab, const char *const *known, const char *table, const char *filename, int *warned)
{
	const char *key;
	int i, n = 0;

	if (tab == NULL)
		return 0;

	for (i = 0; (key = toml_key_in(tab, i)) != NULL; i++) {
		if (is_known(known, key))
			continue;
		n++;
		if (*warned)
			continue;
		if (table != NULL)
			syslog(LOG_NOTICE, STNS_PRODUCT ": %s: unknown key '%s' in [%s], ignored", filename, key,
			    table);
		else
			syslog(LOG_NOTICE, STNS_PRODUCT ": %s: unknown key '%s', ignored", filename, key);
	}
	return n;
}

/*
 * Pick the configuration file to read.  See the STNS_CONFIG_FILE comment in
 * stns.h for why there are two candidates and why neither is a bare stns.conf.
 */
const char *
stns_config_path(void)
{
	static const char *const candidates[] = {
		STNS_CONFIG_FILE,
		STNS_CONFIG_FILE_COMPAT,
	};
	struct stat sb;
	size_t i;

	for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		if (stat(candidates[i], &sb) == 0 && S_ISREG(sb.st_mode))
			return candidates[i];
	}
	/* Nothing found; name the preferred path so the error message is useful. */
	return STNS_CONFIG_FILE;
}

/*
 * Read the configuration.  Every field is given a value, whether from the file
 * or from its default, so callers never have to test for "unset"; the string
 * fields defaulting to NULL are the ones whose absence is itself meaningful,
 * such as auth_token.
 *
 * On failure nothing is left allocated and the caller must not call
 * stns_unload_config().
 */
int
stns_load_config(const char *filename, stns_conf_t *c)
{
	char errbuf[200];
	toml_table_t *tab, *tls, *cached;
	FILE *fp;
	int use_cached;

	memset(c, 0, sizeof(*c));

	if ((fp = fopen(filename, "r")) == NULL) {
		syslog(LOG_ERR, STNS_PRODUCT ": cannot open %s: %s", filename, strerror(errno));
		return STNS_NG;
	}

	tab = toml_parse_file(fp, errbuf, sizeof(errbuf));
	(void)fclose(fp);
	if (tab == NULL) {
		syslog(LOG_ERR, STNS_PRODUCT ": %s: %s", filename, errbuf);
		return STNS_NG;
	}

	conf_str(tab, "api_endpoint", &c->api_endpoint, STNS_DEFAULT_API_ENDPOINT, filename);
	conf_str(tab, "cache_dir", &c->cache_dir, STNS_DEFAULT_CACHE_DIR, filename);
	conf_str(tab, "auth_token", &c->auth_token, NULL, filename);
	conf_str(tab, "user", &c->user, NULL, filename);
	conf_str(tab, "password", &c->password, NULL, filename);
	conf_str(tab, "query_wrapper", &c->query_wrapper, NULL, filename);
	conf_str(tab, "chain_ssh_wrapper", &c->chain_ssh_wrapper, NULL, filename);
	conf_str(tab, "http_proxy", &c->http_proxy, NULL, filename);

	tls = toml_table_in(tab, "tls");
	conf_str(tls, "ca", &c->tls_ca, NULL, filename);
	conf_str(tls, "cert", &c->tls_cert, NULL, filename);
	conf_str(tls, "key", &c->tls_key, NULL, filename);

	cached = toml_table_in(tab, "cached");
	conf_bool(cached, "enable", &c->cached_enable, 0, filename);
	conf_str(cached, "unix_socket", &c->cached_unix_socket, STNS_DEFAULT_CACHED_SOCKET, filename);
	/* "use_cached = true" is the older spelling of "[cached] enable = true". */
	conf_bool(tab, "use_cached", &use_cached, 0, filename);
	if (use_cached)
		c->cached_enable = 1;

	conf_int(tab, "uid_shift", &c->uid_shift, 0, filename);
	conf_int(tab, "gid_shift", &c->gid_shift, 0, filename);
	conf_bool(tab, "cache", &c->cache, 1, filename);
	conf_int(tab, "cache_ttl", &c->cache_ttl, 600, filename);
	conf_int(tab, "negative_cache_ttl", &c->negative_cache_ttl, 10, filename);
	conf_int(tab, "request_retry", &c->request_retry, 3, filename);
	conf_int(tab, "request_locktime", &c->request_locktime, 60, filename);

	{
		int v;

		conf_int(tab, "request_timeout", &v, 10, filename);
		c->request_timeout = (long)v;
		conf_bool(tab, "ssl_verify", &v, 1, filename);
		c->ssl_verify = (long)v;
		conf_bool(tab, "http_location", &v, 0, filename);
		c->http_location = (long)v;
	}

	load_http_headers(tab, c, filename);

	{
		static int warned;
		int already = warned;

		c->unknown_keys = count_unknown(tab, known_keys, NULL, filename, &already);
		c->unknown_keys += count_unknown(tls, known_tls, "tls", filename, &already);
		c->unknown_keys += count_unknown(cached, known_cached, "cached", filename, &already);
		if (c->unknown_keys > 0)
			warned = 1;
	}

	/*
	 * api_endpoint is the one key whose default is a guess rather than a
	 * policy, so its absence is worth a word even though absence normally
	 * is not.
	 */
	if (toml_key_exists(tab, "api_endpoint") == 0) {
		static int warned;

		if (!warned) {
			warned = 1;
			syslog(LOG_NOTICE, STNS_PRODUCT ": %s: no api_endpoint, using %s", filename,
			    STNS_DEFAULT_API_ENDPOINT);
		}
	}

	trim_slash(c->api_endpoint);
	trim_slash(c->cache_dir);

	toml_free(tab);

	if (c->api_endpoint == NULL || c->cache_dir == NULL) {
		stns_unload_config(c);
		return STNS_NG;
	}

	force_create_cache_dir(c);
	return STNS_OK;
}

/*
 * Release everything stns_load_config() allocated.  The struct is zeroed
 * afterwards, so calling this twice is harmless.
 */
void
stns_unload_config(stns_conf_t *c)
{
	size_t i;

	free(c->api_endpoint);
	free(c->auth_token);
	free(c->user);
	free(c->password);
	free(c->query_wrapper);
	free(c->chain_ssh_wrapper);
	free(c->http_proxy);
	free(c->cache_dir);
	free(c->tls_ca);
	free(c->tls_cert);
	free(c->tls_key);
	free(c->cached_unix_socket);

	for (i = 0; i < c->http_headers_size; i++) {
		free(c->http_headers[i].key);
		free(c->http_headers[i].value);
	}
	free(c->http_headers);

	memset(c, 0, sizeof(*c));
}
