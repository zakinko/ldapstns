/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Unit tests for the parts of the STNS API client that do not need a
 * server: config
 * parsing, name validation, cache key escaping and the buffer marshalling.
 *
 * The HTTP path is covered by tests/integration.sh instead.
 */
#include <errno.h>

#include "stns.h"

static int checks;
static int failures;

#define CHECK(cond)                                                                                                    \
	do {                                                                                                           \
		checks++;                                                                                              \
		if (!(cond)) {                                                                                         \
			failures++;                                                                                    \
			(void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                          \
		}                                                                                                      \
	} while (0)

#define CHECK_STR(got, want)                                                                                           \
	do {                                                                                                           \
		checks++;                                                                                              \
		if ((got) == NULL || strcmp((got), (want)) != 0) {                                                      \
			failures++;                                                                                    \
			(void)fprintf(stderr, "FAIL %s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__, (want),  \
			    (got) != NULL ? (got) : "(null)");                                                         \
		}                                                                                                      \
	} while (0)

static char tmpdir[] = "/tmp/stns_test.XXXXXX";
static char conf_path[256];

static void
write_conf(const char *body)
{
	FILE *fp;

	if ((fp = fopen(conf_path, "w")) == NULL) {
		perror("fopen");
		exit(1);
	}
	(void)fputs(body, fp);
	(void)fclose(fp);
}

static void
test_config_defaults(void)
{
	stns_conf_t c;

	write_conf("");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK_STR(c.api_endpoint, STNS_DEFAULT_API_ENDPOINT);
	CHECK_STR(c.cache_dir, STNS_DEFAULT_CACHE_DIR);
	CHECK_STR(c.cached_unix_socket, STNS_DEFAULT_CACHED_SOCKET);
	CHECK(c.auth_token == NULL);
	CHECK(c.user == NULL);
	CHECK(c.uid_shift == 0);
	CHECK(c.gid_shift == 0);
	CHECK(c.cache == 1);
	CHECK(c.cache_ttl == 600);
	CHECK(c.negative_cache_ttl == 10);
	CHECK(c.request_retry == 3);
	CHECK(c.request_locktime == 60);
	CHECK(c.request_timeout == 10);
	CHECK(c.ssl_verify == 1);
	CHECK(c.http_location == 0);
	CHECK(c.cached_enable == 0);
	CHECK(c.http_headers_size == 0);
	stns_unload_config(&c);
}

static void
test_config_values(void)
{
	stns_conf_t c;

	write_conf("api_endpoint = \"https://stns.example.com/v1/\"\n"
		   "auth_token = \"tok\"\n"
		   "user = \"alice\"\n"
		   "password = \"secret\"\n"
		   "uid_shift = 1000\n"
		   "gid_shift = 2000\n"
		   "cache = false\n"
		   "cache_ttl = 30\n"
		   "ssl_verify = false\n"
		   "request_timeout = 3\n"
		   "http_location = true\n"
		   "[tls]\n"
		   "ca = \"/etc/ca.pem\"\n"
		   "[cached]\n"
		   "enable = true\n"
		   "unix_socket = \"/tmp/x.sock\"\n"
		   "[http_headers]\n"
		   "X-Api-Key = \"abc\"\n");

	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	/* The trailing slash must be trimmed or every URL grows a "//". */
	CHECK_STR(c.api_endpoint, "https://stns.example.com/v1");
	CHECK_STR(c.auth_token, "tok");
	CHECK_STR(c.user, "alice");
	CHECK_STR(c.password, "secret");
	CHECK_STR(c.tls_ca, "/etc/ca.pem");
	CHECK_STR(c.cached_unix_socket, "/tmp/x.sock");
	CHECK(c.uid_shift == 1000);
	CHECK(c.gid_shift == 2000);
	CHECK(c.cache == 0);
	CHECK(c.cache_ttl == 30);
	CHECK(c.ssl_verify == 0);
	CHECK(c.request_timeout == 3);
	CHECK(c.http_location == 1);
	CHECK(c.cached_enable == 1);
	CHECK(c.http_headers_size == 1);
	if (c.http_headers_size == 1) {
		CHECK_STR(c.http_headers[0].key, "X-Api-Key");
		CHECK_STR(c.http_headers[0].value, "abc");
	}
	stns_unload_config(&c);
}

static void
test_config_use_cached_alias(void)
{
	stns_conf_t c;

	write_conf("use_cached = true\n");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK(c.cached_enable == 1);
	stns_unload_config(&c);
}

/*
 * A stns.conf written for the Linux module has to load here unchanged: same
 * key names, same tables, same defaults.  This is the regression test that
 * keeps that promise, so it deliberately uses every key upstream documents.
 */
static void
test_config_linux_compatible(void)
{
	stns_conf_t c;

	write_conf("api_endpoint      = \"http://192.0.2.1:1104/v1/\"\n"
		   "auth_token        = \"xxxxxxxxxxxxxxx\"\n"
		   "user              = \"test_user\"\n"
		   "password          = \"test_password\"\n"
		   "chain_ssh_wrapper = \"/usr/libexec/openssh/ssh-ldap-wrapper\"\n"
		   "query_wrapper     = \"/usr/local/bin/stns-wrapper\"\n"
		   "ssl_verify        = true\n"
		   "http_proxy        = \"http://your.proxy.com\"\n"
		   "uid_shift         = 1000\n"
		   "gid_shift         = 2000\n"
		   "request_timeout   = 3\n"
		   "request_retry     = 3\n"
		   "request_locktime  = 30\n"
		   "http_location     = true\n"
		   "cache             = true\n"
		   "cache_dir         = \"/var/cache/stns\"\n"
		   "cache_ttl         = 300\n"
		   "negative_cache_ttl = 5\n"
		   "[tls]\n"
		   "ca   = \"/etc/stns/client/ca.pem\"\n"
		   "cert = \"/etc/stns/client/cert.pem\"\n"
		   "key  = \"/etc/stns/client/key.pem\"\n"
		   "[cached]\n"
		   "enable      = true\n"
		   "unix_socket = \"/var/run/cache-stnsd.sock\"\n"
		   "[http_headers]\n"
		   "X-Api-Key   = \"abc\"\n"
		   "X-Extra     = \"def\"\n");

	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK_STR(c.api_endpoint, "http://192.0.2.1:1104/v1");
	CHECK_STR(c.auth_token, "xxxxxxxxxxxxxxx");
	CHECK_STR(c.user, "test_user");
	CHECK_STR(c.password, "test_password");
	CHECK_STR(c.chain_ssh_wrapper, "/usr/libexec/openssh/ssh-ldap-wrapper");
	CHECK_STR(c.query_wrapper, "/usr/local/bin/stns-wrapper");
	CHECK_STR(c.http_proxy, "http://your.proxy.com");
	CHECK_STR(c.cache_dir, "/var/cache/stns");
	CHECK_STR(c.tls_ca, "/etc/stns/client/ca.pem");
	CHECK_STR(c.tls_cert, "/etc/stns/client/cert.pem");
	CHECK_STR(c.tls_key, "/etc/stns/client/key.pem");
	CHECK_STR(c.cached_unix_socket, "/var/run/cache-stnsd.sock");
	CHECK(c.ssl_verify == 1);
	CHECK(c.uid_shift == 1000);
	CHECK(c.gid_shift == 2000);
	CHECK(c.request_timeout == 3);
	CHECK(c.request_retry == 3);
	CHECK(c.request_locktime == 30);
	CHECK(c.http_location == 1);
	CHECK(c.cache == 1);
	CHECK(c.cache_ttl == 300);
	CHECK(c.negative_cache_ttl == 5);
	CHECK(c.cached_enable == 1);
	CHECK(c.http_headers_size == 2);
	stns_unload_config(&c);
}

/*
 * An absent key is normal; a key that is present but unrecognised is a typo,
 * and the difference is the whole point.  Write api_endpont for api_endpoint
 * and the module would otherwise talk to localhost and fail every lookup with
 * nothing said anywhere.
 */
static void
test_config_unknown_keys(void)
{
	stns_conf_t c;

	/* Everything recognised, including all three tables. */
	write_conf("api_endpoint = \"http://x/v1\"\n"
		   "uid_shift = 1\n"
		   "[tls]\n"
		   "ca = \"/x\"\n"
		   "[cached]\n"
		   "enable = true\n"
		   "[http_headers]\n"
		   "X-Whatever = \"anything at all\"\n");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK(c.unknown_keys == 0);
	stns_unload_config(&c);

	/* A misspelling at the top level. */
	write_conf("api_endpont = \"http://x/v1\"\n");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK(c.unknown_keys == 1);
	/* ... and the default is still in place, which is why it matters. */
	CHECK_STR(c.api_endpoint, STNS_DEFAULT_API_ENDPOINT);
	stns_unload_config(&c);

	/* Misspellings inside the tables are counted too. */
	write_conf("[tls]\n"
		   "cert_file = \"/x\"\n"
		   "[cached]\n"
		   "socket = \"/y\"\n");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK(c.unknown_keys == 2);
	stns_unload_config(&c);

	/* [http_headers] is open ended: any key in it is legitimate. */
	write_conf("[http_headers]\n"
		   "X-One = \"1\"\n"
		   "X-Two = \"2\"\n");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK(c.unknown_keys == 0);
	CHECK(c.http_headers_size == 2);
	stns_unload_config(&c);

	/* An empty file is a valid one: absence is not an error. */
	write_conf("");
	CHECK(stns_load_config(conf_path, &c) == STNS_OK);
	CHECK(c.unknown_keys == 0);
	stns_unload_config(&c);
}

static void
test_config_missing_file(void)
{
	stns_conf_t c;

	CHECK(stns_load_config("/nonexistent/stns.conf", &c) == STNS_NG);
}

static void
test_valid_name(void)
{
	CHECK(stns_is_valid_name("alice"));
	CHECK(stns_is_valid_name("_dhcp"));
	CHECK(stns_is_valid_name("a-b_c.d"));
	CHECK(!stns_is_valid_name(NULL));
	CHECK(!stns_is_valid_name(""));
	CHECK(!stns_is_valid_name("1abc"));
	/* Anything that could break out of the query string must be refused. */
	CHECK(!stns_is_valid_name("a&id=0"));
	CHECK(!stns_is_valid_name("a b"));
	CHECK(!stns_is_valid_name("a/b"));
	CHECK(!stns_is_valid_name("a?b"));
	CHECK(!stns_is_valid_name("a%20b"));
	CHECK(!stns_is_valid_name("a\nb"));
	CHECK(!stns_is_valid_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); /* 33 chars */
}

static void
test_escape_path(void)
{
	char *s;

	s = stns_escape_path("users?name=alice");
	CHECK_STR(s, "users%3Fname%3Dalice");
	free(s);

	s = stns_escape_path("groups");
	CHECK_STR(s, "groups");
	free(s);

	s = stns_escape_path("a/b");
	CHECK_STR(s, "a%2Fb");
	free(s);
}

static JSON_Value *
parse(const char *json)
{
	JSON_Value *v = json_parse_string(json);

	if (v == NULL) {
		(void)fprintf(stderr, "test bug: bad JSON literal\n");
		exit(1);
	}
	return v;
}

static void
test_fill_passwd(void)
{
	static const char *json = "{\"id\":1001,\"name\":\"alice\",\"group_id\":2001,"
				  "\"directory\":\"/home/alice\",\"shell\":\"/bin/ksh\","
				  "\"gecos\":\"Alice\",\"password\":\"$6$hash\"}";
	char buf[1024];
	struct passwd pwd;
	stns_conf_t c;
	JSON_Value *v;
	int errnop = 0;

	memset(&c, 0, sizeof(c));
	v = parse(json);

	CHECK(stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK_STR(pwd.pw_name, "alice");
	CHECK(pwd.pw_uid == 1001);
	CHECK(pwd.pw_gid == 2001);
	CHECK_STR(pwd.pw_dir, "/home/alice");
	CHECK_STR(pwd.pw_shell, "/bin/ksh");
	CHECK_STR(pwd.pw_gecos, "Alice");
	CHECK_STR(pwd.pw_class, "");
	/* The hash is for root's eyes only. */
	if (geteuid() == 0)
		CHECK_STR(pwd.pw_passwd, "$6$hash");
	else
		CHECK_STR(pwd.pw_passwd, "*");

	/* Shifts move the whole range clear of the local accounts. */
	c.uid_shift = 10000;
	c.gid_shift = 20000;
	CHECK(stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK(pwd.pw_uid == 11001);
	CHECK(pwd.pw_gid == 22001);

	json_value_free(v);
}

static void
test_fill_passwd_defaults(void)
{
	static const char *json = "{\"id\":1,\"name\":\"bob\",\"group_id\":1,\"shell\":\"\",\"directory\":\"\"}";
	char buf[1024];
	struct passwd pwd;
	stns_conf_t c;
	JSON_Value *v;
	int errnop = 0;

	memset(&c, 0, sizeof(c));
	v = parse(json);

	CHECK(stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK_STR(pwd.pw_shell, STNS_DEFAULT_SHELL);
	CHECK_STR(pwd.pw_dir, STNS_DEFAULT_HOME_PREFIX "/bob");
	CHECK_STR(pwd.pw_gecos, "");
	CHECK_STR(pwd.pw_passwd, "*");
	json_value_free(v);
}

static void
test_fill_passwd_bad_entry(void)
{
	char buf[1024];
	struct passwd pwd;
	stns_conf_t c;
	JSON_Value *v;
	int errnop = 0;

	memset(&c, 0, sizeof(c));

	v = parse("{\"id\":1,\"group_id\":1}"); /* no name */
	CHECK(stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, sizeof(buf), &errnop) == STNS_LOOKUP_NOTFOUND);
	json_value_free(v);

	v = parse("{\"name\":\"x\",\"group_id\":1}"); /* no id */
	CHECK(stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, sizeof(buf), &errnop) == STNS_LOOKUP_NOTFOUND);
	json_value_free(v);

	v = parse("{\"id\":\"1\",\"name\":\"x\",\"group_id\":1}"); /* id is a string */
	CHECK(stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, sizeof(buf), &errnop) == STNS_LOOKUP_NOTFOUND);
	json_value_free(v);
}

/*
 * Walk every buffer size from zero up to the size that finally works.  Each
 * one has to fail cleanly with ERANGE rather than scribbling past the end,
 * which is exactly what libc relies on when it retries with a bigger buffer.
 */
static void
test_fill_passwd_erange(void)
{
	static const char *json = "{\"id\":1001,\"name\":\"alice\",\"group_id\":2001,"
				  "\"directory\":\"/home/alice\",\"shell\":\"/bin/ksh\",\"gecos\":\"Alice\"}";
	struct passwd pwd;
	stns_conf_t c;
	JSON_Value *v;
	char *buf;
	size_t n;
	int errnop, rv, ok = 0;

	memset(&c, 0, sizeof(c));
	v = parse(json);

	for (n = 0; n <= 128; n++) {
		if ((buf = malloc(n > 0 ? n : 1)) == NULL)
			break;
		errnop = 0;
		rv = stns_fill_passwd(json_value_get_object(v), &c, &pwd, buf, n, &errnop);
		if (rv == STNS_LOOKUP_SUCCESS) {
			ok = 1;
			free(buf);
			break;
		}
		CHECK(rv == STNS_LOOKUP_ERANGE);
		CHECK(errnop == ERANGE);
		free(buf);
	}
	CHECK(ok); /* it has to succeed once the buffer is big enough */
	json_value_free(v);
}

static void
test_fill_group(void)
{
	static const char *json = "{\"id\":3001,\"name\":\"ops\",\"users\":[\"alice\",\"bob\"]}";
	char buf[1024];
	struct group grp;
	stns_conf_t c;
	JSON_Value *v;
	int errnop = 0;

	memset(&c, 0, sizeof(c));
	v = parse(json);

	CHECK(stns_fill_group(json_value_get_object(v), &c, &grp, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK_STR(grp.gr_name, "ops");
	CHECK_STR(grp.gr_passwd, "*");
	CHECK(grp.gr_gid == 3001);
	CHECK(grp.gr_mem != NULL);
	CHECK_STR(grp.gr_mem[0], "alice");
	CHECK_STR(grp.gr_mem[1], "bob");
	CHECK(grp.gr_mem[2] == NULL);
	/* gr_mem is a char ** carved out of buf and must be aligned for one. */
	CHECK(((uintptr_t)grp.gr_mem % sizeof(char *)) == 0);

	c.gid_shift = 5000;
	CHECK(stns_fill_group(json_value_get_object(v), &c, &grp, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK(grp.gr_gid == 8001);

	json_value_free(v);
}

static void
test_fill_group_empty(void)
{
	static const char *json = "{\"id\":3002,\"name\":\"empty\",\"users\":[]}";
	char buf[1024];
	struct group grp;
	stns_conf_t c;
	JSON_Value *v;
	int errnop = 0;

	memset(&c, 0, sizeof(c));
	v = parse(json);
	CHECK(stns_fill_group(json_value_get_object(v), &c, &grp, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK(grp.gr_mem != NULL);
	CHECK(grp.gr_mem[0] == NULL);
	json_value_free(v);

	/* A group with no "users" key at all must behave the same way. */
	v = parse("{\"id\":3003,\"name\":\"nokey\"}");
	CHECK(stns_fill_group(json_value_get_object(v), &c, &grp, buf, sizeof(buf), &errnop) == STNS_LOOKUP_SUCCESS);
	CHECK(grp.gr_mem[0] == NULL);
	json_value_free(v);
}

static void
test_fill_group_erange(void)
{
	static const char *json = "{\"id\":3001,\"name\":\"ops\",\"users\":[\"alice\",\"bob\"]}";
	struct group grp;
	stns_conf_t c;
	JSON_Value *v;
	char *buf;
	size_t n;
	int errnop, rv, ok = 0;

	memset(&c, 0, sizeof(c));
	v = parse(json);

	for (n = 0; n <= 128; n++) {
		if ((buf = malloc(n > 0 ? n : 1)) == NULL)
			break;
		errnop = 0;
		rv = stns_fill_group(json_value_get_object(v), &c, &grp, buf, n, &errnop);
		if (rv == STNS_LOOKUP_SUCCESS) {
			ok = 1;
			free(buf);
			break;
		}
		CHECK(rv == STNS_LOOKUP_ERANGE);
		CHECK(errnop == ERANGE);
		free(buf);
	}
	CHECK(ok);
	json_value_free(v);
}

static void
test_id_range_hints(void)
{
	/* With no hint recorded yet every id is worth asking about. */
	CHECK(stns_user_id_queryable(1));
	CHECK(stns_user_id_queryable(100000));

	stns_set_user_lowest_id(1000);
	stns_set_user_highest_id(2000);
	CHECK(!stns_user_id_queryable(999));
	CHECK(stns_user_id_queryable(1000));
	CHECK(stns_user_id_queryable(2000));
	CHECK(!stns_user_id_queryable(2001));

	stns_set_group_lowest_id(3000);
	stns_set_group_highest_id(4000);
	CHECK(!stns_group_id_queryable(2999));
	CHECK(stns_group_id_queryable(3500));
	CHECK(!stns_group_id_queryable(4001));

	/* Zero means "unknown" and must reopen the whole range. */
	stns_set_user_lowest_id(0);
	stns_set_user_highest_id(0);
	CHECK(stns_user_id_queryable(1));
	stns_set_group_lowest_id(0);
	stns_set_group_highest_id(0);
	CHECK(stns_group_id_queryable(1));
}

int
main(void)
{
	if (mkdtemp(tmpdir) == NULL) {
		perror("mkdtemp");
		return 1;
	}
	(void)snprintf(conf_path, sizeof(conf_path), "%s/stns.conf", tmpdir);

	test_config_defaults();
	test_config_values();
	test_config_use_cached_alias();
	test_config_linux_compatible();
	test_config_unknown_keys();
	test_config_missing_file();
	test_valid_name();
	test_escape_path();
	test_fill_passwd();
	test_fill_passwd_defaults();
	test_fill_passwd_bad_entry();
	test_fill_passwd_erange();
	test_fill_group();
	test_fill_group_empty();
	test_fill_group_erange();
	test_id_range_hints();

	(void)unlink(conf_path);
	(void)rmdir(tmpdir);

	(void)printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
