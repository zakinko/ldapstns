/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * libstns - an STNS API client for the BSDs and macOS.
 *
 * This is the part of nss_stns that had nothing to do with nsswitch: reading
 * stns.conf, talking to the API over HTTP, caching the answers and turning the
 * JSON into something a directory service can serve.  It is a library because
 * the systems that cannot use nsswitch need exactly the same work done before
 * they can start being different from each other.
 *
 * Portions are derived from libnss (https://github.com/STNS/libnss),
 * Copyright (c) 2026 pyama86, distributed under the MIT license.
 * See LICENSE for the full text of both licenses.
 */
#ifndef STNS_H
#define STNS_H

#include <sys/types.h>
#include <sys/stat.h>

#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "parson.h"
#include "toml.h"

/*
 * The systems this builds on.  There is deliberately no nsswitch test here:
 * nss_stns is only one of the consumers, and the other two exist precisely
 * because their systems have no nsswitch to plug into.
 */
#if !defined(__NetBSD__) && !defined(__FreeBSD__) && !defined(__DragonFly__) && !defined(__OpenBSD__) &&                \
    !defined(__APPLE__)
#error "libstns supports NetBSD, FreeBSD, DragonFly BSD, OpenBSD and macOS"
#endif

#define STNS_VERSION "0.1.0"

/*
 * Who we say we are, in the User-Agent header and in every syslog line.
 *
 * The library is linked into nss_stns, ypstns and ldapstns, and whoever is
 * reading the log needs to know which of them is complaining.  Each consumer's
 * Makefile defines this; the default is for someone building the library on
 * its own.
 */
#ifndef STNS_PRODUCT
#define STNS_PRODUCT "libstns"
#endif
#define STNS_USER_AGENT STNS_PRODUCT "/" STNS_VERSION

/*
 * Where the client configuration lives.  STNS_CONFDIR is overridable at build
 * time; each consumer's Makefile points it at that system's LOCALBASE.
 */
#ifndef STNS_CONFDIR
#ifdef __NetBSD__
#define STNS_CONFDIR "/usr/pkg/etc"
#else
#define STNS_CONFDIR "/usr/local/etc"
#endif
#endif

/*
 * Search order for the client configuration.  Both entries keep upstream
 * STNS's stns/client layout rather than flattening to a bare stns.conf: the
 * server's configuration is stns/server/stns.conf, so a flat name would become
 * ambiguous the day an STNS server is packaged for these systems too.  The
 * second entry is where a Linux host keeps the file, honoured so that a
 * stns.conf can be copied over unchanged.
 */
#define STNS_CONFIG_FILE STNS_CONFDIR "/stns/client/stns.conf"
#define STNS_CONFIG_FILE_COMPAT "/etc/stns/client/stns.conf"

#define STNS_DEFAULT_API_ENDPOINT "http://localhost:1104/v1"

/*
 * Where cached responses go by default.  hier(7) differs: FreeBSD documents
 * /var/cache for "miscellaneous cached files", while NetBSD, OpenBSD and macOS
 * have no such directory and keep automatically generated data under /var/db.
 * An explicit cache_dir in stns.conf always wins, so a configuration copied
 * from a Linux host still lands where it says it does.
 */
#if defined(__FreeBSD__) || defined(__DragonFly__)
#define STNS_DEFAULT_CACHE_DIR "/var/cache/stns"
#else
#define STNS_DEFAULT_CACHE_DIR "/var/db/stns"
#endif
#define STNS_DEFAULT_CACHED_SOCKET "/var/run/cache-stnsd.sock"
#define STNS_DEFAULT_SHELL "/bin/sh"
#define STNS_DEFAULT_HOME_PREFIX "/home"

/* 10MB */
#define STNS_MAX_BUFFER_SIZE (10 * 1024 * 1024)
#define STNS_DEFAULT_BUFFER_SIZE (16 * 1024)
#define STNS_MAXBUF 1024
#define STNS_MAX_NAME_LENGTH 32

#define STNS_HTTP_NOTFOUND 404L

#define STNS_LOCK_RETRY 3
#define STNS_LOCK_INTERVAL_MSEC 10

/* stns_request() return values (deliberately not CURLcode). */
#define STNS_OK 0
#define STNS_NG 1

/*
 * What a lookup came to.
 *
 * These used to be nsswitch's NS_* codes, which was fine while nss_stns was
 * the only caller and awkward as soon as it was not: NS_RETURN alone means two
 * different things on NetBSD and FreeBSD, and neither OpenBSD nor macOS has
 * the header that defines any of them.  So the library has its own, and each
 * consumer translates them into whatever its own interface wants to hear.
 */
enum stns_status {
	STNS_LOOKUP_SUCCESS = 0,
	STNS_LOOKUP_NOTFOUND, /* the directory does not hold this name or id */
	STNS_LOOKUP_UNAVAIL,  /* the server could not be asked, or made no sense */
	STNS_LOOKUP_ERANGE    /* the caller's buffer was too small; retry bigger */
};

typedef struct stns_response_t stns_response_t;
struct stns_response_t {
	char *data;
	size_t size;
	long status_code;
};

typedef struct stns_http_header_t stns_http_header_t;
struct stns_http_header_t {
	char *key;
	char *value;
};

typedef struct stns_conf_t stns_conf_t;
struct stns_conf_t {
	char *api_endpoint;
	char *auth_token;
	char *user;
	char *password;
	char *query_wrapper;
	char *chain_ssh_wrapper;
	char *http_proxy;
	char *cache_dir;
	char *tls_ca;
	char *tls_cert;
	char *tls_key;
	char *cached_unix_socket;

	stns_http_header_t *http_headers;
	size_t http_headers_size;

	int cached_enable;
	int uid_shift;
	int gid_shift;
	int cache;
	int cache_ttl;
	int negative_cache_ttl;
	int request_retry;
	int request_locktime;

	long request_timeout;
	long ssl_verify;
	long http_location;

	/*
	 * How many keys in the file we did not recognise.  An absent key is
	 * normal - nearly everything here is optional and has a default - but
	 * a key that is present and unrecognised is a typo or a setting only
	 * the Linux client implements, and either way it is doing nothing.
	 */
	int unknown_keys;
};

/*
 * One directory record, with every string owned by the record itself.
 *
 * struct passwd and struct group cannot carry these: a YP map needs the
 * password hash whatever the caller's euid happens to be, an LDAP entry needs
 * the SSH keys, and both need the whole directory in memory at once rather
 * than one entry at a time in somebody else's stack buffer.  uid and gid have
 * the configured shift already applied, and shell and directory have already
 * fallen back to their defaults, so no consumer repeats that work.
 */
typedef struct stns_user_t stns_user_t;
struct stns_user_t {
	char *name;
	char *password;
	char *gecos;
	char *directory;
	char *shell;
	uid_t uid;
	gid_t gid;
	char **keys;
	size_t keys_size;
};

typedef struct stns_group_t stns_group_t;
struct stns_group_t {
	char *name;
	gid_t gid;
	char **users;
	size_t users_size;
};

/* stns_config.c */
int stns_load_config(const char *filename, stns_conf_t *c);
void stns_unload_config(stns_conf_t *c);
const char *stns_config_path(void);

/* stns_request.c */
int stns_request(stns_conf_t *c, const char *path, stns_response_t *res);
int stns_exec_cmd(const char *cmd, const char *arg, stns_response_t *r);
char *stns_escape_path(const char *path);

/*
 * The API advertises the highest/lowest managed uid/gid through response
 * headers.  Remembering them lets us skip pointless HTTP round trips for ids
 * that STNS can never own (every local account, for instance).
 */
void stns_set_user_highest_id(int id);
void stns_set_user_lowest_id(int id);
void stns_set_group_highest_id(int id);
void stns_set_group_lowest_id(int id);
int stns_user_id_queryable(int id);
int stns_group_id_queryable(int id);

int stns_is_valid_name(const char *name);
int stns_mutex_retrylock(pthread_mutex_t *mutex);

/*
 * stns_lookup.c - one entry at a time, into the caller's buffer.
 *
 * This is the shape nsswitch asks for, and it is what nss_stns uses.  A daemon
 * holding the whole directory wants stns_list.c instead.  Everything here
 * returns an enum stns_status.
 */
int stns_pw_by_name(stns_conf_t *c, const char *name, struct passwd *pwd, char *buf, size_t buflen, int *errnop);
int stns_pw_by_uid(stns_conf_t *c, uid_t uid, struct passwd *pwd, char *buf, size_t buflen, int *errnop);
int stns_pw_setent(void);
int stns_pw_endent(void);
int stns_pw_nextent(stns_conf_t *c, struct passwd *pwd, char *buf, size_t buflen, int *errnop);

int stns_gr_by_name(stns_conf_t *c, const char *name, struct group *grp, char *buf, size_t buflen, int *errnop);
int stns_gr_by_gid(stns_conf_t *c, gid_t gid, struct group *grp, char *buf, size_t buflen, int *errnop);
int stns_gr_setent(void);
int stns_gr_endent(void);
int stns_gr_nextent(stns_conf_t *c, struct group *grp, char *buf, size_t buflen, int *errnop);
int stns_gr_membership(stns_conf_t *c, const char *uname, gid_t agroup, gid_t *groups, int maxgrp, int *groupc);

/*
 * stns_list.c - the whole directory at once, allocated.
 *
 * ypstns and ldapstns are servers: they answer from a snapshot they refresh on
 * a timer, because a lookup that waited on an HTTP round trip would make every
 * login on the machine wait on it too.  Both take that snapshot from here.
 */
int stns_list_users(stns_conf_t *c, stns_user_t **users, size_t *n);
int stns_list_groups(stns_conf_t *c, stns_group_t **groups, size_t *n);
void stns_free_users(stns_user_t *users, size_t n);
void stns_free_groups(stns_group_t *groups, size_t n);

/*
 * A single record, for the callers that want one name rather than the whole
 * directory - stns-key-wrapper, mostly.  Free the result with
 * stns_free_users()/stns_free_groups() and a count of one.
 */
int stns_user_by_name(stns_conf_t *c, const char *name, stns_user_t **user);
int stns_group_by_name(stns_conf_t *c, const char *name, stns_group_t **group);

/*
 * stns_crypt.c - checking a password against the hash the directory holds.
 *
 * Here rather than in a consumer because neither system this is for can do it:
 * STNS deployments hold SHA-512 crypt hashes, macOS's crypt(3) understands
 * only traditional DES and does not say so, and OpenBSD's understands only
 * bcrypt.  See the comment at the top of that file.
 */
void stns_sha256(const void *data, size_t len, uint8_t out[32]);
void stns_sha512(const void *data, size_t len, uint8_t out[64]);

/*
 * STNS_OK only for a positive match.  Every other outcome is a refusal and
 * they are deliberately indistinguishable to the caller.
 */
int stns_crypt_check(const char *password, const char *hash);

/*
 * Hash a password with the scheme and salt a setting names, for the tests to
 * compare against a published vector.  A boolean is a poor thing to debug
 * against; this can say how two strings differ.
 */
int stns_crypt_hash(const char *password, const char *setting, char *out, size_t outlen);

/*
 * Whether a hash of this shape can be checked on this system at all.  Worth
 * asking separately: "wrong password" and "this machine cannot read that kind
 * of hash" are the same answer from stns_crypt_check() and very different
 * answers to whoever is trying to log in.
 */
int stns_crypt_supported(const char *hash);

/* stns_entry.c */
int stns_fill_passwd(JSON_Object *o, stns_conf_t *c, struct passwd *pwd, char *buf, size_t buflen, int *errnop);
int stns_fill_group(JSON_Object *o, stns_conf_t *c, struct group *grp, char *buf, size_t buflen, int *errnop);

/*
 * The two field readers the marshalling shares with the list builder: a string
 * or a number, and NULL or -1 when the key is absent or of another type.  Ids
 * are never negative, so -1 is unambiguous.
 */
const char *stns_json_str(JSON_Object *o, const char *key);
int stns_json_int(JSON_Object *o, const char *key);

/*
 * Fetch a request path and hand back the parsed JSON array.  The API answers
 * with an array even for a lookup that can only match one record.  On
 * STNS_LOOKUP_SUCCESS the caller owns *rootp and must json_value_free() it.
 */
int stns_fetch(stns_conf_t *c, const char *path, JSON_Value **rootp);

#endif /* STNS_H */
