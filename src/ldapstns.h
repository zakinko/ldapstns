/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * ldapstns - a read-only LDAPv3 view of an STNS directory, for macOS.
 *
 * macOS resolves users and groups through opendirectoryd, and opendirectoryd
 * is extended by modules in /System/Library/OpenDirectory/Modules.  Every one
 * of them is an Apple-signed bundle in a directory System Integrity Protection
 * will not let anything be added to, so writing a module is not a thing that
 * can be done at all - not badly, not with an entitlement, not by asking
 * nicely.  What can be done is to speak a protocol one of the shipped modules
 * already knows, which is what this daemon does: it serves LDAPv3 on the
 * loopback interface, and ldap.bundle is pointed at it with dsconfigldap(8).
 *
 * The mapping between LDAP attributes and macOS record types is not ours to
 * invent either.  It is fixed by /System/Library/OpenDirectory/Mappings/
 * RFC2307.plist, and entry.c emits exactly the attributes that file names -
 * see the comment there.
 */
#ifndef LDAPSTNS_H
#define LDAPSTNS_H

#include <sys/types.h>

#include <netinet/in.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stns.h"

#define LDAPSTNS_VERSION "0.1.0"

/*
 * Where the daemon's own configuration lives.  LDAPSTNS_CONFDIR is set by the
 * Makefile; on macOS that is /usr/local/etc, or /opt/homebrew/etc when
 * Homebrew put it there.
 *
 * This is a second file, next to stns.conf rather than merged into it, and
 * deliberately.  stns.conf describes the API client and is meant to be
 * copyable verbatim from a Linux host - it is also what stns-key-wrapper
 * reads.  Which port to listen on and which suffix to serve are nothing to do
 * with the API and belong to this daemon alone.
 */
#ifndef LDAPSTNS_CONFDIR
#define LDAPSTNS_CONFDIR "/usr/local/etc"
#endif
#define LDAPSTNS_CONFIG_FILE LDAPSTNS_CONFDIR "/ldapstns.conf"

/*
 * Both loopbacks by default, and both of them because of one detail of macOS:
 * "localhost" resolves to ::1 before it resolves to 127.0.0.1.  A daemon
 * listening only on the IPv4 address is a daemon that anybody who typed
 * "dsconfigldap -a localhost" cannot reach, with nothing anywhere to say why.
 */
#define LDAPSTNS_DEFAULT_LISTEN_V4 "127.0.0.1"
#define LDAPSTNS_DEFAULT_LISTEN_V6 "::1"
#define LDAPSTNS_DEFAULT_PORT 389
#define LDAPSTNS_DEFAULT_SUFFIX "dc=stns"
#define LDAPSTNS_DEFAULT_USER "nobody"
#define LDAPSTNS_DEFAULT_INTERVAL 60

/*
 * A client that never finishes a message must not be able to hold a child
 * process open for ever, and one that claims a four gigabyte message must not
 * be believed.  Neither limit is reachable by anything opendirectoryd sends.
 */
#define LDAPSTNS_MAX_MESSAGE (1024 * 1024)
#define LDAPSTNS_CLIENT_TIMEOUT 30

/* How many connections may be waiting while a refresh is in progress. */
#define LDAPSTNS_BACKLOG 32

/*
 * BER tags.
 *
 * The universal ones are the primitives every message is built from.  The
 * application ones are the LDAP protocol operations, and the context ones are
 * the choices inside a filter - all as numbered by RFC 4511.
 */
#define BER_UNIVERSAL 0x00
#define BER_APPLICATION 0x40
#define BER_CONTEXT 0x80
#define BER_CONSTRUCTED 0x20

#define BER_BOOLEAN 0x01
#define BER_INTEGER 0x02
#define BER_OCTETSTRING 0x04
#define BER_NULL 0x05
#define BER_ENUMERATED 0x0a
#define BER_SEQUENCE (0x10 | BER_CONSTRUCTED)
#define BER_SET (0x11 | BER_CONSTRUCTED)

#define LDAP_REQ_BIND (BER_APPLICATION | BER_CONSTRUCTED | 0)
#define LDAP_RES_BIND (BER_APPLICATION | BER_CONSTRUCTED | 1)
#define LDAP_REQ_UNBIND (BER_APPLICATION | 2)
#define LDAP_REQ_SEARCH (BER_APPLICATION | BER_CONSTRUCTED | 3)
#define LDAP_RES_SEARCH_ENTRY (BER_APPLICATION | BER_CONSTRUCTED | 4)
#define LDAP_RES_SEARCH_DONE (BER_APPLICATION | BER_CONSTRUCTED | 5)
#define LDAP_REQ_ABANDON (BER_APPLICATION | 16)
#define LDAP_REQ_EXTENDED (BER_APPLICATION | BER_CONSTRUCTED | 23)
#define LDAP_RES_EXTENDED (BER_APPLICATION | BER_CONSTRUCTED | 24)

/* Filter choices, RFC 4511 section 4.5.1. */
#define LDAP_FILT_AND (BER_CONTEXT | BER_CONSTRUCTED | 0)
#define LDAP_FILT_OR (BER_CONTEXT | BER_CONSTRUCTED | 1)
#define LDAP_FILT_NOT (BER_CONTEXT | BER_CONSTRUCTED | 2)
#define LDAP_FILT_EQUALITY (BER_CONTEXT | BER_CONSTRUCTED | 3)
#define LDAP_FILT_SUBSTRINGS (BER_CONTEXT | BER_CONSTRUCTED | 4)
#define LDAP_FILT_GE (BER_CONTEXT | BER_CONSTRUCTED | 5)
#define LDAP_FILT_LE (BER_CONTEXT | BER_CONSTRUCTED | 6)
#define LDAP_FILT_PRESENT (BER_CONTEXT | 7)
#define LDAP_FILT_APPROX (BER_CONTEXT | BER_CONSTRUCTED | 8)

#define LDAP_SUB_INITIAL (BER_CONTEXT | 0)
#define LDAP_SUB_ANY (BER_CONTEXT | 1)
#define LDAP_SUB_FINAL (BER_CONTEXT | 2)

/* Simple authentication choice inside a bindRequest. */
#define LDAP_AUTH_SIMPLE (BER_CONTEXT | 0)
#define LDAP_AUTH_SASL (BER_CONTEXT | BER_CONSTRUCTED | 3)

/* Scopes. */
#define LDAP_SCOPE_BASE 0
#define LDAP_SCOPE_ONE 1
#define LDAP_SCOPE_SUB 2

/* The result codes this daemon can produce. */
#define LDAP_SUCCESS 0
#define LDAP_OPERATIONS_ERROR 1
#define LDAP_PROTOCOL_ERROR 2
#define LDAP_AUTH_METHOD_NOT_SUPPORTED 7
#define LDAP_NO_SUCH_OBJECT 32
#define LDAP_INVALID_CREDENTIALS 49
#define LDAP_INSUFFICIENT_ACCESS 50
#define LDAP_UNAVAILABLE 52
#define LDAP_UNWILLING_TO_PERFORM 53

/*
 * A growable output buffer.
 *
 * BER needs a value's length before its tag can be written, so a nested
 * structure is built innermost first, into a buffer of its own, and then
 * wrapped.  That costs one copy per level of nesting, which for a protocol
 * five levels deep and messages measured in kilobytes is not worth avoiding.
 */
typedef struct bbuf bbuf;
struct bbuf {
	uint8_t *p;
	size_t len;
	size_t cap;
	int error; /* sticky: set once, checked once, at the end */
};

void bbuf_init(bbuf *b);
void bbuf_free(bbuf *b);
void bbuf_bytes(bbuf *b, const void *v, size_t len);
void bbuf_tlv(bbuf *b, uint8_t tag, const void *v, size_t len);
void bbuf_wrap(bbuf *b, uint8_t tag, const bbuf *inner);
void bbuf_int(bbuf *b, uint8_t tag, long v);
void bbuf_str(bbuf *b, uint8_t tag, const char *s);
void bbuf_bool(bbuf *b, uint8_t tag, int v);

/*
 * A cursor over a received message.  Every accessor is bounds checked and
 * leaves the cursor untouched when it fails, so a truncated or hostile message
 * makes the parse fail rather than the process read past its buffer.
 */
typedef struct ber ber;
struct ber {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

void ber_init(ber *b, const void *buf, size_t len);
int ber_peek(const ber *b, uint8_t *tag);
int ber_tlv(ber *b, uint8_t *tag, ber *val);
int ber_expect(ber *b, uint8_t tag, ber *val);
int ber_int(ber *b, uint8_t tag, long *v);
int ber_bool(ber *b, uint8_t tag, int *v);
/* The returned string is freshly allocated and NUL terminated by us: an LDAP
 * octet string may legitimately contain a NUL, and nothing downstream of here
 * would survive one, so any embedded NUL makes the read fail. */
int ber_str(ber *b, uint8_t tag, char **s);
int ber_end(const ber *b);

/*
 * One attribute and one entry, as served.
 *
 * The entries are built once per refresh rather than once per search: a search
 * is answered by a forked child out of memory it inherited, and building three
 * hundred entries for every getpwnam(3) on the machine would be work done at
 * exactly the wrong moment.
 */
typedef struct ldap_attr ldap_attr;
struct ldap_attr {
	char *name;
	char **vals;
	size_t nvals;
};

typedef struct ldap_entry ldap_entry;
struct ldap_entry {
	char *dn;
	char *ndn; /* dn, normalised, for comparison */
	ldap_attr *attrs;
	size_t nattrs;
};

/* entry.c */
int entry_init(ldap_entry *e, const char *dn);
int entry_add(ldap_entry *e, const char *name, const char *value);
int entry_addf(ldap_entry *e, const char *name, const char *fmt, ...);
const ldap_attr *entry_find(const ldap_entry *e, const char *name);
void entry_free_contents(ldap_entry *e);
char *dn_normalise(const char *dn);
int dn_is_child_of(const char *ndn, const char *nbase);
int dn_in_subtree(const char *ndn, const char *nbase);

/* filter.c */
typedef struct ldap_filter ldap_filter;
ldap_filter *filter_parse(ber *b);
void filter_free(ldap_filter *f);
int filter_match(const ldap_filter *f, const ldap_entry *e);
/* The filter as RFC 4515 text, truncated to fit, for the log. */
void filter_describe(const ldap_filter *f, char *buf, size_t buflen);

/*
 * The configuration of the daemon itself.  Everything about the API - the
 * endpoint, the credentials, the timeouts - is in stns.conf and belongs to
 * the STNS API client; none of it appears here.
 */
typedef struct ldapstns_conf ldapstns_conf;
struct ldapstns_conf {
	/*
	 * One or more addresses, because a machine has more than one loopback
	 * and because the configuration may name several.  A "listen" that
	 * failed to bind is not fatal on its own - a machine with IPv6 turned
	 * off should still get its IPv4 listener - but binding none of them is.
	 */
	char **listen;
	size_t nlisten;
	char *suffix;
	char *user;
	char *bind_dn;
	char *bind_password;
	int port;
	int interval;
	int expose_password;
	int unknown_keys;
};

/* conf.c */
int conf_load(const char *filename, ldapstns_conf *c);
void conf_free(ldapstns_conf *c);

/*
 * The directory as it stood at the last refresh, already turned into the
 * entries that will be served.
 */
typedef struct snapshot snapshot;
struct snapshot {
	ldap_entry *entries;
	size_t nentries;
	time_t taken;
};

/* snapshot.c */
int snapshot_refresh(stns_conf_t *sc, const ldapstns_conf *c, snapshot *s);
void snapshot_free(snapshot *s);

/* ldap.c */
void ldap_serve(int fd, const ldapstns_conf *c, const snapshot *s);

/* ldapstns.c */
extern int debug;
void logit(int prio, const char *fmt, ...);

#endif /* LDAPSTNS_H */
