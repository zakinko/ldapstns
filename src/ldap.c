/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * One client connection, from the accept(2) to the close.
 *
 * This runs in a forked child, which is the whole shape of the design.  The
 * parent holds the snapshot and never parses a byte that came off a socket;
 * the child inherits the entries through copy-on-write, answers one client out
 * of them, and exits.  So the code below is the only part of the daemon
 * exposed to a hostile peer, it can neither modify the directory nor outlive
 * the connection, and a fault in it costs one client rather than the service.
 * It also means several clients are answered at once without a line of
 * concurrency control anywhere.
 *
 * Everything here is read-only.  Add, modify, delete, modifyDN and compare are
 * not merely unimplemented but absent: an operation this daemon does not
 * recognise is answered with a notice of disconnection rather than an error
 * the client might retry.
 */
#include <sys/socket.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "ldapstns.h"

/* RFC 4511 section 4.4.1: the unsolicited notification sent before hanging up. */
#define LDAP_NOTICE_OF_DISCONNECTION "1.3.6.1.4.1.1466.20036"

#define LDAP_SIZE_LIMIT_EXCEEDED 4

struct session {
	int fd;
	const ldapstns_conf *conf;
	const snapshot *snap;
	/*
	 * Whether this client has bound as conf->bind_dn.  When no bind_dn is
	 * configured the daemon is open to anonymous clients and this stays
	 * zero and is never consulted.
	 */
	int authenticated;
	char *nbind_dn; /* conf->bind_dn, normalised, or NULL */
};

/*
 * Write out a whole buffer.
 *
 * A short write is normal on a socket and is not an error; only a real failure
 * is, and there the connection is finished either way, so the caller only ever
 * needs to know whether to keep going.
 */
static int
write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int
read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = read(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1; /* the client closed, or a timeout expired */
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * Read one complete LDAPMessage.
 *
 * A BER value does not say how long it is until its length has been read, and
 * the length itself is variable width, so this happens in two steps: enough of
 * the header to learn the length, then the body.  The length is bounded before
 * anything is allocated - a client is perfectly capable of claiming a four
 * gigabyte message and then sending nothing.
 */
static int
read_message(int fd, uint8_t **out, size_t *outlen)
{
	uint8_t hdr[6];
	uint8_t *buf;
	size_t hlen, body, i, n;

	if (read_all(fd, hdr, 2) != 0)
		return -1;
	if (hdr[0] != BER_SEQUENCE)
		return -1;

	if ((hdr[1] & 0x80) == 0) {
		hlen = 2;
		body = hdr[1];
	} else {
		n = hdr[1] & 0x7f;
		if (n == 0 || n > 4)
			return -1; /* indefinite length, or an absurd one */
		if (read_all(fd, hdr + 2, n) != 0)
			return -1;
		hlen = 2 + n;
		body = 0;
		for (i = 0; i < n; i++)
			body = (body << 8) | hdr[2 + i];
	}

	if (body > LDAPSTNS_MAX_MESSAGE)
		return -1;

	if ((buf = malloc(hlen + body)) == NULL)
		return -1;
	memcpy(buf, hdr, hlen);
	if (body > 0 && read_all(fd, buf + hlen, body) != 0) {
		free(buf);
		return -1;
	}

	*out = buf;
	*outlen = hlen + body;
	return 0;
}

/*
 * An LDAPResult, wrapped in the response tag the operation calls for.  Every
 * reply this daemon sends other than a search entry is one of these.
 */
static int
send_result(struct session *ss, long msgid, uint8_t restag, long code, const char *matched, const char *text)
{
	bbuf msg, op, out;
	int rv = -1;

	bbuf_init(&msg);
	bbuf_init(&op);
	bbuf_init(&out);

	bbuf_int(&op, BER_ENUMERATED, code);
	bbuf_str(&op, BER_OCTETSTRING, (matched != NULL) ? matched : "");
	bbuf_str(&op, BER_OCTETSTRING, (text != NULL) ? text : "");

	bbuf_int(&msg, BER_INTEGER, msgid);
	bbuf_wrap(&msg, restag, &op);
	bbuf_wrap(&out, BER_SEQUENCE, &msg);

	if (!out.error)
		rv = write_all(ss->fd, out.p, out.len);

	bbuf_free(&out);
	bbuf_free(&op);
	bbuf_free(&msg);
	return rv;
}

/*
 * Which attributes a search asked for.
 *
 * An empty list, or one containing "*", means every user attribute.  The
 * special description "1.1" means none at all, and is how a client asks
 * "does this entry exist" without wanting to be told anything about it.
 */
struct attrsel {
	char **names;
	size_t n;
	int all;
	int none;
};

static int
attrsel_wants(const struct attrsel *sel, const char *name)
{
	size_t i;

	if (sel->none)
		return 0;
	if (sel->all)
		return 1;
	for (i = 0; i < sel->n; i++) {
		if (strcasecmp(sel->names[i], name) == 0)
			return 1;
	}
	return 0;
}

static void
attrsel_free(struct attrsel *sel)
{
	size_t i;

	for (i = 0; i < sel->n; i++)
		free(sel->names[i]);
	free(sel->names);
	memset(sel, 0, sizeof(*sel));
}

static int
attrsel_parse(ber *b, struct attrsel *sel)
{
	ber list;
	char *s;

	memset(sel, 0, sizeof(*sel));

	if (!ber_expect(b, BER_SEQUENCE, &list))
		return -1;

	while (!ber_end(&list)) {
		char **grown;

		if (!ber_str(&list, BER_OCTETSTRING, &s))
			return -1;
		if ((grown = realloc(sel->names, (sel->n + 1) * sizeof(*grown))) == NULL) {
			free(s);
			return -1;
		}
		sel->names = grown;
		sel->names[sel->n++] = s;
	}

	if (sel->n == 0) {
		sel->all = 1;
	} else {
		size_t i;

		for (i = 0; i < sel->n; i++) {
			if (strcmp(sel->names[i], "*") == 0)
				sel->all = 1;
		}
		if (!sel->all && sel->n == 1 && strcmp(sel->names[0], "1.1") == 0)
			sel->none = 1;
	}
	return 0;
}

/* searchResEntry: the DN, then the attributes that were asked for. */
static int
send_entry(struct session *ss, long msgid, const ldap_entry *e, const struct attrsel *sel, int types_only)
{
	bbuf msg, op, attrs, out;
	size_t i, j;
	int rv = -1;

	bbuf_init(&msg);
	bbuf_init(&op);
	bbuf_init(&attrs);
	bbuf_init(&out);

	for (i = 0; i < e->nattrs; i++) {
		bbuf one, vals;

		if (!attrsel_wants(sel, e->attrs[i].name))
			continue;

		bbuf_init(&one);
		bbuf_init(&vals);
		bbuf_str(&one, BER_OCTETSTRING, e->attrs[i].name);
		/*
		 * typesOnly asks for the attribute names with no values, which
		 * is still a SET, just an empty one.
		 */
		if (!types_only) {
			for (j = 0; j < e->attrs[i].nvals; j++)
				bbuf_str(&vals, BER_OCTETSTRING, e->attrs[i].vals[j]);
		}
		bbuf_wrap(&one, BER_SET, &vals);
		bbuf_wrap(&attrs, BER_SEQUENCE, &one);
		bbuf_free(&vals);
		bbuf_free(&one);
	}

	bbuf_str(&op, BER_OCTETSTRING, e->dn);
	bbuf_wrap(&op, BER_SEQUENCE, &attrs);

	bbuf_int(&msg, BER_INTEGER, msgid);
	bbuf_wrap(&msg, LDAP_RES_SEARCH_ENTRY, &op);
	bbuf_wrap(&out, BER_SEQUENCE, &msg);

	if (!out.error)
		rv = write_all(ss->fd, out.p, out.len);

	bbuf_free(&out);
	bbuf_free(&attrs);
	bbuf_free(&op);
	bbuf_free(&msg);
	return rv;
}

/*
 * BindRequest ::= [APPLICATION 0] SEQUENCE {
 *     version INTEGER (1..127), name LDAPDN, authentication AuthenticationChoice }
 *
 * What this daemon does with a bind depends entirely on whether a bind_dn is
 * configured.  Without one it holds nothing secret and lets anybody read, so
 * an anonymous bind succeeds and a bind with credentials is refused - there
 * are no accounts here to be those credentials.  With one, that DN and
 * password are the key to the whole directory and everything else is refused.
 *
 * In particular this is never a way to check a user's password.  Serving
 * password verification would mean holding the hashes to compare against, and
 * see the comment in snapshot.c about what that would amount to on a loopback
 * socket every process on the machine can reach.
 */
static int
do_bind(struct session *ss, long msgid, ber *op)
{
	char *name = NULL, *password = NULL, *nname = NULL;
	long version;
	uint8_t tag;
	int code = LDAP_INVALID_CREDENTIALS;
	const char *text = "";
	int rv;

	if (!ber_int(op, BER_INTEGER, &version) || !ber_str(op, BER_OCTETSTRING, &name)) {
		free(name);
		return send_result(ss, msgid, LDAP_RES_BIND, LDAP_PROTOCOL_ERROR, "", "malformed bind request");
	}

	if (version != 3) {
		free(name);
		return send_result(ss, msgid, LDAP_RES_BIND, LDAP_PROTOCOL_ERROR, "", "LDAPv3 only");
	}

	if (!ber_peek(op, &tag)) {
		free(name);
		return send_result(ss, msgid, LDAP_RES_BIND, LDAP_PROTOCOL_ERROR, "", "malformed bind request");
	}
	if (tag == LDAP_AUTH_SASL) {
		free(name);
		return send_result(ss, msgid, LDAP_RES_BIND, LDAP_AUTH_METHOD_NOT_SUPPORTED, "", "simple bind only");
	}
	if (!ber_str(op, LDAP_AUTH_SIMPLE, &password)) {
		free(name);
		return send_result(ss, msgid, LDAP_RES_BIND, LDAP_PROTOCOL_ERROR, "", "malformed bind request");
	}

	if (ss->nbind_dn == NULL) {
		/* Open to anonymous readers; there is nobody to bind as. */
		if (*name == '\0' && *password == '\0') {
			code = LDAP_SUCCESS;
			ss->authenticated = 1;
		} else {
			text = "this directory has no bind_dn configured";
		}
	} else if ((nname = dn_normalise(name)) == NULL) {
		code = LDAP_OPERATIONS_ERROR;
	} else if (strcmp(nname, ss->nbind_dn) == 0 && ss->conf->bind_password != NULL &&
	    strcmp(password, ss->conf->bind_password) == 0) {
		code = LDAP_SUCCESS;
		ss->authenticated = 1;
	} else {
		/*
		 * An anonymous bind still succeeds - refusing it would be
		 * wrong, RFC 4513 says so - but it authenticates nobody, and
		 * every operation after it is refused for want of access.
		 */
		if (*name == '\0' && *password == '\0') {
			code = LDAP_SUCCESS;
			ss->authenticated = 0;
		}
	}

	if (code != LDAP_SUCCESS)
		logit(LOG_NOTICE, "bind refused for \"%s\"", name);
	else
		logit(LOG_DEBUG, "bound as \"%s\"", (*name != '\0') ? name : "(anonymous)");

	rv = send_result(ss, msgid, LDAP_RES_BIND, code, "", text);
	free(nname);
	free(password);
	free(name);
	return rv;
}

/*
 * SearchRequest ::= [APPLICATION 3] SEQUENCE {
 *     baseObject LDAPDN, scope ENUMERATED, derefAliases ENUMERATED,
 *     sizeLimit INTEGER, timeLimit INTEGER, typesOnly BOOLEAN,
 *     filter Filter, attributes AttributeDescriptionList }
 *
 * timeLimit is read and ignored: every entry is already in memory, so a search
 * cannot take long enough for a limit on it to mean anything.  derefAliases is
 * read and ignored because there are no aliases to dereference.
 */
static int
do_search(struct session *ss, long msgid, ber *op)
{
	struct attrsel sel;
	ldap_filter *filter = NULL;
	char *base = NULL, *nbase = NULL;
	long scope, deref, sizelimit, timelimit;
	size_t i, sent = 0;
	int types_only, base_found = 0, code = LDAP_SUCCESS;
	int rv;

	memset(&sel, 0, sizeof(sel));

	if (ss->conf->bind_dn != NULL && !ss->authenticated)
		return send_result(ss, msgid, LDAP_RES_SEARCH_DONE, LDAP_INSUFFICIENT_ACCESS, "",
		    "bind first");

	if (!ber_str(op, BER_OCTETSTRING, &base) || !ber_int(op, BER_ENUMERATED, &scope) ||
	    !ber_int(op, BER_ENUMERATED, &deref) || !ber_int(op, BER_INTEGER, &sizelimit) ||
	    !ber_int(op, BER_INTEGER, &timelimit) || !ber_bool(op, BER_BOOLEAN, &types_only))
		goto malformed;

	if ((filter = filter_parse(op)) == NULL)
		goto malformed;
	if (attrsel_parse(op, &sel) != 0)
		goto malformed;
	if (scope != LDAP_SCOPE_BASE && scope != LDAP_SCOPE_ONE && scope != LDAP_SCOPE_SUB)
		goto malformed;

	if ((nbase = dn_normalise(base)) == NULL) {
		code = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	for (i = 0; i < ss->snap->nentries; i++) {
		const ldap_entry *e = &ss->snap->entries[i];
		int in_scope;

		/*
		 * The root DSE is only ever returned by the one search that
		 * names it: an empty base read at base scope.  It is not part
		 * of any naming context, so a subtree search - which formally
		 * covers the whole tree when the base is empty - must not sweep
		 * it up along with the real entries.
		 */
		if (*e->ndn == '\0') {
			if (scope == LDAP_SCOPE_BASE && *nbase == '\0') {
				base_found = 1;
				if (filter_match(filter, e)) {
					if (send_entry(ss, msgid, e, &sel, types_only) != 0)
						goto hangup;
					sent++;
				}
			}
			continue;
		}

		switch (scope) {
		case LDAP_SCOPE_BASE:
			in_scope = strcmp(e->ndn, nbase) == 0;
			break;
		case LDAP_SCOPE_ONE:
			in_scope = dn_is_child_of(e->ndn, nbase);
			break;
		default:
			in_scope = dn_in_subtree(e->ndn, nbase);
			break;
		}

		if (strcmp(e->ndn, nbase) == 0)
			base_found = 1;
		if (!in_scope || !filter_match(filter, e))
			continue;

		if (sizelimit > 0 && sent >= (size_t)sizelimit) {
			code = LDAP_SIZE_LIMIT_EXCEEDED;
			break;
		}
		if (send_entry(ss, msgid, e, &sel, types_only) != 0)
			goto hangup;
		sent++;
	}

	/*
	 * A base scope read of a DN that is not here is "no such object"; a
	 * subtree search that matched nothing is a success with no entries,
	 * because the base of it does exist.  Getting this the wrong way round
	 * is how a client concludes the whole directory has gone away.
	 */
	if (!base_found && scope == LDAP_SCOPE_BASE)
		code = LDAP_NO_SUCH_OBJECT;

	/*
	 * One line per search, at debug.
	 *
	 * The client that matters here is opendirectoryd, and opendirectoryd
	 * cannot be asked what it sent.  When a lookup does not work, the only
	 * two questions are whether it arrived at all and what it asked for,
	 * and without this the answer to both is a shrug.
	 */
	{
		char shown[256];

		filter_describe(filter, shown, sizeof(shown));
		logit(LOG_DEBUG, "search base=\"%s\" scope=%ld filter=%s -> %lu entries, result %d", base,
		    scope, shown, (unsigned long)sent, code);
	}

done:
	rv = send_result(ss, msgid, LDAP_RES_SEARCH_DONE, code, "", "");
	free(nbase);
	free(base);
	filter_free(filter);
	attrsel_free(&sel);
	return rv;

malformed:
	free(nbase);
	free(base);
	filter_free(filter);
	attrsel_free(&sel);
	return send_result(ss, msgid, LDAP_RES_SEARCH_DONE, LDAP_PROTOCOL_ERROR, "", "malformed search request");

hangup:
	free(nbase);
	free(base);
	filter_free(filter);
	attrsel_free(&sel);
	return -1;
}

/*
 * Every extended operation, refused.
 *
 * StartTLS is the one that matters, and refusing it is correct rather than
 * lazy: this daemon listens on the loopback interface only, where there is no
 * network for a transport to be secured against, and a half implemented TLS
 * negotiation would be worse than an honest "no".
 */
static int
do_extended(struct session *ss, long msgid, ber *op)
{
	bbuf msg, res, out;
	char *oid = NULL;
	int rv = -1;

	if (ber_str(op, BER_CONTEXT | 0, &oid))
		logit(LOG_NOTICE, "refused extended operation %s", oid);
	free(oid);

	bbuf_init(&msg);
	bbuf_init(&res);
	bbuf_init(&out);

	bbuf_int(&res, BER_ENUMERATED, LDAP_UNWILLING_TO_PERFORM);
	bbuf_str(&res, BER_OCTETSTRING, "");
	bbuf_str(&res, BER_OCTETSTRING, "no extended operations are supported");

	bbuf_int(&msg, BER_INTEGER, msgid);
	bbuf_wrap(&msg, LDAP_RES_EXTENDED, &res);
	bbuf_wrap(&out, BER_SEQUENCE, &msg);

	if (!out.error)
		rv = write_all(ss->fd, out.p, out.len);

	bbuf_free(&out);
	bbuf_free(&res);
	bbuf_free(&msg);
	return rv;
}

/*
 * Tell the client why the conversation is over, then let the caller hang up.
 *
 * This is an unsolicited notification: message id zero, an extendedResponse
 * carrying the notice of disconnection OID.  Simply closing would leave the
 * client to guess between "rejected" and "crashed".
 */
static void
send_disconnect(struct session *ss, long code, const char *text)
{
	bbuf msg, res, out;

	bbuf_init(&msg);
	bbuf_init(&res);
	bbuf_init(&out);

	bbuf_int(&res, BER_ENUMERATED, code);
	bbuf_str(&res, BER_OCTETSTRING, "");
	bbuf_str(&res, BER_OCTETSTRING, text);
	bbuf_str(&res, BER_CONTEXT | 10, LDAP_NOTICE_OF_DISCONNECTION);

	bbuf_int(&msg, BER_INTEGER, 0);
	bbuf_wrap(&msg, LDAP_RES_EXTENDED, &res);
	bbuf_wrap(&out, BER_SEQUENCE, &msg);

	if (!out.error)
		(void)write_all(ss->fd, out.p, out.len);

	bbuf_free(&out);
	bbuf_free(&res);
	bbuf_free(&msg);
}

void
ldap_serve(int fd, const ldapstns_conf *c, const snapshot *s)
{
	struct timeval tv;
	struct session ss;

	memset(&ss, 0, sizeof(ss));
	ss.fd = fd;
	ss.conf = c;
	ss.snap = s;
	if (c->bind_dn != NULL && (ss.nbind_dn = dn_normalise(c->bind_dn)) == NULL)
		return;

	/*
	 * A client that connects and then says nothing must not keep a child
	 * alive indefinitely.  A receive timeout turns that into a short read
	 * and an ordinary hang up, with no timer bookkeeping anywhere.
	 */
	tv.tv_sec = LDAPSTNS_CLIENT_TIMEOUT;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	for (;;) {
		uint8_t *raw;
		size_t rawlen;
		ber msg, seq, op;
		uint8_t tag;
		long msgid;
		int rv;

		if (read_message(fd, &raw, &rawlen) != 0)
			break;

		ber_init(&msg, raw, rawlen);
		if (!ber_expect(&msg, BER_SEQUENCE, &seq) || !ber_int(&seq, BER_INTEGER, &msgid) ||
		    !ber_peek(&seq, &tag)) {
			send_disconnect(&ss, LDAP_PROTOCOL_ERROR, "malformed message");
			free(raw);
			break;
		}
		if (!ber_tlv(&seq, &tag, &op)) {
			send_disconnect(&ss, LDAP_PROTOCOL_ERROR, "malformed message");
			free(raw);
			break;
		}

		switch (tag) {
		case LDAP_REQ_BIND:
			rv = do_bind(&ss, msgid, &op);
			break;
		case LDAP_REQ_SEARCH:
			rv = do_search(&ss, msgid, &op);
			break;
		case LDAP_REQ_EXTENDED:
			rv = do_extended(&ss, msgid, &op);
			break;
		case LDAP_REQ_ABANDON:
			/*
			 * Abandon has no reply, by definition.  There is also
			 * nothing to abandon: a search is answered in full
			 * before the next message is read.
			 */
			rv = 0;
			break;
		case LDAP_REQ_UNBIND:
			free(raw);
			goto out;
		default:
			send_disconnect(&ss, LDAP_PROTOCOL_ERROR, "this directory is read-only");
			free(raw);
			goto out;
		}

		free(raw);
		if (rv != 0)
			break;
	}

out:
	free(ss.nbind_dn);
}
