/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * LDAP search filters: parsing them out of a request, and matching them
 * against an entry.
 *
 * Every choice RFC 4511 defines is implemented, because it is not this
 * daemon's business to guess which ones opendirectoryd will send.  What it
 * sends for an ordinary getpwnam(3) is
 *
 *	(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)
 *	    (objectClass=shadowAccount))(uid=alice))
 *
 * - the objectClass alternatives coming from "Group Object Classes": "OR" in
 * /System/Library/OpenDirectory/Mappings/RFC2307.plist - but the Users & Groups
 * pane also does substring searches, and a filter that arrives unimplemented
 * would fail as "no such user" with nothing anywhere to say why.
 *
 * Matching is case insensitive throughout.  That is correct for the string
 * syntaxes RFC 2307 uses (caseIgnoreMatch and caseIgnoreIA5Match), and
 * harmless for the numeric ones, whose values contain no letters to fold.
 */
#include <ctype.h>
#include <stdlib.h>

#include "ldapstns.h"

/*
 * A filter is a tree, and it arrives from a client that may have nested it as
 * deeply as it likes.  Recursion depth is capped so that a filter designed to
 * be pathological runs out of permission before the child runs out of stack.
 * Nothing real is more than three or four deep.
 */
#define FILTER_MAX_DEPTH 32

struct ldap_filter {
	uint8_t tag;

	/* and, or, not */
	ldap_filter **sub;
	size_t nsub;

	/* equalityMatch, greaterOrEqual, lessOrEqual, approxMatch, present */
	char *attr;
	char *value;

	/* substrings; any of the three parts may be absent */
	char *initial;
	char *final;
	char **any;
	size_t nany;
};

static ldap_filter *parse(ber *b, int depth);

static int
ci_eq(const char *a, const char *b)
{
	while (*a != '\0' && *b != '\0') {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
		a++;
		b++;
	}
	return *a == *b;
}

/*
 * Case insensitive strstr(3).  Written out rather than using strcasestr(3)
 * because that one is not in any standard, and this is three lines.
 */
static const char *
ci_strstr(const char *hay, const char *needle)
{
	size_t nlen = strlen(needle);
	const char *p;

	if (nlen == 0)
		return hay;
	for (p = hay; *p != '\0'; p++) {
		size_t i;

		for (i = 0; i < nlen; i++) {
			if (tolower((unsigned char)p[i]) != tolower((unsigned char)needle[i]))
				break;
		}
		if (i == nlen)
			return p;
	}
	return NULL;
}

static ldap_filter *
filter_alloc(uint8_t tag)
{
	ldap_filter *f;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		return NULL;
	f->tag = tag;
	return f;
}

void
filter_free(ldap_filter *f)
{
	size_t i;

	if (f == NULL)
		return;
	for (i = 0; i < f->nsub; i++)
		filter_free(f->sub[i]);
	free(f->sub);
	for (i = 0; i < f->nany; i++)
		free(f->any[i]);
	free(f->any);
	free(f->initial);
	free(f->final);
	free(f->attr);
	free(f->value);
	free(f);
}

static int
add_sub(ldap_filter *f, ldap_filter *child)
{
	ldap_filter **grown;

	if ((grown = realloc(f->sub, (f->nsub + 1) * sizeof(*grown))) == NULL) {
		filter_free(child);
		return -1;
	}
	f->sub = grown;
	f->sub[f->nsub++] = child;
	return 0;
}

/* attributeDesc followed by assertionValue, both plain octet strings. */
static int
parse_ava(ber *val, ldap_filter *f)
{
	if (!ber_str(val, BER_OCTETSTRING, &f->attr))
		return -1;
	if (!ber_str(val, BER_OCTETSTRING, &f->value))
		return -1;
	return 0;
}

/*
 * SubstringFilter ::= SEQUENCE { type AttributeDescription,
 *     substrings SEQUENCE SIZE (1..MAX) OF substring CHOICE {
 *         initial [0] ..., any [1] ..., final [2] ... } }
 *
 * At most one initial and one final are permitted, and both must be at the
 * ends; a filter that breaks either rule is refused rather than reinterpreted.
 */
static int
parse_substrings(ber *val, ldap_filter *f)
{
	ber seq;

	if (!ber_str(val, BER_OCTETSTRING, &f->attr))
		return -1;
	if (!ber_expect(val, BER_SEQUENCE, &seq))
		return -1;

	while (!ber_end(&seq)) {
		char **grown, *s;
		uint8_t tag;

		if (!ber_peek(&seq, &tag))
			return -1;
		switch (tag) {
		case LDAP_SUB_INITIAL:
			if (f->initial != NULL || f->nany > 0 || f->final != NULL)
				return -1;
			if (!ber_str(&seq, tag, &f->initial))
				return -1;
			break;
		case LDAP_SUB_ANY:
			if (f->final != NULL)
				return -1;
			if (!ber_str(&seq, tag, &s))
				return -1;
			if ((grown = realloc(f->any, (f->nany + 1) * sizeof(*grown))) == NULL) {
				free(s);
				return -1;
			}
			f->any = grown;
			f->any[f->nany++] = s;
			break;
		case LDAP_SUB_FINAL:
			if (f->final != NULL)
				return -1;
			if (!ber_str(&seq, tag, &f->final))
				return -1;
			break;
		default:
			return -1;
		}
	}

	/* "SIZE (1..MAX)": a substring filter with no substrings is malformed. */
	if (f->initial == NULL && f->nany == 0 && f->final == NULL)
		return -1;
	return 0;
}

static ldap_filter *
parse(ber *b, int depth)
{
	ldap_filter *f;
	ber val;
	uint8_t tag;

	if (depth > FILTER_MAX_DEPTH)
		return NULL;
	if (!ber_tlv(b, &tag, &val))
		return NULL;
	if ((f = filter_alloc(tag)) == NULL)
		return NULL;

	switch (tag) {
	case LDAP_FILT_AND:
	case LDAP_FILT_OR:
		while (!ber_end(&val)) {
			ldap_filter *child = parse(&val, depth + 1);

			if (child == NULL || add_sub(f, child) != 0)
				goto fail;
		}
		break;

	case LDAP_FILT_NOT: {
		ldap_filter *child = parse(&val, depth + 1);

		if (child == NULL || add_sub(f, child) != 0)
			goto fail;
		if (!ber_end(&val))
			goto fail;
		break;
	}

	case LDAP_FILT_EQUALITY:
	case LDAP_FILT_GE:
	case LDAP_FILT_LE:
	case LDAP_FILT_APPROX:
		if (parse_ava(&val, f) != 0)
			goto fail;
		break;

	case LDAP_FILT_SUBSTRINGS:
		if (parse_substrings(&val, f) != 0)
			goto fail;
		break;

	case LDAP_FILT_PRESENT:
		/*
		 * The one primitive choice: the contents are the attribute
		 * description itself rather than a nested value.
		 */
		if (memchr(val.buf, '\0', val.len) != NULL)
			goto fail;
		if ((f->attr = malloc(val.len + 1)) == NULL)
			goto fail;
		memcpy(f->attr, val.buf, val.len);
		f->attr[val.len] = '\0';
		break;

	default:
		/* An extensibleMatch, or something that is not a filter. */
		goto fail;
	}

	return f;

fail:
	filter_free(f);
	return NULL;
}

ldap_filter *
filter_parse(ber *b)
{
	return parse(b, 0);
}

/*
 * Order two values the way a greaterOrEqual or lessOrEqual comparison needs.
 *
 * Both operands are compared as numbers when both look like numbers, and as
 * text otherwise.  That distinction matters: a client asking for
 * (uidNumber>=1000) means 1000 the number, and comparing "999" against "1000"
 * as text answers the opposite of what it asked.
 */
static int
value_cmp(const char *a, const char *b)
{
	char *ea, *eb;
	long la, lb;

	la = strtol(a, &ea, 10);
	lb = strtol(b, &eb, 10);
	if (ea != a && *ea == '\0' && eb != b && *eb == '\0')
		return (la < lb) ? -1 : (la > lb) ? 1 : 0;

	/* Not both numeric; fall back to a case insensitive text ordering. */
	for (; *a != '\0' && *b != '\0'; a++, b++) {
		int ca = tolower((unsigned char)*a);
		int cb = tolower((unsigned char)*b);

		if (ca != cb)
			return (ca < cb) ? -1 : 1;
	}
	return (*a == *b) ? 0 : (*a == '\0') ? -1 : 1;
}

static int
match_substrings(const ldap_filter *f, const char *v)
{
	const char *p = v;
	size_t i, vlen, flen;

	if (f->initial != NULL) {
		flen = strlen(f->initial);
		if (strlen(p) < flen)
			return 0;
		for (i = 0; i < flen; i++) {
			if (tolower((unsigned char)p[i]) != tolower((unsigned char)f->initial[i]))
				return 0;
		}
		p += flen;
	}

	/* Each any must appear after the one before it, hence the moving p. */
	for (i = 0; i < f->nany; i++) {
		const char *hit = ci_strstr(p, f->any[i]);

		if (hit == NULL)
			return 0;
		p = hit + strlen(f->any[i]);
	}

	if (f->final != NULL) {
		flen = strlen(f->final);
		vlen = strlen(p);
		if (vlen < flen)
			return 0;
		if (!ci_eq(p + vlen - flen, f->final))
			return 0;
	}
	return 1;
}

/*
 * Render a filter back into the text form RFC 4515 defines, for the log.
 *
 * The client that matters here cannot be asked what it sent, and "the search
 * matched nothing" is not a diagnosis - the filter is.  Truncated rather than
 * grown without limit, because this goes in a log line and a client is at
 * liberty to send something enormous.
 */
static void
describe(const ldap_filter *f, char *buf, size_t buflen, size_t *off)
{
	size_t i;
	int n;

#define PUT(...)                                                                                                       	do {                                                                                                           		if (*off >= buflen)                                                                                    			return;                                                                                        		n = snprintf(buf + *off, buflen - *off, __VA_ARGS__);                                                  		if (n < 0 || (size_t)n >= buflen - *off) {                                                             			*off = buflen;                                                                                 			return;                                                                                        		}                                                                                                      		*off += (size_t)n;                                                                                     	} while (0)

	switch (f->tag) {
	case LDAP_FILT_AND:
	case LDAP_FILT_OR:
	case LDAP_FILT_NOT:
		PUT("(%c", (f->tag == LDAP_FILT_AND) ? '&' : (f->tag == LDAP_FILT_OR) ? '|' : '!');
		for (i = 0; i < f->nsub; i++)
			describe(f->sub[i], buf, buflen, off);
		PUT(")");
		break;
	case LDAP_FILT_PRESENT:
		PUT("(%s=*)", f->attr);
		break;
	case LDAP_FILT_EQUALITY:
		PUT("(%s=%s)", f->attr, f->value);
		break;
	case LDAP_FILT_APPROX:
		PUT("(%s~=%s)", f->attr, f->value);
		break;
	case LDAP_FILT_GE:
		PUT("(%s>=%s)", f->attr, f->value);
		break;
	case LDAP_FILT_LE:
		PUT("(%s<=%s)", f->attr, f->value);
		break;
	case LDAP_FILT_SUBSTRINGS:
		PUT("(%s=", f->attr);
		if (f->initial != NULL)
			PUT("%s", f->initial);
		PUT("*");
		for (i = 0; i < f->nany; i++)
			PUT("%s*", f->any[i]);
		if (f->final != NULL)
			PUT("%s", f->final);
		PUT(")");
		break;
	default:
		PUT("(?)");
		break;
	}
#undef PUT
}

void
filter_describe(const ldap_filter *f, char *buf, size_t buflen)
{
	size_t off = 0;

	if (buflen == 0)
		return;
	buf[0] = '\0';
	describe(f, buf, buflen, &off);
	if (off >= buflen)
		(void)snprintf(buf + buflen - 4, 4, "...");
}

/*
 * Does this entry satisfy this filter?
 *
 * An attribute the entry does not have simply does not match, which is what
 * makes (!(objectClass=posixGroup)) select the users: LDAP has no undefined
 * third truth value here that would need reasoning about.
 */
int
filter_match(const ldap_filter *f, const ldap_entry *e)
{
	const ldap_attr *a;
	size_t i, j;

	switch (f->tag) {
	case LDAP_FILT_AND:
		/* An "and" of nothing is true, per RFC 4526. */
		for (i = 0; i < f->nsub; i++) {
			if (!filter_match(f->sub[i], e))
				return 0;
		}
		return 1;

	case LDAP_FILT_OR:
		/* An "or" of nothing is false, likewise. */
		for (i = 0; i < f->nsub; i++) {
			if (filter_match(f->sub[i], e))
				return 1;
		}
		return 0;

	case LDAP_FILT_NOT:
		return f->nsub == 1 && !filter_match(f->sub[0], e);

	case LDAP_FILT_PRESENT:
		return entry_find(e, f->attr) != NULL;

	default:
		break;
	}

	if ((a = entry_find(e, f->attr)) == NULL)
		return 0;

	for (j = 0; j < a->nvals; j++) {
		switch (f->tag) {
		case LDAP_FILT_EQUALITY:
		/*
		 * approxMatch has no defined semantics beyond "at least as
		 * permissive as equality", and a sounds-alike match over user
		 * names would be a surprising thing for a directory to do.
		 */
		case LDAP_FILT_APPROX:
			if (ci_eq(a->vals[j], f->value))
				return 1;
			break;
		case LDAP_FILT_SUBSTRINGS:
			if (match_substrings(f, a->vals[j]))
				return 1;
			break;
		case LDAP_FILT_GE:
			if (value_cmp(a->vals[j], f->value) >= 0)
				return 1;
			break;
		case LDAP_FILT_LE:
			if (value_cmp(a->vals[j], f->value) <= 0)
				return 1;
			break;
		default:
			return 0;
		}
	}
	return 0;
}
