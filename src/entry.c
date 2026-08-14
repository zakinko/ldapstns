/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Entries, attributes, and the distinguished name comparisons a search needs.
 *
 * An entry here is deliberately a plain bag of named string values rather than
 * anything that knows it describes a user or a group.  Everything that follows
 * - matching a filter, deciding whether an entry is in scope, choosing which
 * attributes to return - then works the same way for a user, a group, an
 * organisational unit and the root DSE, and none of it has a special case in
 * it.  Only snapshot.c knows what the attributes mean.
 */
#include <ctype.h>
#include <stdarg.h>

#include "ldapstns.h"

int
entry_init(ldap_entry *e, const char *dn)
{
	memset(e, 0, sizeof(*e));
	if ((e->dn = strdup(dn)) == NULL)
		return -1;
	if ((e->ndn = dn_normalise(dn)) == NULL) {
		free(e->dn);
		e->dn = NULL;
		return -1;
	}
	return 0;
}

/*
 * Attribute names are matched without regard to case, here and everywhere
 * else: LDAP attribute descriptions are case insensitive, and opendirectoryd
 * does not spell them the way this daemon does.
 */
static int
name_eq(const char *a, const char *b)
{
	while (*a != '\0' && *b != '\0') {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
		a++;
		b++;
	}
	return *a == *b;
}

const ldap_attr *
entry_find(const ldap_entry *e, const char *name)
{
	size_t i;

	for (i = 0; i < e->nattrs; i++) {
		if (name_eq(e->attrs[i].name, name))
			return &e->attrs[i];
	}
	return NULL;
}

/*
 * Append a value, to the named attribute if the entry already has it and to a
 * new one if it does not.
 *
 * Repeating an attribute is how LDAP expresses a set - objectClass and
 * memberUid both arrive that way - so this is the normal path, not a special
 * case.
 */
int
entry_add(ldap_entry *e, const char *name, const char *value)
{
	ldap_attr *a = NULL, *grown;
	char **vals, *copy;
	size_t i;

	for (i = 0; i < e->nattrs; i++) {
		if (name_eq(e->attrs[i].name, name)) {
			a = &e->attrs[i];
			break;
		}
	}

	if (a == NULL) {
		if ((grown = realloc(e->attrs, (e->nattrs + 1) * sizeof(*grown))) == NULL)
			return -1;
		e->attrs = grown;
		a = &e->attrs[e->nattrs];
		memset(a, 0, sizeof(*a));
		if ((a->name = strdup(name)) == NULL)
			return -1;
		e->nattrs++;
	}

	if ((copy = strdup(value)) == NULL)
		return -1;
	if ((vals = realloc(a->vals, (a->nvals + 1) * sizeof(*vals))) == NULL) {
		free(copy);
		return -1;
	}
	a->vals = vals;
	a->vals[a->nvals++] = copy;
	return 0;
}

int
entry_addf(ldap_entry *e, const char *name, const char *fmt, ...)
{
	char buf[STNS_MAXBUF];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(buf))
		return -1;
	return entry_add(e, name, buf);
}

void
entry_free_contents(ldap_entry *e)
{
	size_t i, j;

	for (i = 0; i < e->nattrs; i++) {
		for (j = 0; j < e->attrs[i].nvals; j++)
			free(e->attrs[i].vals[j]);
		free(e->attrs[i].vals);
		free(e->attrs[i].name);
	}
	free(e->attrs);
	free(e->ndn);
	free(e->dn);
	memset(e, 0, sizeof(*e));
}

/*
 * Reduce a DN to a form two of them can be compared with strcmp(3).
 *
 * The parts of RFC 4514 that matter in practice are that a DN is case
 * insensitive and that whitespace around the ',' and '=' separators is not
 * significant: opendirectoryd may well ask for "DC=stns" or "cn=users, dc=stns"
 * for a suffix this daemon spells "dc=stns", and all three name the same thing.
 * Space inside a value is kept, because there it is significant.
 *
 * Escaping is not handled - a DN containing "\," is left alone and simply will
 * not match.  Nothing this daemon generates can contain one: every DN it
 * builds is made from a name that stns_is_valid_name() has already restricted
 * to letters, digits, '-', '_' and '.'.  A client asking about an escaped DN is
 * asking about an entry that does not exist here.
 */
char *
dn_normalise(const char *dn)
{
	const char *p;
	char *out, *q;
	int prev_sep = 1; /* the start of the string behaves like a separator */

	if ((out = malloc(strlen(dn) + 1)) == NULL)
		return NULL;

	q = out;
	for (p = dn; *p != '\0'; p++) {
		if (*p == ' ' || *p == '\t') {
			const char *n;

			/* Drop it if it follows a separator ... */
			if (prev_sep)
				continue;
			/* ... or if the next thing along is one. */
			for (n = p; *n == ' ' || *n == '\t'; n++)
				;
			if (*n == '\0' || *n == ',' || *n == '=')
				continue;
			*q++ = ' ';
			continue;
		}
		*q++ = (char)tolower((unsigned char)*p);
		prev_sep = (*p == ',' || *p == '=');
	}
	*q = '\0';
	return out;
}

/*
 * Is ndn one level below nbase?
 *
 * The empty base is the root of the tree, whose children are the entries with
 * no comma in them at all - which is to say the suffix itself.
 */
int
dn_is_child_of(const char *ndn, const char *nbase)
{
	const char *comma = strchr(ndn, ',');

	if (*nbase == '\0')
		return comma == NULL && *ndn != '\0';
	if (comma == NULL)
		return 0;
	return strcmp(comma + 1, nbase) == 0;
}

/* Is ndn at or below nbase?  Everything is at or below the empty base. */
int
dn_in_subtree(const char *ndn, const char *nbase)
{
	size_t dl, bl;

	if (*nbase == '\0')
		return 1;

	dl = strlen(ndn);
	bl = strlen(nbase);
	if (dl == bl)
		return strcmp(ndn, nbase) == 0;
	if (dl > bl)
		return ndn[dl - bl - 1] == ',' && strcmp(ndn + dl - bl, nbase) == 0;
	return 0;
}
