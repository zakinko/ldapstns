/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Turning the STNS directory into the LDAP entries that will be served.
 *
 * This runs on a timer in the parent process, never while a client is waiting:
 * a search is answered by a forked child out of the entries it inherited, so
 * the cost of an HTTP round trip and of building a few hundred entries is paid
 * once an interval rather than once per getpwnam(3) on the machine.
 *
 * Which attributes to emit is not a design decision.  macOS maps LDAP onto its
 * own record types with /System/Library/OpenDirectory/Mappings/RFC2307.plist,
 * and that file is the specification this has to meet:
 *
 *	Users	Object Classes: posixAccount, inetOrgPerson, shadowAccount
 *		(combined with OR), Search Base "%!"
 *		RecordName -> uid		UniqueID   -> uidNumber
 *		RealName   -> cn		PrimaryGroupID -> gidNumber
 *		NFSHomeDirectory -> homeDirectory
 *		UserShell  -> loginShell	Password   -> userPassword
 *		Comment    -> description
 *
 *	Groups	Object Classes: posixGroup
 *		RecordName -> cn		PrimaryGroupID -> gidNumber
 *		Member, GroupMembership -> memberUid
 *
 * Two consequences of that file are worth spelling out.
 *
 * The search base is "%!", which means opendirectoryd does not have one
 * configured: it reads namingContexts from the root DSE and uses that.  So the
 * root DSE is not decoration here, it is what makes the whole thing discover
 * itself, and it is built first below.
 *
 * And there is no mapping for GeneratedUID, so nothing needs to supply one:
 * macOS derives the record's UUID from the id, as FFFFEEEE-DDDD-CCCC-BBBB-AAAA
 * followed by the uid in hex for a user and ABCDEFAB-CDEF-ABCD-EFAB-CDEF
 * followed by the gid for a group.  That is the same scheme its own local
 * records below uid 500 use, and it means a user has the same UUID on every
 * machine that resolves them here without this daemon inventing one.
 */
#include <time.h>

#include "ldapstns.h"

/*
 * Grow the entry array by one and initialise the new entry's DN.
 *
 * The array is sized exactly once by the caller, so this never actually
 * reallocates; it is written as a growable list anyway because getting the
 * count wrong would otherwise be a buffer overflow rather than a wasted
 * realloc.
 */
static ldap_entry *
add_entry(snapshot *s, const char *dn)
{
	ldap_entry *grown;

	if ((grown = realloc(s->entries, (s->nentries + 1) * sizeof(*grown))) == NULL)
		return NULL;
	s->entries = grown;
	if (entry_init(&s->entries[s->nentries], dn) != 0)
		return NULL;
	return &s->entries[s->nentries++];
}

/*
 * The objectClass that goes with the attribute a suffix begins with.
 *
 * "dc=stns" is a domain, "o=example" an organization, and so on.  A client
 * that asks for the suffix entry by name gets something structurally sensible
 * back rather than a bare "top"; nothing in the macOS path depends on it, but
 * ldapsearch(1) and Directory Utility both show it to whoever is debugging.
 */
static const char *
suffix_class(const char *rdn_attr)
{
	if (strcasecmp(rdn_attr, "dc") == 0)
		return "domain";
	if (strcasecmp(rdn_attr, "o") == 0)
		return "organization";
	if (strcasecmp(rdn_attr, "ou") == 0)
		return "organizationalUnit";
	if (strcasecmp(rdn_attr, "cn") == 0)
		return "container";
	return "top";
}

/*
 * The root DSE: the entry with an empty DN that a client reads before it knows
 * anything else about the server.  opendirectoryd reads namingContexts from
 * here because RFC2307.plist leaves its search base as "%!".
 */
static int
build_rootdse(snapshot *s, const ldapstns_conf *c)
{
	ldap_entry *e;

	if ((e = add_entry(s, "")) == NULL)
		return -1;
	if (entry_add(e, "objectClass", "top") != 0 || entry_add(e, "objectClass", "OpenLDAProotDSE") != 0)
		return -1;
	if (entry_add(e, "namingContexts", c->suffix) != 0)
		return -1;
	if (entry_add(e, "supportedLDAPVersion", "3") != 0)
		return -1;
	if (entry_add(e, "vendorName", "ldapstns") != 0)
		return -1;
	if (entry_add(e, "vendorVersion", LDAPSTNS_VERSION) != 0)
		return -1;
	/*
	 * Neither an alternative server nor any SASL mechanism, said explicitly.
	 * A client that finds the attribute absent may go looking; one that
	 * finds it empty knows the answer.
	 */
	if (entry_add(e, "supportedSASLMechanisms", "") != 0)
		return -1;
	return 0;
}

/* The suffix, and the two organisational units the records hang under. */
static int
build_skeleton(snapshot *s, const ldapstns_conf *c)
{
	char dn[STNS_MAXBUF];
	char rdn_attr[64];
	const char *eq, *comma;
	ldap_entry *e;
	size_t n;

	if ((e = add_entry(s, c->suffix)) == NULL)
		return -1;

	/* Split the first RDN of the suffix into its attribute and its value. */
	if ((eq = strchr(c->suffix, '=')) == NULL)
		return -1;
	n = (size_t)(eq - c->suffix);
	if (n == 0 || n >= sizeof(rdn_attr))
		return -1;
	memcpy(rdn_attr, c->suffix, n);
	rdn_attr[n] = '\0';

	if ((comma = strchr(eq + 1, ',')) != NULL) {
		char value[STNS_MAXBUF];

		n = (size_t)(comma - (eq + 1));
		if (n >= sizeof(value))
			return -1;
		memcpy(value, eq + 1, n);
		value[n] = '\0';
		if (entry_add(e, rdn_attr, value) != 0)
			return -1;
	} else if (entry_add(e, rdn_attr, eq + 1) != 0) {
		return -1;
	}

	if (entry_add(e, "objectClass", "top") != 0)
		return -1;
	if (entry_add(e, "objectClass", suffix_class(rdn_attr)) != 0)
		return -1;

	/*
	 * cn=users and cn=groups, which is where the Open Directory mapping
	 * looks, and containers rather than organizational units for the same
	 * reason: that is what an Open Directory server has.
	 */
	if (snprintf(dn, sizeof(dn), "cn=users,%s", c->suffix) >= (int)sizeof(dn))
		return -1;
	if ((e = add_entry(s, dn)) == NULL)
		return -1;
	if (entry_add(e, "objectClass", "top") != 0 || entry_add(e, "objectClass", "container") != 0 ||
	    entry_add(e, "cn", "users") != 0)
		return -1;

	if (snprintf(dn, sizeof(dn), "cn=groups,%s", c->suffix) >= (int)sizeof(dn))
		return -1;
	if ((e = add_entry(s, dn)) == NULL)
		return -1;
	if (entry_add(e, "objectClass", "top") != 0 || entry_add(e, "objectClass", "container") != 0 ||
	    entry_add(e, "cn", "groups") != 0)
		return -1;

	return 0;
}

static int
build_user(snapshot *s, const ldapstns_conf *c, const stns_user_t *u)
{
	char dn[STNS_MAXBUF];
	ldap_entry *e;
	size_t i;

	if (snprintf(dn, sizeof(dn), "uid=%s,cn=users,%s", u->name, c->suffix) >= (int)sizeof(dn))
		return -1;
	if ((e = add_entry(s, dn)) == NULL)
		return -1;

	/*
	 * Every class either mapping asks for, plus the superclasses
	 * inetOrgPerson is defined in terms of.
	 *
	 * The Open Directory mapping combines its five with AND, so all five
	 * have to be present or nothing matches at all; the RFC2307 one
	 * combines three of them with OR, and those three are among the five.
	 * The superclasses are for a client that checks the chain, and for
	 * anybody reading the entry in ldapsearch(1).
	 */
	if (entry_add(e, "objectClass", "top") != 0 || entry_add(e, "objectClass", "person") != 0 ||
	    entry_add(e, "objectClass", "organizationalPerson") != 0 ||
	    entry_add(e, "objectClass", "inetOrgPerson") != 0 || entry_add(e, "objectClass", "posixAccount") != 0 ||
	    entry_add(e, "objectClass", "shadowAccount") != 0 || entry_add(e, "objectClass", "apple-user") != 0 ||
	    entry_add(e, "objectClass", "extensibleObject") != 0)
		return -1;

	/*
	 * The UUID macOS would give a local record with this id.
	 *
	 * The Open Directory mapping reads GeneratedUID from here and the
	 * RFC2307 one does not map it at all - in which case macOS derives
	 * exactly this value for itself.  Emitting it means the answer is the
	 * same either way, and the same as it would be for a local account.
	 */
	if (entry_addf(e, "apple-generateduid", "FFFFEEEE-DDDD-CCCC-BBBB-AAAA%08lX", (unsigned long)u->uid) != 0)
		return -1;
	/* ldapPublicKey is what says sshPublicKey below is meant to be there. */
	if (u->keys_size > 0 && entry_add(e, "objectClass", "ldapPublicKey") != 0)
		return -1;

	if (entry_add(e, "uid", u->name) != 0)
		return -1;
	/*
	 * cn is RealName and is what shows up wherever macOS displays a person,
	 * so an empty gecos has to fall back to the account name rather than
	 * leaving the field blank.  sn is required by inetOrgPerson and has
	 * nothing in STNS to come from; the account name is the honest answer.
	 */
	if (entry_add(e, "cn", (*u->gecos != '\0') ? u->gecos : u->name) != 0)
		return -1;
	if (entry_add(e, "sn", u->name) != 0)
		return -1;
	if (*u->gecos != '\0') {
		if (entry_add(e, "gecos", u->gecos) != 0 || entry_add(e, "description", u->gecos) != 0)
			return -1;
	}
	if (entry_addf(e, "uidNumber", "%lu", (unsigned long)u->uid) != 0)
		return -1;
	if (entry_addf(e, "gidNumber", "%lu", (unsigned long)u->gid) != 0)
		return -1;
	if (entry_add(e, "homeDirectory", u->directory) != 0)
		return -1;
	if (entry_add(e, "loginShell", u->shell) != 0)
		return -1;

	for (i = 0; i < u->keys_size; i++) {
		if (entry_add(e, "sshPublicKey", u->keys[i]) != 0)
			return -1;
	}

	/*
	 * The password hash is withheld unless it has been asked for.
	 *
	 * This daemon listens on the loopback interface, so every process on
	 * the machine can reach it; serving the hashes to an anonymous bind
	 * would be a world readable /etc/master.passwd with extra steps.  When
	 * expose_password is on, conf.c has already refused to start without a
	 * bind_dn, and ldap.c answers nothing at all to a session that has not
	 * bound as it - so the hash is only ever on the wire to a client that
	 * proved it knew a secret.
	 */
	if (c->expose_password && entry_add(e, "userPassword", u->password) != 0)
		return -1;

	return 0;
}

static int
build_group(snapshot *s, const ldapstns_conf *c, const stns_group_t *g)
{
	char dn[STNS_MAXBUF];
	ldap_entry *e;
	size_t i;

	if (snprintf(dn, sizeof(dn), "cn=%s,cn=groups,%s", g->name, c->suffix) >= (int)sizeof(dn))
		return -1;
	if ((e = add_entry(s, dn)) == NULL)
		return -1;

	/* posixGroup alone satisfies RFC2307; the Open Directory mapping wants all three. */
	if (entry_add(e, "objectClass", "top") != 0 || entry_add(e, "objectClass", "posixGroup") != 0 ||
	    entry_add(e, "objectClass", "apple-group") != 0 ||
	    entry_add(e, "objectClass", "extensibleObject") != 0)
		return -1;
	if (entry_add(e, "cn", g->name) != 0)
		return -1;
	/* RealName, which the Open Directory mapping takes from here rather than cn. */
	if (entry_add(e, "apple-group-realname", g->name) != 0)
		return -1;
	if (entry_addf(e, "apple-generateduid", "ABCDEFAB-CDEF-ABCD-EFAB-CDEF%08lX", (unsigned long)g->gid) != 0)
		return -1;
	if (entry_addf(e, "gidNumber", "%lu", (unsigned long)g->gid) != 0)
		return -1;

	for (i = 0; i < g->users_size; i++) {
		if (entry_add(e, "memberUid", g->users[i]) != 0)
			return -1;
	}

	return 0;
}

void
snapshot_free(snapshot *s)
{
	size_t i;

	for (i = 0; i < s->nentries; i++)
		entry_free_contents(&s->entries[i]);
	free(s->entries);
	memset(s, 0, sizeof(*s));
}

/*
 * Rebuild the snapshot from the API.
 *
 * On failure the caller's snapshot is left exactly as it was.  That is the
 * important part: an API server that is down or slow must not empty the
 * directory out from under everybody logged in.  Serving entries that are an
 * interval or two stale is a far better failure than serving none, and the
 * refresh will simply succeed the next time round.
 */
int
snapshot_refresh(stns_conf_t *sc, const ldapstns_conf *c, snapshot *s)
{
	snapshot fresh;
	stns_user_t *users = NULL;
	stns_group_t *groups = NULL;
	size_t nusers = 0, ngroups = 0, i;
	int rv = -1;

	memset(&fresh, 0, sizeof(fresh));

	if (stns_list_users(sc, &users, &nusers) != STNS_LOOKUP_SUCCESS) {
		logit(LOG_ERR, "cannot list users; keeping the previous snapshot");
		return -1;
	}
	if (stns_list_groups(sc, &groups, &ngroups) != STNS_LOOKUP_SUCCESS) {
		logit(LOG_ERR, "cannot list groups; keeping the previous snapshot");
		stns_free_users(users, nusers);
		return -1;
	}

	if (build_rootdse(&fresh, c) != 0 || build_skeleton(&fresh, c) != 0)
		goto done;
	for (i = 0; i < nusers; i++) {
		if (build_user(&fresh, c, &users[i]) != 0)
			goto done;
	}
	for (i = 0; i < ngroups; i++) {
		if (build_group(&fresh, c, &groups[i]) != 0)
			goto done;
	}

	fresh.taken = time(NULL);
	snapshot_free(s);
	*s = fresh;
	memset(&fresh, 0, sizeof(fresh));
	rv = 0;

	logit(LOG_INFO, "refreshed: %lu users, %lu groups, %lu entries", (unsigned long)nusers,
	    (unsigned long)ngroups, (unsigned long)s->nentries);

done:
	if (rv != 0)
		logit(LOG_ERR, "out of memory building the snapshot; keeping the previous one");
	snapshot_free(&fresh);
	stns_free_users(users, nusers);
	stns_free_groups(groups, ngroups);
	return rv;
}
