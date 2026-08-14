/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Lookups of a single name or id, in the shape libc's reentrant interfaces
 * want: the answer written into a buffer the caller supplied and sized.
 *
 * Everything here speaks enum stns_status and knows nothing about how any
 * particular system dispatches a name lookup.  On NetBSD, FreeBSD and
 * DragonFly that translation is nss_stns's job; OpenBSD and macOS have no such
 * dispatch to translate for, which is why ypstns and ldapstns exist and why
 * they use stns_list.c rather than this file.
 */
#include <errno.h>

#include "stns.h"

static pthread_mutex_t pw_mutex = PTHREAD_MUTEX_INITIALIZER;
static JSON_Value *pw_entries;
static size_t pw_index;

static pthread_mutex_t gr_mutex = PTHREAD_MUTEX_INITIALIZER;
static JSON_Value *gr_entries;
static size_t gr_index;

/*
 * Perform a request and hand back the parsed JSON array.  The API always
 * answers with an array, even for a single name lookup.
 */
int
stns_fetch(stns_conf_t *c, const char *path, JSON_Value **rootp)
{
	stns_response_t r;
	JSON_Value *root;

	if (stns_request(c, path, &r) != STNS_OK) {
		free(r.data);
		return (r.status_code == STNS_HTTP_NOTFOUND) ? STNS_LOOKUP_NOTFOUND : STNS_LOOKUP_UNAVAIL;
	}

	root = json_parse_string(r.data);
	free(r.data);
	if (root == NULL) {
		syslog(LOG_ERR, STNS_PRODUCT ": cannot parse the response to /%s", path);
		return STNS_LOOKUP_UNAVAIL;
	}
	if (json_value_get_array(root) == NULL) {
		syslog(LOG_ERR, STNS_PRODUCT ": unexpected response shape for /%s", path);
		json_value_free(root);
		return STNS_LOOKUP_UNAVAIL;
	}

	*rootp = root;
	return STNS_LOOKUP_SUCCESS;
}

/*
 * A query by name is answered server side, but a stale or over-eager server
 * could still return neighbours; re-check the key before believing an entry.
 */
int
stns_pw_by_name(stns_conf_t *c, const char *name, struct passwd *pwd, char *buf, size_t buflen, int *errnop)
{
	char path[STNS_MAXBUF];
	JSON_Value *root;
	JSON_Array *arr;
	size_t i, n;
	int rv;

	if (!stns_is_valid_name(name))
		return STNS_LOOKUP_NOTFOUND;

	(void)snprintf(path, sizeof(path), "users?name=%s", name);
	if ((rv = stns_fetch(c, path, &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(root);
	n = json_array_get_count(arr);
	rv = STNS_LOOKUP_NOTFOUND;

	for (i = 0; i < n; i++) {
		JSON_Object *o = json_array_get_object(arr, i);
		const char *found;

		if (o == NULL)
			continue;
		if ((found = stns_json_str(o, "name")) == NULL || strcmp(found, name) != 0)
			continue;
		rv = stns_fill_passwd(o, c, pwd, buf, buflen, errnop);
		break;
	}

	json_value_free(root);
	return rv;
}

/*
 * Look a user up by uid.  uid_shift moves the whole directory clear of the
 * local accounts, so it comes off the id on the way out and goes back on on
 * the way in; an id below the shift cannot be ours at all.
 */
int
stns_pw_by_uid(stns_conf_t *c, uid_t uid, struct passwd *pwd, char *buf, size_t buflen, int *errnop)
{
	char path[STNS_MAXBUF];
	JSON_Value *root;
	JSON_Array *arr;
	size_t i, n;
	int rv, id;

	if (!stns_user_id_queryable((int)uid))
		return STNS_LOOKUP_NOTFOUND;

	id = (int)uid - c->uid_shift;
	if (id < 0)
		return STNS_LOOKUP_NOTFOUND;

	(void)snprintf(path, sizeof(path), "users?id=%d", id);
	if ((rv = stns_fetch(c, path, &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(root);
	n = json_array_get_count(arr);
	rv = STNS_LOOKUP_NOTFOUND;

	for (i = 0; i < n; i++) {
		JSON_Object *o = json_array_get_object(arr, i);

		if (o == NULL || stns_json_int(o, "id") != id)
			continue;
		rv = stns_fill_passwd(o, c, pwd, buf, buflen, errnop);
		break;
	}

	json_value_free(root);
	return rv;
}

/* Look a group up by name; see stns_pw_by_name() for why the key is rechecked. */
int
stns_gr_by_name(stns_conf_t *c, const char *name, struct group *grp, char *buf, size_t buflen, int *errnop)
{
	char path[STNS_MAXBUF];
	JSON_Value *root;
	JSON_Array *arr;
	size_t i, n;
	int rv;

	if (!stns_is_valid_name(name))
		return STNS_LOOKUP_NOTFOUND;

	(void)snprintf(path, sizeof(path), "groups?name=%s", name);
	if ((rv = stns_fetch(c, path, &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(root);
	n = json_array_get_count(arr);
	rv = STNS_LOOKUP_NOTFOUND;

	for (i = 0; i < n; i++) {
		JSON_Object *o = json_array_get_object(arr, i);
		const char *found;

		if (o == NULL)
			continue;
		if ((found = stns_json_str(o, "name")) == NULL || strcmp(found, name) != 0)
			continue;
		rv = stns_fill_group(o, c, grp, buf, buflen, errnop);
		break;
	}

	json_value_free(root);
	return rv;
}

/* Look a group up by gid; see stns_pw_by_uid() for the shift handling. */
int
stns_gr_by_gid(stns_conf_t *c, gid_t gid, struct group *grp, char *buf, size_t buflen, int *errnop)
{
	char path[STNS_MAXBUF];
	JSON_Value *root;
	JSON_Array *arr;
	size_t i, n;
	int rv, id;

	if (!stns_group_id_queryable((int)gid))
		return STNS_LOOKUP_NOTFOUND;

	id = (int)gid - c->gid_shift;
	if (id < 0)
		return STNS_LOOKUP_NOTFOUND;

	(void)snprintf(path, sizeof(path), "groups?id=%d", id);
	if ((rv = stns_fetch(c, path, &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(root);
	n = json_array_get_count(arr);
	rv = STNS_LOOKUP_NOTFOUND;

	for (i = 0; i < n; i++) {
		JSON_Object *o = json_array_get_object(arr, i);

		if (o == NULL || stns_json_int(o, "id") != id)
			continue;
		rv = stns_fill_group(o, c, grp, buf, buflen, errnop);
		break;
	}

	json_value_free(root);
	return rv;
}

/*
 * Enumeration.  The whole list is fetched once, on the first get*ent_r(), and
 * walked from there, so a getent(1) run costs a single HTTP request.
 */
static int
ent_start(stns_conf_t *c, const char *path, JSON_Value **entries, size_t *index)
{
	JSON_Value *root;
	int rv;

	if ((rv = stns_fetch(c, path, &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	json_value_free(*entries);
	*entries = root;
	*index = 0;
	return STNS_LOOKUP_SUCCESS;
}

/*
 * Hand back the next entry, fetching the listing first if this is the start of
 * a pass.  An entry that fails to convert is skipped rather than ending the
 * enumeration, so one malformed record cannot hide every record after it.
 */
static int
ent_next(stns_conf_t *c, const char *path, JSON_Value **entries, size_t *index, void *rbuf, char *buf, size_t buflen,
    int *errnop, int (*fill)(JSON_Object *, stns_conf_t *, void *, char *, size_t, int *))
{
	JSON_Array *arr;
	JSON_Object *o;
	int rv;

	if (*entries == NULL && (rv = ent_start(c, path, entries, index)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(*entries);
	while (*index < json_array_get_count(arr)) {
		if ((o = json_array_get_object(arr, *index)) == NULL) {
			(*index)++;
			continue;
		}
		rv = fill(o, c, rbuf, buf, buflen, errnop);
		/*
		 * Hold our place when the buffer was too small: libc will come
		 * back for the very same entry with more room.
		 */
		if (rv == STNS_LOOKUP_ERANGE)
			return rv;
		(*index)++;
		if (rv == STNS_LOOKUP_SUCCESS)
			return STNS_LOOKUP_SUCCESS;
	}

	*errnop = ENOENT;
	return STNS_LOOKUP_NOTFOUND;
}

static int
fill_passwd_thunk(JSON_Object *o, stns_conf_t *c, void *rbuf, char *buf, size_t buflen, int *errnop)
{
	return stns_fill_passwd(o, c, rbuf, buf, buflen, errnop);
}

static int
fill_group_thunk(JSON_Object *o, stns_conf_t *c, void *rbuf, char *buf, size_t buflen, int *errnop)
{
	return stns_fill_group(o, c, rbuf, buf, buflen, errnop);
}

/*
 * set*ent() and end*ent() both just discard the iteration state.
 *
 * In particular set*ent() does not fetch anything: getent(1) and other callers
 * open the database before a plain getpwnam(3) too, so fetching here would
 * cost a full listing on every single-name lookup.  The first get*ent_r() does
 * the fetch instead, which is where the result is actually wanted.
 */
static int
ent_reset(pthread_mutex_t *mutex, JSON_Value **entries, size_t *index)
{
	if (stns_mutex_retrylock(mutex) != 0)
		return STNS_LOOKUP_UNAVAIL;
	json_value_free(*entries);
	*entries = NULL;
	*index = 0;
	(void)pthread_mutex_unlock(mutex);
	return STNS_LOOKUP_SUCCESS;
}

int
stns_pw_setent(void)
{
	return ent_reset(&pw_mutex, &pw_entries, &pw_index);
}

int
stns_pw_endent(void)
{
	return ent_reset(&pw_mutex, &pw_entries, &pw_index);
}

int
stns_pw_nextent(stns_conf_t *c, struct passwd *pwd, char *buf, size_t buflen, int *errnop)
{
	int rv;

	if (stns_mutex_retrylock(&pw_mutex) != 0)
		return STNS_LOOKUP_UNAVAIL;
	rv = ent_next(c, "users", &pw_entries, &pw_index, pwd, buf, buflen, errnop, fill_passwd_thunk);
	(void)pthread_mutex_unlock(&pw_mutex);
	return rv;
}

int
stns_gr_setent(void)
{
	return ent_reset(&gr_mutex, &gr_entries, &gr_index);
}

int
stns_gr_endent(void)
{
	return ent_reset(&gr_mutex, &gr_entries, &gr_index);
}

int
stns_gr_nextent(stns_conf_t *c, struct group *grp, char *buf, size_t buflen, int *errnop)
{
	int rv;

	if (stns_mutex_retrylock(&gr_mutex) != 0)
		return STNS_LOOKUP_UNAVAIL;
	rv = ent_next(c, "groups", &gr_entries, &gr_index, grp, buf, buflen, errnop, fill_group_thunk);
	(void)pthread_mutex_unlock(&gr_mutex);
	return rv;
}

/*
 * Same contract as NetBSD's __gr_addgid(): duplicates are skipped and *groupc
 * keeps counting past maxgrp so that the caller can learn how much room it
 * really needs.
 */
static int
add_gid(gid_t gid, gid_t *groups, int maxgrp, int *groupc)
{
	int i, limit;

	limit = (*groupc < maxgrp) ? *groupc : maxgrp;
	for (i = 0; i < limit; i++) {
		if (groups[i] == gid)
			return 1;
	}

	if (*groupc < maxgrp) {
		groups[*groupc] = gid;
		(*groupc)++;
		return 1;
	}
	(*groupc)++;
	return 0;
}

/*
 * Collect the groups a user belongs to, for getgrouplist(3) and initgroups(3).
 *
 * One request for the whole listing beats one request per group, and the
 * caller has already supplied the primary group to seed the list with.
 */
int
stns_gr_membership(stns_conf_t *c, const char *uname, gid_t agroup, gid_t *groups, int maxgrp, int *groupc)
{
	JSON_Value *root;
	JSON_Array *arr;
	size_t i, n;
	int rv;

	if (!stns_is_valid_name(uname))
		return STNS_LOOKUP_NOTFOUND;

	(void)add_gid(agroup, groups, maxgrp, groupc);

	if ((rv = stns_fetch(c, "groups", &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(root);
	n = json_array_get_count(arr);

	for (i = 0; i < n; i++) {
		JSON_Object *o = json_array_get_object(arr, i);
		JSON_Array *users;
		size_t j, m;
		int id;

		if (o == NULL || (id = stns_json_int(o, "id")) < 0)
			continue;
		if ((users = json_object_get_array(o, "users")) == NULL)
			continue;

		m = json_array_get_count(users);
		for (j = 0; j < m; j++) {
			const char *member = json_array_get_string(users, j);

			if (member != NULL && strcmp(member, uname) == 0) {
				(void)add_gid((gid_t)(c->gid_shift + id), groups, maxgrp, groupc);
				break;
			}
		}
	}

	json_value_free(root);

	/*
	 * Report STNS_LOOKUP_NOTFOUND even on success.  This mirrors what
	 * getgroupmembership(3) wants: it merges the result of every source, so
	 * an answer of "found" would stop the search and drop the local groups
	 * in /etc/group on the floor.
	 */
	return STNS_LOOKUP_NOTFOUND;
}
