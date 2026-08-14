/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The whole directory at once, into memory the library allocates.
 *
 * stns_lookup.c answers one question at a time and writes into a buffer the
 * caller sized, which is what libc asks a name service backend for.  A daemon
 * needs the opposite: it is asked its questions by a client that is waiting on
 * a socket, so it cannot afford an HTTP round trip per question, and it holds
 * a snapshot of the directory and refreshes it on a timer instead.  ypstns and
 * ldapstns both do exactly that, and both take the snapshot from here.
 *
 * Two things this does that stns_fill_passwd() cannot, and which are the whole
 * reason the record structs exist:
 *
 *   - it keeps the password hash as the server sent it.  struct passwd is
 *     filled for an arbitrary process, so it masks the hash unless the caller
 *     is root; a snapshot is held by a daemon that already runs as root and
 *     has to be able to put the hash in a master.passwd map.  Which means the
 *     consumer, not the library, decides who is allowed to see it - ldapstns
 *     withholds userPassword, ypstns serves master.passwd.byname only to a
 *     reserved port, and both of those are decisions this file must not make
 *     for them.
 *
 *   - it keeps the SSH public keys, which struct passwd has nowhere to put.
 *
 * Everything else the consumers would otherwise each have to redo is done
 * here: the configured uid_shift and gid_shift are already applied to uid and
 * gid, and an empty shell or home directory has already fallen back to its
 * default.  What comes out needs no further interpretation.
 */
#include <errno.h>

#include "stns.h"

/*
 * strdup(3) that turns an absent field into an empty string rather than a NULL
 * pointer.
 *
 * Every consumer of these records formats them into a text protocol - a YP map
 * line, an LDAP attribute value - and a NULL there is a crash, not a blank.
 * Absent and empty mean the same thing to all of them, so collapse the two
 * here once instead of at every use.
 */
static char *
dup_field(const char *s)
{
	size_t len;
	char *p;

	if (s == NULL)
		s = "";
	len = strlen(s) + 1;
	if ((p = malloc(len)) == NULL)
		return NULL;
	memcpy(p, s, len);
	return p;
}

/*
 * Copy a JSON array of strings into a NULL free char * array.
 *
 * Elements that are not strings are dropped rather than stored as NULL: the
 * count and the array have to agree, because unlike gr_mem there is no
 * terminator here for a caller to trip over instead.
 */
static int
dup_strings(JSON_Array *arr, char ***outp, size_t *countp)
{
	char **out;
	size_t i, n, kept;

	*outp = NULL;
	*countp = 0;

	n = (arr != NULL) ? json_array_get_count(arr) : 0;
	if (n == 0)
		return STNS_OK;

	if ((out = calloc(n, sizeof(*out))) == NULL)
		return STNS_NG;

	for (i = 0, kept = 0; i < n; i++) {
		const char *s = json_array_get_string(arr, i);

		if (s == NULL)
			continue;
		if ((out[kept] = dup_field(s)) == NULL) {
			while (kept > 0)
				free(out[--kept]);
			free(out);
			return STNS_NG;
		}
		kept++;
	}

	*outp = out;
	*countp = kept;
	return STNS_OK;
}

static void
free_strings(char **v, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

/*
 * Fill one user record from one JSON object.
 *
 * A record without a name, an id or a group id is refused the same way
 * stns_fill_passwd() refuses it: it is skipped, and the rest of the listing is
 * still perfectly good.  Refusing the whole snapshot over one bad record would
 * mean a single malformed entry could lock every user out of the machine.
 */
static int
fill_user(JSON_Object *o, stns_conf_t *c, stns_user_t *u)
{
	char home[STNS_MAXBUF];
	const char *name, *shell, *dir, *password;
	int id, group_id;

	name = stns_json_str(o, "name");
	id = stns_json_int(o, "id");
	group_id = stns_json_int(o, "group_id");
	if (name == NULL || id < 0 || group_id < 0)
		return STNS_NG;

	shell = stns_json_str(o, "shell");
	if (shell == NULL || *shell == '\0')
		shell = STNS_DEFAULT_SHELL;

	dir = stns_json_str(o, "directory");
	if (dir == NULL || *dir == '\0') {
		(void)snprintf(home, sizeof(home), "%s/%s", STNS_DEFAULT_HOME_PREFIX, name);
		dir = home;
	}

	/*
	 * A locked account is the safe default.  An empty password field in a
	 * passwd line means "no password required", so an entry the server sent
	 * without one must come out as "*" and not as "".
	 */
	password = stns_json_str(o, "password");
	if (password == NULL || *password == '\0')
		password = "*";

	u->uid = (uid_t)(c->uid_shift + id);
	u->gid = (gid_t)(c->gid_shift + group_id);
	u->name = dup_field(name);
	u->password = dup_field(password);
	u->gecos = dup_field(stns_json_str(o, "gecos"));
	u->directory = dup_field(dir);
	u->shell = dup_field(shell);

	if (u->name == NULL || u->password == NULL || u->gecos == NULL || u->directory == NULL || u->shell == NULL)
		return STNS_NG;
	if (dup_strings(json_object_get_array(o, "keys"), &u->keys, &u->keys_size) != STNS_OK)
		return STNS_NG;

	return STNS_OK;
}

static int
fill_group(JSON_Object *o, stns_conf_t *c, stns_group_t *g)
{
	const char *name;
	int id;

	name = stns_json_str(o, "name");
	id = stns_json_int(o, "id");
	if (name == NULL || id < 0)
		return STNS_NG;

	g->gid = (gid_t)(c->gid_shift + id);
	if ((g->name = dup_field(name)) == NULL)
		return STNS_NG;
	if (dup_strings(json_object_get_array(o, "users"), &g->users, &g->users_size) != STNS_OK)
		return STNS_NG;

	return STNS_OK;
}

/*
 * Releasing one record's fields and releasing an array of records are
 * deliberately two different operations.
 *
 * A record that lives inside a calloc()ed array must never be handed to
 * free(3) on its own, and both the listing loop below and stns_user_by_name()
 * need to discard individual records out of an array they are still holding.
 * Only the public functions, which own the array, free the array.
 */
static void
free_user_fields(stns_user_t *u)
{
	free(u->name);
	free(u->password);
	free(u->gecos);
	free(u->directory);
	free(u->shell);
	free_strings(u->keys, u->keys_size);
}

static void
free_group_fields(stns_group_t *g)
{
	free(g->name);
	free_strings(g->users, g->users_size);
}

void
stns_free_users(stns_user_t *users, size_t n)
{
	size_t i;

	if (users == NULL)
		return;
	for (i = 0; i < n; i++)
		free_user_fields(&users[i]);
	free(users);
}

void
stns_free_groups(stns_group_t *groups, size_t n)
{
	size_t i;

	if (groups == NULL)
		return;
	for (i = 0; i < n; i++)
		free_group_fields(&groups[i]);
	free(groups);
}

/*
 * The body both listing calls share.
 *
 * The array is allocated once at the JSON array's length and then filled with
 * however many records survive; that over-allocates by the number of malformed
 * entries, which is nearly always none and never enough to be worth a second
 * pass or a realloc.  A record that fails to convert because we ran out of
 * memory, rather than because the server sent nonsense, is indistinguishable
 * here - so the count is checked afterwards by the callers that care, and in
 * either case what is returned is internally consistent.
 */
static int
list(stns_conf_t *c, const char *path, void **vp, size_t *np, size_t size,
    int (*fill)(JSON_Object *, stns_conf_t *, void *), void (*freefields)(void *))
{
	JSON_Value *root;
	JSON_Array *arr;
	char *v;
	size_t i, n, kept;
	int rv;

	*vp = NULL;
	*np = 0;

	if ((rv = stns_fetch(c, path, &root)) != STNS_LOOKUP_SUCCESS)
		return rv;

	arr = json_value_get_array(root);
	n = json_array_get_count(arr);
	if (n == 0) {
		json_value_free(root);
		return STNS_LOOKUP_SUCCESS;
	}

	if ((v = calloc(n, size)) == NULL) {
		json_value_free(root);
		return STNS_LOOKUP_UNAVAIL;
	}

	for (i = 0, kept = 0; i < n; i++) {
		JSON_Object *o = json_array_get_object(arr, i);

		if (o == NULL)
			continue;
		if (fill(o, c, v + kept * size) != STNS_OK) {
			/*
			 * fill() may have got several fields in before it gave
			 * up, so release them, and zero the slot so that the
			 * next record starts from a clean one.  The slot itself
			 * belongs to the array and is not freed.
			 */
			freefields(v + kept * size);
			memset(v + kept * size, 0, size);
			continue;
		}
		kept++;
	}

	json_value_free(root);
	*vp = v;
	*np = kept;
	return STNS_LOOKUP_SUCCESS;
}

/* The four thunks exist only to get the concrete types past list()'s void *. */
static int
fill_user_thunk(JSON_Object *o, stns_conf_t *c, void *p)
{
	return fill_user(o, c, p);
}

static int
fill_group_thunk(JSON_Object *o, stns_conf_t *c, void *p)
{
	return fill_group(o, c, p);
}

static void
free_user_fields_thunk(void *p)
{
	free_user_fields(p);
}

static void
free_group_fields_thunk(void *p)
{
	free_group_fields(p);
}

int
stns_list_users(stns_conf_t *c, stns_user_t **users, size_t *n)
{
	return list(c, "users", (void **)users, n, sizeof(**users), fill_user_thunk, free_user_fields_thunk);
}

int
stns_list_groups(stns_conf_t *c, stns_group_t **groups, size_t *n)
{
	return list(c, "groups", (void **)groups, n, sizeof(**groups), fill_group_thunk, free_group_fields_thunk);
}

/*
 * One user by name.
 *
 * The server answers a name query with an array, and a stale or over-eager
 * server could return neighbours in it, so the key is checked again here for
 * the same reason stns_pw_by_name() checks it.  Anything that is not an exact
 * match is not the record that was asked for.
 */
int
stns_user_by_name(stns_conf_t *c, const char *name, stns_user_t **user)
{
	char path[STNS_MAXBUF];
	stns_user_t *v;
	size_t i, j, n;
	int rv;

	*user = NULL;

	if (!stns_is_valid_name(name))
		return STNS_LOOKUP_NOTFOUND;

	(void)snprintf(path, sizeof(path), "users?name=%s", name);
	rv = list(c, path, (void **)&v, &n, sizeof(*v), fill_user_thunk, free_user_fields_thunk);
	if (rv != STNS_LOOKUP_SUCCESS)
		return rv;

	for (i = 0; i < n; i++) {
		if (strcmp(v[i].name, name) != 0)
			continue;
		/*
		 * Keep the allocation and move the match into its first slot,
		 * rather than copying the record out and freeing the rest.  The
		 * caller releases what it gets with a count of one, so every
		 * other slot's fields have to go now - but the array itself is
		 * a single allocation and only its base may ever be freed.
		 */
		if (i != 0) {
			stns_user_t tmp = v[0];

			v[0] = v[i];
			v[i] = tmp;
		}
		for (j = 1; j < n; j++)
			free_user_fields(&v[j]);
		*user = v;
		return STNS_LOOKUP_SUCCESS;
	}

	stns_free_users(v, n);
	return STNS_LOOKUP_NOTFOUND;
}

/* One group by name; see stns_user_by_name() for why the key is rechecked. */
int
stns_group_by_name(stns_conf_t *c, const char *name, stns_group_t **group)
{
	char path[STNS_MAXBUF];
	stns_group_t *v;
	size_t i, j, n;
	int rv;

	*group = NULL;

	if (!stns_is_valid_name(name))
		return STNS_LOOKUP_NOTFOUND;

	(void)snprintf(path, sizeof(path), "groups?name=%s", name);
	rv = list(c, path, (void **)&v, &n, sizeof(*v), fill_group_thunk, free_group_fields_thunk);
	if (rv != STNS_LOOKUP_SUCCESS)
		return rv;

	for (i = 0; i < n; i++) {
		if (strcmp(v[i].name, name) != 0)
			continue;
		if (i != 0) {
			stns_group_t tmp = v[0];

			v[0] = v[i];
			v[i] = tmp;
		}
		for (j = 1; j < n; j++)
			free_group_fields(&v[j]);
		*group = v;
		return STNS_LOOKUP_SUCCESS;
	}

	stns_free_groups(v, n);
	return STNS_LOOKUP_NOTFOUND;
}
