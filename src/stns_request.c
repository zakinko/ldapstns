/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * HTTP transport, on-disk response cache and the circuit breaker that keeps a
 * dead STNS server from stalling every name lookup on the machine.
 *
 * Portions are derived from libnss (https://github.com/STNS/libnss),
 * Copyright (c) 2026 pyama86, distributed under the MIT license.
 */
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <curl/curl.h>

#include "stns.h"

static pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;
static int highest_user_id;
static int lowest_user_id;
static int highest_group_id;
static int lowest_group_id;

/*
 * Take a mutex, but give up rather than block forever.
 *
 * This code runs inside somebody else's process, and a caller that forked
 * while another thread held one of our mutexes would otherwise deadlock in a
 * name lookup.  Failing the lookup is the lesser evil.
 */
int
stns_mutex_retrylock(pthread_mutex_t *mutex)
{
	struct timespec ts;
	int i, ret;

	ts.tv_sec = STNS_LOCK_INTERVAL_MSEC / 1000;
	ts.tv_nsec = (STNS_LOCK_INTERVAL_MSEC % 1000) * 1000000L;

	for (i = 0;; i++) {
		ret = pthread_mutex_trylock(mutex);
		if (ret == 0 || i >= STNS_LOCK_RETRY)
			break;
		(void)nanosleep(&ts, NULL);
	}
	return ret;
}

#define STNS_ID_ACCESSOR(which, kind)                                                                                  \
	void stns_set_##kind##_##which##_id(int id)                                                                    \
	{                                                                                                              \
		if (stns_mutex_retrylock(&id_mutex) != 0)                                                              \
			return;                                                                                        \
		which##_##kind##_id = id;                                                                              \
		(void)pthread_mutex_unlock(&id_mutex);                                                                 \
	}                                                                                                              \
	static int get_##kind##_##which##_id(void)                                                                     \
	{                                                                                                              \
		int r;                                                                                                 \
		if (stns_mutex_retrylock(&id_mutex) != 0)                                                              \
			return 0;                                                                                      \
		r = which##_##kind##_id;                                                                               \
		(void)pthread_mutex_unlock(&id_mutex);                                                                 \
		return r;                                                                                              \
	}

STNS_ID_ACCESSOR(highest, user)
STNS_ID_ACCESSOR(lowest, user)
STNS_ID_ACCESSOR(highest, group)
STNS_ID_ACCESSOR(lowest, group)

/*
 * Is this id worth asking the server about?
 *
 * Zero means the range is not known yet, in which case everything is worth
 * asking about.  Once the server has told us, the answer is no for every id
 * outside its range - which is most of them, since the local accounts sit well
 * below it, and each one saved is a round trip a program does not wait for.
 */
int
stns_user_id_queryable(int id)
{
	int hi = get_user_highest_id();
	int lo = get_user_lowest_id();

	if (hi != 0 && hi < id)
		return 0;
	if (lo != 0 && lo > id)
		return 0;
	return 1;
}

int
stns_group_id_queryable(int id)
{
	int hi = get_group_highest_id();
	int lo = get_group_lowest_id();

	if (hi != 0 && hi < id)
		return 0;
	if (lo != 0 && lo > id)
		return 0;
	return 1;
}

/*
 * Is this a name we are willing to put in a query string?
 *
 * The character set is restricted deliberately: it is what lets the name be
 * interpolated into "users?name=%s" without percent encoding, and it is the
 * only thing standing between a crafted account name and an injected query
 * parameter.  A name that fails here is simply not ours, and is reported as
 * not found without any request being made at all.
 */
int
stns_is_valid_name(const char *name)
{
	size_t i, len;

	if (name == NULL)
		return 0;
	len = strnlen(name, STNS_MAX_NAME_LENGTH + 1);
	if (len == 0 || len > STNS_MAX_NAME_LENGTH)
		return 0;
	if (!isalpha((unsigned char)name[0]) && name[0] != '_')
		return 0;
	/*
	 * Restricting the character set is what lets us paste the name straight
	 * into a query string without percent encoding it.
	 */
	for (i = 1; i < len; i++) {
		if (!isalnum((unsigned char)name[i]) && name[i] != '-' && name[i] != '_' && name[i] != '.')
			return 0;
	}
	return 1;
}

/* Turn a request path into something safe to use as a cache file name. */
char *
stns_escape_path(const char *path)
{
	static const char hex[] = "0123456789ABCDEF";
	const unsigned char *p;
	char *out, *q;
	size_t len;

	if (path == NULL)
		return NULL;
	len = strlen(path);
	if (len > STNS_MAXBUF)
		return NULL;
	if ((out = malloc(len * 3 + 1)) == NULL)
		return NULL;

	for (p = (const unsigned char *)path, q = out; *p != '\0'; p++) {
		if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.') {
			*q++ = (char)*p;
		} else {
			*q++ = '%';
			*q++ = hex[(*p >> 4) & 0xf];
			*q++ = hex[*p & 0xf];
		}
	}
	*q = '\0';
	return out;
}

/*
 * libcurl write callback: append this chunk to the response body.
 *
 * Returning short aborts the transfer, which is what happens when the body
 * would grow past STNS_MAX_BUFFER_SIZE or an allocation fails.
 */
static size_t
response_callback(void *buffer, size_t size, size_t nmemb, void *userp)
{
	stns_response_t *res = userp;
	size_t segsize = size * nmemb;
	char *grown;

	if (res->size + segsize + 1 > STNS_MAX_BUFFER_SIZE) {
		syslog(LOG_ERR, STNS_PRODUCT ": response is too large");
		return 0;
	}
	if ((grown = realloc(res->data, res->size + segsize + 1)) == NULL)
		return 0;

	res->data = grown;
	memcpy(res->data + res->size, buffer, segsize);
	res->size += segsize;
	res->data[res->size] = '\0';
	return segsize;
}

/*
 * libcurl header callback: remember the id ranges the server advertises.
 *
 * Knowing the highest and lowest id the directory holds is what lets
 * stns_user_id_queryable() skip a request for an id the server could not
 * possibly own.
 */
static size_t
header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
	stns_conf_t *c = userdata;
	size_t len = size * nitems;
	char name[64];
	char value[32];
	size_t i, j;
	int id;

	for (i = 0; i < len && i < sizeof(name) - 1 && buffer[i] != ':'; i++)
		name[i] = buffer[i];
	if (i >= len || i >= sizeof(name) - 1)
		return len;
	name[i] = '\0';

	/*
	 * libcurl does not NUL terminate the header buffer, so the value has to
	 * be copied out before anything reads it as a string.
	 */
	for (i++; i < len && (buffer[i] == ' ' || buffer[i] == '\t'); i++)
		;
	for (j = 0; i < len && j < sizeof(value) - 1 && buffer[i] != '\r' && buffer[i] != '\n'; i++, j++)
		value[j] = buffer[i];
	value[j] = '\0';
	id = atoi(value);

	if (strcasecmp(name, "User-Highest-Id") == 0)
		stns_set_user_highest_id(id + c->uid_shift);
	else if (strcasecmp(name, "User-Lowest-Id") == 0)
		stns_set_user_lowest_id(id + c->uid_shift);
	else if (strcasecmp(name, "Group-Highest-Id") == 0)
		stns_set_group_highest_id(id + c->gid_shift);
	else if (strcasecmp(name, "Group-Lowest-Id") == 0)
		stns_set_group_lowest_id(id + c->gid_shift);

	return len;
}

/* Assemble the Authorization header and anything from [http_headers]. */
static struct curl_slist *
build_headers(stns_conf_t *c)
{
	struct curl_slist *headers = NULL, *tmp;
	char *line;
	size_t i, len;

	if (c->auth_token != NULL) {
		len = strlen(c->auth_token) + sizeof("Authorization: token ");
		if ((line = malloc(len)) == NULL)
			return headers;
		(void)snprintf(line, len, "Authorization: token %s", c->auth_token);
		if ((tmp = curl_slist_append(headers, line)) != NULL)
			headers = tmp;
		free(line);
	}

	for (i = 0; i < c->http_headers_size; i++) {
		if (c->http_headers[i].key == NULL || c->http_headers[i].value == NULL)
			continue;
		len = strlen(c->http_headers[i].key) + strlen(c->http_headers[i].value) + 3;
		if ((line = malloc(len)) == NULL)
			continue;
		(void)snprintf(line, len, "%s: %s", c->http_headers[i].key, c->http_headers[i].value);
		if ((tmp = curl_slist_append(headers, line)) != NULL)
			headers = tmp;
		free(line);
	}
	return headers;
}

/*
 * One HTTP request.  Returns STNS_OK, STNS_NG, or -1 for the failures that
 * mean the server is unreachable rather than merely unhappy - the only case
 * worth tripping the circuit breaker for.
 */
static int
http_request(stns_conf_t *c, const char *path, stns_response_t *res)
{
	struct curl_slist *headers = NULL;
	CURL *curl;
	CURLcode result;
	char *url;
	const char *base;
	size_t len;
	long code = 0;
	int rc = STNS_NG;

	if ((curl = curl_easy_init()) == NULL)
		return STNS_NG;

	/*
	 * Start from an empty body every time.  A retry after a half written
	 * response would otherwise append to whatever the failed attempt left
	 * behind and hand the parser two concatenated documents.
	 */
	res->size = 0;
	if (res->data != NULL)
		res->data[0] = '\0';

	base = c->cached_enable ? "http://unix" : c->api_endpoint;
	len = strlen(base) + strlen(path) + 2;
	if ((url = malloc(len)) == NULL) {
		curl_easy_cleanup(curl);
		return STNS_NG;
	}
	(void)snprintf(url, len, "%s/%s", base, path);

	if (c->cached_enable) {
		/* cache-stnsd owns the credentials; we just talk to its socket. */
		(void)curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, c->cached_unix_socket);
	} else {
		headers = build_headers(c);
		if (headers != NULL)
			(void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		(void)curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, c->ssl_verify);
		(void)curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, c->ssl_verify ? 2L : 0L);
		if (c->http_location)
			(void)curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		if (c->tls_cert != NULL && c->tls_key != NULL) {
			(void)curl_easy_setopt(curl, CURLOPT_SSLCERT, c->tls_cert);
			(void)curl_easy_setopt(curl, CURLOPT_SSLKEY, c->tls_key);
		}
		if (c->tls_ca != NULL)
			(void)curl_easy_setopt(curl, CURLOPT_CAINFO, c->tls_ca);
		if (c->user != NULL)
			(void)curl_easy_setopt(curl, CURLOPT_USERNAME, c->user);
		if (c->password != NULL)
			(void)curl_easy_setopt(curl, CURLOPT_PASSWORD, c->password);
		if (c->http_proxy != NULL)
			(void)curl_easy_setopt(curl, CURLOPT_PROXY, c->http_proxy);
	}

	(void)curl_easy_setopt(curl, CURLOPT_URL, url);
	(void)curl_easy_setopt(curl, CURLOPT_USERAGENT, STNS_USER_AGENT);
	(void)curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	(void)curl_easy_setopt(curl, CURLOPT_TIMEOUT, c->request_timeout);
	(void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
	(void)curl_easy_setopt(curl, CURLOPT_WRITEDATA, res);
	(void)curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	(void)curl_easy_setopt(curl, CURLOPT_HEADERDATA, c);
	/* We are running inside somebody else's process; never touch signals. */
	(void)curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	result = curl_easy_perform(curl);
	(void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	res->status_code = code;

	if (result != CURLE_OK) {
		if (result == CURLE_COULDNT_CONNECT || result == CURLE_OPERATION_TIMEDOUT ||
		    result == CURLE_COULDNT_RESOLVE_HOST)
			rc = -1; /* caller trips the circuit breaker */
		else
			rc = STNS_NG;
		syslog(LOG_ERR, STNS_PRODUCT ": request to %s failed: %s", url, curl_easy_strerror(result));
	} else if (code >= 400) {
		res->size = 0;
		if (res->data != NULL)
			res->data[0] = '\0';
		if (code != STNS_HTTP_NOTFOUND)
			syslog(LOG_ERR, STNS_PRODUCT ": request to %s failed with status %ld", url, code);
		rc = STNS_NG;
	} else {
		rc = STNS_OK;
	}

	if (headers != NULL)
		curl_slist_free_all(headers);
	free(url);
	curl_easy_cleanup(curl);
	return rc;
}

/*
 * Per euid cache directory.  Everything below cache_dir belongs to exactly one
 * user, which is what makes the ownership checks meaningful.
 */
/*
 * Build the cache directory and file name for a request path.  The directory
 * is per euid, which is what makes the ownership checks elsewhere meaningful:
 * every file under it has exactly one legitimate owner.
 */
static int
cache_paths(stns_conf_t *c, const char *path, char *dir, size_t dirlen, char *file, size_t filelen)
{
	char *escaped;
	int n;

	if ((escaped = stns_escape_path(path)) == NULL)
		return STNS_NG;

	n = snprintf(dir, dirlen, "%s/%lu", c->cache_dir, (unsigned long)geteuid());
	if (n < 0 || (size_t)n >= dirlen) {
		free(escaped);
		return STNS_NG;
	}
	n = snprintf(file, filelen, "%s/%s", dir, escaped);
	free(escaped);
	if (n < 0 || (size_t)n >= filelen)
		return STNS_NG;
	return STNS_OK;
}

/*
 * Read a cached response.  The ownership check is the point: cache_dir is
 * shared, and a file planted by another user must never be believed.
 */
static int
cache_read(const char *file, stns_response_t *res)
{
	struct stat sb;
	char *data;
	FILE *fp;
	size_t got;

	if ((fp = fopen(file, "r")) == NULL)
		return STNS_NG;
	if (fstat(fileno(fp), &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_uid != geteuid()) {
		(void)fclose(fp);
		return STNS_NG;
	}
	if ((data = malloc((size_t)sb.st_size + 1)) == NULL) {
		(void)fclose(fp);
		return STNS_NG;
	}
	got = fread(data, 1, (size_t)sb.st_size, fp);
	(void)fclose(fp);
	data[got] = '\0';

	free(res->data);
	res->data = data;
	res->size = got;
	return STNS_OK;
}

/*
 * Store a response.  A zero length file is how a 404 is remembered, and it
 * expires on negative_cache_ttl rather than on cache_ttl.
 */
static void
cache_write(const char *dir, const char *file, const stns_response_t *res)
{
	struct stat sb;
	mode_t um;
	FILE *fp;
	int fd;

	if (stat(dir, &sb) != 0) {
		um = umask(0);
		(void)mkdir(dir, S_IRWXU);
		(void)umask(um);
	}
	/* Never overwrite a file we do not own. */
	if (stat(file, &sb) == 0 && sb.st_uid != geteuid())
		return;

	if ((fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) == -1)
		return;
	if ((fp = fdopen(fd, "w")) == NULL) {
		(void)close(fd);
		return;
	}
	if (res->data != NULL && res->size > 0)
		(void)fwrite(res->data, 1, res->size, fp);
	(void)fclose(fp);
}

/*
 * Sweep expired entries out of this euid's cache directory.  It is called when
 * a lookup finds its own entry stale, so the directory is tidied by the same
 * traffic that fills it and no daemon is involved.
 */
static void
cache_expire(stns_conf_t *c)
{
	char dir[STNS_MAXBUF];
	char buf[STNS_MAXBUF * 2];
	struct dirent *ent;
	struct stat sb;
	time_t now = time(NULL);
	DIR *dp;

	if (snprintf(dir, sizeof(dir), "%s/%lu", c->cache_dir, (unsigned long)geteuid()) >= (int)sizeof(dir))
		return;
	if ((dp = opendir(dir)) == NULL)
		return;

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;
		if (snprintf(buf, sizeof(buf), "%s/%s", dir, ent->d_name) >= (int)sizeof(buf))
			continue;
		if (stat(buf, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_uid != geteuid())
			continue;

		{
			double diff = difftime(now, sb.st_mtime);

			if ((sb.st_size > 0 && diff > c->cache_ttl) ||
			    (sb.st_size == 0 && diff > c->negative_cache_ttl)) {
				if (unlink(buf) == -1)
					syslog(LOG_ERR, STNS_PRODUCT ": cannot unlink %s: %s", buf, strerror(errno));
			}
		}
	}
	(void)closedir(dp);
}

/*
 * Circuit breaker.  The lock file lives inside the caller's own cache
 * directory rather than in a world writable place, so an unprivileged user
 * cannot wedge name resolution for everybody else.
 *
 * request_locktime of zero turns it off, and turning it off is a real setting
 * rather than a degenerate case.  The breaker exists because a name lookup
 * happens in every process on the machine and a dead server would otherwise be
 * dialled by all of them; a daemon that holds a snapshot and refreshes it on a
 * timer has exactly one caller and no such problem.  What it does have is a
 * pledge(2) without cpath, and tripping the breaker means creating a file - so
 * for ypstns the difference between off and on is the difference between
 * carrying on with slightly stale maps and being killed by the kernel the first
 * time the API server hiccups.
 */
static int
breaker_path(stns_conf_t *c, char *buf, size_t buflen)
{
	int n = snprintf(buf, buflen, "%s/%lu/.lock", c->cache_dir, (unsigned long)geteuid());

	return (n > 0 && (size_t)n < buflen) ? STNS_OK : STNS_NG;
}

static int
breaker_open(stns_conf_t *c)
{
	char path[STNS_MAXBUF];
	struct stat sb;

	if (c->request_locktime <= 0)
		return 0;
	if (breaker_path(c, path, sizeof(path)) != STNS_OK)
		return 0;
	if (stat(path, &sb) != 0 || sb.st_uid != geteuid())
		return 0;
	if (difftime(time(NULL), sb.st_mtime) > c->request_locktime) {
		(void)unlink(path);
		return 0;
	}
	return 1;
}

static void
breaker_trip(stns_conf_t *c)
{
	char path[STNS_MAXBUF];
	char dir[STNS_MAXBUF];
	struct stat sb;
	int fd;

	if (c->request_locktime <= 0)
		return;
	if (snprintf(dir, sizeof(dir), "%s/%lu", c->cache_dir, (unsigned long)geteuid()) >= (int)sizeof(dir))
		return;
	if (stat(dir, &sb) != 0)
		(void)mkdir(dir, S_IRWXU);
	if (breaker_path(c, path, sizeof(path)) != STNS_OK)
		return;
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) != -1)
		(void)close(fd);
}

/*
 * Fetch a request path, through the cache and the circuit breaker.
 *
 * On success res->data holds the body and the caller owns it.  On failure
 * res->status_code separates "the server said no" - a 404, which is a real
 * answer and worth caching - from everything else.
 */
int
stns_request(stns_conf_t *c, const char *path, stns_response_t *res)
{
	char dir[STNS_MAXBUF];
	char file[STNS_MAXBUF * 2];
	int cacheable, retry, rc;

	res->data = NULL;
	res->size = 0;
	res->status_code = 200L;

	if (path == NULL)
		return STNS_NG;

	cacheable = c->cache && !c->cached_enable && cache_paths(c, path, dir, sizeof(dir), file, sizeof(file)) == STNS_OK;

	if (cacheable) {
		struct stat sb;

		if (stat(file, &sb) == 0 && sb.st_uid == geteuid()) {
			double diff = difftime(time(NULL), sb.st_mtime);

			/* A zero length entry is how a 404 is remembered. */
			if (sb.st_size == 0 && diff < c->negative_cache_ttl) {
				res->status_code = STNS_HTTP_NOTFOUND;
				return STNS_NG;
			}
			if (sb.st_size > 0 && diff < c->cache_ttl && cache_read(file, res) == STNS_OK)
				return STNS_OK;
			cache_expire(c);
		}
	}

	if (breaker_open(c))
		return STNS_NG;

	if (c->query_wrapper != NULL) {
		rc = stns_exec_cmd(c->query_wrapper, path, res);
	} else {
		rc = http_request(c, path, res);
		for (retry = c->request_retry; rc != STNS_OK && retry > 0; retry--) {
			if (res->status_code >= 400)
				break; /* the server answered; retrying will not help */
			(void)sleep(1);
			syslog(LOG_NOTICE, STNS_PRODUCT ": retrying request, %d attempts left", retry);
			rc = http_request(c, path, res);
		}
		if (rc == -1) {
			breaker_trip(c);
			rc = STNS_NG;
		}
	}

	if (cacheable && (rc == STNS_OK || res->status_code == STNS_HTTP_NOTFOUND))
		cache_write(dir, file, res);

	return rc;
}

/*
 * Run query_wrapper or chain_ssh_wrapper and collect its output.
 *
 * The argument reaches a shell command line, so it is checked against a strict
 * character set first: the same reasoning as stns_is_valid_name(), one layer
 * further out.
 */
int
stns_exec_cmd(const char *cmd, const char *arg, stns_response_t *r)
{
	char buf[STNS_MAXBUF];
	char *line;
	size_t len, n;
	FILE *fp;
	int rc = STNS_NG;

	r->size = 0;
	r->status_code = 200L;

	/* The argument is interpolated into a shell command line, so be strict. */
	for (n = 0; arg != NULL && arg[n] != '\0'; n++) {
		if (!isalnum((unsigned char)arg[n]) && strchr("_-.=?/", arg[n]) == NULL)
			return STNS_NG;
	}

	len = strlen(cmd) + (arg != NULL ? strlen(arg) : 0) + 2;
	if ((line = malloc(len)) == NULL)
		return STNS_NG;
	if (arg != NULL)
		(void)snprintf(line, len, "%s %s", cmd, arg);
	else
		(void)snprintf(line, len, "%s", cmd);

	if ((fp = popen(line, "r")) == NULL) {
		free(line);
		return STNS_NG;
	}

	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		char *grown;

		if (r->size + n + 1 > STNS_MAX_BUFFER_SIZE)
			break;
		if ((grown = realloc(r->data, r->size + n + 1)) == NULL)
			break;
		r->data = grown;
		memcpy(r->data + r->size, buf, n);
		r->size += n;
		r->data[r->size] = '\0';
	}
	(void)pclose(fp);
	free(line);

	if (r->size > 0)
		rc = STNS_OK;
	return rc;
}
