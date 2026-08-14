/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The daemon: configuration, the listening socket, and the accept loop.
 *
 * The shape of this program is one decision repeated.  The parent holds the
 * directory and never reads from a client socket; every connection is handled
 * by a forked child which inherits the entries and exits when the client goes
 * away.  That is what keeps the BER parser - the only code here an untrusted
 * peer can reach - away from the data it is serving, gives several clients an
 * answer at the same time without any locking, and means the periodic refresh
 * can take as long as an HTTP round trip takes without a single client waiting
 * on it.
 *
 * It does not daemonize, on purpose.  On macOS starting and supervising a
 * service is launchd's job, and a program that forks itself into the
 * background takes that job away from it - launchd would watch the process
 * that exited immediately rather than the one doing the work.  So ldapstns
 * runs in the foreground and launchd is given jp.stns.ldapstns.plist.
 */
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <launch.h>
#endif

#include "ldapstns.h"

/*
 * A local user cannot be allowed to fork this process as many times as it can
 * open sockets.  Beyond the cap a connection is accepted and immediately
 * closed, which the client sees as a refusal rather than as a hang.
 */
#define LDAPSTNS_MAX_CHILDREN 64

int debug;

static volatile sig_atomic_t want_quit;
static volatile sig_atomic_t want_reload;

void
logit(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(prio, fmt, ap);
	va_end(ap);

	if (debug) {
		va_start(ap, fmt);
		(void)fprintf(stderr, "ldapstns: ");
		(void)vfprintf(stderr, fmt, ap);
		(void)fputc('\n', stderr);
		va_end(ap);
	}
}

static void
on_quit(int sig)
{
	want_quit = 1;
}

static void
on_reload(int sig)
{
	want_reload = 1;
}

/*
 * A child finished.  There is nothing to do about it here - the reaping
 * happens at the top of the main loop, where a counter can safely be
 * decremented - but the handler has to exist all the same, because the
 * alternative spellings both do the wrong thing: SIG_DFL for SIGCHLD leaves
 * the children as zombies, and SIG_IGN reaps them where the loop cannot see it
 * and leaves the count of live children wrong for ever.
 */
static void
on_child(int sig)
{
}

static void
usage(void)
{
	(void)fprintf(stderr, "usage: ldapstns [-dnv] [-f file]\n");
	exit(1);
}

/*
 * Install the handlers.
 *
 * SA_RESTART is deliberately not set for the two that ask the daemon to stop
 * or to reload: the main loop spends nearly all its time in poll(2), and
 * interrupting it is the only way either gets looked at promptly.
 *
 * Each signal gets a handler of its own rather than one that switches on the
 * number.  A shared handler with a default case is a trap: SIGCHLD arrives
 * every time a client disconnects, and falling through to "stop" would have
 * the daemon shut itself down the first time anybody closed a connection.
 */
static void
setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_quit;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGTERM, &sa, NULL);
	(void)sigaction(SIGINT, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_reload;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGHUP, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	/* A client that hangs up mid reply must not take the child with it. */
	(void)sigaction(SIGPIPE, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_child;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGCHLD, &sa, NULL);
}

/*
 * One listening socket, for an address of either family.
 *
 * getaddrinfo(3) rather than inet_pton(3) with a family chosen in advance.
 * The default is to listen on both loopbacks, and hardcoding AF_INET made the
 * second of them a configuration error rather than a listener - which matters
 * on macOS, where "localhost" resolves to ::1 first and an IPv4-only daemon is
 * one that anybody who typed "dsconfigldap -a localhost" cannot reach.
 *
 * AI_NUMERICHOST keeps it to addresses.  A hostname here would be ambiguous
 * the moment it resolved to more than one thing, and this is a setting about
 * which socket to open rather than about who to talk to.
 */
static int
listen_socket(const char *addr, int port)
{
	struct addrinfo hints, *res;
	char service[16];
	int fd, on = 1, err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
	(void)snprintf(service, sizeof(service), "%d", port);

	if ((err = getaddrinfo(addr, service, &hints, &res)) != 0) {
		logit(LOG_ERR, "listen: \"%s\" is not an address: %s", addr, gai_strerror(err));
		return -1;
	}

	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
		logit(LOG_ERR, "socket for %s: %s", addr, strerror(errno));
		freeaddrinfo(res);
		return -1;
	}
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	/*
	 * An IPv6 socket that also accepted IPv4 would collide with the IPv4
	 * listener bound beside it, and which of the two received a connection
	 * would come down to the order they happened to be opened in.
	 */
	if (res->ai_family == AF_INET6)
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

	if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		logit(LOG_ERR, "cannot bind %s port %d: %s", addr, port, strerror(errno));
		(void)close(fd);
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);

	if (listen(fd, LDAPSTNS_BACKLOG) == -1) {
		logit(LOG_ERR, "listen on %s: %s", addr, strerror(errno));
		(void)close(fd);
		return -1;
	}

	logit(LOG_INFO, "listening on %s port %d", addr, port);
	return fd;
}

/*
 * Take the listening sockets launchd has already opened, if there are any.
 *
 * This is the macOS way round: the Sockets key in jp.stns.ldapstns.plist names
 * a listener, launchd binds it as root before the job starts, and the job is
 * handed the descriptor.  Which means the daemon never needs to be root at all
 * to listen on port 389 - it can be started as the unprivileged user in the
 * plist and stay that way from its first instruction.
 *
 * ESRCH is the ordinary answer when nobody was started by launchd, and is not
 * an error: the daemon binds its own socket and drops privileges the classical
 * way instead.
 */
static int
launchd_sockets(int **fds, size_t *n)
{
#ifdef __APPLE__
	int *v = NULL;
	size_t cnt = 0;
	int err;

	err = launch_activate_socket("Listeners", &v, &cnt);
	if (err == 0 && cnt > 0) {
		*fds = v;
		*n = cnt;
		logit(LOG_INFO, "using %lu listener(s) from launchd", (unsigned long)cnt);
		return 0;
	}
	free(v);
	if (err != 0 && err != ESRCH && err != ENOENT)
		logit(LOG_NOTICE, "launch_activate_socket: %s", strerror(err));
#else
	(void)fds;
	(void)n;
#endif
	return -1;
}

/*
 * Give up root.
 *
 * The lookup has to happen here, before the daemon is answering anything.
 * Once opendirectoryd has been pointed at this socket, a getpwnam(3) from
 * inside the very process that serves it is a question that could come back
 * round to itself; asking it while the listener is not yet accepting means the
 * only possible answer is the local one, which is the answer wanted anyway.
 */
static int
drop_privileges(const char *user)
{
	struct passwd *pw;

	if (geteuid() != 0) {
		logit(LOG_INFO, "not running as root; staying as uid %lu", (unsigned long)geteuid());
		return 0;
	}

	if ((pw = getpwnam(user)) == NULL) {
		logit(LOG_ERR, "no such user \"%s\" to run as", user);
		return -1;
	}
	if (pw->pw_uid == 0) {
		logit(LOG_ERR, "\"%s\" is root; refusing to keep full privileges", user);
		return -1;
	}

	if (setgid(pw->pw_gid) == -1) {
		logit(LOG_ERR, "setgid: %s", strerror(errno));
		return -1;
	}
	if (setgroups(1, &pw->pw_gid) == -1) {
		logit(LOG_ERR, "setgroups: %s", strerror(errno));
		return -1;
	}
	if (setuid(pw->pw_uid) == -1) {
		logit(LOG_ERR, "setuid: %s", strerror(errno));
		return -1;
	}
	/*
	 * Prove it took.  A setuid(2) that silently did nothing would leave a
	 * network facing daemon running as root, which is worth one more system
	 * call to rule out.
	 */
	if (setuid(0) != -1) {
		logit(LOG_ERR, "still able to regain root; refusing to run");
		return -1;
	}

	logit(LOG_INFO, "running as \"%s\" (uid %lu)", user, (unsigned long)pw->pw_uid);
	return 0;
}

int
main(int argc, char *argv[])
{
	const char *conffile = LDAPSTNS_CONFIG_FILE;
	struct pollfd *pfd = NULL;
	ldapstns_conf conf;
	stns_conf_t sc;
	snapshot snap;
	int *listeners = NULL;
	size_t nlisteners = 0, i;
	int children = 0, check_only = 0, from_launchd = 0;
	int rv = 1, ch;
	time_t next_refresh;

	memset(&conf, 0, sizeof(conf));
	memset(&sc, 0, sizeof(sc));
	memset(&snap, 0, sizeof(snap));

	while ((ch = getopt(argc, argv, "df:nv")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			check_only = 1;
			break;
		case 'v':
			(void)printf("ldapstns %s\n", LDAPSTNS_VERSION);
			return 0;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	openlog("ldapstns", LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);

	if (conf_load(conffile, &conf) != 0)
		return 1;

	/*
	 * stns.conf is read while still root, because it may hold an API token
	 * and therefore may well be readable by nobody else.  It stays in
	 * memory from here on.
	 */
	if (stns_load_config(stns_config_path(), &sc) != STNS_OK) {
		logit(LOG_ERR, "cannot load %s", stns_config_path());
		conf_free(&conf);
		return 1;
	}

	/*
	 * Two of the library's settings make no sense for a daemon, whatever
	 * stns.conf says, so they are turned off here rather than left as
	 * something an administrator has to remember.
	 *
	 * The on-disk cache would be a second and staler copy of a directory
	 * already held in memory, written by the unprivileged user this drops
	 * to rather than by the euid that created the directory.
	 *
	 * The circuit breaker suppresses requests for a minute after a failure,
	 * which is the right answer when every process on the machine is making
	 * them and the wrong one here: it would silently skip refreshes for one
	 * interval after any hiccup, and there is only ever one caller.
	 */
	sc.cache = 0;
	sc.request_locktime = 0;

	if (check_only) {
		(void)printf("configuration ok\n");
		for (i = 0; i < conf.nlisten; i++)
			(void)printf("  listen          %s port %d\n", conf.listen[i], conf.port);
		(void)printf("  suffix          %s\n", conf.suffix);
		(void)printf("  user            %s\n", conf.user);
		(void)printf("  interval        %d\n", conf.interval);
		(void)printf("  bind_dn         %s\n", (conf.bind_dn != NULL) ? conf.bind_dn : "(anonymous)");
		(void)printf("  expose_password %s\n", conf.expose_password ? "yes" : "no");
		(void)printf("  api_endpoint    %s\n", sc.api_endpoint);
		rv = 0;
		goto out;
	}

	if (launchd_sockets(&listeners, &nlisteners) == 0) {
		from_launchd = 1;
	} else {
		size_t bound = 0;

		if ((listeners = calloc(conf.nlisten, sizeof(*listeners))) == NULL)
			goto out;
		for (i = 0; i < conf.nlisten; i++) {
			int fd = listen_socket(conf.listen[i], conf.port);

			if (fd != -1)
				listeners[bound++] = fd;
		}
		/*
		 * One address failing is survivable - a machine with IPv6
		 * turned off should still get its IPv4 listener, and has
		 * already been told which one did not work.  None of them
		 * binding is not.
		 */
		if (bound == 0) {
			logit(LOG_ERR, "not one of the configured addresses could be listened on");
			goto out;
		}
		nlisteners = bound;
	}

	if (drop_privileges(conf.user) != 0)
		goto out;

	if ((pfd = calloc(nlisteners, sizeof(*pfd))) == NULL)
		goto out;
	for (i = 0; i < nlisteners; i++) {
		pfd[i].fd = listeners[i];
		pfd[i].events = POLLIN;
	}

	setup_signals();

	/*
	 * The first refresh has to succeed.  Coming up with an empty directory
	 * would have opendirectoryd answer "no such user" for everybody in it,
	 * which is a far worse outcome than not coming up: launchd will start
	 * the job again, and in the meantime the machine's local accounts are
	 * untouched.
	 */
	if (snapshot_refresh(&sc, &conf, &snap) != 0) {
		logit(LOG_ERR, "no directory to serve; exiting rather than serving an empty one");
		goto out;
	}
	next_refresh = time(NULL) + conf.interval;

	logit(LOG_NOTICE, "ldapstns %s serving %s", LDAPSTNS_VERSION, conf.suffix);

	while (!want_quit) {
		time_t now;
		int timeout, n;

		/* Reap whatever finished while we were asleep. */
		while (waitpid(-1, NULL, WNOHANG) > 0) {
			if (children > 0)
				children--;
		}

		/*
		 * A reload re-reads both files.  stns.conf may no longer be
		 * readable now that root has been given up - it is the file
		 * with the API token in it - so a failure there keeps the
		 * settings already in memory rather than taking the daemon
		 * down over a permission the administrator chose deliberately.
		 */
		if (want_reload) {
			ldapstns_conf fresh;
			stns_conf_t freshsc;

			want_reload = 0;
			logit(LOG_NOTICE, "reloading");

			if (conf_load(conffile, &fresh) == 0) {
				int moved = (fresh.port != conf.port || fresh.nlisten != conf.nlisten);
				size_t j;

				for (j = 0; !moved && j < conf.nlisten; j++) {
					if (strcmp(conf.listen[j], fresh.listen[j]) != 0)
						moved = 1;
				}
				if (moved)
					logit(LOG_NOTICE, "listen addresses changed; restart to apply them");
				conf_free(&conf);
				conf = fresh;
			}
			if (stns_load_config(stns_config_path(), &freshsc) == STNS_OK) {
				stns_unload_config(&sc);
				sc = freshsc;
			} else {
				logit(LOG_NOTICE, "cannot re-read %s; keeping the settings in memory",
				    stns_config_path());
			}

			(void)snapshot_refresh(&sc, &conf, &snap);
			next_refresh = time(NULL) + conf.interval;
		}

		now = time(NULL);
		timeout = (next_refresh > now) ? (int)((next_refresh - now) * 1000) : 0;

		n = poll(pfd, (nfds_t)nlisteners, timeout);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			logit(LOG_ERR, "poll: %s", strerror(errno));
			break;
		}
		if (n == 0) {
			/*
			 * Nothing waiting, so this is the refresh tick.  It
			 * happens here, between accepts, which is why no client
			 * ever waits on an HTTP round trip: the ones that
			 * arrive meanwhile sit in the listen backlog for as
			 * long as it takes.
			 */
			(void)snapshot_refresh(&sc, &conf, &snap);
			next_refresh = time(NULL) + conf.interval;
			continue;
		}

		for (i = 0; i < nlisteners; i++) {
			pid_t pid;
			int cfd;

			if ((pfd[i].revents & POLLIN) == 0)
				continue;
			if ((cfd = accept(pfd[i].fd, NULL, NULL)) == -1) {
				if (errno != EINTR && errno != ECONNABORTED && errno != EAGAIN)
					logit(LOG_ERR, "accept: %s", strerror(errno));
				continue;
			}

			if (children >= LDAPSTNS_MAX_CHILDREN) {
				logit(LOG_NOTICE, "%d connections already; refusing another",
				    LDAPSTNS_MAX_CHILDREN);
				(void)close(cfd);
				continue;
			}

			if ((pid = fork()) == -1) {
				logit(LOG_ERR, "fork: %s", strerror(errno));
				(void)close(cfd);
				continue;
			}
			if (pid == 0) {
				size_t j;

				/*
				 * The child has no business with the listener,
				 * and closing it means a stuck child cannot
				 * hold the port open after the parent has gone.
				 */
				for (j = 0; j < nlisteners; j++)
					(void)close(pfd[j].fd);
				ldap_serve(cfd, &conf, &snap);
				(void)close(cfd);
				_exit(0);
			}
			children++;
			(void)close(cfd);
		}
	}

	logit(LOG_NOTICE, "exiting");
	rv = 0;

out:
	for (i = 0; i < nlisteners; i++)
		(void)close(listeners[i]);
	free(listeners);
	free(pfd);
	snapshot_free(&snap);
	stns_unload_config(&sc);
	conf_free(&conf);
	closelog();
	(void)from_launchd;
	return rv;
}
