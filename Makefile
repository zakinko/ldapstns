# SPDX-License-Identifier: BSD-2-Clause
#
# ldapstns - a read-only LDAPv3 view of an STNS directory, for macOS.
#
# Written to the POSIX make subset.  make(1) on macOS is GNU make, not the BSD
# make the rest of these repositories are built with, so this file uses neither
# dialect's conditionals - which also rules out looking at uname(1) or asking
# brew(1) where it put itself.  Hence:
#
#	make					Intel Homebrew, or /usr/local by hand
#	make PREFIX=/opt/homebrew		Apple Silicon Homebrew
#	make PREFIX=$(brew --prefix)		either, if brew is installed
#
# The STNS API client - the configuration, the HTTP, the cache, the circuit
# breaker and the marshalling - is in src/ beside the daemon rather than shared
# from anywhere.  It was a library for a while and is not one any more: nothing
# linked it, and an upstream for two programs cost a repository, a manifest and
# a commit in three places to change one line.  The same code is in nss_stns
# and in ypstns, each owning its copy the way a port owns what it builds.

PREFIX?=	/usr/local
SYSCONFDIR?=	$(PREFIX)/etc
BINDIR?=	$(PREFIX)/bin
MANDIR?=	$(PREFIX)/share/man
EXAMPLESDIR?=	$(PREFIX)/share/examples/ldapstns
LAUNCHDDIR?=	$(PREFIX)/share/ldapstns

PARSON=		external/mit/parson
TOMLC99=	external/mit/tomlc99

PROG=		ldapstns
KEY_WRAPPER=	stns-key-wrapper

# The PAM module.  A dylib rather than a bundle, because that is what the
# modules in /usr/lib/pam are and what OpenPAM's loader expects.  It goes under
# PREFIX and is named by absolute path in /etc/pam.d, since /usr/lib/pam is
# inside the signed system volume and nothing may be added to it.
PAM_MODULE=	pam_stns.so
PAMDIR?=	$(PREFIX)/lib/pam

CC?=		cc
INSTALL?=	install
CFLAGS?=	-O2 -pipe
WARNS=		-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes \
		-Wpointer-arith -Wno-unused-parameter
CPPFLAGS+=	-Isrc \
		-I$(PARSON) \
		-I$(TOMLC99) \
		-DSTNS_PRODUCT=\"ldapstns\" \
		-DSTNS_CONFDIR=\"$(SYSCONFDIR)\" \
		-DLDAPSTNS_CONFDIR=\"$(SYSCONFDIR)\"
LDFLAGS+=
LIBS+=		-lcurl

# The API client.  Every program below is built from these plus its own.
CORE_OBJS=	src/stns_config.o \
		src/stns_request.o \
		src/stns_entry.o \
		src/stns_lookup.o \
		src/stns_list.o \
		src/stns_crypt.o \
		$(PARSON)/parson.o \
		$(TOMLC99)/toml.o

PROG_OBJS=	src/ldapstns.o \
		src/conf.o \
		src/ber.o \
		src/entry.o \
		src/filter.o \
		src/snapshot.o \
		src/ldap.o

TEST=		ber_test
TEST_OBJS=	tests/ber_test.o
# The API client's own tests.  ber_test covers the protocol this daemon
# speaks; these two cover the half underneath it, which is the half that is
# the same in all three STNS clients and so the half nobody's daemon tests.
CLIENT_TEST=	stns_test
CRYPT_TEST=	stns_crypt_test

OBJS=		$(CORE_OBJS) $(PROG_OBJS) $(TEST_OBJS) \
		src/stns_key_wrapper.o

all: $(PROG) $(KEY_WRAPPER) $(PAM_MODULE)

.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) $(WARNS) $(CPPFLAGS) -c $< -o $@

$(PROG): $(PROG_OBJS) $(CORE_OBJS)
	$(CC) -o $@ $(PROG_OBJS) $(CORE_OBJS) $(LDFLAGS) $(LIBS)

# The one piece of STNS support that needs nothing from the system's directory
# machinery: sshd runs a command and reads its output.  All three STNS clients
# install this same program.
$(KEY_WRAPPER): src/stns_key_wrapper.o $(CORE_OBJS)
	$(CC) -o $@ src/stns_key_wrapper.o $(CORE_OBJS) $(LDFLAGS) $(LIBS)

# Compiled with -fPIC and linked as a dylib: the library objects above are
# built for an executable, so the module gets its own copies rather than
# sharing them.
$(PAM_MODULE): src/pam_stns.c
	$(CC) $(CFLAGS) $(WARNS) $(CPPFLAGS) -fPIC -dynamiclib -o $@ \
		src/pam_stns.c \
		src/stns_config.c \
		src/stns_request.c \
		src/stns_entry.c \
		src/stns_lookup.c \
		src/stns_list.c \
		src/stns_crypt.c \
		$(PARSON)/parson.c \
		$(TOMLC99)/toml.c \
		$(LDFLAGS) $(LIBS) -lpam

# The protocol tests need the protocol code but not the daemon around it.
$(TEST): $(TEST_OBJS) src/ber.o src/entry.o src/filter.o $(CORE_OBJS)
	$(CC) -o $@ $(TEST_OBJS) src/ber.o src/entry.o src/filter.o $(CORE_OBJS) $(LDFLAGS) $(LIBS)

$(CLIENT_TEST): tests/stns_test.o $(CORE_OBJS)
	$(CC) -o $@ tests/stns_test.o $(CORE_OBJS) $(LDFLAGS) $(LIBS)

$(CRYPT_TEST): tests/crypt_test.o $(CORE_OBJS)
	$(CC) -o $@ tests/crypt_test.o $(CORE_OBJS) $(LDFLAGS) $(LIBS)

test: $(TEST) $(CLIENT_TEST) $(CRYPT_TEST)
	./$(TEST)
	./$(CLIENT_TEST)
	./$(CRYPT_TEST)

asan:
	$(CC) -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
		$(WARNS) $(CPPFLAGS) \
		tests/ber_test.c src/ber.c src/entry.c src/filter.c \
		src/stns_config.c src/stns_request.c \
		src/stns_entry.c src/stns_lookup.c \
		src/stns_list.c \
		$(PARSON)/parson.c \
		$(TOMLC99)/toml.c \
		$(LDFLAGS) $(LIBS) -o $(TEST)-asan
	./$(TEST)-asan
	$(CC) -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
		$(WARNS) $(CPPFLAGS) \
		tests/crypt_test.c src/stns_crypt.c \
		src/stns_config.c src/stns_request.c src/stns_entry.c \
		src/stns_lookup.c src/stns_list.c \
		$(PARSON)/parson.c $(TOMLC99)/toml.c \
		$(LDFLAGS) $(LIBS) -o $(CRYPT_TEST)-asan
	./$(CRYPT_TEST)-asan

# Drives the real daemon with ldapsearch(1) against the mock STNS server.
# Needs no root: it listens on a high port in a scratch directory.
integration:
	sh tests/integration.sh

# Drives the real opendirectoryd through the daemon, which is the only client
# it exists for and the one no test without root can stand in for.  It changes
# the machine's Open Directory configuration for the duration, so it refuses to
# run unless asked twice - as root, and with LDAPSTNS_OD_TEST=yes.  See the
# comment at the top of the script.
opendirectory:
	sh tests/opendirectory.sh

# Authenticates through the real PAM against the real module.  Needs root, and
# writes one policy file into /etc/pam.d for the duration, so it refuses to run
# unless asked twice - as root and with LDAPSTNS_PAM_TEST=yes.
pam:
	sh tests/pam.sh

# Check the bundled third party code against external/MANIFEST.  Add
# --upstream and it also asks github whether the recorded revisions are still
# current, which needs the network.
external:
	sh tests/check_external.sh

# Check that the ident line in the sample configurations is really substituted.
ident:
	sh tests/check_ident.sh

install: all
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 555 $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)
	$(INSTALL) -m 555 $(KEY_WRAPPER) $(DESTDIR)$(BINDIR)/$(KEY_WRAPPER)
	$(INSTALL) -d $(DESTDIR)$(PAMDIR)
	$(INSTALL) -m 444 $(PAM_MODULE) $(DESTDIR)$(PAMDIR)/$(PAM_MODULE)
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) -m 444 man/ldapstns.conf.5 $(DESTDIR)$(MANDIR)/man5/ldapstns.conf.5
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 444 man/ldapstns.8 $(DESTDIR)$(MANDIR)/man8/ldapstns.8
	$(INSTALL) -m 444 man/pam_stns.8 $(DESTDIR)$(MANDIR)/man8/pam_stns.8
	$(INSTALL) -m 444 man/stns-key-wrapper.8 \
		$(DESTDIR)$(MANDIR)/man8/stns-key-wrapper.8
	$(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)
	$(INSTALL) -m 444 ldapstns.conf.example $(DESTDIR)$(EXAMPLESDIR)/ldapstns.conf
	$(INSTALL) -m 444 stns.conf.example $(DESTDIR)$(EXAMPLESDIR)/stns.conf
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/stns/client
	# The job description is staged, not installed.  /Library/LaunchDaemons
	# is the system's, not a package's, and putting a file there is the
	# administrator's decision - see ldapstns(8).
	$(INSTALL) -d $(DESTDIR)$(LAUNCHDDIR)
	$(INSTALL) -m 444 launchd/jp.stns.ldapstns.plist \
		$(DESTDIR)$(LAUNCHDDIR)/jp.stns.ldapstns.plist

deinstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROG)
	rm -f $(DESTDIR)$(BINDIR)/$(KEY_WRAPPER)
	rm -f $(DESTDIR)$(PAMDIR)/$(PAM_MODULE)
	rm -f $(DESTDIR)$(MANDIR)/man5/ldapstns.conf.5
	rm -f $(DESTDIR)$(MANDIR)/man8/ldapstns.8
	rm -f $(DESTDIR)$(MANDIR)/man8/pam_stns.8
	rm -f $(DESTDIR)$(MANDIR)/man8/stns-key-wrapper.8
	rm -f $(DESTDIR)$(EXAMPLESDIR)/ldapstns.conf
	rm -f $(DESTDIR)$(EXAMPLESDIR)/stns.conf
	rm -f $(DESTDIR)$(LAUNCHDDIR)/jp.stns.ldapstns.plist

clean:
	rm -f $(OBJS) $(PROG) $(KEY_WRAPPER) $(PAM_MODULE) \
		$(TEST) $(TEST)-asan $(CLIENT_TEST) \
		$(CRYPT_TEST) $(CRYPT_TEST)-asan

.PHONY: all test asan integration opendirectory pam external ident install deinstall clean
