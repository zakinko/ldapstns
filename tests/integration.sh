#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Drive the real daemon with ldapsearch(1), against the mock STNS server.
#
# The unit tests take the protocol apart; this puts it back together and asks
# an LDAP client that was not written here whether the result is LDAP.  That
# distinction matters more than usual for this daemon: everything it does is
# in service of being understood by opendirectoryd, which is a client nothing
# in a test suite can stand in for, and ldapsearch(1) is the closest available
# thing - the same OpenLDAP library, on the same machine, over the same socket.
#
# The searches below are not invented.  The filter in "the search
# opendirectoryd makes" is the one macOS builds from
# /System/Library/OpenDirectory/Mappings/RFC2307.plist, whose Users record type
# lists posixAccount, inetOrgPerson and shadowAccount combined with OR.
#
# Nothing needs root: the daemon listens on a high port and everything lives in
# a scratch directory.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
STNS_PORT=${STNS_PORT:-11106}
LDAP_PORT=${LDAP_PORT:-11389}
PYTHON=${PYTHON:-python3}
MAKE=${MAKE:-make}
WORK=${WORK:-/tmp/ldapstns_integration}

MOCK=$SRCDIR/libstns/tests/mock_stns_server.py
CONF=$WORK/etc/ldapstns.conf
URI=ldap://127.0.0.1:$LDAP_PORT

checks=0
failures=0
stns_pid=
ldap_pid=

# Set KEEP_WORK to leave the scratch directory, and with it both daemons' logs,
# behind for inspection.  A failure here is usually a question about what the
# daemon thought it was doing, and the answer is in $WORK/ldapstns.log.
cleanup() {
	if [ -n "$ldap_pid" ]; then
		kill "$ldap_pid" 2>/dev/null || true
	fi
	if [ -n "$stns_pid" ]; then
		kill "$stns_pid" 2>/dev/null || true
	fi
	wait 2>/dev/null || true
	if [ -z "${KEEP_WORK:-}" ]; then
		rm -rf "$WORK"
	else
		echo "left $WORK in place"
	fi
}
trap cleanup EXIT INT TERM

# Compare a command's output against a fixture.  Blank lines are dropped
# first: LDIF separates entries with one, which carries no information here
# because every entry starts with its own dn: line, and writing them into the
# fixtures would only make them harder to read.
check() {
	label=$1
	shift
	expected=$(cat)
	actual=$("$@" 2>&1 | grep -v '^[[:space:]]*$' || true)
	checks=$((checks + 1))
	if [ "$actual" = "$expected" ]; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label"
		echo "       expected:"
		echo "$expected" | sed 's/^/         /'
		echo "       got:"
		echo "$actual" | sed 's/^/         /'
	fi
}

ok() {
	checks=$((checks + 1))
	echo "ok   - $1"
}

fail() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	echo "FAIL - $1"
}

check_status() {
	label=$1
	want=$2
	shift 2
	"$@" >/dev/null 2>&1 && got=0 || got=$?
	checks=$((checks + 1))
	if [ "$got" = "$want" ]; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label: exit status $got, expected $want"
	fi
}

# ldapsearch(1) with the arguments every one of these searches wants: simple
# authentication, no SASL, LDIF with none of the comment lines, and no implicit
# operational attributes.
search() {
	ldapsearch -x -LLL -o ldif-wrap=no -H "$URI" "$@"
}

start_stns() {
	_saddr=127.0.0.1
	_prev=
	for a in "$@"; do
		[ "$_prev" = "--listen" ] && _saddr=$a
		_prev=$a
	done
	$PYTHON "$MOCK" "$STNS_PORT" "$@" >>"$WORK/stns.log" 2>&1 &
	stns_pid=$!
	wait_for_port "$STNS_PORT" "$_saddr"
}

stop_stns() {
	if [ -n "$stns_pid" ]; then
		kill "$stns_pid" 2>/dev/null || true
		wait "$stns_pid" 2>/dev/null || true
		stns_pid=
	fi
}

start_daemon() {
	"$SRCDIR/ldapstns" -d -f "$CONF" >>"$WORK/ldapstns.log" 2>&1 &
	ldap_pid=$!
	wait_for_port "$LDAP_PORT" || { cat "$WORK/ldapstns.log" >&2; exit 1; }
}

stop_daemon() {
	if [ -n "$ldap_pid" ]; then
		kill "$ldap_pid" 2>/dev/null || true
		wait "$ldap_pid" 2>/dev/null || true
		ldap_pid=
	fi
}

# The ten keys the mock server gives stnskeys.  Nine are predictable by
# construction and the tenth is 768 characters, so a literal fixture would be
# unreadable and would drift from the server the first time either changed.
expected_keys() {
	i=1
	while [ "$i" -lt 10 ]; do
		printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKEY%02d stnskeys\n' "$i"
		i=$((i + 1))
	done
	awk 'BEGIN {
		s = sprintf("%716s", "")
		gsub(/ /, "D", s)
		print "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ" s " stnskeys@long"
	}'
}

# A self-signed certificate that is also its own CA, so it can be handed to
# tls.ca.  Written through a configuration file rather than -addext, which not
# every openssl(1) this has to run under agrees about.
make_cert() {
	cat >"$WORK/openssl.cnf" <<-'CNF'
	[req]
	distinguished_name = dn
	x509_extensions = ext
	prompt = no
	[dn]
	CN = localhost
	[ext]
	subjectAltName = DNS:localhost,IP:127.0.0.1
	basicConstraints = critical,CA:TRUE
	CNF
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-config "$WORK/openssl.cnf" \
		-keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1
}

# How many requests the mock server has been asked, which is how the refresh
# timer is observed without waiting on anything to change.
stns_requests() {
	$PYTHON -c "
import json, urllib.request
print(len(json.load(urllib.request.urlopen('http://127.0.0.1:$STNS_PORT/v1/_requests'))))"
}

# wait_for_port PORT [ADDRESS].  create_connection rather than a bare socket,
# because the address may be an IPv6 one and the family has to follow it.
wait_for_port() {
	_addr=${2:-127.0.0.1}
	i=0
	while [ "$i" -lt 100 ]; do
		if $PYTHON -c "import socket, sys
try:
    socket.create_connection(('$_addr', $1), 0.2).close()
except OSError:
    sys.exit(1)" 2>/dev/null; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	echo "nothing came up on $_addr port $1" >&2
	return 1
}

command -v ldapsearch >/dev/null 2>&1 || {
	echo "skip - ldapsearch(1) is not installed" >&2
	exit 0
}

rm -rf "$WORK"
mkdir -p "$WORK/etc/stns/client"

echo "== building against $WORK/etc =="
cd "$SRCDIR"
# MAKE is deliberately unquoted: a caller may pass it with arguments, as in
# MAKE="make LOCALBASE=/usr/pkg", and those have to be split into words.
# shellcheck disable=SC2086
$MAKE clean >/dev/null
# shellcheck disable=SC2086
$MAKE SYSCONFDIR="$WORK/etc" all >"$WORK/build.log" 2>&1 || {
	cat "$WORK/build.log" >&2
	exit 1
}

cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
EOF

cat >"$CONF" <<EOF
listen = "127.0.0.1"
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF

start_stns
start_daemon

echo "== the root DSE =="

# macOS never has a search base configured: RFC2307.plist leaves it as "%!",
# which means "read namingContexts from the root DSE".  If this one search
# fails, nothing else about the daemon matters.
check "namingContexts is advertised" search -b "" -s base "(objectclass=*)" namingContexts <<'EOF'
dn:
namingContexts: dc=stns
EOF

check "and LDAPv3 is claimed" search -b "" -s base "(objectclass=*)" supportedLDAPVersion <<'EOF'
dn:
supportedLDAPVersion: 3
EOF

# A subtree search of the naming context must not sweep the root DSE up with
# the real entries: it is not part of any naming context.
check "the root DSE is not in the tree" \
	search -b "dc=stns" -s sub "(objectclass=OpenLDAProotDSE)" dn </dev/null

echo "== the search opendirectoryd makes =="

check "a user by name, with the RFC2307.plist filter" \
	search -b "dc=stns" \
	"(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=shadowAccount))(uid=stnsuser))" \
	uid uidNumber gidNumber cn homeDirectory loginShell <<'EOF'
dn: uid=stnsuser,cn=users,dc=stns
uid: stnsuser
cn: STNS test user
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/stnsuser
loginShell: /bin/sh
EOF

check "a user by uidNumber" search -b "dc=stns" "(&(objectClass=posixAccount)(uidNumber=1003))" uid <<'EOF'
dn: uid=stnskeys,cn=users,dc=stns
uid: stnskeys
EOF

check "a group by name, with its members" \
	search -b "dc=stns" "(&(objectClass=posixGroup)(cn=stnsgroup))" cn gidNumber memberUid <<'EOF'
dn: cn=stnsgroup,cn=groups,dc=stns
cn: stnsgroup
gidNumber: 1001
memberUid: stnsuser
memberUid: stnsdefault
EOF

check "the groups a user is in" \
	search -b "dc=stns" "(&(objectClass=posixGroup)(memberUid=stnsuser))" cn <<'EOF'
dn: cn=stnsgroup,cn=groups,dc=stns
cn: stnsgroup
dn: cn=stnsops,cn=groups,dc=stns
cn: stnsops
dn: cn=stnsextra,cn=groups,dc=stns
cn: stnsextra
EOF

# An empty gecos has to fall back to the account name: cn is RealName, and
# macOS shows it wherever it shows a person.
check "cn falls back to the account name" search -b "dc=stns" "(uid=stnsdefault)" cn sn <<'EOF'
dn: uid=stnsdefault,cn=users,dc=stns
cn: stnsdefault
sn: stnsdefault
EOF

echo "== withholding the password hash =="

# The one entry the mock server gives a real hash to.  Nothing may hand it out
# without expose_password, and this daemon listens where every process on the
# machine can reach it.
check "userPassword is not served" search -b "dc=stns" "(uid=stnshash)" userPassword <<'EOF'
dn: uid=stnshash,cn=users,dc=stns
EOF

check "and cannot be found by filtering on it" \
	search -b "dc=stns" "(userPassword=*)" dn </dev/null

echo "== filters =="

check "substring, initial" search -b "dc=stns" "(&(objectClass=posixAccount)(uid=stnsk*))" uid <<'EOF'
dn: uid=stnskeys,cn=users,dc=stns
uid: stnskeys
EOF

check "substring, final" search -b "dc=stns" "(&(objectClass=posixAccount)(uid=*hash))" uid <<'EOF'
dn: uid=stnshash,cn=users,dc=stns
uid: stnshash
EOF

check "substring, any" search -b "dc=stns" "(&(objectClass=posixGroup)(cn=*bi*))" cn <<'EOF'
dn: cn=stnsbig,cn=groups,dc=stns
cn: stnsbig
EOF

# Numeric, not textual: compared as strings, "999" would sort after "1003".
check "greaterOrEqual on a number" \
	search -b "dc=stns" "(&(objectClass=posixAccount)(uidNumber>=1003))" uid <<'EOF'
dn: uid=stnshash,cn=users,dc=stns
uid: stnshash
dn: uid=stnskeys,cn=users,dc=stns
uid: stnskeys
EOF

check "not" search -b "dc=stns" "(&(objectClass=posixGroup)(!(memberUid=*)))" cn <<'EOF'
dn: cn=stnsempty,cn=groups,dc=stns
cn: stnsempty
EOF

check "a name is matched without regard to case" search -b "dc=stns" "(UID=STNSUSER)" uid <<'EOF'
dn: uid=stnsuser,cn=users,dc=stns
uid: stnsuser
EOF

echo "== scopes and bases =="

check "one level below the suffix" search -b "dc=stns" -s one "(objectclass=*)" cn <<'EOF'
dn: cn=users,dc=stns
cn: users
dn: cn=groups,dc=stns
cn: groups
EOF

check "a base with spaces in it is the same base" \
	search -b "cn=users, DC=stns" -s base "(objectclass=*)" cn <<'EOF'
dn: cn=users,dc=stns
cn: users
EOF

# 32 is noSuchObject.  A base scope read of a DN that is not here has to say
# so; answering "success, no entries" would tell a client the entry exists and
# is merely empty.
check_status "a base that does not exist is noSuchObject" 32 \
	search -b "ou=Nowhere,dc=stns" -s base "(objectclass=*)"

check_status "but an empty subtree search is a success" 0 \
	search -b "dc=stns" "(uid=nobodyhere)"

echo "== SSH keys =="

# Ten values in one attribute, in order, and the last of them 768 characters.
# Ten is a SET this size has never been asked to encode, and the long one is
# past the short form of a BER length - a value that came back truncated here
# would be an SSH key that silently stops working for one person.
check "all ten keys, in order" search -b "dc=stns" "(uid=stnskeys)" sshPublicKey <<EOF
dn: uid=stnskeys,cn=users,dc=stns
$(expected_keys | sed 's/^/sshPublicKey: /')
EOF

checks=$((checks + 1))
longest=$(search -b "dc=stns" "(uid=stnskeys)" sshPublicKey |
	awk '/^sshPublicKey: / { if (length($0) - 14 > n) n = length($0) - 14 } END { print n + 0 }')
if [ "$longest" = "768" ]; then
	echo "ok   - and the long one is whole, not wrapped or truncated"
else
	failures=$((failures + 1))
	echo "FAIL - the longest key came back at $longest characters, expected 768"
fi

# The key list also has to survive being filtered on, since a substring search
# over a long value is a different path through filter.c than returning it.
check "a key can be found by a substring of itself" \
	search -b "dc=stns" "(sshPublicKey=*KEY07*)" uid <<'EOF'
dn: uid=stnskeys,cn=users,dc=stns
uid: stnskeys
EOF

echo "== a large entry =="

# 300 members, which is past any first guess at a buffer size and well past the
# short form of a BER length.
checks=$((checks + 1))
n=$(search -b "dc=stns" "(cn=stnsbig)" memberUid | grep -c '^memberUid: ' || true)
if [ "$n" = "300" ]; then
	echo "ok   - a group with 300 members comes back whole"
else
	failures=$((failures + 1))
	echo "FAIL - a group with 300 members returned $n of them"
fi

echo "== requiring a bind =="

stop_daemon

cat >"$CONF" <<EOF
listen = "127.0.0.1"
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
bind_dn = "cn=reader,dc=stns"
bind_password = "sekrit"
expose_password = true
EOF

start_daemon

# 50 is insufficientAccessRights.  With a bind_dn configured the directory is
# closed, and that is what lets expose_password be allowed at all.
check_status "an anonymous search is refused" 50 search -b "dc=stns" "(uid=stnsuser)"

# 49 is invalidCredentials.
check_status "the wrong password is refused" 49 \
	ldapsearch -x -LLL -H "$URI" -D "cn=reader,dc=stns" -w wrong -b "dc=stns" "(uid=stnsuser)"

check "the right one is not" \
	ldapsearch -x -LLL -o ldif-wrap=no -H "$URI" -D "cn=reader,dc=stns" -w sekrit \
	-b "dc=stns" "(uid=stnsuser)" uid <<'EOF'
dn: uid=stnsuser,cn=users,dc=stns
uid: stnsuser
EOF

# userPassword has Octet String syntax, so ldapsearch(1) always writes it out
# base64 encoded whatever is in it.  The value below is $6$stnssalt$0123456789abcdef,
# which is what the mock server serves for this user.
check "and it may read the hash" \
	ldapsearch -x -LLL -o ldif-wrap=no -H "$URI" -D "cn=reader,dc=stns" -w sekrit \
	-b "dc=stns" "(uid=stnshash)" userPassword <<'EOF'
dn: uid=stnshash,cn=users,dc=stns
userPassword:: JDYkc3Ruc3NhbHQkMDEyMzQ1Njc4OWFiY2RlZg==
EOF

echo "== fetching over TLS =="

# Everything above talks to the mock server over plain HTTP on 127.0.0.1,
# which never touches libcurl's TLS path: not the handshake, not the trust
# store, not the hostname check.  A daemon that passes all of that and cannot
# reach an https:// API on a real machine would look perfectly healthy here.
stop_daemon
stop_stns
make_cert
start_stns --tls "$WORK/cert.pem,$WORK/key.pem"

# localhost rather than 127.0.0.1, so the name in the certificate is checked.
cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "https://localhost:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
ssl_verify = true
[tls]
ca = "$WORK/cert.pem"
EOF

cat >"$CONF" <<EOF
listen = "127.0.0.1"
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF

start_daemon

check "the directory arrived over TLS" search -b "dc=stns" "(uid=stnsuser)" uid uidNumber <<'EOF'
dn: uid=stnsuser,cn=users,dc=stns
uid: stnsuser
uidNumber: 1001
EOF

stop_daemon

# With the certificate untrusted the first fetch cannot succeed, and the
# daemon must exit rather than come up with an empty directory - which would
# have opendirectoryd answer "no such user" for everybody in it.  This checks
# the TLS verification and that rule at the same time, because a daemon that
# started here would be failing at both.
cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "https://localhost:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
ssl_verify = true
EOF

check_status "an untrusted certificate stops it starting at all" 1 \
	"$SRCDIR/ldapstns" -d -f "$CONF"

echo "== the refresh timer =="

stop_stns
start_stns

cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
EOF

# Ten seconds is the floor the configuration allows, which makes this the
# shortest honest way to watch the timer actually fire.  Nothing else in this
# file has ever waited for one: every phase so far sets an hour and relies on
# the fetch that happens at startup.
cat >"$CONF" <<EOF
listen = "127.0.0.1"
port = $LDAP_PORT
suffix = "dc=stns"
interval = 10
EOF

start_daemon

before=$(stns_requests)
sleep 13
after=$(stns_requests)

checks=$((checks + 1))
if [ "$after" -gt "$before" ]; then
	echo "ok   - the directory was fetched again on the interval"
else
	failures=$((failures + 1))
	echo "FAIL - no refresh happened in thirteen seconds ($before -> $after)"
fi

echo "== when the API goes away =="

# The daemon has to keep serving what it already has.  An API server that is
# briefly unreachable must not empty the directory out from under everybody
# logged in, and with a ten second interval this is several failed refreshes.
stop_stns
sleep 13

check "a lookup still works from the last good snapshot" \
	search -b "dc=stns" "(uid=stnsuser)" uid <<'EOF'
dn: uid=stnsuser,cn=users,dc=stns
uid: stnsuser
EOF

checks=$((checks + 1))
if kill -0 "$ldap_pid" 2>/dev/null; then
	echo "ok   - and the daemon is still running"
else
	failures=$((failures + 1))
	echo "FAIL - the daemon exited when the API went away"
	tail -20 "$WORK/ldapstns.log"
fi

start_stns

echo "== several clients at once =="

# One child per connection is the whole concurrency design, and nothing has
# yet opened two at the same time.
# Each search's own pid is kept, and only those are waited for.  A bare wait
# here waits for every background job the script has, which includes the mock
# server and the daemon itself - neither of which is going to exit.
conc_pids=
i=0
while [ "$i" -lt 8 ]; do
	search -b "dc=stns" "(uid=stnsuser)" uid >"$WORK/conc.$i" 2>&1 &
	conc_pids="$conc_pids $!"
	i=$((i + 1))
done
# shellcheck disable=SC2086  # a list of pids, split on purpose
for p in $conc_pids; do
	wait "$p" 2>/dev/null || true
done

n=$(grep -l '^uid: stnsuser$' "$WORK"/conc.* 2>/dev/null | wc -l | tr -d ' ')
checks=$((checks + 1))
if [ "$n" = "8" ]; then
	echo "ok   - eight simultaneous searches were all answered"
else
	failures=$((failures + 1))
	echo "FAIL - $n of 8 simultaneous searches were answered"
fi

echo "== IPv6 =="

# Both loopbacks, which is the default and has never been exercised: every
# phase above pins listen to 127.0.0.1.  It matters here more than it looks -
# on macOS "localhost" resolves to ::1 first, so a daemon that only listened
# on the IPv4 address would be unreachable to anybody who ran
# "dsconfigldap -a localhost", with nothing anywhere to say why.
stop_daemon
stop_stns
start_stns --listen ::1

# The API over IPv6 as well, which is a URL spelling with brackets in it that
# nothing in this daemon has ever had to assemble.
cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "http://[::1]:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
EOF

cat >"$CONF" <<EOF
listen = ["127.0.0.1", "::1"]
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF

start_daemon

check "a search over IPv4, with the API reached over IPv6" \
	search -b "dc=stns" "(uid=stnsuser)" uid <<'EOF'
dn: uid=stnsuser,cn=users,dc=stns
uid: stnsuser
EOF

checks=$((checks + 1))
if ldapsearch -x -LLL -o ldif-wrap=no -H "ldap://[::1]:$LDAP_PORT" \
	-b "dc=stns" "(uid=stnsuser)" uid 2>/dev/null | grep -q '^uid: stnsuser$'; then
	echo "ok   - and the same search over IPv6"
else
	failures=$((failures + 1))
	echo "FAIL - the IPv6 listener did not answer"
	tail -10 "$WORK/ldapstns.log"
fi

# An address that cannot be bound must not stop the ones that can.  A machine
# with IPv6 turned off should still get its IPv4 listener rather than a daemon
# that refuses to start.
stop_daemon
cat >"$CONF" <<EOF
listen = ["127.0.0.1", "203.0.113.1"]
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF

if start_daemon; then
	ok "an address that cannot be bound does not stop the others"
else
	fail "one unbindable address stopped the daemon starting"
fi

# None of them binding is a different matter.
stop_daemon
cat >"$CONF" <<EOF
listen = ["203.0.113.1"]
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF
check_status "but no address at all is fatal" 1 "$SRCDIR/ldapstns" -d -f "$CONF"

# A hostname is refused rather than resolved: "listen" says which socket to
# open, and a name that resolves to three things does not say that.
cat >"$CONF" <<EOF
listen = "localhost"
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF
check_status "and a hostname is not an address" 1 "$SRCDIR/ldapstns" -d -f "$CONF"

# Put it back for whatever comes next.
stop_stns
start_stns
cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
EOF
cat >"$CONF" <<EOF
listen = "127.0.0.1"
port = $LDAP_PORT
suffix = "dc=stns"
interval = 3600
EOF
start_daemon

echo "== refusing to start on a dangerous configuration =="

cat >"$WORK/etc/bad.conf" <<EOF
suffix = "dc=stns"
expose_password = true
EOF

# Serving crypt hashes to anonymous clients on a socket every process on the
# machine can reach is not a thing to warn about and then do anyway.
check_status "expose_password without a bind_dn is refused" 1 \
	"$SRCDIR/ldapstns" -n -f "$WORK/etc/bad.conf"

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
