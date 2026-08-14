#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Point the real opendirectoryd at the real daemon, and ask the machine.
#
# tests/integration.sh proves the daemon speaks LDAP, by asking OpenLDAP's own
# ldapsearch(1).  That is as far as a test without root can go, and it leaves
# one thing unproven: whether opendirectoryd - which is the only client this
# daemon exists for - can actually resolve a user through it.  ypstns has the
# equivalent check and has had it from the start; getent(1) and id(1) there go
# through libc, and nothing else in that suite shows the maps are the shape a
# real lookup needs.  This is that check.
#
# It is also the only thing that exercises binding port 389 as root and then
# dropping to an unprivileged user, which every other phase avoids by using a
# high port.
#
# THIS CHANGES THE MACHINE IT RUNS ON.  It adds an LDAPv3 node to Open
# Directory and puts it in the search policy, which is a system-wide setting
# and not a thing to do to a laptop out of curiosity.  It is removed again on
# the way out, however the script exits.  Because of that it refuses to run
# unless it is asked twice: as root, and with LDAPSTNS_OD_TEST=yes in the
# environment.  CI sets both; nothing else should.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
STNS_PORT=${STNS_PORT:-11108}
PYTHON=${PYTHON:-python3}
WORK=${WORK:-/tmp/ldapstns_od}
NODE=${NODE:-127.0.0.1}

MOCK=$SRCDIR/external/bsd/libstns/tests/mock_stns_server.py
CONF=$WORK/etc/ldapstns.conf

checks=0
failures=0
stns_pid=
ldap_pid=
node_added=

# shellcheck disable=SC2317  # reached through the trap below
cleanup() {
	set +e
	if [ -n "$node_added" ]; then
		dsconfigldap -f -r "$NODE" >/dev/null 2>&1
		dscacheutil -flushcache
		killall -HUP opendirectoryd 2>/dev/null
	fi
	[ -n "$ldap_pid" ] && kill "$ldap_pid" 2>/dev/null
	[ -n "$stns_pid" ] && kill "$stns_pid" 2>/dev/null
	rm -rf "$WORK"
	set -e
}
trap cleanup EXIT INT TERM

ok() {
	checks=$((checks + 1))
	echo "ok   - $1"
}

fail() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	echo "FAIL - $1"
}

# Compare a command's output against a fixture, blank lines dropped.
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

# Everything worth knowing when opendirectoryd will not answer.
#
# The daemon's own log is first and is the most useful of the three: it says
# whether opendirectoryd connected at all, whether it bound, and what it
# searched for - none of which opendirectoryd itself can be asked.
diagnose() {
	echo "--- ldapstns log"
	sed 's/^/    /' "$WORK/ldapstns.log"
	echo "--- nodes Open Directory knows about"
	dscl localhost -list /LDAPv3 2>&1 | sed 's/^/    /'
	echo "--- search policy"
	dscl /Search -read / CSPSearchPath 2>&1 | sed 's/^/    /'
	echo "--- what dsconfigldap said"
	sed 's/^/    /' "$WORK/dsconfigldap.log"
}

# opendirectoryd caches, and it does not answer the instant a node is added.
# Everything below is asked in a loop rather than once, so that a slow machine
# fails the check for being wrong rather than for being slow.
retry() {
	want=$1
	shift
	i=0
	while [ "$i" -lt 60 ]; do
		if "$@" 2>/dev/null | grep -q "$want"; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.5
	done
	return 1
}

[ "$(uname -s)" = "Darwin" ] || {
	echo "skip - macOS only" >&2
	exit 0
}
[ "$(id -u)" = "0" ] || {
	echo "skip - this one needs root: it binds port 389 and reconfigures Open Directory" >&2
	exit 0
}
[ "${LDAPSTNS_OD_TEST:-}" = "yes" ] || {
	echo "skip - set LDAPSTNS_OD_TEST=yes to let this reconfigure Open Directory" >&2
	exit 0
}

rm -rf "$WORK"
mkdir -p "$WORK/etc/stns/client"

echo "== building against $WORK/etc =="
cd "$SRCDIR"
make clean >/dev/null
make SYSCONFDIR="$WORK/etc" all >"$WORK/build.log" 2>&1 || {
	cat "$WORK/build.log" >&2
	exit 1
}

cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
EOF

# Port 389 and the default user, which is the arrangement a real installation
# has: bind as root, then drop.  Every other phase in this repository uses a
# high port and stays unprivileged, so this is the only place drop_privileges()
# is ever reached.
cat >"$CONF" <<EOF
port = 389
suffix = "dc=stns"
interval = 3600
EOF

$PYTHON "$MOCK" "$STNS_PORT" >"$WORK/stns.log" 2>&1 &
stns_pid=$!
i=0
while [ "$i" -lt 100 ]; do
	$PYTHON -c "import socket, sys
try:
    socket.create_connection(('127.0.0.1', $STNS_PORT), 0.2).close()
except OSError:
    sys.exit(1)" 2>/dev/null && break
	i=$((i + 1))
	sleep 0.1
done

echo "== the daemon, on port 389, as root then not =="

"$SRCDIR/ldapstns" -d -f "$CONF" >"$WORK/ldapstns.log" 2>&1 &
ldap_pid=$!

i=0
while [ "$i" -lt 100 ]; do
	$PYTHON -c "import socket, sys
try:
    socket.create_connection(('127.0.0.1', 389), 0.2).close()
except OSError:
    sys.exit(1)" 2>/dev/null && break
	i=$((i + 1))
	sleep 0.1
done

if $PYTHON -c "import socket, sys
try:
    socket.create_connection(('127.0.0.1', 389), 0.5).close()
except OSError:
    sys.exit(1)" 2>/dev/null; then
	ok "it bound the privileged port"
else
	fail "nothing is listening on 389"
	cat "$WORK/ldapstns.log"
	exit 1
fi

# It was started as root and must not still be root.  ps(1) is asked rather
# than the log, because the log is the daemon's own account of itself.
owner=$(ps -o user= -p "$ldap_pid" | tr -d ' ')
checks=$((checks + 1))
if [ "$owner" = "nobody" ]; then
	echo "ok   - and gave up root, running as nobody"
else
	failures=$((failures + 1))
	echo "FAIL - the daemon is running as \"$owner\", expected nobody"
fi

echo "== adding the node =="

# No search base, no mapping, no schema: RFC2307.plist leaves the search base
# as "%!" and opendirectoryd reads namingContexts from the root DSE.  If that
# were wrong, this one command would be where it showed.
if dsconfigldap -f -a "$NODE" >"$WORK/dsconfigldap.log" 2>&1; then
	node_added=yes
	ok "dsconfigldap added the node with no other argument"
else
	fail "dsconfigldap refused the node"
	cat "$WORK/dsconfigldap.log"
	exit 1
fi

dscacheutil -flushcache
killall -HUP opendirectoryd 2>/dev/null || true

# What dsconfigldap(8) actually wrote.
#
# It is printed every run, not only on failure, because the one thing this
# whole exercise turns on is which mapping template opendirectoryd chose - and
# that is a decision it makes by probing the server, not one this daemon or
# the command line gets to state.  Reading it out of the generated
# configuration is the only way to know rather than assume.
echo "--- the node configuration dsconfigldap generated"
plutil -convert xml1 -o - "/Library/Preferences/OpenDirectory/Configurations/LDAPv3/$NODE.plist" \
	2>/dev/null | sed 's/^/    /' | head -80 || echo "    (no configuration file)"
echo "--- odutil"
odutil show configuration "/LDAPv3/$NODE" 2>&1 | sed 's/^/    /' | head -40

echo "== through the node itself =="

if retry 'stnsuser' dscl "/LDAPv3/$NODE" -list /Users; then
	ok "dscl lists the directory's users"
else
	fail "dscl could not list users from the node"
	diagnose
	exit 1
fi

# One attribute at a time, because dscl(1) does not promise to print several
# in the order they were asked for and a fixture that assumed it would be
# testing dscl rather than this daemon.
check "RecordName maps to uid" dscl "/LDAPv3/$NODE" -read /Users/stnsuser RecordName <<'EOF'
RecordName: stnsuser
EOF
check "UniqueID maps to uidNumber" dscl "/LDAPv3/$NODE" -read /Users/stnsuser UniqueID <<'EOF'
UniqueID: 1001
EOF
check "PrimaryGroupID maps to gidNumber" dscl "/LDAPv3/$NODE" -read /Users/stnsuser PrimaryGroupID <<'EOF'
PrimaryGroupID: 1001
EOF
check "NFSHomeDirectory maps to homeDirectory" \
	dscl "/LDAPv3/$NODE" -read /Users/stnsuser NFSHomeDirectory <<'EOF'
NFSHomeDirectory: /home/stnsuser
EOF
check "UserShell maps to loginShell" dscl "/LDAPv3/$NODE" -read /Users/stnsuser UserShell <<'EOF'
UserShell: /bin/sh
EOF
# Containment rather than an exact match, because dscl(1) puts a value with a
# space in it on a continuation line of its own:
#
#	RealName:
#	 STNS test user
#
# which is dscl's formatting and nothing to do with what came off the wire.
checks=$((checks + 1))
if dscl "/LDAPv3/$NODE" -read /Users/stnsuser RealName 2>/dev/null | grep -q 'STNS test user'; then
	echo "ok   - RealName maps to cn"
else
	failures=$((failures + 1))
	echo "FAIL - RealName did not come through"
	dscl "/LDAPv3/$NODE" -read /Users/stnsuser RealName 2>&1 | sed 's/^/       /'
fi

# The claim in the README, checked rather than asserted: RFC2307.plist has no
# mapping for GeneratedUID, and macOS derives one from the id - the same
# FFFFEEEE-DDDD-CCCC-BBBB-AAAA scheme its own local records below 500 use.
# 1001 is 0x3E9.
check "the UUID macOS derives from the uid" \
	dscl "/LDAPv3/$NODE" -read /Users/stnsuser GeneratedUID <<'EOF'
GeneratedUID: FFFFEEEE-DDDD-CCCC-BBBB-AAAA000003E9
EOF

if retry 'stnsgroup' dscl "/LDAPv3/$NODE" -list /Groups; then
	ok "and the groups"
else
	fail "dscl could not list groups from the node"
fi

check "a group's id" dscl "/LDAPv3/$NODE" -read /Groups/stnsgroup PrimaryGroupID <<'EOF'
PrimaryGroupID: 1001
EOF

# Both members, without insisting on the order or the separator dscl chooses.
for member in stnsuser stnsdefault; do
	checks=$((checks + 1))
	if dscl "/LDAPv3/$NODE" -read /Groups/stnsgroup GroupMembership 2>/dev/null |
		grep -q "$member"; then
		echo "ok   - $member is in the group"
	else
		failures=$((failures + 1))
		echo "FAIL - $member is not in the group"
	fi
done

echo "== through the search policy, which is what everything else uses =="

# This is the check the whole file exists for.  dscl above asks the node by
# name; id(1) and dscacheutil(1) ask the machine, and only get an answer if
# opendirectoryd has the node in its search policy and understood what it
# found there.
if retry '1001' id -u stnsuser; then
	ok "id resolves a directory user"
else
	fail "id could not resolve stnsuser through the search policy"
	diagnose
fi

# The supplementary groups, checked for presence rather than as a whole line:
# macOS composes that list from more than one source and may add groups of its
# own, so an exact match would be a test of the local directory as much as of
# this one.  stnsuser is in stnsgroup, stnsops and stnsextra.
gidlist=$(id -G stnsuser 2>/dev/null || true)
for gid in 1001 1002 1005; do
	checks=$((checks + 1))
	case " $gidlist " in
	*" $gid "*)
		echo "ok   - group $gid is in the supplementary list"
		;;
	*)
		failures=$((failures + 1))
		echo "FAIL - group $gid is missing from \"$gidlist\""
		;;
	esac
done

if retry 'stnsuser' dscacheutil -q user -a name stnsuser; then
	ok "and dscacheutil agrees"
else
	fail "dscacheutil did not find stnsuser"
fi

# A user the directory does not hold must not resolve, or the test above would
# prove nothing about where the answer came from.
checks=$((checks + 1))
if id -u nosuchstnsuser >/dev/null 2>&1; then
	failures=$((failures + 1))
	echo "FAIL - a user that does not exist resolved anyway"
else
	echo "ok   - and a user that does not exist still does not"
fi

echo "== SSH keys, which need none of the above =="

# The other half of the answer to "can STNS be used for keys alone": this
# program is what sshd runs, and it works whether or not any of the machinery
# above is configured at all.
check "stns-key-wrapper, unrelated to Open Directory" \
	sh -c "'$SRCDIR/stns-key-wrapper' stnsuser" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEY stnsuser
EOF

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
