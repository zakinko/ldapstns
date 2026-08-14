#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Authenticate through the real PAM, against the real module.
#
# Calling the module's functions directly would test the arithmetic and not the
# thing that goes wrong: whether OpenPAM loads the file, finds the entry
# points, runs the stack, and turns what the module returns into the answer
# sshd(8) and su(1) see.  tests/pam_client.c is an ordinary PAM application and
# reaches the module the way they do.
#
# THIS CHANGES THE MACHINE IT RUNS ON, though far less than the Open Directory
# test does: it writes one policy file into /etc/pam.d and removes it again,
# however the script exits.  /etc/pam.d is the only place OpenPAM looks - the
# prefix is compiled into the library - so there is nowhere else to put it.
# Because of that it refuses to run unless asked twice: as root, and with
# LDAPSTNS_PAM_TEST=yes in the environment.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
STNS_PORT=${STNS_PORT:-11109}
PYTHON=${PYTHON:-python3}
WORK=${WORK:-/tmp/ldapstns_pam}
SERVICE=${SERVICE:-stnstest}
POLICY=/etc/pam.d/$SERVICE

checks=0
failures=0
stns_pid=
policy_written=

# shellcheck disable=SC2317  # reached through the trap below
cleanup() {
	set +e
	[ -n "$policy_written" ] && rm -f "$POLICY"
	[ -n "$stns_pid" ] && kill "$stns_pid" 2>/dev/null
	rm -rf "$WORK"
	set -e
}
trap cleanup EXIT INT TERM

check() {
	label=$1
	want=$2
	shift 2
	got=$("$@" 2>&1 || true)
	checks=$((checks + 1))
	if [ "$got" = "$want" ]; then
		echo "ok   - $label"
	else
		failures=$((failures + 1))
		echo "FAIL - $label: expected \"$want\", got \"$got\""
	fi
}

[ "$(uname -s)" = "Darwin" ] || {
	echo "skip - macOS only" >&2
	exit 0
}
[ "$(id -u)" = "0" ] || {
	echo "skip - this one needs root: only /etc/pam.d is consulted for a policy" >&2
	exit 0
}
[ "${LDAPSTNS_PAM_TEST:-}" = "yes" ] || {
	echo "skip - set LDAPSTNS_PAM_TEST=yes to let this write a file into /etc/pam.d" >&2
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
cc -o "$WORK/pam_client" tests/pam_client.c -lpam >>"$WORK/build.log" 2>&1 || {
	cat "$WORK/build.log" >&2
	exit 1
}

cat >"$WORK/etc/stns/client/stns.conf" <<EOF
api_endpoint = "http://127.0.0.1:$STNS_PORT/v1"
cache = false
cache_dir = "$WORK/cache"
EOF

# The module is named by absolute path.  /usr/lib/pam is inside the signed
# system volume and nothing can be added to it, so this is the only way a
# third-party module is ever reached on this system - which makes it the
# arrangement worth testing rather than a shortcut for the test.
cat >"$POLICY" <<EOF
auth required $SRCDIR/pam_stns.so
EOF
policy_written=yes

$PYTHON tests/mock_stns_server.py "$STNS_PORT" >"$WORK/stns.log" 2>&1 &
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

echo "== through PAM =="

# The fixture's stnshash carries a real SHA-512 crypt hash of the password
# below.  tests/crypt_test.c checks the hashing against published vectors;
# what is checked
# here is the module around it and OpenPAM's loading of it.
check "the right password" ok \
	"$WORK/pam_client" "$SERVICE" stnshash "correct horse battery staple"

check "the wrong one" denied \
	"$WORK/pam_client" "$SERVICE" stnshash "incorrect horse battery staple"

# Refused before it is hashed: the hash of an empty string is a perfectly good
# hash, and an account holding one must not be open to pressing return.
check "an empty one" denied "$WORK/pam_client" "$SERVICE" stnshash ""

# stnsuser's password field is empty, so the library stored "*".  A locked
# account is not opened by anything, including by typing the lock.
check "a locked account" denied "$WORK/pam_client" "$SERVICE" stnsuser "anything"
check "nor by its own lock string" denied "$WORK/pam_client" "$SERVICE" stnsuser "*"

# PAM_USER_UNKNOWN rather than PAM_AUTH_ERR, so a stack that lists this module
# before pam_opendirectory carries on to it for a local account.
check "a user the directory does not hold" unknown \
	"$WORK/pam_client" "$SERVICE" nosuchuser "anything"

check "a name outside the character set" unknown \
	"$WORK/pam_client" "$SERVICE" "bad name" "anything"

echo "== when the API is unreachable =="

# Distinct from "wrong password", and the distinction matters to a stack: a
# module that said PAM_AUTH_ERR when it simply could not ask would turn an API
# outage into an account lockout wherever a policy counts failures.
kill "$stns_pid" 2>/dev/null || true
wait "$stns_pid" 2>/dev/null || true
stns_pid=

check "is unavailable, not a denial" unavailable \
	"$WORK/pam_client" "$SERVICE" stnshash "correct horse battery staple"

echo
echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
