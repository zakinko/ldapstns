#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Check that the ident lines in the sample configurations are really
# substituted.
#
# git archive expands $Format:...$ only for paths marked export-subst in
# .gitattributes, and nothing complains if that marking is lost - the released
# tarball would just quietly carry the raw placeholder for ever.  So build an
# archive the way a release does and look at what came out.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/ldapstns_ident}
FILES="stns.conf.example ldapstns.conf.example"

cd "$SRCDIR"
if ! git rev-parse --git-dir >/dev/null 2>&1; then
	echo "skip - not a git checkout" >&2
	exit 0
fi

rm -rf "$WORK"
mkdir -p "$WORK"
# shellcheck disable=SC2086
git archive --format=tar HEAD $FILES | tar -x -C "$WORK"

rc=0
for f in $FILES; do
	line=$(head -1 "$WORK/$f")
	name=${f%.example}

	echo "  $line"
	# The single quotes are the point: this looks for the literal
	# placeholder, which is exactly the thing that must not have survived.
	# shellcheck disable=SC2016
	case "$line" in
	*'$Format:'*)
		echo "FAIL - $f was not substituted; is the export-subst" >&2
		echo "       attribute still set for it in .gitattributes?" >&2
		rc=1
		continue
		;;
	esac
	case "$line" in
	"# \$SNOWRABBIT: $name,v "*' Exp $') ;;
	*)
		echo "FAIL - the ident line in $f does not have the expected shape" >&2
		rc=1
		;;
	esac
done

rm -rf "$WORK"
[ "$rc" -eq 0 ] && echo "ok   - the ident lines are substituted on export"
exit "$rc"
