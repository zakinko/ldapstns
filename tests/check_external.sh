#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Check the bundled third party code under external/ against external/MANIFEST.
#
# Two separate questions, because they fail for different reasons and want
# different answers:
#
#   integrity   do the bundled files still match the recorded checksums?
#               A mismatch means somebody edited a bundled copy in place,
#               which is exactly what must not happen: the whole point of
#               recording an upstream revision is that the copy is that
#               revision and nothing else.  Checked on every build.
#
#   freshness   is the recorded revision still upstream's current one, and
#               does upstream at that revision still match what is bundled?
#               A mismatch means the copy has quietly rotted.  Needs the
#               network, so it is checked on a schedule with --upstream.

set -eu

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
MANIFEST=$SRCDIR/external/MANIFEST
WORK=${WORK:-/tmp/ldapstns_external}

check_upstream=0
[ "${1:-}" = "--upstream" ] && check_upstream=1

failures=0
skipped=0

fail() {
	echo "FAIL - $1" >&2
	failures=$((failures + 1))
}

sha256_of() {
	if command -v sha256 >/dev/null 2>&1; then
		sha256 -q "$1"
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# curl first because every CI image has it; then NetBSD's ftp(1) and
# FreeBSD's fetch(1), so the script also works on a bare system.
fetch_to() {
	# -f so that a 404 is a failed fetch and not a file containing GitHub's
	# apology, which would otherwise be reported as the bundled copy
	# differing from upstream - true, but never the useful thing to say.
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	elif command -v ftp >/dev/null 2>&1; then
		ftp -o "$2" "$1" >/dev/null 2>&1
	elif command -v fetch >/dev/null 2>&1; then
		fetch -q -o "$2" "$1"
	else
		return 1
	fi
}

echo "== integrity: the bundled copies match external/MANIFEST =="
while read -r kind a b _; do
	[ "$kind" = file ] || continue
	path=$SRCDIR/external/$b
	if [ ! -f "$path" ]; then
		fail "$b is in the manifest but not in the tree"
		continue
	fi
	got=$(sha256_of "$path")
	if [ "$got" = "$a" ]; then
		echo "ok   - external/$b"
	else
		fail "external/$b has been modified"
		echo "       manifest: $a" >&2
		echo "       tree:     $got" >&2
	fi
done < "$MANIFEST"

# Anything in the tree that the manifest does not account for is untracked
# provenance, which is the same problem seen from the other side.  Build
# output is not provenance, and the objects land beside their sources, so
# skip what .gitignore already ignores.
for f in $(cd "$SRCDIR/external" && find . -type f \
    ! -name MANIFEST ! -name '*.o' ! -name '*.a' ! -name '*.so' \
    ! -name '*.core' ! -name '*~' |
    sed 's|^\./||' | sort); do
	# By field rather than by line, because a file line may carry a fourth
	# one: matching the path at end of line silently stopped finding
	# anything the moment the first component with an upstream path was
	# added, and reported every one of its files as untracked.
	if ! awk -v want="$f" '$1 == "file" && $3 == want { found = 1 }
	    END { exit !found }' "$MANIFEST"; then
		fail "external/$f is in the tree but not in the manifest"
	fi
done

if [ "$check_upstream" -eq 0 ]; then
	echo
	echo "(run with --upstream to check the recorded revisions against upstream)"
	[ "$failures" -eq 0 ] || exit 1
	exit 0
fi

echo
echo "== freshness: the recorded revisions are still current =="
rm -rf "$WORK"
mkdir -p "$WORK"

component=""
repo=""
ref=""
imported=""

while read -r kind a b c d; do
	case "$kind" in
	component)
		component=$a
		repo=$b
		ref=$c
		imported=$d
		head=""
		if fetch_to "https://api.github.com/repos/$repo/commits/HEAD" \
		    "$WORK/head.json" 2>/dev/null; then
			head=$(sed -n 's/.*"sha"[ ]*:[ ]*"\([0-9a-f]\{40\}\)".*/\1/p' \
			    "$WORK/head.json" | head -1)
		fi
		if [ -z "$head" ]; then
			# Also what a private repository looks like from here.
			# The integrity half above still checked every file
			# against its checksum, so this is a check that could
			# not run rather than a check that failed - but it is
			# worth saying which repository went quiet, because a
			# manifest nobody can verify is one nobody will notice
			# rotting.
			echo "warn - could not ask github for $repo; it may be" \
			    "private or unreachable, so its freshness is" \
			    "unchecked" >&2
			skipped=$((skipped + 1))
		elif [ "$head" = "$ref" ]; then
			echo "ok   - $component is at upstream HEAD ($(echo "$ref" | cut -c1-12))"
		else
			fail "$component is behind upstream"
			echo "       bundled:  $ref ($imported)" >&2
			echo "       upstream: $head" >&2
			echo "       see https://github.com/$repo/compare/$ref...$head" >&2
		fi
		;;
	file)
		[ -n "$repo" ] || continue
		# The fourth field is where the file lives in the upstream
		# repository.  Components whose files sit at the repository
		# root - which is every parser bundled here - leave it out and
		# are found by basename.
		upstream=${c:-$(basename "$b")}
		name=$(echo "$b" | tr / _)
		url="https://raw.githubusercontent.com/$repo/$ref/$upstream"
		if ! fetch_to "$url" "$WORK/$name" 2>/dev/null; then
			continue
		fi
		if cmp -s "$WORK/$name" "$SRCDIR/external/$b"; then
			echo "ok   - external/$b is $repo@$(echo "$ref" | cut -c1-12) verbatim"
		else
			fail "external/$b differs from $repo at the recorded revision"
		fi
		;;
	esac
done < "$MANIFEST"

rm -rf "$WORK"

echo
if [ "$failures" -eq 0 ]; then
	if [ "$skipped" -gt 0 ]; then
		echo "external/ is intact; $skipped component(s) could not be" \
		    "checked against upstream"
		exit 0
	fi
	echo "external/ is intact and up to date"
	exit 0
fi
echo "$failures problem(s) found" >&2
exit 1
