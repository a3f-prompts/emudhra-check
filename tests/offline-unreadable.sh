# SPDX-License-Identifier: MIT
# offline-unreadable.sh BINARY DATADIR
#
# Unreadable paths make the result UNKNOWN (exit 2) for every root that no
# readable file decided, with a note; a root found elsewhere stays
# VULNERABLE.  Skipped as root (root reads everything).
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

[ "$(id -u)" != 0 ] || skip "running as root: nothing is unreadable"

# expect_prefix NAME PREFIX: a line of NAME.out starts with PREFIX
expect_prefix() {
	if norm "$T/$1.out" | awk -v p="$2" 'index($0, p) == 1 { f = 1 } END { exit !f }'; then
		ok "$1: has '$2...'"
	else
		fail "$1: no line starting with '$2'"
		SHOW=1
	fi
}

# a directory we cannot enter
D=$T/locked-dir
mkdir -p "$D/sub"
cp "$G3_PEM" "$AAA_PEM" "$D/sub/"
chmod 000 "$D/sub"
# a readable G3 copy and an unreadable file
F=$T/locked-file
mkdir -p "$F"
cp "$G3_PEM" "$F/g3.pem"
cp "$AAA_PEM" "$F/aaa.pem"
chmod 000 "$F/aaa.pem"

n=0
for s in rg grep; do
	setup_searcher "$s" "$T/bin-$s" 2>/dev/null || link_tool "$T/bin-$s" "$s" 2>/dev/null || {
		note "$s not installed"
		continue
	}
	n=$((n + 1))
	ROOT=$D
	run dir-$s PATH="$T/bin-$s" -- --offline="$ROOT" --searcher=$s
	expect_rc dir-$s 2
	for r in emSign-G3 Comodo-AAA; do
		expect_prefix dir-$s "[UNKNOWN]    offline search of @ROOT@ ($s) | $r | none in readable files; 1 path(s) unreadable, e.g. @ROOT@/sub: Permission denied"
	done
	expect_prefix dir-$s "note: 1 path(s) unreadable, e.g. @ROOT@/sub: Permission denied"
	expect_line dir-$s "Summary: 0 VULNERABLE, 2 UNKNOWN, 0 PATCHED, 0 SKIPPED"
	show_if_needed dir-$s

	ROOT=$F
	run file-$s PATH="$T/bin-$s" -- --offline="$ROOT" --searcher=$s
	expect_rc file-$s 1
	expect_line file-$s "[VULNERABLE] @ROOT@/g3.pem | emSign-G3 | PEM bundle trusts $G3_CN"
	expect_prefix file-$s "[UNKNOWN]    offline search of @ROOT@ ($s) | Comodo-AAA | none in readable files; 1 path(s) unreadable, e.g. @ROOT@/aaa.pem: Permission denied"
	expect_no_line file-$s "offline search of @ROOT@ ($s) | emSign-G3"
	expect_line file-$s "Summary: 1 VULNERABLE, 1 UNKNOWN, 0 PATCHED, 0 SKIPPED"
	show_if_needed file-$s
done
[ "$n" -gt 0 ] || skip "neither rg nor grep installed"
chmod 755 "$D/sub"
chmod 644 "$F/aaa.pem"
expect_tmp_clean
finish
