# SPDX-License-Identifier: MIT
# offline-xdev.sh BINARY DATADIR
#
# --xdev: a filesystem mounted inside ROOT (a tmpfs holding a G3 copy,
# mounted in a user and mount namespace) is searched without --xdev and
# skipped with it, for rg and grep.  Skipped where unprivileged user
# namespaces are not available.
. "$(dirname "$0")/lib.sh"

user_ns || skip "no unprivileged user namespaces (or no unshare)"

ROOT=$T/tree
mkdir -p "$ROOT/mnt" "$ROOT/etc"
cp "$AAA_PEM" "$ROOT/etc/aaa.pem"
ns_mount "$ROOT/mnt" "$G3_PEM" g3.pem
ran=0
for s in rg grep; do
	link_tool "$T/bin-$s" "$s" 2>/dev/null || { note "$s not installed"; continue; }
	ran=1
	run $s-all PATH="$T/bin-$s" -- --offline="$ROOT" --searcher=$s
	expect_rc $s-all 1
	expect_line $s-all "[VULNERABLE] @ROOT@/etc/aaa.pem | Comodo-AAA | PEM bundle trusts $AAA_CN"
	expect_line $s-all "[VULNERABLE] @ROOT@/mnt/g3.pem | emSign-G3 | PEM bundle trusts $G3_CN"
	show_if_needed $s-all

	run $s-xdev PATH="$T/bin-$s" -- --offline="$ROOT" --searcher=$s --xdev
	expect_rc $s-xdev 1
	expect_line $s-xdev "[VULNERABLE] @ROOT@/etc/aaa.pem | Comodo-AAA | PEM bundle trusts $AAA_CN"
	expect_line $s-xdev "[PATCHED]    offline search of @ROOT@ ($s) | emSign-G3 | no trusted copy found"
	expect_no_line $s-xdev "/mnt/"
	show_if_needed $s-xdev
done
[ "$ran" = 1 ] || skip "neither rg nor grep installed"
finish
