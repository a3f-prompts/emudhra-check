# SPDX-License-Identifier: MIT
# fake-all.sh BINARY DATADIR
#
# --all=ROOT runs the offline search of ROOT first, then the online checks
# (fake clients).  With ROOT other than "/", files found offline are not fed
# to the online probes (they are not this system's stores).
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

hermetic
fake_bin "$T/bin" curl tstclnt certutil modutil
link_tool "$T/bin" rg 2> /dev/null || link_tool "$T/bin" grep || skip "neither rg nor grep installed"
s=rg
[ -e "$T/bin/rg" ] || s='grep'

ROOT=$T/rootfs
mkdir -p "$ROOT/etc/ssl/certs" "$ROOT/usr/lib/x86_64-linux-gnu"
cat "$DATA/others.pem" "$G3_PEM" > "$ROOT/etc/ssl/certs/ca-certificates.crt"
mk_ckbi "$ROOT/usr/lib/x86_64-linux-gnu/libnssckbi.so" "$G3_DER"
run all CSC_DEFAULT_TRUST=g3 -- --all="$ROOT" --timeout 2
expect_line all "== offline: searching @ROOT@ with $s (a whole system takes minutes) =="
expect_line all "[VULNERABLE] @ROOT@/etc/ssl/certs/ca-certificates.crt | emSign-G3 | PEM bundle trusts $G3_CN"
expect_line all "[UNKNOWN]    @ROOT@/usr/lib/x86_64-linux-gnu/libnssckbi.so | emSign-G3 | DER copy; NSS builtins, keeps distrusted roots (see NSS probes)"
expect_line all "[PATCHED]    offline search of @ROOT@ ($s) | Comodo-AAA | no trusted copy found"
expect_line all '== online =='
expect_line all "control: curl @ $EP_G3 -> OK"
expect_line all '[VULNERABLE] curl, default CA store | emSign-G3 @ dv-g3b-emudhra | chain accepted (curl exit 0)'
expect_no_line all 'judged below'
expect_no_line all 'found offline'
expect_no_regex all '^bundle   @ROOT@'
expect_no_regex all '^module   @ROOT@'
off=$(grep -n '^== offline' "$T/all.out" | cut -d: -f1)
on=$(grep -n '^== online' "$T/all.out" | cut -d: -f1)
if [ -n "$off" ] && [ -n "$on" ] && [ "$off" -lt "$on" ]; then
	ok "all: offline search before the online checks"
else
	fail "all: offline section (line $off) not before online (line $on)"
fi
expect_rc_consistent all
if [ "$HERMETIC" = 1 ]; then
	sed "s/@SEARCHER@/$s/g" "$TESTS/expected/fake-all.txt" > "$T/all.expected"
	expect_golden all "$T/all.expected"
fi
show_if_needed all
expect_tmp_clean
finish
