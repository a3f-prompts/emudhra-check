# SPDX-License-Identifier: MIT
# offline-bundle-self.sh BINARY DATADIR
#
# --bundle files are confirmed offline too (also outside ROOT; a TRUSTED
# CERTIFICATE rejecting serverAuth is PATCHED), and the running binary
# skips its own file while a copy of it is reported (it embeds both roots).
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

for s in rg grep; do
	link_tool "$T/bin" "$s" 2>/dev/null && break
done
[ -x "$T/bin/rg" ] || [ -x "$T/bin/grep" ] || skip "neither rg nor grep installed"
s=$(ls "$T/bin")

mkdir -p "$T/clean" "$T/b"
cp "$G3_PEM" "$T/b/only-g3.pem"
cp "$AAA_DER" "$T/b/aaa.der"
cp "$DATA/aaa-reject-serverauth.pem" "$T/b/reject-aaa.pem"
ROOT=$T/clean
run bundles -- --offline="$ROOT" --bundle "$T/b/only-g3.pem" --bundle="$T/b/aaa.der" \
	--bundle "$T/b/reject-aaa.pem"
expect_rc bundles 1
expect_line bundles "[VULNERABLE] @T@/b/only-g3.pem | emSign-G3 | PEM bundle trusts $G3_CN"
expect_line bundles "[VULNERABLE] @T@/b/aaa.der | Comodo-AAA | DER copy of $AAA_CN embedded"
expect_line bundles "[PATCHED]    @T@/b/reject-aaa.pem | Comodo-AAA | OpenSSL TRUSTED CERTIFICATE entry for $AAA_CN excludes TLS server auth"
expect_line bundles "Summary: 2 VULNERABLE, 0 UNKNOWN, 1 PATCHED, 0 SKIPPED"
show_if_needed bundles

if [ -n "$WRAP" ]; then
	note "exe_wrapper in use: /proc/self/exe is the wrapper, self check skipped"
	finish
fi
# A copy of the binary in a tree: reported by the original binary ...
ROOT=$T/self
mkdir -p "$ROOT"
cp "$BIN" "$ROOT/certstore-check"
run other -- --offline="$ROOT"
expect_rc other 1
expect_line other "[VULNERABLE] @ROOT@/certstore-check | emSign-G3 | PEM copy of $G3_CN embedded (binary)"
expect_line other "[VULNERABLE] @ROOT@/certstore-check | Comodo-AAA | PEM copy of $AAA_CN embedded (binary)"
show_if_needed other
# ... but not by itself
SAVE=$BIN
BIN=$ROOT/certstore-check
run self -- --offline="$ROOT"
BIN=$SAVE
sed "s/@SEARCHER@/$s/g" "$TESTS/expected/offline-clean.txt" > "$T/clean.expected"
expect_golden self "$T/clean.expected"
expect_tmp_clean
finish
