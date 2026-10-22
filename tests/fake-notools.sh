# SPDX-License-Identifier: MIT
# fake-notools.sh BINARY DATADIR
#
# Online mode with no client at all on PATH: every client probe is SKIPPED
# ("not installed"), there is no control, CA bundles and libnssckbi.so are
# checked statically (presence of the root; a TRUSTED CERTIFICATE rejecting
# serverAuth is PATCHED; a module with the root is UNKNOWN, one without it
# PATCHED).
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

hermetic
for t in curl openssl tstclnt certutil modutil; do
	in_extra_tool_dirs "$t" && skip "$t is installed in an NSS unsupported-tools dir, which the binary also searches"
done
use_ckbi || note "no libnssckbi.so available: module checks limited to SKIPPED lines"

B=$T/b
mkdir -p "$B"
cp "$G3_PEM" "$B/only-g3.pem"
cp "$DATA/g3-reject-serverauth.pem" "$B/reject-g3.pem"
cat "$DATA/others.pem" "$AAA_PEM" > "$B/aaa-bundle.pem"
run notools PATH="$T/empty" -- --timeout 2 --bundle "$B/only-g3.pem" --bundle "$B/reject-g3.pem" \
	--bundle "$B/aaa-bundle.pem"
for c in 'curl, default CA store' 'curl --cacert <bundle>'; do
	expect_line notools "[SKIPPED]    $c | - | curl not installed"
done
for c in 'openssl s_client, default CA store' 'openssl s_client -CAfile <bundle>'; do
	expect_line notools "[SKIPPED]    $c | - | openssl not installed"
done
expect_line notools "control: curl @ $EP_G3 -> no control (curl not installed)"
expect_line notools "control: openssl @ $EP_G3 -> no control (openssl not installed)"
expect_line notools "[VULNERABLE] CA bundle @T@/b/only-g3.pem | emSign-G3 | contains $G3_CN (static check)"
expect_line notools "[PATCHED]    CA bundle @T@/b/only-g3.pem | Comodo-AAA | root not in file (static check)"
expect_line notools "[PATCHED]    CA bundle @T@/b/reject-g3.pem | emSign-G3 | entry excludes TLS server auth (static check)"
expect_line notools "[PATCHED]    CA bundle @T@/b/aaa-bundle.pem | emSign-G3 | root not in file (static check)"
expect_line notools "[VULNERABLE] CA bundle @T@/b/aaa-bundle.pem | Comodo-AAA | contains $AAA_CN (static check)"
expect_no_line notools 'control: tstclnt'
case $CKBI in
ns)
	expect_line notools "module   $MODULE [NSS builtins]"
	expect_line notools '[SKIPPED]    NSS builtins (tstclnt -D -b) | - | tstclnt not installed'
	expect_line notools '[SKIPPED]    NSS builtins <ckbi> (certutil) | - | certutil not installed'
	expect_line notools "[UNKNOWN]    NSS builtins $MODULE (static) | emSign-G3 | module contains $G3_CN; trust flags unknown without certutil"
	expect_line notools "[PATCHED]    NSS builtins $MODULE (static) | Comodo-AAA | $AAA_CN not in module (removed)"
	expect_golden notools "$TESTS/expected/fake-notools.txt" ;;
host)
	expect_line notools '[SKIPPED]    NSS builtins (tstclnt -D -b) | - | tstclnt not installed'
	expect_line notools '[SKIPPED]    NSS builtins <ckbi> (certutil) | - | certutil not installed' ;;
none)
	expect_line notools '[SKIPPED]    NSS builtins (tstclnt -D -b) | - | no libnssckbi.so found, -b would load no roots'
	expect_line notools '[SKIPPED]    NSS builtins <ckbi> (static) | - | no libnssckbi.so found' ;;
esac
expect_rc_consistent notools
show_if_needed notools
expect_tmp_clean
finish
