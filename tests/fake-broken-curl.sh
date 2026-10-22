# SPDX-License-Identifier: MIT
# fake-broken-curl.sh BINARY DATADIR
#
# Online mode with a curl whose control fails: one that accepts every chain
# (would make everything look VULNERABLE) and one that cannot do https.  All
# curl results must be UNKNOWN with the reason; without another working
# client the bundles are checked statically.  With a working (fake) openssl
# s_client, it is used as the fallback.
. "$(dirname "$0")/lib.sh"

hermetic
fake_bin "$T/bin" curl tstclnt certutil modutil
fake_bin "$T/bin-ossl" curl openssl tstclnt certutil modutil
B=$T/b
mkdir -p "$B"
cp "$G3_PEM" "$B/only-g3.pem"
cp "$AAA_PEM" "$B/only-aaa.pem"
cp "$DATA/g3-reject-serverauth.pem" "$B/reject-g3.pem"
set -- --timeout 2 --bundle "$B/only-g3.pem" --bundle "$B/only-aaa.pem" --bundle "$B/reject-g3.pem"

static_lines() {
	expect_line "$1" "[VULNERABLE] CA bundle @T@/b/only-g3.pem | emSign-G3 | contains $G3_CN (static check)"
	expect_line "$1" "[PATCHED]    CA bundle @T@/b/only-g3.pem | Comodo-AAA | root not in file (static check)"
	expect_line "$1" "[PATCHED]    CA bundle @T@/b/only-aaa.pem | emSign-G3 | root not in file (static check)"
	expect_line "$1" "[VULNERABLE] CA bundle @T@/b/only-aaa.pem | Comodo-AAA | contains $AAA_CN (static check)"
	expect_line "$1" "[PATCHED]    CA bundle @T@/b/reject-g3.pem | emSign-G3 | entry excludes TLS server auth (static check)"
	expect_line "$1" "[PATCHED]    CA bundle @T@/b/reject-g3.pem | Comodo-AAA | root not in file (static check)"
}
all_curl_unknown() {
	expect_all "$1" ' curl, default CA store |' UNKNOWN
	expect_all "$1" ' curl --cacert @T@/b/' UNKNOWN
	expect_no_regex "$1" '^  curl'	# nothing from curl in "Not patched"
}

# accepts everything: the control trusting only the other root fails
run accept CSC_CURL=accept -- "$@"
expect_line accept "control: curl @ $EP_G3 -> curl control failed (trusting only Comodo-AAA): chain accepted (curl exit 0)"
expect_line accept "control: curl @ $EP_AAA -> curl control failed (trusting only emSign-G3): chain accepted (curl exit 0)"
expect_line accept "[UNKNOWN]    curl --cacert @T@/b/only-aaa.pem | emSign-G3 @ dv-g3b-emudhra | curl control failed (trusting only Comodo-AAA): chain accepted (curl exit 0)"
all_curl_unknown accept
expect_line accept '[SKIPPED]    openssl s_client, default CA store | - | openssl not installed'
expect_line accept "control: openssl @ $EP_G3 -> no control (openssl not installed)"
static_lines accept
expect_rc_consistent accept
show_if_needed accept

# cannot do https at all
run broken CSC_CURL=broken -- "$@"
expect_line broken "control: curl @ $EP_G3 -> curl control failed (trusting only emSign-G3): curl exit 1: curl: (1) Protocol \"https\" not supported or disabled in libcurl"
all_curl_unknown broken
static_lines broken
expect_rc_consistent broken
show_if_needed broken

# broken curl, working openssl: s_client is the fallback (its default store
# trusts only AAA here); the static checks are skipped
V='chain verified (openssl exit 0)'
P='openssl verify error 20'
run openssl PATH="$T/bin-ossl" CSC_CURL=broken CSC_DEFAULT_TRUST=aaa -- "$@"
expect_line openssl "control: openssl @ $EP_G3 -> OK"
expect_line openssl "control: openssl @ $EP_AAA -> OK"
expect_line openssl "[PATCHED]    openssl s_client, default CA store | emSign-G3 @ dv-g3b-emudhra | $P"
expect_line openssl "[VULNERABLE] openssl s_client, default CA store | Comodo-AAA @ dv-g3b-aaa-emudhra | $V"
expect_line openssl "[VULNERABLE] openssl s_client -CAfile @T@/b/only-g3.pem | emSign-G3 @ dv-g3b-emudhra | $V"
expect_line openssl "[PATCHED]    openssl s_client -CAfile @T@/b/only-g3.pem | Comodo-AAA @ dv-g3b-aaa-emudhra | $P"
expect_line openssl "[PATCHED]    openssl s_client -CAfile @T@/b/only-aaa.pem | emSign-G3 @ dv-g3b-emudhra | $P"
expect_line openssl "[VULNERABLE] openssl s_client -CAfile @T@/b/only-aaa.pem | Comodo-AAA @ dv-g3b-aaa-emudhra | $V"
expect_line openssl "[PATCHED]    openssl s_client -CAfile @T@/b/reject-g3.pem | emSign-G3 @ dv-g3b-emudhra | $P"
expect_line openssl '[SKIPPED]    CA bundle <bundle> | - | checked with openssl'
all_curl_unknown openssl
expect_rc_consistent openssl
show_if_needed openssl

# the real curl without network (own network namespace per call): a failed
# connection is UNKNOWN, never PATCHED
REAL_CURL=$(command -v curl)
if [ -n "$REAL_CURL" ] && command -v unshare > /dev/null && unshare -rn true 2> /dev/null; then
	mkdir -p "$T/bin-nonet"
	printf '#!%s\nPATH=$CSC_REAL_PATH exec unshare -rn %s "$@"\n' "$SH" "$(q "$REAL_CURL")" > "$T/bin-nonet/curl"
	chmod 755 "$T/bin-nonet/curl"
	run nonet PATH="$T/bin-nonet" -- "$@"
	if grep -q "^control: curl @ $EP_G3 -> curl control failed (trusting only emSign-G3): curl exit [1-9]" "$T/nonet.out"; then
		ok "nonet: curl control failed"
	else
		fail "nonet: no failed curl control"
		SHOW=1
	fi
	expect_no_regex nonet '^control: curl @ .* -> OK$'
	all_curl_unknown nonet
	expect_no_line nonet '(curl exit 60)'
	static_lines nonet
	expect_rc_consistent nonet
	show_if_needed nonet
else
	note "real curl or user namespaces not available: no-network case skipped"
fi

expect_tmp_clean
finish
