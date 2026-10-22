# SPDX-License-Identifier: MIT
# fake-errors.sh BINARY DATADIR
#
# Clients that pass their controls and then fail on one store in a way that
# is no verdict on its chain: the result is UNKNOWN, never PATCHED (every
# store here holds the G3 root, a working client accepts it at the G3
# endpoint).  curl: exit 77 (cannot load the CA file), exit 56 (connection
# reset); openssl s_client: verify error 10 (certificate expired), a reset
# without verify error; tstclnt on the NSS builtins: connection reset.
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

hermetic
fake_bin "$T/bin" curl tstclnt certutil modutil
fake_bin "$T/bin-ossl" curl openssl tstclnt certutil modutil
B=$T/b
mkdir -p "$B"
for f in only-g3 err77-g3 reset-g3 expired-g3; do
	cp "$G3_PEM" "$B/$f.pem"
done
set -- --timeout 2 --bundle "$B/only-g3.pem" --bundle "$B/err77-g3.pem" --bundle "$B/reset-g3.pem" \
	--bundle "$B/expired-g3.pem"
G="emSign-G3 @ dv-g3b-emudhra"
A="Comodo-AAA @ dv-g3b-aaa-emudhra"

run curl -- "$@"
expect_line curl "control: curl @ $EP_G3 -> OK"
expect_line curl "control: curl @ $EP_AAA -> OK"
expect_line curl "[VULNERABLE] curl --cacert @T@/b/only-g3.pem | $G | chain accepted (curl exit 0)"
for e in "$G" "$A"; do
	expect_line curl "[UNKNOWN]    curl --cacert @T@/b/err77-g3.pem | $e | curl exit 77: curl: (77) error setting certificate file: @T@/b/err77-g3.pem"
	expect_line curl "[UNKNOWN]    curl --cacert @T@/b/reset-g3.pem | $e | curl exit 56: curl: (56) Recv failure: Connection reset by peer"
done
expect_rc curl 1
show_if_needed curl

# curl cannot do https: openssl s_client is used
run openssl PATH="$T/bin-ossl" CSC_CURL=broken -- "$@"
expect_line openssl "control: openssl @ $EP_G3 -> OK"
expect_line openssl "control: openssl @ $EP_AAA -> OK"
expect_line openssl "[VULNERABLE] openssl s_client -CAfile @T@/b/only-g3.pem | $G | chain verified (openssl exit 0)"
for e in "$G" "$A"; do
	expect_line openssl "[UNKNOWN]    openssl s_client -CAfile @T@/b/expired-g3.pem | $e | openssl verify error 10"
	expect_line openssl "[UNKNOWN]    openssl s_client -CAfile @T@/b/reset-g3.pem | $e | openssl exit 1: 40C7B1E1D07F0000:error:0A000126:SSL routines::unexpected eof while reading"
done
expect_rc openssl 1
show_if_needed openssl

# tstclnt: the control (a temp db) passes, the builtins run is reset
if use_ckbi; then
	run tstclnt CSC_TSTCLNT=reset -- --timeout 2
	expect_line tstclnt "control: tstclnt @ $EP_G3 -> OK"
	expect_line tstclnt "control: tstclnt @ $EP_AAA -> OK"
	for e in "$G" "$A"; do
		expect_line tstclnt "[UNKNOWN]    NSS builtins (tstclnt -D -b) | $e | tstclnt exit 1: tstclnt: read from socket failed: PR_CONNECT_RESET_ERROR: TCP connection reset by peer"
	done
	expect_rc_consistent tstclnt
	show_if_needed tstclnt
else
	note "no libnssckbi.so available: tstclnt case skipped"
fi
expect_tmp_clean
finish
