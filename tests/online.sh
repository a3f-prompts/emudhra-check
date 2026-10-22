# SPDX-License-Identifier: MIT
# online.sh BINARY DATADIR
#
# The real test endpoints (network), with the real curl and openssl
# s_client.  First each client itself (not the binary) connects to both
# endpoints trusting only one root: the endpoint's own root must be
# accepted, the other one rejected.  A client that cannot reach them is
# skipped (network?); one that gets other results is a FAIL (the endpoints
# changed).  Then the binary's controls for that client must pass, and a
# bundle holding only the G3 root is VULNERABLE at the G3 endpoint and
# PATCHED at the AAA endpoint, a bundle holding only the AAA root the
# reverse (also with CRLF line ends or base64 wrapped at 76 columns).
# Skipped (77) when no client reaches the endpoints.
. "$(dirname "$0")/lib.sh"

B=$T/b
mkdir -p "$B"
cp "$G3_PEM" "$B/only-g3.pem"
cp "$AAA_PEM" "$B/only-aaa.pem"
# the same roots with CRLF line ends / base64 wrapped at 76 columns
awk '{ printf "%s\r\n", $0 }' "$G3_PEM" > "$B/crlf-g3.pem"
awk '/^-----/ { if (b != "") { while (length(b) > 76) { print substr(b, 1, 76); b = substr(b, 77) } print b; b = "" } print; next }
     { b = b $0 }' "$AAA_PEM" > "$B/wrap76-aaa.pem"
set -- --timeout 20 --bundle "$B/only-g3.pem" --bundle "$B/only-aaa.pem" --bundle "$B/crlf-g3.pem" \
	--bundle "$B/wrap76-aaa.pem"

# The clients run with the clean environment the binary gets from run().
TIMEOUT=$(command -v timeout) && TIMEOUT="$TIMEOUT 30"
client() {
	# shellcheck disable=SC2086 # $TIMEOUT: command and argument
	env -i HOME="$T/home" TMPDIR="$T/tmpdir" PATH="$REAL_PATH" LC_ALL=C ${TIMEOUT:-} "$@" \
		< /dev/null > /dev/null 2> "$T/direct.err"
}
# direct CLIENT HOST PEM: 0 chain accepted, 1 rejected, 2 no answer
direct() {
	case $1 in
	curl)
		client curl -q -sS -o /dev/null --max-time 20 --cacert "$3" --capath /dev/null "https://$2/"
		case $? in 0) return 0 ;; 60) return 1 ;; *) return 2 ;; esac ;;
	openssl)
		client openssl s_client -connect "$2:443" -servername "$2" -verify_return_error \
			-CAfile "$3" -no-CApath && return 0
		grep -q 'verify error:num=' "$T/direct.err" && return 1
		return 2 ;;
	esac
}
# reachable CLIENT: the client itself sees the endpoints as documented
reachable() {
	_bad=
	for _ep in "$EP_G3 g3" "$EP_AAA aaa"; do
		# shellcheck disable=SC2086 # host and root name
		set -- $_ep
		for _r in g3 aaa; do
			case $_r in g3) _pem=$G3_PEM ;; aaa) _pem=$AAA_PEM ;; esac
			direct "$C" "$1" "$_pem"
			_got=$?
			[ "$_r" = "$2" ] && _want=0 || _want=1
			if [ "$_got" = 2 ]; then
				note "$C: no answer from $1: $(tail -n 1 "$T/direct.err")"
				return 1
			fi
			[ "$_got" = "$_want" ] || _bad="$_bad $1 trusting only $_r: $(
				[ "$_got" = 0 ] && echo accepted || echo rejected);"
		done
	done
	if [ -n "$_bad" ]; then
		fail "$C itself: the endpoints do not behave as documented:$_bad"
		return 1
	fi
	ok "$C itself: each endpoint accepted with its root only"
}

# check CLIENT STORE-PREFIX ACCEPTED REJECTED
check() {
	for _ep in "$EP_G3" "$EP_AAA"; do
		if grep -qxF "control: $1 @ $_ep -> OK" "$T/$1.out"; then
			ok "$1: control @ $_ep passed"
		else
			fail "$1: control @ $_ep failed although $1 itself works:"
			grep "^control: $1 @ $_ep" "$T/$1.out" | sed 's/^/	/'
		fi
	done
	expect_line "$1" "[VULNERABLE] $2 @T@/b/only-g3.pem | emSign-G3 @ dv-g3b-emudhra | $3"
	expect_line "$1" "[PATCHED]    $2 @T@/b/only-g3.pem | Comodo-AAA @ dv-g3b-aaa-emudhra | $4"
	expect_line "$1" "[PATCHED]    $2 @T@/b/only-aaa.pem | emSign-G3 @ dv-g3b-emudhra | $4"
	expect_line "$1" "[VULNERABLE] $2 @T@/b/only-aaa.pem | Comodo-AAA @ dv-g3b-aaa-emudhra | $3"
	expect_line "$1" "[VULNERABLE] $2 @T@/b/crlf-g3.pem | emSign-G3 @ dv-g3b-emudhra | $3"
	expect_line "$1" "[PATCHED]    $2 @T@/b/crlf-g3.pem | Comodo-AAA @ dv-g3b-aaa-emudhra | $4"
	expect_line "$1" "[PATCHED]    $2 @T@/b/wrap76-aaa.pem | emSign-G3 @ dv-g3b-emudhra | $4"
	expect_line "$1" "[VULNERABLE] $2 @T@/b/wrap76-aaa.pem | Comodo-AAA @ dv-g3b-aaa-emudhra | $3"
	expect_rc_consistent "$1"
	show_if_needed "$1"
}

checked=0
for C in curl openssl; do
	if ! command -v "$C" > /dev/null; then
		note "$C not installed"
		continue
	fi
	reachable || continue
	checked=$((checked + 1))
	case $C in
	curl)
		link_tool "$T/bin" curl
		run curl -- "$@"
		check curl 'curl --cacert' 'chain accepted (curl exit 0)' \
			'certificate verification failed (curl exit 60)' ;;
	openssl)
		# without curl, so that s_client is used
		link_tool "$T/bin-openssl" openssl
		run openssl PATH="$T/bin-openssl" -- "$@"
		check openssl 'openssl s_client -CAfile' 'chain verified (openssl exit 0)' \
			'openssl verify error 20' ;;
	esac
done
[ "$checked" -gt 0 ] || [ "$FAILS" -gt 0 ] || skip "no client reaches the test endpoints (network?)"
expect_tmp_clean
finish
