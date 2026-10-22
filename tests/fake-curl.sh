# SPDX-License-Identifier: MIT
# fake-curl.sh BINARY DATADIR
#
# Online mode with a correctly behaving fake curl (tests/fakes/curl, no
# network): the controls pass, the default store and every --cacert bundle
# get the status their content implies; ~/.curlrc ("insecure") is ignored
# (-q) and the default CA path is not used with --cacert ("--capath
# /dev/null"); bundles named by environment variables, the system bundle
# gRPC C-core loads and the files python3 reports for certifi, pip and
# grpcio are found, labelled and deduplicated.  The host's bundles are hidden
# (hermetic); without user namespaces they are probed too and only the lines
# of our own bundles are checked.
. "$(dirname "$0")/lib.sh"

hermetic
fake_bin "$T/bin" curl tstclnt certutil modutil
B=$T/b
mkdir -p "$B" "$T/insecure-home"
cp "$G3_PEM" "$B/only-g3.pem"
cp "$AAA_PEM" "$B/only-aaa.pem"
cat "$G3_PEM" "$DATA/others.pem" "$AAA_PEM" > "$B/both.pem"
cp "$DATA/others.pem" "$B/none.pem"
echo insecure > "$T/insecure-home/.curlrc"

V='chain accepted (curl exit 0)'
P='certificate verification failed (curl exit 60)'
# probe_lines NAME BUNDLE G3-STATUS AAA-STATUS
probe_lines() {
	for _r in g3 aaa; do
		case $_r in g3) _st=$3 _id='emSign-G3 @ dv-g3b-emudhra' ;; aaa) _st=$4 _id='Comodo-AAA @ dv-g3b-aaa-emudhra' ;; esac
		case $_st in VULNERABLE) _l="[VULNERABLE] $2 | $_id | $V" ;; PATCHED) _l="[PATCHED]    $2 | $_id | $P" ;; esac
		expect_line "$1" "$_l"
	done
}
check_good() {
	expect_line "$1" "control: curl @ $EP_G3 -> OK"
	expect_line "$1" "control: curl @ $EP_AAA -> OK"
	# the fake default store trusts only G3
	probe_lines "$1" 'curl, default CA store' VULNERABLE PATCHED
	for b in only-g3 only-aaa both none; do
		expect_line "$1" "bundle   @T@/b/$b.pem [--bundle]"
	done
	probe_lines "$1" 'curl --cacert @T@/b/only-g3.pem' VULNERABLE PATCHED
	probe_lines "$1" 'curl --cacert @T@/b/only-aaa.pem' PATCHED VULNERABLE
	probe_lines "$1" 'curl --cacert @T@/b/both.pem' VULNERABLE VULNERABLE
	probe_lines "$1" 'curl --cacert @T@/b/none.pem' PATCHED PATCHED
	expect_line "$1" '[SKIPPED]    openssl s_client, default CA store | - | fallback only, curl works'
	expect_line "$1" '[SKIPPED]    openssl s_client -CAfile <bundle> | - | fallback only, curl works'
	expect_line "$1" '[SKIPPED]    CA bundle <bundle> | - | checked with curl'
	expect_line "$1" 'Not patched (still trusting a compromised root):'
	expect_line "$1" '  curl, default CA store'
	expect_line "$1" '  curl --cacert @T@/b/only-g3.pem'
	expect_no_exact "$1" '  curl --cacert @T@/b/none.pem'
	expect_rc_consistent "$1"
	show_if_needed "$1"
}
set -- --timeout 2 --bundle "$B/only-g3.pem" --bundle "$B/only-aaa.pem" --bundle="$B/both.pem" \
	--bundle "$B/none.pem"
run good CSC_DEFAULT_TRUST=g3 -- "$@"
check_good good
if [ "$HERMETIC" = 1 ]; then
	expect_rc good 1
	expect_golden good "$TESTS/expected/fake-curl-good.txt"
fi

# The fake behaves like the real curl in the ways the binary must avoid:
# -k, and ~/.curlrc with "insecure" without -q, accept any chain; ports
# other than 443 do not answer
fake_curl() {
	HOME=${FAKE_HOME:-$T/home} CSC_FAKES=$TESTS/fakes CSC_REAL_PATH=$REAL_PATH "$T/bin/curl" "$@" 2> /dev/null
}
if fake_curl -q -sSk "https://$EP_G3:443/" && fake_curl -q --insecure "https://$EP_G3:443/"; then
	ok "control: the fake curl accepts any chain with -k"
else
	fail "control: the fake curl ignores -k"
fi
if FAKE_HOME=$T/insecure-home fake_curl -sS "https://$EP_G3:443/"; then
	ok "control: the fake curl honours ~/.curlrc without -q"
else
	fail "control: the fake curl ignores ~/.curlrc"
fi
fake_curl -q --cacert "$G3_PEM" "https://$EP_G3:8443/"
if [ $? = 28 ]; then ok "control: the fake curl answers on port 443 only"; else fail "control: the fake curl answers on port 8443"; fi
run curlrc HOME="$T/insecure-home" CSC_DEFAULT_TRUST=g3 -- "$@"
check_good curlrc

# bundles from environment variables: labelled, made absolute, merged by realpath
cp "$G3_PEM" "$B/env.pem"
ln -s env.pem "$B/env-link.pem"
cp "$AAA_PEM" "$B/req.pem"
cp "$DATA/others.pem" "$B/node.pem"
cat "$AAA_PEM" "$G3_PEM" > "$B/grpc.pem"
run env SSL_CERT_FILE="$B/env.pem" CURL_CA_BUNDLE="$B/env-link.pem" REQUESTS_CA_BUNDLE=b/req.pem \
	NODE_EXTRA_CA_CERTS="$B/node.pem" GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="$B/grpc.pem" \
	-- --timeout 2 --bundle "$B/env.pem"
expect_line env 'bundle   @T@/b/env.pem [--bundle, $SSL_CERT_FILE (OpenSSL), $CURL_CA_BUNDLE (curl)]'
expect_line env 'bundle   @T@/b/grpc.pem [used by gRPC ($GRPC_DEFAULT_SSL_ROOTS_FILE_PATH)]'
expect_line env 'bundle   @T@/b/req.pem [$REQUESTS_CA_BUNDLE (python requests)]'
expect_line env 'bundle   @T@/b/node.pem [$NODE_EXTRA_CA_CERTS (Node.js extra CAs)]'
expect_no_line env 'env-link.pem'
expect_no_line env 'used by gRPC C-core'
probe_lines env 'curl --cacert @T@/b/env.pem' VULNERABLE PATCHED
probe_lines env 'curl --cacert @T@/b/req.pem' PATCHED VULNERABLE
probe_lines env 'curl --cacert @T@/b/node.pem' PATCHED PATCHED
probe_lines env 'curl --cacert @T@/b/grpc.pem' VULNERABLE VULNERABLE
probe_lines env 'curl, default CA store' PATCHED PATCHED
expect_rc_consistent env
show_if_needed env

# gRPC C-core loads the first system bundle (here a Debian one), unless
# GRPC_NOT_USE_SYSTEM_SSL_ROOTS is set: then its bundled roots.pem
SYS=/etc/ssl/certs/ca-certificates.crt
GRPC=/usr/share/grpc/roots.pem
if [ "$HERMETIC" = 1 ] && [ -d /etc/ssl ]; then
	cat "$DATA/others.pem" "$G3_PEM" > "$B/sys.pem"
	cp "$AAA_PEM" "$B/grpc-roots.pem"
	SAVE=$NS_ARGS
	NS_ALLOW="$SYS $GRPC"
	ns_mount /etc/ssl "$B/sys.pem" certs/ca-certificates.crt
	run grpcsys -- --timeout 2
	expect_line grpcsys "bundle   $SYS [system bundle (Debian/Ubuntu/Alpine), used by gRPC C-core]"
	probe_lines grpcsys "curl --cacert $SYS" VULNERABLE PATCHED
	show_if_needed grpcsys
	run grpcnosys GRPC_NOT_USE_SYSTEM_SSL_ROOTS=1 -- --timeout 2
	expect_line grpcnosys "bundle   $SYS [system bundle (Debian/Ubuntu/Alpine)]"
	show_if_needed grpcnosys
	if [ -d "${GRPC%/*}" ]; then
		ns_mount "${GRPC%/*}" "$B/grpc-roots.pem" roots.pem
		run grpcbundled GRPC_NOT_USE_SYSTEM_SSL_ROOTS=1 -- --timeout 2
		expect_line grpcbundled "bundle   $SYS [system bundle (Debian/Ubuntu/Alpine)]"
		expect_line grpcbundled "bundle   $GRPC [gRPC C-core bundled roots, used by gRPC C-core]"
		probe_lines grpcbundled "curl --cacert $GRPC" PATCHED VULNERABLE
		show_if_needed grpcbundled
	else
		note "no ${GRPC%/*} to mount on: bundled roots.pem case skipped"
	fi
	NS_ARGS=$SAVE
else
	# the host's bundles: at most one system bundle is labelled as its default
	n=$(grep -c '^bundle .*used by gRPC C-core' "$T/good.out")
	if [ "$n" -le 1 ]; then ok "good: $n bundle(s) labelled 'used by gRPC C-core'"; else fail "good: $n bundles labelled 'used by gRPC C-core'"; fi
	run grpcnosys GRPC_NOT_USE_SYSTEM_SSL_ROOTS=1 -- --timeout 2
	if grep '^bundle .*used by gRPC C-core' "$T/grpcnosys.out" | grep -v '^bundle   [^ ]*/grpc/roots\.pem \['; then
		fail "grpcnosys: a system bundle is labelled 'used by gRPC C-core'"
	else
		ok "grpcnosys: no system bundle labelled 'used by gRPC C-core'"
	fi
fi

# python3 tells where certifi, pip's vendored certifi and grpcio keep their
# bundles: the binary's python code runs on fake packages (fakes/python3)
if command -v python3 > /dev/null; then
	PY=$T/py
	mkdir -p "$PY/certifi" "$PY/pip/_vendor/certifi" "$PY/grpc/_cython/_credentials"
	where='import os
def where():
    return os.path.join(os.path.dirname(__file__), "cacert.pem")'
	printf '%s\n' "$where" > "$PY/certifi/__init__.py"
	printf '%s\n' "$where" > "$PY/pip/_vendor/certifi/__init__.py"
	: > "$PY/pip/__init__.py"
	: > "$PY/pip/_vendor/__init__.py"
	: > "$PY/grpc/__init__.py"
	cat "$DATA/others.pem" "$G3_PEM" > "$PY/certifi/cacert.pem"
	cp "$DATA/others.pem" "$PY/pip/_vendor/certifi/cacert.pem"
	cp "$AAA_PEM" "$PY/grpc/_cython/_credentials/roots.pem"
	fake_bin "$T/bin-py" curl python3
	run python PATH="$T/bin-py" CSC_PYTHONPATH="$PY" -- --timeout 2
	expect_line python 'bundle   @T@/py/certifi/cacert.pem [used by certifi]'
	expect_line python 'bundle   @T@/py/pip/_vendor/certifi/cacert.pem [used by pip]'
	expect_line python 'bundle   @T@/py/grpc/_cython/_credentials/roots.pem [used by grpcio (always)]'
	probe_lines python 'curl --cacert @T@/py/certifi/cacert.pem' VULNERABLE PATCHED
	probe_lines python 'curl --cacert @T@/py/pip/_vendor/certifi/cacert.pem' PATCHED PATCHED
	probe_lines python 'curl --cacert @T@/py/grpc/_cython/_credentials/roots.pem' PATCHED VULNERABLE
	expect_rc_consistent python
	show_if_needed python
else
	note "python3 not installed: certifi/pip/grpcio discovery not checked"
fi
expect_tmp_clean
finish
