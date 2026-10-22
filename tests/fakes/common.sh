# SPDX-License-Identifier: MIT
# Sourced by the fake clients in this directory.  They stand in for curl,
# openssl s_client, tstclnt, certutil and modutil in the fake-clients tests:
# no network, deterministic.  A "good" fake behaves like a correct client
# against the two test endpoints: the chain of an endpoint validates iff the
# trust store in use contains the root that endpoint needs.
#
# Environment (set by the tests, passed through by the binary):
#   CSC_REAL_PATH      PATH for the tools the fakes use
#   CSC_DEFAULT_TRUST  roots the client's default store trusts: "g3", "aaa",
#                      "g3 aaa" (default: none)
#   CSC_BUILTINS_TRUST roots NSS builtins (tstclnt -b) trust (default: none)
#   CSC_TOKEN          marks processes of hanging fakes (leftover check)
#   CSC_HANG_PIDS      file the hanging processes write their PIDs to
#   CSC_PYTHONPATH     the only package dir of the fake python3
# Only port 443 of the endpoints answers.  A trust file (curl --cacert,
# openssl -CAfile) whose name starts with err77-, reset- or expired- makes
# the client fail in a way that is no verdict on the chain (see the fakes).
PATH=$CSC_REAL_PATH
export PATH

# The first and last base64 lines of each root's PEM
G3_FIRST=MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
G3_LAST=+JbNR6iC8hZVdyR+EhCVBCyj
AAA_FIRST=MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
AAA_LAST=smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==

# root_of HOST: the root the endpoint's chain needs (g3/aaa), empty if unknown
root_of() {
	case $1 in
	dv-g3b-emudhra.we-have-a-problem.com) echo g3 ;;
	dv-g3b-aaa-emudhra.we-have-a-problem.com) echo aaa ;;
	esac
}
# file_trusts FILE ROOT: the PEM file contains ROOT
file_trusts() {
	case $2 in
	g3) grep -qxF -e "$G3_FIRST" "$1" 2>/dev/null && grep -qxF -e "$G3_LAST" "$1" ;;
	aaa) grep -qxF -e "$AAA_FIRST" "$1" 2>/dev/null && grep -qxF -e "$AAA_LAST" "$1" ;;
	*) return 1 ;;
	esac
}
# in_list ROOT LIST
in_list() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }
# Never answer; the background child must be killed with us (process group).
hang() {
	sh -c 'echo $$ >> "$CSC_HANG_PIDS"; sleep 300; :' "csc-hang-$CSC_TOKEN" &
	exec sh -c 'echo $$ >> "$CSC_HANG_PIDS"; sleep 300; :' "csc-hang-$CSC_TOKEN"
}
