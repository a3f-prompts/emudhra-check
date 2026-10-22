# SPDX-License-Identifier: MIT
# fake-hang.sh BINARY DATADIR
#
# Clients that never answer are killed --timeout + 1 seconds after their
# start, together with every process they started (process group): a curl
# that hangs, a tstclnt that hangs and one that closes stdout/stderr first
# (the child outlives its output).  Their controls fail, so their results
# are UNKNOWN; no process and no temp dir is left behind.
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

hermetic
fake_bin "$T/bin" curl tstclnt certutil modutil
use_ckbi || note "no libnssckbi.so available: tstclnt cases skipped"

# elapsed SECONDS-AT-START NAME: each run below has two killed client runs
# (one control per endpoint) of --timeout 1 + 1 s each, 4 s in all; the
# limit adds 5 s for everything else (killing after 5 x timeout + 1 s would
# take 12 s).
LIMIT=9
elapsed() {
	_s=$(($(date +%s) - $1))
	if [ "$_s" -le "$LIMIT" ]; then ok "$2: finished in ${_s}s"; else fail "$2: took ${_s}s (limit ${LIMIT}s)"; fi
}
K='no result within 2 s, killed'

mkdir -p "$T/b"
cp "$G3_PEM" "$T/b/only-g3.pem"
start=$(date +%s)
run curl CSC_CURL=hang -- --timeout 1 --bundle "$T/b/only-g3.pem"
elapsed "$start" curl
expect_line curl "control: curl @ $EP_G3 -> curl control failed (trusting only emSign-G3): $K"
expect_line curl "control: curl @ $EP_AAA -> curl control failed (trusting only Comodo-AAA): $K"
expect_line curl "[UNKNOWN]    curl, default CA store | emSign-G3 @ dv-g3b-emudhra | curl control failed (trusting only emSign-G3): $K"
expect_all curl ' curl --cacert ' UNKNOWN
expect_no_leftovers curl
show_if_needed curl

if [ "$CKBI" != none ]; then
	for mode in hang close; do
		start=$(date +%s)
		run tst-$mode CSC_TSTCLNT=$mode -- --timeout 1
		elapsed "$start" tst-$mode
		expect_line tst-$mode "control: tstclnt @ $EP_G3 -> tstclnt control failed (trusting only emSign-G3): $K"
		expect_line tst-$mode "control: tstclnt @ $EP_AAA -> tstclnt control failed (trusting only Comodo-AAA): $K"
		expect_all tst-$mode ' NSS builtins (tstclnt -D -b) |' UNKNOWN
		expect_line tst-$mode "control: curl @ $EP_G3 -> OK"
		expect_no_leftovers tst-$mode
		show_if_needed tst-$mode
	done
fi
expect_tmp_clean
finish
