# SPDX-License-Identifier: MIT
# fake-interrupt.sh BINARY DATADIR
#
# SIGINT or SIGTERM while a client hangs: the client's process group is
# killed, temp dirs are removed, "interrupted" goes to stderr, no summary is
# printed and the exit status is 130.
. "$(dirname "$0")/lib.sh"

hermetic
fake_bin "$T/bin" curl tstclnt certutil modutil
[ -d /proc/self ] || skip "needs /proc to see when the fake curl runs"

for sig in INT TERM; do
	RUN_BG=1
	run $sig CSC_CURL=hang -- --timeout 60
	RUN_BG=0
	pid=$BGPID
	i=0
	while [ -z "$(hang_pids)" ] && [ "$i" -lt 20 ]; do
		sleep 1
		i=$((i + 1))
	done
	if [ -z "$(hang_pids)" ]; then
		fail "$sig: the hanging fake curl never started"
		kill -9 "$pid" 2> /dev/null
	fi
	kill -s "$sig" "$pid"
	wait "$pid"
	RC=$?
	expect_rc $sig 130
	expect_err $sig 'certstore-check: interrupted'
	expect_no_line $sig 'Summary:'
	expect_no_leftovers $sig
	expect_tmp_clean
	show_if_needed $sig
done
finish
