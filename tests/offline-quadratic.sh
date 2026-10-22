# SPDX-License-Identifier: MIT
# offline-quadratic.sh BINARY DATADIR
#
# A 6 MB candidate made of "-----BEGIN CERTIFICATE-----" lines with a single
# END line just before each 1 MiB boundary, so that every 1 MiB window the
# binary confirms holds ~32000 BEGINs before one END: the PEM scan must stay
# linear (a quadratic one needs minutes and hits the timeout).  The
# candidate is rejected.
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

ROOT=$T/tree
mkdir -p "$ROOT"
awk -v cn="$G3_CN" 'BEGIN {
	print cn
	pos = length(cn) + 1
	for (k = 1; k <= 6; k++) {
		while (pos + 33 < k * 1048576 - 200) {
			printf "-----BEGIN CERTIFICATE-----\nMIIx\n"
			pos += 33
		}
		print "-----END CERTIFICATE-----"
		pos += 26
	}
}' > "$ROOT/log.txt"

for s in rg grep; do
	setup_searcher "$s" "$T/bin" 2>/dev/null || link_tool "$T/bin" "$s" 2>/dev/null && break
done
[ -x "$T/bin/rg" ] || [ -x "$T/bin/grep" ] || skip "neither rg nor grep installed"
s=$(ls "$T/bin")
start=$(date +%s)
run tree -- -v --offline="$ROOT"
secs=$(($(date +%s) - start))
expect_rc tree 0
expect_line tree "    candidate rejected (no exact DER/PEM match): @ROOT@/log.txt"
expect_line tree "[PATCHED]    offline search of @ROOT@ ($s) | emSign-G3 | no trusted copy found"
show_if_needed tree
# generous: a linear scan takes about a second
if [ "$secs" -le 20 ]; then ok "finished in ${secs}s"; else fail "took ${secs}s"; fi
finish
