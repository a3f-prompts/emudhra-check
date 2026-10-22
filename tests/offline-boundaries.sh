# SPDX-License-Identifier: MIT
# offline-boundaries.sh BINARY DATADIR
#
# Files are confirmed in 1 MiB chunks that overlap by 64 KiB: a DER copy or
# PEM block lying across a chunk boundary (1 MiB, 2 MiB), or ending right
# before or starting right after it, must still be found.  DER files are
# sparse (NUL padding), PEM files are padded with text lines.  Every file is
# VULNERABLE, for rg and for grep.
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

ROOT=$T/straddle
mkdir -p "$ROOT"
MIB=1048576
# The first PEM_MAX-sized window must not be the only place where a block
# is seen, so place blocks around 1 MiB and DERs also around 2 MiB.
nfiles=0
for r in g3 aaa; do
	case $r in g3) der=$G3_DER pem=$G3_PEM ;; aaa) der=$AAA_DER pem=$AAA_PEM ;; esac
	dl=$(wc -c < "$der" | tr -d ' ')
	pl=$(wc -c < "$pem" | tr -d ' ')
	for b in $MIB $((2 * MIB)); do
		# ends 1 before / at the boundary, crosses it by 1, half, all but 1, starts at / after it
		for off in $((b - dl - 1)) $((b - dl)) $((b - dl + 1)) $((b - dl / 2)) $((b - 1)) $b $((b + 1)); do
			dd if="$der" of="$ROOT/der-$r-$off.bin" bs=1 seek="$off" 2>/dev/null
			nfiles=$((nfiles + 1))
		done
	done
	b=$MIB
	awk 'BEGIN { l = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; for (i = 0; i < 16400; i++) print l }' \
		> "$T/padding"	# 1 MiB + 1600 bytes of 64-byte text lines
	for off in $((b - pl - 1)) $((b - pl)) $((b - pl + 1)) $((b - pl / 2)) $((b - 1)) $b $((b + 1)); do
		# padding up to off: whole lines plus one short line ending at off
		{ dd if="$T/padding" bs=$((off / 64 * 64)) count=1 2>/dev/null
		  awk -v n=$((off % 64)) 'BEGIN { if (n) { s = ""; for (i = 1; i < n; i++) s = s "y"; print s } }'
		  cat "$pem"; } > "$ROOT/pem-$r-$off.txt"
		nfiles=$((nfiles + 1))
	done
done
rm -f "$T/padding"

ran=0
for s in rg grep; do
	setup_searcher "$s" "$T/bin-$s" 2>/dev/null || link_tool "$T/bin-$s" "$s" 2>/dev/null || {
		note "$s not installed"
		continue
	}
	ran=1
	run $s PATH="$T/bin-$s" -- --offline="$ROOT" --searcher=$s
	expect_rc $s 1
	expect_line $s "Summary: $nfiles VULNERABLE, 0 UNKNOWN, 0 PATCHED, 0 SKIPPED"
	for f in "$ROOT"/*; do
		b=${f##*/}
		case $b in
		*-g3-*) id=emSign-G3 cn=$G3_CN ;;
		*) id=Comodo-AAA cn=$AAA_CN ;;
		esac
		case $b in
		der-*) why="DER copy of $cn embedded" ;;
		*) why="PEM bundle trusts $cn" ;;
		esac
		if ! norm "$T/$s.out" | grep -qxF "[VULNERABLE] @ROOT@/$b | $id | $why"; then
			fail "$s: $b not reported as '$why'"
			SHOW=1
		fi
	done
	ok "$s: checked $nfiles files"
	show_if_needed $s
done
[ "$ran" = 1 ] || skip "neither rg nor grep installed"
expect_tmp_clean
finish
