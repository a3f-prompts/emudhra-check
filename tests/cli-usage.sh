# SPDX-License-Identifier: MIT
# cli-usage.sh BINARY DATADIR
#
# --help/-h (exit 0, stdout), usage errors (exit 3, one message on stderr,
# nothing on stdout, the usage text after unknown arguments), and the valid
# argument forms ("--opt VAL", "--opt=VAL", optional arguments).
. "$(dirname "$0")/lib.sh"

link_tool "$T/bin" grep
mkdir -p "$T/clean"

run help -- --help
expect_rc help 0
if [ "$(sed -n 1p "$T/help.out")" = 'Usage: certstore-check [-v] [--timeout SEC] [--bundle FILE]... [--xdev]' ]; then
	ok "help: usage line first"
else
	fail "help: first line is '$(sed -n 1p "$T/help.out")'"
fi
expect_line help 'Exit codes: 0 nothing VULNERABLE/UNKNOWN, 1 something VULNERABLE, 2 something'
expect_line help 'UNKNOWN but nothing VULNERABLE, 3 usage/internal error, 130 interrupted.'
for o in --offline --all --timeout --bundle --searcher --xdev ' -v ' --color --no-color; do
	if grep -qF -- "$o" "$T/help.out"; then ok "help: mentions '$o'"; else fail "help: does not mention '$o'"; fi
done
[ -s "$T/help.err" ] && fail "help: wrote to stderr"
run h -- -h
if cmp -s "$T/help.out" "$T/h.out" && [ "$RC" = 0 ]; then ok "-h = --help"; else fail "-h differs from --help"; fi

# usage_error NAME MESSAGE ARG...: exit 3, MESSAGE as first stderr line, empty stdout
usage_error() {
	_n=$1 _m=$2
	shift 2
	run "$_n" -- "$@"
	expect_rc "$_n" 3
	_first=$(norm "$T/$_n.err" | sed -n 1p)
	if [ "$_first" = "$_m" ]; then ok "$_n: '$_m'"; else fail "$_n: stderr starts with '$_first', expected '$_m'"; fi
	if [ -s "$T/$_n.out" ]; then fail "$_n: wrote to stdout"; fi
}
for a in --bogus -x --timeoutx --offlinex -vv; do
	usage_error "unknown$a" "certstore-check: unknown argument '$a'" "$a"
	if grep -qxF 'Usage: certstore-check [-v] [--timeout SEC] [--bundle FILE]... [--xdev]' "$T/unknown$a.err"; then
		ok "unknown$a: usage on stderr"
	else
		fail "unknown$a: no usage on stderr"
	fi
done
usage_error help-then-bogus "certstore-check: unknown argument '--bogus'" --help --bogus
for v in 0 86401 abc 5s -1 ''; do
	usage_error "timeout=$v" 'certstore-check: --timeout needs 1..86400 seconds' "--timeout=$v"
done
usage_error timeout-space 'certstore-check: --timeout needs 1..86400 seconds' --timeout 0
for o in --timeout --bundle --searcher; do
	usage_error "missing$o" "certstore-check: $o needs an argument" "$o"
done
usage_error searcher 'certstore-check: --searcher: unknown searcher '"'ag'" --searcher=ag
usage_error nobundle 'certstore-check: --bundle @T@/nonexistent: not a regular file' --bundle "$T/nonexistent"
usage_error dirbundle 'certstore-check: --bundle @T@/clean: not a regular file' --bundle="$T/clean"
usage_error noroot 'certstore-check: cannot access @T@/nonexistent: No such file or directory' --offline="$T/nonexistent"
usage_error noroot-all 'certstore-check: cannot access @T@/nonexistent: No such file or directory' --all "$T/nonexistent"
usage_error color 'certstore-check: --color: WHEN is always, never or auto' --color=sometimes

# valid forms (offline on an empty dir: exit 0)
clean="[PATCHED]    offline search of @T@/clean (grep) | emSign-G3 | no trusted copy found"
run valid1 -- --offline "$T/clean" --searcher grep --timeout 5 -v --xdev --no-color
expect_rc valid1 0
expect_line valid1 "$clean"
run valid2 -- --timeout=86400 --searcher=grep --color=never --offline="$T/clean"
expect_rc valid2 0
expect_line valid2 "$clean"
RUN_CWD=$T/clean
run relative -- --offline=. --searcher=grep
RUN_CWD=
expect_rc relative 0
expect_line relative "$clean"
show_if_needed relative
expect_tmp_clean
finish
