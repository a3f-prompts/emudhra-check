# SPDX-License-Identifier: MIT
# cli-color.sh BINARY DATADIR
#
# Colors with stdout/stderr not on a terminal (pipes, files): none by
# default (also with TERM=xterm), --color/--color=always forces them (also
# over NO_COLOR), --color=auto/never and --no-color give none, the last
# option wins; help headings, the error prefix and -v lines are colored
# when colors are on.  The terminal cases are in cli-tty.sh.
. "$(dirname "$0")/lib.sh"

link_tool "$T/bin" grep
mkdir -p "$T/tree"
cp "$G3_PEM" "$T/tree/g3.pem"
set -- --offline="$T/tree" --searcher=grep
RED="${ESC}[1;31m"
BOLD="${ESC}[1m"
RESET="${ESC}[0m"
has() {
	if grep -qF -- "$2" "$T/$1"; then ok "$1: has '$3'"; else fail "$1: lacks '$3'"; fi
}

run plain TERM=xterm -- "$@"
expect_rc plain 1
expect_plain plain.out
expect_plain plain.err
has plain.out "[VULNERABLE] $T/tree/g3.pem | emSign-G3 |" "uncolored status line"
for o in --color --color=always; do
	run "always$o" TERM=dumb NO_COLOR=1 -- "$o" "$@"
	expect_rc "always$o" 1
	has "always$o.out" "${RED}[VULNERABLE]$RESET" "red [VULNERABLE]"
	has "always$o.out" "${BOLD}Summary:$RESET" "bold Summary:"
done
for o in --color=auto --color=never --no-color; do
	run "off$o" TERM=xterm -- "$o" "$@"
	expect_plain "off$o.out"
done
run last-no-color TERM=xterm -- --color "$@" --no-color
expect_plain last-no-color.out
run last-color TERM=xterm -- --no-color "$@" --color
expect_colored last-color.out

run help TERM=xterm -- --help
expect_plain help.out
run help-color TERM=xterm -- --help --color
has help-color.out "${BOLD}Usage:$RESET" "bold Usage:"
has help-color.out "${BOLD}Exit codes:$RESET" "bold Exit codes:"

run err-color -- --color --bogus
expect_rc err-color 3
has err-color.err "${RED}certstore-check:$RESET unknown argument '--bogus'" "red error prefix"
has err-color.err "${BOLD}Usage:$RESET" "bold Usage: in the usage on stderr"
run err-plain TERM=xterm -- --bogus
expect_plain err-plain.err

run verbose-color -- -v --color "$@"
has verbose-color.out "${ESC}[90m    \$ " "grey command lines"
run verbose -- -v "$@"
expect_plain verbose.out
expect_tmp_clean
finish
