# SPDX-License-Identifier: MIT
# cli-tty.sh BINARY DATADIR
#
# Colors on a terminal (a pty from util-linux script(1)): on by default,
# off with NO_COLOR set and not empty, TERM=dumb, --no-color or
# --color=never; NO_COLOR is overridden by --color; stdout and stderr are
# decided separately (a redirected stream gets none).
. "$(dirname "$0")/lib.sh"

SCRIPT=$(command -v script) || skip "script(1) not installed"
"$SCRIPT" --version 2>&1 | grep -q util-linux || skip "script(1) is not the util-linux one"

link_tool "$T/bin" grep
mkdir -p "$T/tree"
cp "$G3_PEM" "$T/tree/g3.pem"
RED="${ESC}[1;31m"
RESET="${ESC}[0m"
ARGS="--offline=$(q "$T/tree") --searcher=grep"
B=$(q "$BIN")
[ -n "$WRAP" ] && B="$WRAP $B"

# tty NAME SHELL-COMMAND: run the command on a pty, its output -> NAME.out
tty() {
	printf '%s\n' "$2" > "$T/$1.sh"
	(cd "$T" && env -i HOME="$T/home" TMPDIR="$T/tmpdir" PATH="$T/bin" LC_ALL=C TERM=xterm \
		SHELL="$SH" "$SCRIPT" -qec "$SH $(q "$T/$1.sh")" /dev/null) < /dev/null > "$T/$1.out" 2>&1
	RC=$?
}
has_red() {
	if grep -qF -- "${RED}[VULNERABLE]$RESET" "$T/$1.out"; then ok "$1: red [VULNERABLE]"; else fail "$1: no red [VULNERABLE]"; show "$1"; fi
}

tty default "exec $B $ARGS"
expect_rc default 1
has_red default
tty nocolor-empty "NO_COLOR= exec $B $ARGS"
has_red nocolor-empty
tty nocolor-forced "NO_COLOR=1 exec $B --color $ARGS"
has_red nocolor-forced
tty auto "exec $B --color=auto $ARGS"
has_red auto
tty nocolor "NO_COLOR=1 exec $B $ARGS"
expect_rc nocolor 1
expect_plain nocolor.out
tty dumb "TERM=dumb exec $B $ARGS"
expect_plain dumb.out
tty no-color "exec $B --no-color $ARGS"
expect_plain no-color.out
tty never "exec $B --color=never $ARGS"
expect_plain never.out

# stderr on the terminal, stdout redirected: only stderr colored
tty err-tty "exec $B --bogus"
expect_rc err-tty 3
if grep -qF -- "${RED}certstore-check:$RESET unknown argument" "$T/err-tty.out"; then
	ok "err-tty: red error prefix on the terminal"
else
	fail "err-tty: no red error prefix"
fi
tty out-file "exec $B $ARGS > $(q "$T/out-file.txt")"
expect_plain out-file.txt
tty err-file "exec $B --bogus 2> $(q "$T/err-file.txt")"
expect_plain err-file.txt
expect_tmp_clean
finish
