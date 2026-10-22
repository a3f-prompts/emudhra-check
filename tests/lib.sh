# SPDX-License-Identifier: MIT
# Shared helpers of the test scripts (POSIX sh), sourced first by each of them.
#
# Every test is run by meson as:  sh TEST.sh BINARY DATADIR [ARG]...
# with $CSC_TEST_NAME (test name) and $CSC_TEST_TMP (scratch area in the build
# dir) in the environment.  In a cross build meson sets $MESON_EXE_WRAPPER
# (the cross file's exe_wrapper, shell-quoted), which is put in front of
# BINARY.  Exit status: 0 pass, 1 fail, 77 skip.
# Set CSC_KEEP=1 to keep the scratch dir of a passing test.

set -u
LC_ALL=C
export LC_ALL
unset CDPATH GREP_OPTIONS GREP_COLOR GREP_COLORS

if [ $# -lt 2 ]; then
	echo "usage: sh $0 BINARY DATADIR [ARG]..." >&2
	exit 99
fi
abspath() { case $1 in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$(pwd)" "$1" ;; esac; }
# q STRING: STRING quoted for sh (eval, generated scripts)
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
BIN=$(abspath "$1")
DATA=$(abspath "$2")
shift 2
TESTS=$(cd "$(dirname "$0")" && pwd -P)
TNAME=${CSC_TEST_NAME:-$(basename "$0" .sh)}
REAL_PATH=$PATH
SH=$(command -v sh)
TOKEN=$$.$TNAME			# marks the processes our fake clients start

# The exe_wrapper as quoted words, its program as a full path (run() gives
# the binary PATH=$T/bin, where it would not be found).
wrapper_words() {
	eval "set -- $1"
	[ $# -gt 0 ] || return 0
	_w=$(command -v "$1") || _w=$1
	shift
	q "$_w"
	for _a; do printf ' %s' "$(q "$_a")"; done
}
WRAP=$(wrapper_words "${MESON_EXE_WRAPPER:-}")

# Scratch dir, one per test process (meson --repeat runs copies of a test in
# parallel), physical path (the tool prints realpath()s).  The dirs of
# earlier runs of this test are removed unless their process still runs.
TBASE=${CSC_TEST_TMP:-${TMPDIR:-/tmp}/csc-tests}
for _d in "$TBASE/$TNAME".[0-9]*; do
	_p=${_d##*.}
	case $_p in *[!0-9]*) continue ;; esac
	if [ -d "$_d" ] && { [ "$_p" = $$ ] || ! kill -0 "$_p" 2>/dev/null; }; then
		chmod -R u+rwx "$_d" 2>/dev/null
		rm -rf "$_d"
	fi
done
T=$TBASE/$TNAME.$$
mkdir -p "$T/home" "$T/tmpdir" "$T/bin" "$T/empty" || exit 99
T=$(cd "$T" && pwd -P)

G3_PEM=$DATA/emSign_ECC_Root_CA_-_G3.pem
AAA_PEM=$DATA/Comodo_AAA_Services_root.pem
G3_DER=$DATA/emSign_ECC_Root_CA_-_G3.der
AAA_DER=$DATA/Comodo_AAA_Services_root.der
G3_CN='emSign ECC Root CA - G3'
AAA_CN='AAA Certificate Services'
AAA_LABEL='Comodo AAA Services root'
EP_G3=dv-g3b-emudhra.we-have-a-problem.com
EP_AAA=dv-g3b-aaa-emudhra.we-have-a-problem.com
ESC=$(printf '\033')

FAILS=0
BGPID=
# Killed (meson timeout, ^C): take the binary under test and the fakes along.
on_signal() {
	[ -n "$BGPID" ] && kill -9 "$BGPID" 2> /dev/null
	kill_leftovers
	echo "FAIL: interrupted (timeout?)"
	exit 1
}
trap on_signal HUP INT TERM
fail() { printf 'FAIL: %s\n' "$*"; FAILS=$((FAILS + 1)); }
ok() { printf 'ok: %s\n' "$*"; }
note() { printf 'note: %s\n' "$*"; }
skip() {
	printf 'SKIP: %s\n' "$*"
	kill_leftovers
	cleanup_scratch
	exit 77
}
cleanup_scratch() {
	[ -n "${CSC_KEEP:-}" ] && return
	chmod -R u+rwx "$T" 2>/dev/null
	rm -rf "$T"
}
# Last call of every test.
finish() {
	kill_leftovers
	expect_hermetic
	if [ "$FAILS" -gt 0 ]; then
		echo "$FAILS check(s) failed; outputs kept in $T"
		exit 1
	fi
	cleanup_scratch
	exit 0
}

# run NAME [VAR=VALUE]... -- [ARG]...
# Runs BINARY ARG... with a clean environment (HOME=$T/home, TMPDIR=$T/tmpdir,
# PATH=$T/bin, LC_ALL=C, CSC_* for the fakes; VAR=VALUE adds or overrides) in
# $RUN_CWD (default $T).  After hermetic() or ns_mount it runs inside
# tests/in-ns.sh (user and mount namespace).
# stdout -> $T/NAME.out, stderr -> $T/NAME.err, exit status -> $RC.
HIDE=0 NS_ARGS=
run() {
	_r_name=$1
	shift
	_r_n=$# _r_i=0
	while [ "$_r_i" -lt "$_r_n" ]; do
		_r_a=$1
		shift
		_r_i=$((_r_i + 1))
		if [ "$_r_a" = -- ]; then
			if [ "$HIDE" = 1 ] || [ -n "$NS_ARGS" ]; then
				set -- "$@" "$SH" "$TESTS/in-ns.sh"
				[ "$HIDE" = 1 ] && set -- "$@" -h
				eval "set -- \"\$@\" $NS_ARGS --"
			fi
			eval "set -- \"\$@\" $WRAP \"\$BIN\""
		else
			set -- "$@" "$_r_a"
		fi
	done
	(cd "${RUN_CWD:-$T}" && exec env -i HOME="$T/home" TMPDIR="$T/tmpdir" PATH="$T/bin" \
		LC_ALL=C CSC_REAL_PATH="$REAL_PATH" CSC_TOKEN="$TOKEN" CSC_FAKES="$TESTS/fakes" \
		CSC_HANG_PIDS="$T/hang.pids" "$@") > "$T/$_r_name.out" 2> "$T/$_r_name.err" &
	BGPID=$!
	# RUN_BG=1: leave it running in the background (PID in $BGPID)
	if [ "${RUN_BG:-0}" != 1 ]; then
		wait "$BGPID"
		RC=$?
	fi
}

# user_ns: unprivileged user and mount namespaces work (see in-ns.sh)
user_ns() {
	command -v unshare > /dev/null &&
		env CSC_REAL_PATH="$REAL_PATH" "$SH" "$TESTS/in-ns.sh" -h -- true 2> /dev/null
}
# ns_mount MOUNTPOINT FILE NAME: later runs see an empty tmpfs on MOUNTPOINT
# holding only MOUNTPOINT/NAME, a copy of FILE (in-ns.sh -m).
ns_mount() { NS_ARGS="$NS_ARGS -m $(q "$1") $(q "$2") $(q "$3")"; }
# hermetic: later runs do not see this host's CA bundles, NSS modules and NSS
# tool dirs (in-ns.sh -h), so their output depends only on the test:
# HERMETIC=1.  Without user namespaces they see them: HERMETIC=0, and checks
# of exact outputs are skipped.
HERMETIC=0
hermetic() {
	if user_ns; then
		HIDE=1 HERMETIC=1
	else
		note "no user namespaces: the binary sees this host's CA bundles and NSS modules"
	fi
}
# After hermetic(): no output of an online run names a CA bundle or NSS module
# outside $T other than $NS_ALLOW (paths a test mounted itself, space
# separated), and no /etc/pki/nssdb was found.  Called by finish().
expect_hermetic() {
	[ "$HERMETIC" = 1 ] || return 0
	for _o in "$T"/*.out; do
		[ -f "$_o" ] && grep -q '^== online ==' "$_o" || continue
		_n=$(basename "$_o" .out)
		_bad=$(norm "$_o" | awk -v ok="@T@/ /opt/csc-test/ ${NS_ALLOW:-}" '
			BEGIN { n = split(ok, a, " ") }
			/^(bundle|module)   / {
				f = 0
				for (i = 1; i <= n; i++) if (index($2, a[i]) == 1) f = 1
				if (!f) print $2
			}
			/ NSS system db / && !/ \| no \/etc\/pki\/nssdb$/ { print "/etc/pki/nssdb" }')
		if [ -n "$_bad" ]; then
			fail "$_n: the binary saw host files (add them to in-ns.sh): $(echo $_bad)"
		fi
	done
}

# Literal replacement of the scratch paths: $ROOT -> @ROOT@, $T -> @T@.
norm() {
	NORM_ROOT=${ROOT:-/nonexistent/} NORM_T=$T awk '
	function rep(s, f, r,   i, o) {
		o = ""
		while (f != "" && (i = index(s, f)) > 0) {
			o = o substr(s, 1, i - 1) r
			s = substr(s, i + length(f))
		}
		return o s
	}
	BEGIN { a = ENVIRON["NORM_ROOT"]; b = ENVIRON["NORM_T"] }
	{ print rep(rep($0, a, "@ROOT@"), b, "@T@") }' "$@"
}

# expect_rc NAME CODE
expect_rc() {
	if [ "$RC" = "$2" ]; then ok "$1: exit $2"; else fail "$1: exit $RC, expected $2"; show "$1"; fi
}
# expect_line NAME LINE: LINE (exact, after norm) is in NAME.out
expect_line() {
	if norm "$T/$1.out" | grep -qxF -- "$2"; then
		ok "$1: has '$2'"
	else
		fail "$1: no line '$2'"
		SHOW=1
	fi
}
# expect_no_line NAME STRING: no line of NAME.out contains STRING (after norm)
expect_no_line() {
	if norm "$T/$1.out" | grep -qF -- "$2"; then
		fail "$1: unexpected '$2':"
		norm "$T/$1.out" | grep -F -- "$2" | sed 's/^/	/'
	else
		ok "$1: no '$2'"
	fi
}
# expect_no_exact NAME LINE: LINE (exact, after norm) is not in NAME.out
expect_no_exact() {
	if norm "$T/$1.out" | grep -qxF -- "$2"; then
		fail "$1: unexpected line '$2'"
	else
		ok "$1: no line '$2'"
	fi
}
# expect_no_regex NAME RE: no line of NAME.out matches the basic regex RE
expect_no_regex() {
	if norm "$T/$1.out" | grep -q -- "$2"; then
		fail "$1: unexpected lines matching '$2':"
		norm "$T/$1.out" | grep -- "$2" | sed 's/^/	/'
	else
		ok "$1: nothing matches '$2'"
	fi
}
# expect_all NAME STRING STATUS: at least one line contains STRING and all
# of them have [STATUS]
expect_all() {
	_n=$(norm "$T/$1.out" | grep -cF -- "$2")
	_bad=$(norm "$T/$1.out" | grep -F -- "$2" | grep -cvF -- "[$3]")
	if [ "$_n" -gt 0 ] && [ "$_bad" -eq 0 ]; then
		ok "$1: all $_n '$2' lines are $3"
	else
		fail "$1: '$2': $_n line(s), $_bad not $3"
		SHOW=1
	fi
}
# expect_err NAME LINE: LINE (exact, after norm) is in NAME.err
expect_err() {
	if norm "$T/$1.err" | grep -qxF -- "$2"; then
		ok "$1: stderr has '$2'"
	else
		fail "$1: stderr lacks '$2'"
		SHOW=1
	fi
}
# expect_golden NAME FILE: NAME.out + "rc=N" equals FILE (after norm)
expect_golden() {
	{ norm "$T/$1.out"; echo "rc=$RC"; } > "$T/$1.norm"
	if diff -u "$2" "$T/$1.norm" > "$T/$1.diff"; then
		ok "$1: output as expected ($(basename "$2"))"
	else
		fail "$1: output differs from $(basename "$2"):"
		sed 's/^/	/' "$T/$1.diff"
	fi
}
# The exit status follows from the output: 1 with a VULNERABLE line, else 2
# with an UNKNOWN line, else 0.
expect_rc_consistent() {
	if grep -q '^\[VULNERABLE\]' "$T/$1.out"; then _want=1
	elif grep -q '^\[UNKNOWN\]' "$T/$1.out"; then _want=2
	else _want=0; fi
	if [ "$RC" = "$_want" ]; then ok "$1: exit $RC matches the statuses"
	else fail "$1: exit $RC but the statuses imply $_want"; fi
}
# No escape sequence in FILE
expect_plain() {
	if grep -qF -- "$ESC" "$T/$1"; then fail "$1: contains escape sequences"; else ok "$1: no escape sequences"; fi
}
expect_colored() {
	if grep -qF -- "$ESC" "$T/$1"; then ok "$1: has escape sequences"; else fail "$1: no escape sequences"; fi
}
# TMPDIR of the runs must be left empty (temp dirs removed)
expect_tmp_clean() {
	if [ -z "$(ls -A "$T/tmpdir")" ]; then ok "temp dirs removed"
	else fail "left in TMPDIR: $(ls -A "$T/tmpdir" | tr '\n' ' ')"; fi
}
# After a failed expect_line etc.: show the output once
show() {
	echo "--- $1.out:"
	norm "$T/$1.out" | sed 's/^/	/'
	echo "--- $1.err:"
	norm "$T/$1.err" | sed 's/^/	/'
}
show_if_needed() {
	if [ "${SHOW:-0}" = 1 ]; then show "$1"; fi
	SHOW=0
}

# PIDs of the hanging processes of our fakes that still run: the fakes write
# them to $T/hang.pids, their argv contains csc-hang-$TOKEN (see common.sh).
hang_pids() {
	[ -d /proc/self ] && [ -s "$T/hang.pids" ] || return 0
	while read -r _p; do
		if tr '\0' ' ' 2>/dev/null < "/proc/$_p/cmdline" | grep -q "csc-han[g]-$TOKEN"; then
			echo "$_p"
		fi
	done < "$T/hang.pids"
}
expect_no_leftovers() {
	if [ ! -d /proc/self ]; then
		note "no /proc: leftover process check skipped"
		return
	fi
	_p=$(hang_pids | tr '\n' ' ')
	if [ -z "$_p" ]; then ok "$1: no leftover child processes"; else fail "$1: leftover processes: $_p"; fi
	kill_leftovers
}
kill_leftovers() {
	for _p in $(hang_pids); do kill -9 "$_p" 2>/dev/null; done
}

# fake_bin DIR NAME...: install the fake clients tests/fakes/NAME into DIR
fake_bin() {
	_d=$1
	shift
	mkdir -p "$_d"
	for _f; do
		cp "$TESTS/fakes/$_f" "$_d/$_f" && chmod 755 "$_d/$_f"
	done
}
# link_tool DIR NAME [TARGET]: DIR/NAME -> TARGET (default: NAME from $PATH)
link_tool() {
	_t=${3:-$(command -v "$2")} || return 1
	mkdir -p "$1" && ln -sf "$_t" "$1/$2"
}
# use_ckbi: let the binary find a libnssckbi.so (needs trees.sh).  After
# hermetic(): /opt holds only /opt/csc-test/libnssckbi.so, a synthetic module
# containing only the G3 DER (CKBI=ns, MODULE=its path).  Without user
# namespaces: the host's modules (CKBI=host).  Returns 1 if neither.
use_ckbi() {
	mk_ckbi "$T/libnssckbi.so" "$G3_DER"
	MODULE=
	if [ "$HERMETIC" = 1 ]; then
		CKBI=none
		[ -d /opt ] || return 1
		ns_mount /opt "$T/libnssckbi.so" csc-test/libnssckbi.so
		CKBI=ns MODULE=/opt/csc-test/libnssckbi.so
		return 0
	fi
	run modules PATH="$T/empty" -- --timeout 1
	if grep -q '^module   ' "$T/modules.out"; then
		CKBI=host
		note "using the host's NSS modules"
		return 0
	fi
	CKBI=none
	return 1
}
# One of the tools is installed where the binary also looks (EXTRA_TOOL_DIRS)
# and not hidden by hermetic()
in_extra_tool_dirs() {
	[ "$HERMETIC" = 1 ] && return 1
	for _d in /usr/lib64/nss/unsupported-tools /usr/lib/nss/unsupported-tools; do
		[ -x "$_d/$1" ] && return 0
	done
	return 1
}
