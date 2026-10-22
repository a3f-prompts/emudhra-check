# SPDX-License-Identifier: MIT
# offline-select.sh BINARY DATADIR
#
# Choice of the searcher and searcher failures: rg is preferred; an rg that
# fails its self-test falls back to grep; no usable searcher gives UNKNOWN
# (exit 2); a searcher killed mid-run, reporting a global error or exiting
# 2 without a message makes the search incomplete (UNKNOWN) while its hits
# are still reported; files that vanished during the search (also after
# being listed) are not errors, whatever the user's locale;
# $RIPGREP_CONFIG_PATH is ignored.
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

ROOT=$T/rootfs
mk_rootfs "$ROOT" || { fail "cannot build the mock rootfs"; finish; }
for s in rg grep; do
	sed "s/@SEARCHER@/$s/g" "$TESTS/expected/offline-rootfs.txt" > "$T/rootfs-$s.expected"
	sed "s/@SEARCHER@/$s/g" "$TESTS/expected/offline-clean.txt" > "$T/clean-$s.expected"
done
RG=$(command -v rg) || RG=
GREP=$(command -v grep)
link_tool "$T/grep-only" grep "$GREP"
unusable() { echo "[UNKNOWN]    offline search | $1 | no usable searcher ($2)"; }

# rg is the first choice; its config file is ignored
if [ -n "$RG" ]; then
	link_tool "$T/bin" rg "$RG"
	link_tool "$T/bin" grep "$GREP"
	run default -- --offline="$ROOT"
	expect_golden default "$T/rootfs-rg.expected"
	printf -- '--max-filesize=10\n--glob=!*.pem\n--type=c\n' > "$T/rgconfig"
	run rgconfig RIPGREP_CONFIG_PATH="$T/rgconfig" -- --offline="$ROOT" --searcher=rg
	expect_golden rgconfig "$T/rootfs-rg.expected"
else
	note "rg not installed: default choice and config checks skipped"
fi

# an rg failing its self-test (here: finds nothing) is not used: grep is
mkdir -p "$T/badrg"
link_tool "$T/badrg" grep "$GREP"
printf '#!%s\nexit 1\n' "$SH" > "$T/badrg/rg"
chmod 755 "$T/badrg/rg"
run fallback PATH="$T/badrg" -- --offline="$ROOT"
expect_golden fallback "$T/rootfs-grep.expected"
run fallback-rg PATH="$T/badrg" -- --offline="$ROOT" --searcher=rg
expect_rc fallback-rg 2
expect_line fallback-rg "$(unusable emSign-G3 'rg: did not find the test file bin0')"
expect_line fallback-rg "$(unusable Comodo-AAA 'rg: did not find the test file bin0')"
show_if_needed fallback-rg

# the requested searcher is missing / there is none at all
run norg PATH="$T/grep-only" -- --offline="$ROOT" --searcher=rg
expect_rc norg 2
expect_line norg "$(unusable emSign-G3 'rg: not installed')"
expect_line norg "$(unusable Comodo-AAA 'rg: not installed')"
expect_no_line norg "== offline: searching"
show_if_needed norg
run nosearcher PATH="$T/empty" -- --offline="$ROOT"
expect_rc nosearcher 2
expect_line nosearcher "$(unusable emSign-G3 'rg: not installed; grep: not installed')"
expect_line nosearcher "$(unusable Comodo-AAA 'rg: not installed; grep: not installed')"
show_if_needed nosearcher

# fake rgs: pass the self-test (list the files of the self-test dir), then
# misbehave on the real search.  fake_rg DIR BODY
fake_rg() {
	mkdir -p "$1"
	cat > "$1/rg" <<-EOF
	#!$SH
	for a do last=\$a; done
	case \$last in
	"\$TMPDIR"/certstore-check.*)
	    for f in "\$last"/*; do printf '%s\0' "\$f"; done
	    exit 0 ;;
	esac
	$2
	EOF
	chmod 755 "$1/rg"
}
# killed after printing two hits: hits reported, search incomplete
fake_rg "$T/killedrg" "printf '%s\\0' $(q "$ROOT/opt/app/g3.der") $(q "$ROOT/usr/bin/app"); kill -9 \$\$"
run killed PATH="$T/killedrg" -- --offline="$ROOT" --searcher=rg
expect_rc killed 1
expect_line killed "[VULNERABLE] @ROOT@/opt/app/g3.der | emSign-G3 | DER copy of $G3_CN embedded"
expect_line killed "[VULNERABLE] @ROOT@/usr/bin/app | Comodo-AAA | DER copy of $AAA_CN embedded"
expect_line killed "[UNKNOWN]    offline search of @ROOT@ (rg) | emSign-G3 | search incomplete: rg exit 137"
expect_line killed "[UNKNOWN]    offline search of @ROOT@ (rg) | Comodo-AAA | search incomplete: rg exit 137"
expect_line killed "Summary: 2 VULNERABLE, 2 UNKNOWN, 0 PATCHED, 0 SKIPPED"
show_if_needed killed

# a message that is not about one file means the search went wrong
fake_rg "$T/errrg" "printf '%s\\0' $(q "$ROOT/opt/app/g3.der"); echo 'rg: failed to read the directory tree' >&2; exit 2"
run globalerr PATH="$T/errrg" -- --offline="$ROOT" --searcher=rg
expect_rc globalerr 1
expect_line globalerr "[VULNERABLE] @ROOT@/opt/app/g3.der | emSign-G3 | DER copy of $G3_CN embedded"
expect_line globalerr "[UNKNOWN]    offline search of @ROOT@ (rg) | Comodo-AAA | search incomplete: rg: failed to read the directory tree"
show_if_needed globalerr

# exit 2 (error) without any message: incomplete, nothing found is no PATCHED
fake_rg "$T/silentrg" "exit 2"
run silent PATH="$T/silentrg" -- --offline="$ROOT" --searcher=rg
expect_rc silent 2
expect_line silent "[UNKNOWN]    offline search of @ROOT@ (rg) | emSign-G3 | search incomplete: rg exit 2"
expect_line silent "[UNKNOWN]    offline search of @ROOT@ (rg) | Comodo-AAA | search incomplete: rg exit 2"
expect_line silent "Summary: 0 VULNERABLE, 2 UNKNOWN, 0 PATCHED, 0 SKIPPED"
show_if_needed silent

# files that vanished during the search are no error: one rg could not
# open, and one it listed that is gone when the binary reads it.  rg
# writes the reason in the user's locale (like strerror()), so the binary
# must run it with LC_ALL=C to recognise it.
fake_rg "$T/gonerg" "printf '%s\\0' $(q "$ROOT/vanished.pem")
case \${LC_ALL:-\${LC_MESSAGES:-\${LANG:-C}}} in
de*) echo $(q "rg: $ROOT/gone.pem: Datei oder Verzeichnis nicht gefunden (os error 2)") >&2 ;;
*) echo $(q "rg: $ROOT/gone.pem: No such file or directory (os error 2)") >&2 ;;
esac
exit 2"
run vanished PATH="$T/gonerg" -- --offline="$ROOT" --searcher=rg
expect_golden vanished "$T/clean-rg.expected"
run vanished-de PATH="$T/gonerg" LC_ALL= LANG=de_DE.UTF-8 -- --offline="$ROOT" --searcher=rg
expect_golden vanished-de "$T/clean-rg.expected"

expect_tmp_clean
finish
