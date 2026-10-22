# SPDX-License-Identifier: MIT
# fake-nss.sh BINARY DATADIR
#
# NSS probes with fake certutil/modutil/tstclnt: the "certutil -L" listing
# of each libnssckbi.so is classified by the trust flags of the root's
# entry (by NSS label or CN; 'C' in the SSL field = trusted for TLS
# servers; p, c, T or nothing = not; absent = removed; of several entries
# a trusted one wins; empty listing or a failing certutil/modutil =
# UNKNOWN).  Without modutil the module is checked statically.  tstclnt on
# the builtins is judged with its control (an NSS temp db trusting one
# root); without a control its rejections are UNKNOWN.  Needs a
# libnssckbi.so (synthetic one in a user namespace, or the host's).
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

hermetic
use_ckbi || skip "no libnssckbi.so: neither user namespaces nor a host module"
fake_bin "$T/bin" curl tstclnt certutil modutil
fake_bin "$T/bin-nocertutil" curl tstclnt
fake_bin "$T/bin-nomodutil" curl tstclnt certutil

# listing NAME [NICKNAME FLAGS]...: write a "certutil -L" listing
listing() {
	_f=$T/$1.listing
	shift
	printf '\n%-60s %s\n%-60s %s\n\n' "Certificate Nickname" "Trust Attributes" "" "SSL,S/MIME,JAR/XPI" > "$_f"
	while [ $# -ge 2 ]; do
		printf '%-60s %s\n' "Builtin Object Token:$1" "$2" >> "$_f"
		shift 2
	done
}
G=$G3_CN
A=$AAA_LABEL
listing l1 ACCVRAIZ1 C,C, "$G" p,p,p "$A" p,p,
listing l2 ACCVRAIZ1 C,C, "$G" CT,C,C
listing l3
listing l4 "$G" ,C, "$A" c,c,c
listing l5 "$AAA_CN" C,,
listing l6 "$G" p,p,p "$G" C,C, "$A" T,c,
listing l7 "$G" C,C, "$G" p,p,p "$A" p,p,
# certutil NAME G3-STATUS G3-REASON AAA-STATUS AAA-REASON
certutil_case() {
	expect_all "$1" "(certutil) | emSign-G3 | $3" "$2"
	expect_all "$1" "(certutil) | Comodo-AAA | $5" "$4"
	expect_line "$1" '[SKIPPED]    NSS builtins <ckbi> (static) | - | checked with certutil'
	expect_rc_consistent "$1"
	show_if_needed "$1"
}
present() { echo "\"$1\" present, not trusted for TLS (trust flags $2)"; }
trusted() { echo "\"$1\" trusted for TLS (trust flags $2)"; }
removed() { echo "\"$1\" not in module (removed)"; }
nolist='module listed no certificates (failed to load?)'

# listing_case NAME ...: run with listing NAME, then certutil_case NAME ...
listing_case() {
	run "$1" CSC_LISTING="$T/$1.listing" -- --timeout 2
	certutil_case "$@"
}
listing_case l1 PATCHED "$(present "$G" p,p,p)" PATCHED "$(present "$A" p,p,)"
listing_case l2 VULNERABLE "$(trusted "$G" CT,C,C)" PATCHED "$(removed "$A")"
listing_case l3 UNKNOWN "$nolist" UNKNOWN "$nolist"
# nothing else is VULNERABLE: UNKNOWN gives exit 2
[ "$HERMETIC" = 1 ] && expect_rc l3 2
listing_case l4 PATCHED "$(present "$G" ,C,)" PATCHED "$(present "$A" c,c,c)"
listing_case l5 PATCHED "$(removed "$G")" VULNERABLE "$(trusted "$A" C,,)"
listing_case l6 VULNERABLE "$(trusted "$G" C,C,)" PATCHED "$(present "$A" T,c,)"
listing_case l7 VULNERABLE "$(trusted "$G" C,C,)" PATCHED "$(present "$A" p,p,)"

# failing certutil -L / modutil
run certutil-fails CSC_LISTING="$T/l2.listing" CSC_CERTUTIL_FAIL=1 -- --timeout 2
m='certutil -L exit 255: certutil: function failed: SEC_ERROR_BAD_DATABASE: security library: bad database.'
certutil_case certutil-fails UNKNOWN "$m" UNKNOWN "$m"
run modutil-fails CSC_LISTING="$T/l2.listing" CSC_MODUTIL_FAIL=1 -- --timeout 2
m='setup: modutil exit 1: modutil: ERROR: Failed to add module "Builtin Roots". Probable cause : "Failure to load dynamic library.".'
certutil_case modutil-fails UNKNOWN "$m" UNKNOWN "$m"

# certutil but no modutil: the module cannot be loaded into a db, so it is
# checked statically
run nomodutil PATH="$T/bin-nomodutil" CSC_LISTING="$T/l2.listing" -- --timeout 2
expect_line nomodutil '[SKIPPED]    NSS builtins <ckbi> (certutil) | - | modutil not installed'
if [ "$CKBI" = ns ]; then
	expect_line nomodutil "[UNKNOWN]    NSS builtins $MODULE (static) | emSign-G3 | module contains $G3_CN; trust flags unknown without certutil"
	expect_line nomodutil "[PATCHED]    NSS builtins $MODULE (static) | Comodo-AAA | $AAA_CN not in module (removed)"
else
	expect_no_regex nomodutil '^\[SKIPPED\]    NSS builtins <ckbi> (static)'
fi
expect_rc_consistent nomodutil
show_if_needed nomodutil

# tstclnt on the builtins, which trust only AAA here; its control passes
run tstclnt CSC_BUILTINS_TRUST=aaa -- --timeout 2
expect_line tstclnt "control: tstclnt @ $EP_G3 -> OK"
expect_line tstclnt "control: tstclnt @ $EP_AAA -> OK"
expect_line tstclnt '[PATCHED]    NSS builtins (tstclnt -D -b) | emSign-G3 @ dv-g3b-emudhra | rejected: SEC_ERROR_UNKNOWN_ISSUER (tstclnt exit 1)'
expect_line tstclnt '[VULNERABLE] NSS builtins (tstclnt -D -b) | Comodo-AAA @ dv-g3b-aaa-emudhra | handshake accepted (tstclnt exit 0)'
expect_rc_consistent tstclnt
show_if_needed tstclnt

# no certutil: no control for tstclnt, a rejection proves nothing
run nocontrol PATH="$T/bin-nocertutil" CSC_BUILTINS_TRUST=aaa -- --timeout 2
expect_line nocontrol "control: tstclnt @ $EP_G3 -> no control (certutil not installed)"
expect_line nocontrol '[UNKNOWN]    NSS builtins (tstclnt -D -b) | emSign-G3 @ dv-g3b-emudhra | rejected: SEC_ERROR_UNKNOWN_ISSUER (tstclnt exit 1), but no control (certutil not installed)'
expect_line nocontrol '[VULNERABLE] NSS builtins (tstclnt -D -b) | Comodo-AAA @ dv-g3b-aaa-emudhra | handshake accepted (tstclnt exit 0)'
expect_line nocontrol '[SKIPPED]    NSS builtins <ckbi> (certutil) | - | certutil not installed'
expect_rc_consistent nocontrol
show_if_needed nocontrol

expect_tmp_clean
finish
