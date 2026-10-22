# SPDX-License-Identifier: MIT
# Builders of the mock trees searched by the offline tests (POSIX sh, sourced
# after lib.sh).  Everything is generated here from the fixtures in DATADIR;
# nothing on the host is read.  Symlinks that escape a tree point to
# $T/outside, which holds copies of both roots: following one would show up as
# an extra (wrong) result line.

zeros() { dd if=/dev/zero bs="$1" count=1 2>/dev/null; }
# The start of an ELF header: binaries begin with NUL bytes, like real ones.
elf() { printf '\177ELF\002\001\001'; zeros 9; }
# flip_byte FILE OFFSET: change one byte in place
flip_byte() {
	_b=$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' \n')
	printf "\\$(printf '%03o' $((_b ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
# A synthetic libnssckbi.so: ELF-looking file with the root DERs inside.
# mk_ckbi FILE DER...
mk_ckbi() {
	_f=$1
	shift
	{
		elf
		zeros 1000
		for _d; do
			cat "$_d"
			zeros 100
		done
	} > "$_f"
}
# PEM as a C string literal / as a one-line JSON value (escaped newlines)
c_string() {
	printf 'static const char root[] =\n'
	while IFS= read -r _l; do printf '\t"%s\\n"\n' "$_l"; done < "$1"
	printf ';\n'
}
json_string() { awk 'BEGIN { printf "{\"ca\": \"" } { printf "%s\\n", $0 } END { print "\"}" }' "$1"; }
crlf() { awk '{ printf "%s\r\n", $0 }' "$1"; }
# rewrap WIDTH FILE: the PEM with its base64 wrapped at WIDTH columns
rewrap() {
	awk -v w="$1" '/^-----/ { if (b != "") { while (length(b) > w) { print substr(b, 1, w); b = substr(b, w + 1) } print b; b = "" } print; next }
	     { b = b $0 }' "$2"
}

mk_outside() {
	mkdir -p "$T/outside/dir"
	cp "$G3_PEM" "$T/outside/dir/g3.pem"
	cp "$AAA_PEM" "$T/outside/aaa.pem"
	mk_ckbi "$T/outside/libnssckbi.so" "$G3_DER" "$AAA_DER"
}

# mk_negatives ROOT (ROOT = $T/NAME): files that mention the roots or look
# like them, and special files.  Nothing here may be reported.
mk_negatives() {
	_r=$1
	mk_outside
	mkdir -p "$_r/opt/neg" "$_r/var/log" "$_r/srv" || return 1
	# same subject, serial and first 346 DER bytes as the real AAA root, other key
	{ echo "# $AAA_LABEL"; cat "$DATA/fake-aaa.pem"; } > "$_r/opt/neg/fake-aaa-commented.pem"
	cat "$DATA/others.pem" "$DATA/fake-aaa.pem" > "$_r/opt/neg/fake-aaa-nocomment.pem"
	# a bundle entry with the issuer named in a comment (as in curl's cacert.pem)
	{ printf '# Issuer: CN=%s O=Comodo CA Limited\n# Subject: CN=leaf.example\n' "$AAA_CN"
	  cat "$DATA/leaf-fake-aaa.pem"; } > "$_r/opt/neg/issued-by-fake-aaa.pem"
	cp "$DATA/leaf-fake-aaa.der" "$_r/opt/neg/leaf.der"
	{ elf; zeros 300; cat "$DATA/fake-aaa.der"; zeros 20; printf '%s\n%s\n' "$G3_CN" "$AAA_LABEL"; } \
		> "$_r/opt/neg/neg-binary"
	{
		printf 'issuer=%s\n%s\n%s mentioned\n' "$AAA_CN" "$AAA_LABEL" "$G3_CN"
		cat "$DATA/leaf-fake-aaa.pem"
	} > "$_r/var/log/app.log"
	cp "$G3_DER" "$_r/opt/neg/modified.der"
	flip_byte "$_r/opt/neg/modified.der" 589
	awk 'NR == 6 { c = substr($0, length($0)); $0 = substr($0, 1, length($0) - 1) (c == "A" ? "B" : "A") } { print }' \
		"$G3_PEM" > "$_r/opt/neg/modified.pem"
	dd if="$G3_DER" of="$_r/opt/neg/truncated.der" bs=593 count=1 2>/dev/null
	awk 'NR != 5' "$G3_PEM" > "$_r/opt/neg/truncated.pem"
	# special files: FIFO, empty file, symlinks out of the tree
	mkfifo "$_r/srv/fifo"
	: > "$_r/srv/empty"
	ln -s "$T/outside/dir" "$_r/srv/escape-dir"
	ln -s "$T/outside/dir/g3.pem" "$_r/srv/escape.pem"
	ln -s ../../outside/aaa.pem "$_r/srv/escape-relative.pem"
	ln -s "$T/outside/libnssckbi.so" "$_r/srv/libnssckbi-escape.so"
}

# mk_rootfs ROOT: the mock rootfs of tests/expected/offline-rootfs.txt
mk_rootfs() {
	_r=$1
	mk_negatives "$_r" || return 1
	mkdir -p "$_r/etc/ssl/certs" "$_r/etc/pki/ca-trust/source/blocklist" \
		"$_r/etc/pki/ca-trust/source/blacklist" "$_r/etc/pki/ca-trust/source/anchors" \
		"$_r/usr/share/ca-certificates/mozilla" "$_r/usr/share/pki/ca-trust-source/anchors" \
		"$_r/usr/lib/x86_64-linux-gnu" "$_r/usr/bin" "$_r/home/u/.mozilla/firefox/p" \
		"$_r/home/u/.pki/nssdb" "$_r/opt/app" "$_r/opt/bom" "$_r/opt/ign" "$_r/src" || return 1
	# PEM bundles (positives)
	{
		echo "# $G3_CN"
		cat "$G3_PEM" "$DATA/others.pem"
		echo "# $AAA_LABEL"
		cat "$AAA_PEM"
	} > "$_r/etc/ssl/certs/ca-certificates.crt"
	cp "$G3_PEM" "$_r/opt/app/nocomment.pem"
	cat "$DATA/others.pem" "$AAA_PEM" > "$_r/opt/app/bundle-nocomment.pem"
	cp "$AAA_PEM" "$_r/opt/app/with space.pem"
	cp "$G3_PEM" "$_r/opt/app/-dash.pem"
	cp "$AAA_PEM" "$_r/opt/app/$(printf 'new\nline.pem')"
	cp "$G3_PEM" "$_r/opt/app/$(printf 'we\001ird.pem')"
	crlf "$G3_PEM" > "$_r/opt/app/crlf.pem"
	rewrap 76 "$AAA_PEM" > "$_r/opt/app/wrap76.pem"
	# found only through the NSS label: the CN is not in the text, and the
	# base64 wrapped at 48 columns does not contain the first PEM line
	{ echo "# $AAA_LABEL"; rewrap 48 "$AAA_PEM"; } > "$_r/opt/app/label-only.pem"
	# OpenSSL TRUSTED CERTIFICATEs: trusted for serverAuth / plain anchor
	# (VULNERABLE), serverAuth rejected / only emailProtection (PATCHED)
	cp "$DATA/g3-trust-serverauth.pem" "$_r/opt/app/trusted-g3.pem"
	cp "$DATA/aaa-alias-only.pem" "$_r/opt/app/anchor-aaa.pem"
	cp "$DATA/g3-reject-serverauth.pem" "$_r/etc/ssl/trusted-reject.pem"
	cp "$DATA/aaa-reject-serverauth.pem" "$_r/opt/app/reject-aaa.pem"
	cp "$DATA/aaa-trust-email.pem" "$_r/opt/app/email-only-aaa.pem"
	# the same with anyExtendedKeyUsage: rejected (PATCHED), trusted (VULNERABLE)
	cp "$DATA/g3-reject-anyeku.pem" "$_r/opt/app/reject-any-g3.pem"
	cp "$DATA/aaa-trust-anyeku.pem" "$_r/opt/app/trust-any-aaa.pem"
	# embedded copies: DER, escaped PEM in source code and JSON
	cp "$G3_DER" "$_r/opt/app/g3.der"
	{ elf; zeros 200; cat "$AAA_DER"; zeros 50; } > "$_r/usr/bin/app"
	c_string "$G3_PEM" > "$_r/src/roots.c"
	json_string "$AAA_PEM" > "$_r/opt/app/roots.json"
	# DER after a UTF-16 / UTF-8 byte order mark (rg must not transcode)
	{ printf '\376\377'; cat "$AAA_DER"; } > "$_r/opt/bom/fe-ff.bin"
	{ printf '\377\376'; zeros 100; cat "$G3_DER"; } > "$_r/opt/bom/ff-fe.bin"
	{ printf '\357\273\277'; cat "$G3_DER"; } > "$_r/opt/bom/utf8bom.bin"
	# ignore files (.ignore, .rgignore) must not hide anything from rg
	printf '*.pem\n' > "$_r/opt/ign/.ignore"
	printf '*.der\n' > "$_r/opt/ign/.rgignore"
	cp "$G3_PEM" "$_r/opt/ign/g3.pem"
	cp "$AAA_DER" "$_r/opt/ign/aaa.der"
	# path classes: NSS modules/dbs (UNKNOWN), distrust lists (PATCHED),
	# CA source files (SKIPPED)
	mk_ckbi "$_r/usr/lib/x86_64-linux-gnu/libnssckbi.so" "$G3_DER" "$AAA_DER"
	ln -s usr/lib "$_r/lib"		# merged /usr: must not be searched twice
	{ printf 'SQLite format 3\000'; zeros 84; cat "$G3_DER"; zeros 64; } > "$_r/home/u/.mozilla/firefox/p/cert9.db"
	{ zeros 16; cat "$AAA_DER"; } > "$_r/home/u/.pki/nssdb/cert8.db"
	cp "$G3_PEM" "$_r/etc/pki/ca-trust/source/blocklist/g3.pem"
	cp "$AAA_PEM" "$_r/etc/pki/ca-trust/source/blacklist/aaa.pem"
	cp "$G3_PEM" "$_r/etc/pki/ca-trust/source/anchors/g3.pem"
	cp "$AAA_PEM" "$_r/usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt"
	cp "$G3_PEM" "$_r/usr/share/pki/ca-trust-source/anchors/emSign.pem"
	mkfifo "$_r/opt/app/fifo"
}

# Searchers, each alone in a PATH directory; return 1 if not available.
# setup_searcher NAME DIR: rg, grep (GNU), busybox (busybox grep), nozgrep
# (grep that rejects -z like Yocto's busybox without CONFIG_EXTRA_COMPAT).
setup_searcher() {
	_d=$2
	mkdir -p "$_d"
	case $1 in
	rg)
		link_tool "$_d" rg 2>/dev/null || return 1 ;;
	grep)
		_g=$(command -v grep) || return 1
		"$_g" --version 2>/dev/null | head -n 1 | grep -q 'GNU grep' || return 1
		link_tool "$_d" grep "$_g" ;;
	busybox)
		_b=$(command -v busybox) || return 1
		"$_b" --list 2>/dev/null | grep -qx grep || return 1
		link_tool "$_d" grep "$_b" ;;
	nozgrep)
		# wraps busybox grep if there is one, else the system grep
		_nz=$_d
		setup_searcher busybox "$_nz/real" || link_tool "$_nz/real" grep || return 1
		_d=$_nz
		cat > "$_d/grep" <<-EOF
		#!$SH
		for a do
		    case \$a in
		    --) break ;;
		    -z | --null-data | -[!-]*z*)
		        echo "grep: invalid option -- 'z'" >&2
		        echo "BusyBox v1.36.1 multi-call binary." >&2
		        exit 2 ;;
		    esac
		done
		exec $(q "$_d/real/grep") "\$@"
		EOF
		chmod 755 "$_d/grep" ;;
	*)
		return 1 ;;
	esac
}
# The searcher name the binary reports
searcher_name() { case $1 in rg) echo rg ;; *) echo grep ;; esac; }
