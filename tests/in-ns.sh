# SPDX-License-Identifier: MIT
# sh in-ns.sh [-h] [-m MOUNTPOINT FILE NAME]... -- COMMAND [ARG]...
# Runs COMMAND in a new user and mount namespace; the host is not changed.
# Used by lib.sh's run() after hermetic() (-h) or ns_mount (-m).
#  -h  hide this host's trust stores from COMMAND: /dev/null, which is not a
#      regular file, is bound over every CA bundle and libnssckbi.so that the
#      binary looks for (bundle_globs[] and ckbi_globs[] in certstore-check.c:
#      keep hide_files in sync; lib.sh's expect_hermetic() fails a test whose
#      output still names a host file), and empty tmpfs are mounted on
#      /etc/pki (also hides /etc/pki/nssdb) and the NSS tool dirs the binary
#      searches after $PATH (EXTRA_TOOL_DIRS).
#  -m  MOUNTPOINT becomes an empty tmpfs holding only MOUNTPOINT/NAME, a copy
#      of FILE (after -h, in order): a known NSS module in /opt, a second
#      filesystem in a tree (--xdev), a system bundle in /etc/ssl.
# $CSC_REAL_PATH is the PATH of the test, $PATH the one COMMAND gets.
hide_files='
	/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt
	/etc/ssl/ca-bundle.pem /etc/pki/tls/cacert.pem
	/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem
	/usr/share/grpc/roots.pem /usr/local/share/grpc/roots.pem
	/usr/lib/python3*/*-packages/certifi/cacert.pem
	/usr/lib/python3*/*-packages/pip/_vendor/certifi/cacert.pem
	/usr/lib/python3*/*-packages/grpc/_cython/_credentials/roots.pem
	/usr/lib64/libnssckbi.so /usr/lib/libnssckbi.so /lib64/libnssckbi.so
	/usr/lib/*/libnssckbi.so /usr/lib/*/nss/libnssckbi.so /usr/lib64/*/libnssckbi.so
	/usr/lib/nss/libnssckbi.so /usr/lib64/nss/libnssckbi.so /lib/*/libnssckbi.so
	/usr/local/lib/libnssckbi.so /opt/*/libnssckbi.so'
hide_dirs='/etc/pki /usr/lib64/nss/unsupported-tools /usr/lib/nss/unsupported-tools'

if [ "${1:-}" != --in-ns ]; then
	cmd_path=$PATH
	PATH=$CSC_REAL_PATH
	exec unshare -rm sh "$0" --in-ns "$cmd_path" "$@"
fi
cmd_path=$2
shift 2
while [ $# -gt 0 ]; do
	case $1 in
	-h)
		for f in $hide_files; do
			if [ -e "$f" ]; then mount -o bind /dev/null "$f" || exit 98; fi
		done
		for d in $hide_dirs; do
			if [ -d "$d" ]; then mount -t tmpfs csc-hide "$d" || exit 98; fi
		done
		shift ;;
	-m)
		mount -t tmpfs csc-test "$2" && mkdir -p "$(dirname "$2/$4")" &&
			cp "$3" "$2/$4" || exit 98
		shift 4 ;;
	--)
		shift
		break ;;
	*)
		echo "in-ns.sh: unknown option '$1'" >&2
		exit 99 ;;
	esac
done
PATH=$cmd_path
exec "$@"
