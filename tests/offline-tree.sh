# SPDX-License-Identifier: MIT
# offline-tree.sh BINARY DATADIR SEARCHER (rg, grep, busybox or nozgrep)
#
# --offline on the mock rootfs with one searcher: every positive is reported
# with the right status and reason (also one found only through its NSS
# label, and files that .ignore/.rgignore list), path classes apply,
# negative controls (lookalikes, modified/truncated copies, mentions) are
# candidates that the exact DER comparison rejects, FIFOs do not block,
# symlinks out of the tree are not followed, names with spaces, a leading
# dash, a newline or a control character work.  A negatives-only tree and an
# empty tree give exit 0.
. "$(dirname "$0")/lib.sh"
. "$TESTS/trees.sh"

S=$1
setup_searcher "$S" "$T/bin" || skip "searcher $S is not available"
NAME=$(searcher_name "$S")
for f in offline-rootfs offline-clean; do
	sed "s/@SEARCHER@/$NAME/g" "$TESTS/expected/$f.txt" > "$T/$f.expected"
done

ROOT=$T/rootfs
mk_rootfs "$ROOT" || { fail "cannot build the mock rootfs"; finish; }

run rootfs -- --offline="$ROOT" --searcher="$NAME"
expect_golden rootfs "$T/offline-rootfs.expected"

# --xdev on a single filesystem changes nothing
run xdev -- --offline="$ROOT" --searcher "$NAME" --xdev
expect_golden xdev "$T/offline-rootfs.expected"

# a --bundle inside the tree is reported once
run inbundle -- --bundle "$ROOT/opt/app/nocomment.pem" --offline="$ROOT" --searcher="$NAME"
expect_golden inbundle "$T/offline-rootfs.expected"

# -v: the negative controls were candidates, rejected by the exact comparison
run verbose -- -v --offline="$ROOT" --searcher="$NAME"
norm "$T/verbose.out" | grep '^    candidate rejected' > "$T/rejected.txt"
if diff -u "$TESTS/expected/offline-rejected.txt" "$T/rejected.txt" > "$T/rejected.diff"; then
	ok "verbose: all negative controls were candidates and were rejected"
else
	fail "verbose: rejected candidates differ:"
	sed 's/^/	/' "$T/rejected.diff"
fi
norm "$T/verbose.out" | grep -v '^    ' > "$T/verbose.short"
cp "$T/verbose.short" "$T/verbose.out"
expect_golden verbose "$T/offline-rootfs.expected"

# only negatives and special files: nothing found, exit 0
ROOT=$T/negatives
mk_negatives "$ROOT" || { fail "cannot build the negatives tree"; finish; }
run negatives -- --offline="$ROOT" --searcher="$NAME"
expect_golden negatives "$T/offline-clean.expected"

ROOT=$T/emptydir
mkdir -p "$ROOT"
run empty -- --offline "$ROOT" --searcher="$NAME"
expect_golden empty "$T/offline-clean.expected"

expect_tmp_clean
finish
