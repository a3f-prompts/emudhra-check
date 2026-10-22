# SPDX-License-Identifier: MIT
# Each test: sh SCRIPT BINARY DATADIR [ARG]...; exit 77 = skipped.
# "meson test" runs everything but the 'online' suite (no network);
# "meson test --setup online" runs all suites.  In a cross build meson
# passes the exe_wrapper (with its arguments) as $MESON_EXE_WRAPPER, which
# the scripts put in front of the binary.
sh = find_program('sh')
data_dir = meson.current_source_dir() / 'data'
test_env = {'CSC_TEST_TMP': meson.current_build_dir() / 'tmp'}

tests = [
  # name, suite, script, extra arguments, timeout (s)
  ['offline-rg', 'offline', 'offline-tree.sh', ['rg'], 120],
  ['offline-grep', 'offline', 'offline-tree.sh', ['grep'], 120],
  ['offline-busybox', 'offline', 'offline-tree.sh', ['busybox'], 120],
  ['offline-nozgrep', 'offline', 'offline-tree.sh', ['nozgrep'], 120],
  ['offline-select', 'offline', 'offline-select.sh', [], 120],
  ['offline-unreadable', 'offline', 'offline-unreadable.sh', [], 60],
  ['offline-boundaries', 'offline', 'offline-boundaries.sh', [], 120],
  ['offline-quadratic', 'offline', 'offline-quadratic.sh', [], 60],
  ['offline-bundle-self', 'offline', 'offline-bundle-self.sh', [], 60],
  ['offline-xdev', 'offline', 'offline-xdev.sh', [], 60],
  ['fake-curl', 'fake-clients', 'fake-curl.sh', [], 60],
  ['fake-broken-curl', 'fake-clients', 'fake-broken-curl.sh', [], 60],
  ['fake-notools', 'fake-clients', 'fake-notools.sh', [], 60],
  ['fake-hang', 'fake-clients', 'fake-hang.sh', [], 120],
  ['fake-nss', 'fake-clients', 'fake-nss.sh', [], 60],
  ['fake-interrupt', 'fake-clients', 'fake-interrupt.sh', [], 90],
  ['fake-all', 'fake-clients', 'fake-all.sh', [], 60],
  ['fake-errors', 'fake-clients', 'fake-errors.sh', [], 60],
  ['cli-usage', 'cli', 'cli-usage.sh', [], 60],
  ['cli-color', 'cli', 'cli-color.sh', [], 60],
  ['cli-tty', 'cli', 'cli-tty.sh', [], 60],
  ['online-endpoints', 'online', 'online.sh', [], 300],
]
foreach t : tests
  test(t[0], sh,
    args: [files(t[2]), certstore_check, data_dir] + t[3],
    env: test_env + {'CSC_TEST_NAME': t[0]},
    suite: t[1],
    timeout: t[4])
endforeach

add_test_setup('default', exclude_suites: ['online'], is_default: true)
add_test_setup('online')
