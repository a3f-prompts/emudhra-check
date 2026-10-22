# SPDX-License-Identifier: MIT
project('emudhra-check', 'c',
  version: '1.0.0',
  license: 'MIT',
  meson_version: '>= 0.57',
  default_options: ['c_std=c99', 'warning_level=3', 'buildtype=release'])

# gcc at -O3 (buildtype=release) warns that "no control (%s)" may be
# truncated to its 256-byte buffer: the %s is "TOOL not installed" for one of
# five short tool names, and snprintf() truncation would be harmless anyway.
# -O2 and clang do not warn.
cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments('-Wno-format-truncation'), language: 'c')

# One C99/POSIX file, libc only.  Without meson:
#   cc -std=c99 -O2 -o certstore-check certstore-check.c
certstore_check = executable('certstore-check', 'certstore-check.c', install: true)

# The tests run the binary; a cross build needs an exe_wrapper for that.
if meson.can_run_host_binaries()
  subdir('tests')
else
  message('cross build without exe_wrapper: tests not defined')
endif
