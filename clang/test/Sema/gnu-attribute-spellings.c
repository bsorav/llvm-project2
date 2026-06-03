// RUN: %clang_cc1 -triple i686-pc-linux-gnu -fsyntax-only %s
// RUN: %clang_cc1 -triple i686-pc-windows-borland -DONLY_DOUBLE_UNDERSCORE -fsyntax-only %s

#ifndef ONLY_DOUBLE_UNDERSCORE
int bare_gnu_attribute __attribute((unused));
#endif
int double_underscore_gnu_attribute __attribute__((unused));
