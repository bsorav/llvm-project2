// REQUIRES: shell
// UNSUPPORTED: system-windows
//
// RUN: rm -rf %t
// RUN: mkdir -p %t/src/SubDir
// RUN: touch %t/src/SubDir/MixedCase.h
// RUN: printf '#include "subdir/mixedcase.h"\nvoid old(void);\nvoid test(void) { old(); }\n' > %t/src/Main.c
// RUN: callee-rename -D old=replacement %t/src/Main.c -- \
// RUN:   -target i686-pc-windows-borland | FileCheck %s

// CHECK: void test(void) { replacement(); }
