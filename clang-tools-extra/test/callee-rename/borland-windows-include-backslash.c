// REQUIRES: shell
// UNSUPPORTED: system-windows
//
// RUN: rm -rf %t
// RUN: mkdir -p %t/include/WinApi
// RUN: touch %t/include/WinApi/Header.h
// RUN: printf '#include <WinApi\\Header.h>\nvoid old(void);\nvoid test(void) { old(); }\n' > %t/main.c
// RUN: callee-rename -D old=replacement %t/main.c -- \
// RUN:   -target i686-pc-windows-borland -I %t/include | FileCheck %s

// CHECK: void test(void) { replacement(); }
