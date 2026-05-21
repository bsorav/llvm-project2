// REQUIRES: shell
// UNSUPPORTED: system-windows
//
// RUN: rm -rf %t
// RUN: mkdir -p %t/sysroot/BorlandSDK/SubDir
// RUN: touch %t/sysroot/BorlandSDK/SubDir/SysHeader.h
// RUN: printf '#include <subdir/sysheader.h>\nvoid old(void);\nvoid test(void) { old(); }\n' > %t/main.c
// RUN: callee-rename -D old=replacement %t/main.c -- \
// RUN:   -target i686-pc-windows-borland -isysroot %t/sysroot \
// RUN:   -iwithsysroot /BorlandSDK | FileCheck %s

// CHECK: void test(void) { replacement(); }
