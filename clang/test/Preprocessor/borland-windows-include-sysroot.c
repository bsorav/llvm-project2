// REQUIRES: shell
// UNSUPPORTED: system-windows
//
// RUN: rm -rf %t
// RUN: mkdir -p %t/sysroot/BorlandSDK/SubDir
// RUN: touch %t/sysroot/BorlandSDK/SubDir/SysHeader.h
// RUN: printf '#include <subdir/sysheader.h>\n' > %t/main.c
// RUN: %clang_cc1 -triple i686-pc-windows-borland -fsyntax-only \
// RUN:   -isysroot %t/sysroot -iwithsysroot /BorlandSDK %t/main.c
