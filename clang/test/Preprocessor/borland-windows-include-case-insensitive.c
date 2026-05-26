// REQUIRES: shell
// UNSUPPORTED: system-windows
//
// RUN: rm -rf %t
// RUN: mkdir -p %t/include/WinApi
// RUN: touch %t/include/WinApi/Header.h
// RUN: printf '#include <winapi/header.h>\n' > %t/main.c
// RUN: %clang_cc1 -triple i686-pc-windows-borland -fsyntax-only \
// RUN:   -I %t/include %t/main.c
