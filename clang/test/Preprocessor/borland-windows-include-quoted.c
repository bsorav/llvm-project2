// REQUIRES: shell
// UNSUPPORTED: system-windows
//
// RUN: rm -rf %t
// RUN: mkdir -p %t/src/SubDir
// RUN: touch %t/src/SubDir/MixedCase.h
// RUN: printf '#include "subdir/mixedcase.h"\n' > %t/src/Main.c
// RUN: %clang_cc1 -triple i686-pc-windows-borland -fsyntax-only %t/src/Main.c
