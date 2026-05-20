// RUN: %clang_cc1 -triple i686-pc-windows-borland -fsyntax-only %s

typedef __int64 BorlandInt64;
typedef unsigned __int64 BorlandUInt64;

BorlandInt64 signed_value;
BorlandUInt64 unsigned_value;
