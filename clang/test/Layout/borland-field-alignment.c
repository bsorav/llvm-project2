// RUN: %clang_cc1 -triple i686-pc-windows-borland -fdump-record-layouts \
// RUN:   -fsyntax-only %s | FileCheck %s

struct A {
  char c;
  int i;
  long long ll;
};

int use_a[sizeof(struct A)];

// CHECK:      *** Dumping AST Record Layout
// CHECK-NEXT:          0 | struct A
// CHECK-NEXT:          0 |   char c
// CHECK-NEXT:          1 |   int i
// CHECK-NEXT:          5 |   long long ll
// CHECK-NEXT:            | [sizeof=13, align=1]
