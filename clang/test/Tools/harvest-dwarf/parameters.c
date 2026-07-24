// REQUIRES: x86-registered-target
// RUN: %clang -target i386-unknown-linux-gnu -g -O0 -c %s -o %t.o
// RUN: harvest-dwarf %t.o | FileCheck %s

struct Pair {
  int a;
  int b;
};

int parameter_locations(int x, struct Pair pair, int y) {
  return x + pair.a + pair.b + y;
}

// CHECK: =SubprogramBegin: parameter_locations
// CHECK: =ParamName: x
// CHECK-NEXT: =ParamIndex: 0
// CHECK: =LocRange
// CHECK: =Expr
// CHECK: =ParamName: pair
// CHECK-NEXT: =ParamIndex: 1
// CHECK: =LocRange
// CHECK: =Expr
// CHECK: =ParamName: y
// CHECK-NEXT: =ParamIndex: 2
// CHECK: =LocRange
// CHECK: =Expr
// CHECK: =SubprogramEnd: parameter_locations
