// RUN: %clang_cc1 -triple i386-unknown-linux-gnu -debug-info-kind=limited \
// RUN:   -emit-llvm -o - %s | FileCheck %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -debug-info-kind=limited \
// RUN:   -emit-llvm -o - %s | FileCheck %s --check-prefix=UNSUPPORTED
// RUN: %clang_cc1 -triple i386-unknown-linux-gnu -mregparm 2 \
// RUN:   -debug-info-kind=limited -emit-llvm -o - %s | \
// RUN:   FileCheck %s --check-prefix=UNSUPPORTED

struct Single {
  int x;
};

struct Pair {
  int x;
  int y;
};

struct ByVal {
  int x;
  char y;
};

typedef struct Pair PairTypedef;

int parameter_allocas(int x, struct Single single, struct Pair pair,
                      struct ByVal byval, PairTypedef wrapped) {
  return x + single.x + pair.x + byval.y + wrapped.y;
}

int argument_index(struct Pair prefix, int value) {
  return prefix.x + value;
}

// CHECK-LABEL: define {{.*}}i32 @parameter_allocas(
// CHECK-SAME: i32 noundef %[[X:[^,]+]],
// CHECK-SAME: ptr noundef byval(%struct.ByVal) align 4 %byval,
// CHECK: %single = alloca %struct.Single, align 4, !superopt.parameter.alloca ![[SINGLE:[0-9]+]]
// CHECK: %pair = alloca %struct.Pair, align 4, !superopt.parameter.alloca ![[PAIR:[0-9]+]]
// CHECK: %wrapped = alloca %struct.Pair, align 4, !superopt.parameter.alloca ![[WRAPPED:[0-9]+]]
// CHECK: %x.addr = alloca i32, align 4, !superopt.parameter.alloca ![[X_MD:[0-9]+]]
// CHECK-NOT: %byval.addr = alloca
// CHECK: store i32 %[[X]], ptr %x.addr

// CHECK-LABEL: define {{.*}}i32 @argument_index(
// CHECK: %prefix = alloca %struct.Pair, align 4, !superopt.parameter.alloca ![[PREFIX:[0-9]+]]
// CHECK: %value.addr = alloca i32, align 4, !superopt.parameter.alloca ![[VALUE:[0-9]+]]
// CHECK: ![[SINGLE]] = !{!"param", i32 2, i32 1, i32 1}
// CHECK: ![[PAIR]] = !{!"param", i32 3, i32 2, i32 2}
// CHECK: ![[WRAPPED]] = !{!"param", i32 5, i32 5, i32 2}
// CHECK: ![[X_MD]] = !{!"param", i32 1, i32 0, i32 1}
// CHECK: ![[PREFIX]] = !{!"param", i32 1, i32 0, i32 2}
// CHECK: ![[VALUE]] = !{!"param", i32 2, i32 2, i32 1}

// UNSUPPORTED-NOT: !superopt.parameter.alloca
