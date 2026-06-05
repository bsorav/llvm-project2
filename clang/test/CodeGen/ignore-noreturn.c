// RUN: %clang_cc1 -emit-llvm -fignore-noreturn %s -o - | FileCheck %s

void callee(void) __attribute__((noreturn));

void caller(void) {
  callee();
}

void exit(int);
void exits(void) {
  exit(1);
}

void self(void) __attribute__((noreturn));
void self(void) {}

// CHECK-LABEL: define{{.*}} void @caller(
// CHECK: call void @callee()
// CHECK-NEXT: ret void

// CHECK-LABEL: define{{.*}} void @exits(
// CHECK: call void @exit(i32 noundef 1)
// CHECK-NEXT: ret void

// CHECK-LABEL: define{{.*}} void @self(
// CHECK: ret void

// CHECK-NOT: attributes {{#[0-9]+}} = { {{.*}}noreturn
