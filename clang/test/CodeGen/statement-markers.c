// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -emit-llvm -o - %s | FileCheck %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -emit-llvm -o - %s | FileCheck %s --check-prefix=DECL

void break_marker(int *p) {
// CHECK-LABEL: define {{.*}}void @break_marker(
  while (*p) {
    if (*p)
      break;
// CHECK: call void @llvm.break.statement.marker()
  }
}

void goto_marker(int *p) {
// CHECK-LABEL: define {{.*}}void @goto_marker(
  while (*p) {
    if (*p)
      goto done;
// CHECK: call void @llvm.goto.statement.marker()
    ++*p;
  }
done:
  return;
}

void indirect_goto_marker(int i) {
// CHECK-LABEL: define {{.*}}void @indirect_goto_marker(
  void *labels[] = {&&done};
  while (i--)
    goto *labels[0];
// CHECK: call void @llvm.goto.statement.marker()
done:
  return;
}

int return_marker(int *p) {
// CHECK-LABEL: define {{.*}}i32 @return_marker(
  while (*p) {
    if (*p == 1)
      return 1;
// CHECK: call void @llvm.return.statement.marker()
    if (*p == 2)
      return 2;
// CHECK: call void @llvm.return.statement.marker()
    ++*p;
  }
  return 0;
}

// DECL-DAG: declare void @llvm.break.statement.marker()
// DECL-DAG: declare void @llvm.goto.statement.marker()
// DECL-DAG: declare void @llvm.return.statement.marker()
