// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -emit-llvm -o - %s | FileCheck %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -emit-llvm -o - %s | FileCheck %s --check-prefix=DECL

void break_marker(int *p) {
// CHECK-LABEL: define {{.*}}void @break_marker(
  while (*p) {
    if (*p)
      break;
// CHECK: call void @llvm.break.statement.marker(i32 1, i32 0)
  }
}

void switch_break_no_marker(int *p) {
// CHECK-LABEL: define {{.*}}void @switch_break_no_marker(
// CHECK-NOT: statement.marker
// CHECK-LABEL: define {{.*}}void @goto_marker(
  while (*p) {
    switch (*p) {
    case 1:
      break;
    }
  }
}

void goto_marker(int *p) {
  while (*p) {
    if (*p)
      goto done;
// CHECK: call void @llvm.goto.statement.marker(i32 1, i32 0)
    ++*p;
  }
done:
  return;
}

void indirect_goto_marker(int i) {
// CHECK-LABEL: define {{.*}}void @indirect_goto_marker(
// CHECK-NOT: statement.marker
// CHECK-LABEL: define {{.*}}void @same_loop_goto_no_marker(
  void *labels[] = {&&done};
  while (i--)
    goto *labels[0];
done:
  return;
}

void same_loop_goto_no_marker(int *p) {
  while (*p) {
  again:
    if (*p)
      goto again;
    --*p;
  }
}

void nested_goto_marker(int *p) {
// CHECK-LABEL: define {{.*}}void @nested_goto_marker(
  while (*p) {
    while (*p > 1) {
      if (*p == 2)
        goto outer;
// CHECK: call void @llvm.goto.statement.marker(i32 2, i32 1)
      --*p;
    }
  outer:
    --*p;
  }
}

int return_marker(int *p) {
// CHECK-LABEL: define {{.*}}i32 @return_marker(
  while (*p) {
    if (*p == 1)
      return 1;
// CHECK: call void @llvm.return.statement.marker(i32 1, i32 0)
    if (*p == 2)
      return 2;
// CHECK: call void @llvm.return.statement.marker(i32 1, i32 0)
    ++*p;
  }
  return 0;
}

int nested_return_marker(int *p) {
// CHECK-LABEL: define {{.*}}i32 @nested_return_marker(
  while (*p) {
    while (*p > 1) {
      if (*p == 3)
        return 3;
// CHECK: call void @llvm.return.statement.marker(i32 2, i32 0)
      --*p;
    }
  }
  return 0;
}

int non_loop_return_no_marker(int *p) {
// CHECK-LABEL: define {{.*}}i32 @non_loop_return_no_marker(
// CHECK-NOT: statement.marker
  if (*p)
    return 1;
  return 0;
}

// DECL-DAG: declare void @llvm.break.statement.marker(i32, i32)
// DECL-DAG: declare void @llvm.goto.statement.marker(i32, i32)
// DECL-DAG: declare void @llvm.return.statement.marker(i32, i32)
