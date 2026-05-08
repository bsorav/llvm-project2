// RUN: %clang_cc1 -triple i686-pc-windows-borland -fborland-extensions -emit-llvm -o - %s | FileCheck %s

struct S1 {
  int a;
};

struct S3 {
  char a;
  char b;
  char c;
};

struct S4 {
  short a;
  short b;
};

struct SF {
  float f;
};

struct S2 {
  int a;
  int b;
};

// CHECK-LABEL: define dso_local i32 @return_int()
int return_int(void) {
  return 1;
}

// CHECK-LABEL: define dso_local ptr @return_pointer(
int *return_pointer(int *p) {
  return p;
}

// CHECK-LABEL: define dso_local i64 @return_long_long()
long long return_long_long(void) {
  return 1;
}

// CHECK-LABEL: define dso_local double @return_double()
double return_double(void) {
  return 1.0;
}

// CHECK-LABEL: define dso_local float @return_float()
float return_float(void) {
  return 1.0f;
}

// CHECK-LABEL: define dso_local void @return_s3(ptr dead_on_unwind noalias writable sret(%struct.S3) align 1 %agg.result)
struct S3 return_s3(void) {
  struct S3 s = {1, 2, 3};
  return s;
}

// CHECK-LABEL: define dso_local i32 @return_s4()
struct S4 return_s4(void) {
  struct S4 s = {1, 2};
  return s;
}

// CHECK-LABEL: define dso_local i32 @return_sf()
struct SF return_sf(void) {
  struct SF s = {1.0f};
  return s;
}

// CHECK-LABEL: define dso_local i32 @return_s1()
struct S1 return_s1(void) {
  struct S1 s = {1};
  return s;
}

// CHECK-LABEL: define dso_local void @return_s2(ptr dead_on_unwind noalias writable sret(%struct.S2) align 1 %agg.result)
struct S2 return_s2(void) {
  struct S2 s = {1, 2};
  return s;
}

// CHECK-LABEL: define dso_local i32 @call_return_s3()
// CHECK: call void @return_s3(ptr dead_on_unwind writable sret(%struct.S3) align 1 %
int call_return_s3(void) {
  struct S3 s = return_s3();
  return s.a + s.b + s.c;
}

// CHECK-LABEL: define dso_local i32 @call_return_s4()
// CHECK: call i32 @return_s4()
int call_return_s4(void) {
  struct S4 s = return_s4();
  return s.a + s.b;
}

// CHECK-LABEL: define dso_local i32 @call_return_sf()
// CHECK: call i32 @return_sf()
int call_return_sf(void) {
  struct SF s = return_sf();
  return s.f != 0.0f;
}

// CHECK-LABEL: define dso_local i32 @call_return_s2()
// CHECK: call void @return_s2(ptr dead_on_unwind writable sret(%struct.S2) align 1 %
int call_return_s2(void) {
  struct S2 s = return_s2();
  return s.a + s.b;
}

// CHECK-LABEL: define dso_local float @call_return_float()
// CHECK: call float @return_float()
float call_return_float(void) {
  return return_float();
}
