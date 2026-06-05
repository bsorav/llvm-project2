// RUN: %clang -### -fignore-noreturn -c %s 2>&1 | FileCheck %s

// CHECK: "-cc1"
// CHECK-SAME: "-fignore-noreturn"
