// RUN: %clang -### --target=i686-pc-windows-borland -c %s 2>&1 \
// RUN:   | FileCheck %s --implicit-check-not=-fborland-extensions

// CHECK: "-cc1"
// CHECK: "-triple" "i686-pc-windows-borland"
