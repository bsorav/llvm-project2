// RUN: %clang_cc1 -triple i686-pc-windows-borland %s -E -dM -o - \
// RUN:   | FileCheck -match-full-lines %s --check-prefix=CHECK-BORLAND

#if __BORLANDC__ < 0x0500
#error __BORLANDC__ must be compatible with Borland C++ 5.0 or newer
#endif

#if __TURBOC__ < 0x0500
#error __TURBOC__ must be compatible with Borland C++ 5.0 or newer
#endif

// CHECK-BORLAND: #define _M_IX86 300
// CHECK-BORLAND: #define _WIN32 1
// CHECK-BORLAND: #define __BORLANDC__ {{.*}}
// CHECK-BORLAND: #define __FLAT__ 1
// CHECK-BORLAND: #define __TURBOC__ {{.*}}
// CHECK-BORLAND: #define __WIN32__ 1
// CHECK-BORLAND: #define __int64 long long
