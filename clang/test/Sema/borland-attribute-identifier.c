// RUN: %clang_cc1 -triple i686-pc-windows-borland -fsyntax-only %s

int f(int __attribute) {
  return __attribute;
}
