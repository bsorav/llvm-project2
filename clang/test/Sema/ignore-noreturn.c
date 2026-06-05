// RUN: %clang_cc1 -verify -x c++ -std=c++11 -Werror=invalid-noreturn -fsyntax-only -fignore-noreturn %s

// expected-no-diagnostics

void f(void) __attribute__((noreturn));
void f(void) {
  return;
}

[[noreturn]] void g(void);
void g(void) {
  return;
}

void h(void);
[[noreturn]] void h(void);
