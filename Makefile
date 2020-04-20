DISTCC_AVAILABLE := $(shell command -v dot 2> /dev/null)
ifdef DISTCC_AVAILABLE
  DISTCC_AVAILABLE_HOSTS := $(shell distcc --show-hosts 2>/dev/null | wc -l)
  ifneq (DISTCC_AVAILABLE_HOSTS, 0)
  	DISTCC_OPTS := -DCMAKE_C_COMPILER_LAUNCHER=distcc -DCMAKE_CXX_COMPILER_LAUNCHER=distcc
	endif
endif

all::
	ninja -C build llc clang opt llvm-config llvm-dis llvm-link lli llvm-as

first::
	#for first time build
	ninja -C build llc clang opt llvm-config llvm-dis llvm-link lli llvm-as #-j 1

install::
	#https://llvm.org/docs/GettingStarted.html
	mkdir -p build
	cd build && cmake $(DISTCC_OPTS) -G Ninja -DLLVM_ENABLE_BINDINGS=OFF -DLLVM_ENABLE_FFI=ON -DLLVM_USE_LINKER=gold -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_BUILD_EXAMPLES=1 ../llvm && cd ..
