DISTCC_AVAILABLE := $(shell command -v distcc 2> /dev/null)
ifdef DISTCC_AVAILABLE
  ifneq ($(shell distcc --show-hosts 2>/dev/null | wc -l),0)
  	DISTCC_OPTS := -DCMAKE_C_COMPILER_LAUNCHER=distcc -DCMAKE_CXX_COMPILER_LAUNCHER=distcc
	endif
endif

all: install

build_dir:
	mkdir -p build

configure: build_dir
	#https://llvm.org/docs/GettingStarted.html
	mkdir -p build
	cd build && cmake $(DISTCC_OPTS) -G Ninja -DCMAKE_CXX_COMPILER=clang++-11 -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_CXX_STANDARD="17" -DLLVM_ENABLE_BINDINGS=OFF -DLLVM_ENABLE_FFI=ON -DLLVM_USE_LINKER=gold -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_BUILD_EXAMPLES=1 -DARCH_SRC="etfg" -DARCH_DST="x64" ../llvm && cd ..

install: configure
	ninja -C build llc opt llvm-config llvm-dis llvm-link llvm-as llvm2tfg harvest-dwarf LLVMSuperopt.so LLVMLockstep.so UnsequencedAliasVisitor.so harvest-dwarf scan-build scan-view #clang

llvm2tfg:
	ninja -l`nproc` -C build llvm2tfg

harvest-dwarf:
	ninja -l1 -C build harvest-dwarf

clean:
	ninja -C build clean

distclean:
	rm -rf build

.PHONY: all install llvm2tfg harvest-dwarf clean distclean
