.PHONY: all
all: install

.PHONY: build
build:
	mkdir -p build
	#https://llvm.org/docs/GettingStarted.html
	cd build && cmake $(DISTCC_OPTS) -G Ninja -DCMAKE_CXX_COMPILER=clang++-12 -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_CXX_STANDARD="17" -DLLVM_ENABLE_BINDINGS=OFF -DLLVM_ENABLE_FFI=ON -DLLVM_USE_LINKER=lld -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_BUILD_EXAMPLES=1 -DARCH_SRC="etfg" -DARCH_DST="x64" ../llvm && cd ..

.PHONY: install
install: build
	ninja -C build llc opt llvm-config llvm-dis llvm-link llvm-as llvm2tfg harvest-dwarf LLVMSuperopt.so clang scan-build scan-view

.PHONY: llvm2tfg
llvm2tfg:
	ninja -l`nproc` -C build llvm2tfg

.PHONY: harvest-dwarf
harvest-dwarf:
	ninja -l1 -C build harvest-dwarf

.PHONY: clean
clean:
	ninja -C build clean

.PHONY: distclean
distclean:
	-rm -rf build cscope.files
	-find . -name cscope.out |xargs rm -f
	-find . -name tags |xargs rm -f
	git clean -df
