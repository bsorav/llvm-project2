DISTCC_AVAILABLE := $(shell command -v distcc 2> /dev/null)
ifdef DISTCC_AVAILABLE
  ifneq ($(shell distcc --show-hosts 2>/dev/null | wc -l),0)
  	DISTCC_OPTS := -DCMAKE_C_COMPILER_LAUNCHER=distcc -DCMAKE_CXX_COMPILER_LAUNCHER=distcc
	endif
endif

.PHONY: all
all: install

.PHONY: build
build:
	mkdir -p build
	#https://llvm.org/docs/GettingStarted.html
	cd build && cmake $(DISTCC_OPTS) -G Ninja -DCMAKE_CXX_COMPILER=clang++-11 -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_CXX_STANDARD="17" -DLLVM_ENABLE_BINDINGS=OFF -DLLVM_ENABLE_FFI=ON -DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_EH=ON -DLLVM_USE_LINKER=lld -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_BUILD_EXAMPLES=1 -DARCH_SRC="etfg" -DARCH_DST="x64" ../llvm && cd ..

.PHONY: tidy
tidy:
	#run-clang-tidy -clang-tidy-binary ../llvm-project/build/bin/clang-tidy -p build/etfg_i386 -checks='-*,clang-analyzer-core*,clang-analyzer-cplusplus*,cppcoreguidelines*,modernize-*'
	#run-clang-tidy -p build -checks='-*,clang-analyzer-core*,clang-analyzer-cplusplus*,cppcoreguidelines*,modernize-*'
	run-clang-tidy -clang-tidy-binary ./build/bin/clang-tidy -p build -checks='-*,clang-analyzer-core*'

.PHONY: install
install: build
	# ninja -C build llc opt llvm-config llvm-dis llvm-link llvm-as llvm2tfg harvest-dwarf LLVMSuperopt.so LLVMLockstep.so harvest-dwarf clang scan-build scan-view #UnsequencedAliasVisitor.so 
	ninja -C build llc opt llvm-config llvm-dis llvm-link llvm-as llvm2tfg clang scan-build scan-view clang-tidy #UnsequencedAliasVisitor.so LLVMLockstep.so LLVMSuperopt.so harvest-dwarf

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
