include_directories(
  ${LLVM_MAIN_SRC_DIR}/lib/Target/X86
  ${LLVM_BINARY_DIR}/lib/Target/X86
  )

set(LLVM_LINK_COMPONENTS
  BitReader
  IRReader
  Core
  Support
  Analysis
  CodeGen
  )

INCLUDE_DIRECTORIES(../../lib/Analysis/Superopt)

add_llvm_tool(llvm2tfg
  main.cpp
)

add_superopt_libs(slibs)
message(STATUS "slibs=${slibs}")

target_link_libraries(llvm2tfg PRIVATE ${slibs})
