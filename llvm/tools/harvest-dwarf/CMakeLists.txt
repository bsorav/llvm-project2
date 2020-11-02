set(LLVM_LINK_COMPONENTS
  DebugInfoDWARF
  AllTargetsDescs
  AllTargetsInfos
  MC
  Object
  Support
  )

add_llvm_tool(harvest-dwarf
  main.cpp
  )

add_superopt_libs(slibs)
target_link_libraries(harvest-dwarf PRIVATE ${slibs})
