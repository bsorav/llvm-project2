add_llvm_library( LLVMBackdoor MODULE
  InstrumentBackdoor.cpp

  DEPENDS
  intrinsics_gen
  PLUGIN_TOOL
  opt
  )

#add_superopt_libs(slibs)
#target_link_libraries(LLVMSuperopt PRIVATE ${slibs})
