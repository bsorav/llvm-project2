add_clang_executable(callee-rename
  CalleeRename.cpp
)

target_link_libraries(callee-rename
  PRIVATE
  clangTooling
  clangASTMatchers
  clangRewrite
  clangFrontend
)

