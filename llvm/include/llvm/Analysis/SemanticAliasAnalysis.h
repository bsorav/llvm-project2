#ifndef LLVM_ANALYSIS_SEMANTICALIASANALYSIS_H
#define LLVM_ANALYSIS_SEMANTICALIASANALYSIS_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "tfg/tfg_llvm.h"

#include <set>

namespace llvm {

class SemanticAAResult : public AAResultBase<SemanticAAResult> {
private:
  shared_ptr<tfg_llvm_t const> m_tfg_llvm;
public:
  explicit SemanticAAResult(shared_ptr<tfg_llvm_t const> const& t_llvm) : AAResultBase(), m_tfg_llvm(t_llvm) {}
  SemanticAAResult(SemanticAAResult &&Arg)
      : AAResultBase(std::move(Arg)), m_tfg_llvm(Arg.m_tfg_llvm) {}

  AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB, AAQueryInfo &AAQI);
};

/// Analysis pass providing a never-invalidated alias analysis result.
class SemanticAA : public AnalysisInfoMixin<SemanticAA> {
  friend AnalysisInfoMixin<SemanticAA>;
  static AnalysisKey Key;

public:
  typedef SemanticAAResult Result;

  SemanticAAResult run(Function &F, FunctionAnalysisManager &AM);
};

/// Legacy wrapper pass to provide the SemanticAAResult object.
class SemanticAAWrapperPass : public FunctionPass {
  std::unique_ptr<SemanticAAResult> Result;

public:
  static char ID;

  SemanticAAWrapperPass();

  SemanticAAResult &getResult() { return *Result; }
  const SemanticAAResult &getResult() const { return *Result; }

  bool runOnFunction(Function &F) override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
};

/// Creates an instance of \c SemanticAAWrapperPass.
FunctionPass *createSemanticAAWrapperPass();
}

#endif
