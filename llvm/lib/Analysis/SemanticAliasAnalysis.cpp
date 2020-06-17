#include "llvm/Analysis/SemanticAliasAnalysis.h"

#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/InitializePasses.h"
#include "Superopt/dfa_helper.h"

#include "tfg/tfg_llvm.h"

using namespace llvm;

AliasResult SemanticAAResult::alias(const MemoryLocation &LocA,
                                    const MemoryLocation &LocB,
                                    AAQueryInfo &AAQI) {

  // Check if there is a predicate corresponding to LocA and LocB
  //if ((predicates.count(LocA.Ptr) && predicates[LocA.Ptr].count(LocB.Ptr)) ||
  //    (predicates.count(LocB.Ptr) && predicates[LocB.Ptr].count(LocA.Ptr))) {
  //  return NoAlias;
  //}

  // Forward the query to the next analysis.
  return AAResultBase::alias(LocA, LocB, AAQI);
}

char SemanticAAWrapperPass::ID = 0;
INITIALIZE_PASS(SemanticAAWrapperPass, "semantic-aa", "Semantic Alias Analysis",
                false, true)

FunctionPass *llvm::createSemanticAAWrapperPass() {
  return new SemanticAAWrapperPass();
}

SemanticAAWrapperPass::SemanticAAWrapperPass() : FunctionPass(ID) {
  initializeSemanticAAWrapperPassPass(*PassRegistry::getPassRegistry());
}

bool SemanticAAWrapperPass::runOnFunction(Function &F)
{
  Module &M = *F.getParent();
  map<shared_ptr<tfg_edge const>, Instruction *> eimap;
  shared_ptr<tfg_llvm_t const> t_llvm = function2tfg(&F, &M, eimap);
  Result.reset(new SemanticAAResult(t_llvm));
  return false;
}

void SemanticAAWrapperPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
}
