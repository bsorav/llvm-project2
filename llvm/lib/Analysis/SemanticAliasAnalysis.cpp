#include "llvm/Analysis/SemanticAliasAnalysis.h"

#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/InitializePasses.h"
#include "Superopt/dfa_helper.h"
#include "Superopt/sym_exec_llvm.h"

#include "tfg/tfg_llvm.h"

using namespace llvm;

AliasResult
SemanticAAResult::convertTfgAliasResultToAliasResult(tfg_alias_result_t tfg_alias_result)
{
  switch (tfg_alias_result) {
    case TfgMayAlias: {
      return MayAlias;
    }
    case TfgMustNotAlias: {
      return NoAlias;
    }
    case TfgMustAlias: {
      return MustAlias;
    }
    case TfgPartialAlias: {
      return PartialAlias;
    }
    default: NOT_REACHED();
  }
}

#ifndef NDEBUG
static const Function *getParent(const Value *V) {
  if (const Instruction *inst = dyn_cast<Instruction>(V)) {
    if (!inst->getParent())
      return nullptr;
    return inst->getParent()->getParent();
  }

  if (const Argument *arg = dyn_cast<Argument>(V))
    return arg->getParent();

  return nullptr;
}

static bool notDifferentParent(const Value *O1, const Value *O2) {

  const Function *F1 = getParent(O1);
  const Function *F2 = getParent(O2);

  return !F1 || !F2 || F1 == F2;
}
#endif


AliasResult
SemanticAAResult::alias(const MemoryLocation &LocA,
                        const MemoryLocation &LocB,
                        AAQueryInfo &AAQI) {
  assert(notDifferentParent(LocA.Ptr, LocB.Ptr) &&
         "SemanticAliasAnalysis doesn't support interprocedural queries.");

  Function const* F1 = getParent(LocA.Ptr);
  Function const* F2 = getParent(LocB.Ptr);
  Function const* F = nullptr;

  if (F1) {
    F = F1;
  }
  if (F2) {
    F = F2;
  }

  string fname = F ? F->getName().str() : "";

  string nameA = sym_exec_common::get_value_name(*LocA.Ptr);
  string nameB = sym_exec_common::get_value_name(*LocB.Ptr);

  DYN_DEBUG2(aliasAnalysis, std::cout << "SemanticAAResult::" << __func__ << " " << __LINE__ << ": LocA = " << nameA << "\n");
  DYN_DEBUG2(aliasAnalysis, std::cout << "SemanticAAResult::" << __func__ << " " << __LINE__ << ": LocB = " << nameB << "\n");

  uint64_t sizeA = LocA.Size.hasValue() ? LocA.Size.getValue() : (uint64_t)-1;
  uint64_t sizeB = LocB.Size.hasValue() ? LocB.Size.getValue() : (uint64_t)-1;

  return convertTfgAliasResultToAliasResult(tfg_llvm_t::get_aliasing_relationship_between_memaccesses(*m_function_tfg_map, fname, nameA, sizeA, nameB, sizeB));

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

ImmutablePass *llvm::createSemanticAAWrapperPass() {
  return new SemanticAAWrapperPass();
}

SemanticAAWrapperPass::SemanticAAWrapperPass() : ImmutablePass(ID) {
  initializeSemanticAAWrapperPassPass(*PassRegistry::getPassRegistry());
}

bool SemanticAAWrapperPass::doInitialization(Module &M)
{
  //string const& fname = F.getName().str();
  //if (m_function_tfg_map->count(fname)) {
  //  return false;
  //}
  //Module &M = *F.getParent();
  //map<shared_ptr<tfg_edge const>, Instruction *> eimap;
  //DYN_DEBUG(llvm2tfg, std::cout << "SemanticAAWrapperPass::" << __func__ << " " << __LINE__ << ": F.getName() = " << F.getName() << "\n");
  if (!g_ctx) {
    g_ctx_init();
  }
  ASSERT(g_ctx);
  shared_ptr<SemanticAAResult::function_tfg_map_t const> function_tfg_map = make_shared<SemanticAAResult::function_tfg_map_t const>(sym_exec_llvm::get_function_tfg_map(&M, set<string>(), false, g_ctx));
  Result.reset(new SemanticAAResult(function_tfg_map));
  return false;
}

bool SemanticAAWrapperPass::doFinalization(Module &M)
{
  return false;
}

void SemanticAAWrapperPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
}
