#include "llvm/Transforms/IPO/SCCP.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar/SCCP.h"

using namespace llvm;

static cl::opt<bool>
NoIPSCCP("no-ip-sparse-conditional-constant-prop",
       cl::desc("Do not propagate conditional constants through IPO"),
       cl::init(false));

PreservedAnalyses IPSCCPPass::run(Module &M, ModuleAnalysisManager &AM) {
  const DataLayout &DL = M.getDataLayout();
  auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto GetTLI = [&FAM](Function &F) -> const TargetLibraryInfo & {
    return FAM.getResult<TargetLibraryAnalysis>(F);
  };
  auto getAnalysis = [&FAM](Function &F) -> AnalysisResultsForFn {
    DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(F);
    return {
        std::make_unique<PredicateInfo>(F, DT, FAM.getResult<AssumptionAnalysis>(F)),
        &DT, FAM.getCachedResult<PostDominatorTreeAnalysis>(F)};
  };

  if (!runIPSCCP(M, DL, GetTLI, getAnalysis))
    return PreservedAnalyses::all();

  PreservedAnalyses PA;
  PA.preserve<DominatorTreeAnalysis>();
  PA.preserve<PostDominatorTreeAnalysis>();
  PA.preserve<FunctionAnalysisManagerModuleProxy>();
  return PA;
}

namespace {

//===--------------------------------------------------------------------===//
//
/// IPSCCP Class - This class implements interprocedural Sparse Conditional
/// Constant Propagation.
///
class IPSCCPLegacyPass : public ModulePass {
public:
  static char ID;

  IPSCCPLegacyPass() : ModulePass(ID) {
    initializeIPSCCPLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override {
    if (NoIPSCCP) {
      return false;
    }
    if (skipModule(M))
      return false;
    const DataLayout &DL = M.getDataLayout();
    auto GetTLI = [this](Function &F) -> const TargetLibraryInfo & {
      return this->getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
    };
    auto getAnalysis = [this](Function &F) -> AnalysisResultsForFn {
      DominatorTree &DT =
          this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
      return {
          std::make_unique<PredicateInfo>(
              F, DT,
              this->getAnalysis<AssumptionCacheTracker>().getAssumptionCache(
                  F)),
          nullptr,  // We cannot preserve the DT or PDT with the legacy pass
          nullptr}; // manager, so set them to nullptr.
    };

    return runIPSCCP(M, DL, GetTLI, getAnalysis);
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<AssumptionCacheTracker>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }
};

} // end anonymous namespace

char IPSCCPLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(IPSCCPLegacyPass, "ipsccp",
                      "Interprocedural Sparse Conditional Constant Propagation",
                      false, false)
INITIALIZE_PASS_DEPENDENCY(AssumptionCacheTracker)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfoWrapperPass)
INITIALIZE_PASS_END(IPSCCPLegacyPass, "ipsccp",
                    "Interprocedural Sparse Conditional Constant Propagation",
                    false, false)

// createIPSCCPPass - This is the public interface to this file.
ModulePass *llvm::createIPSCCPPass() { return new IPSCCPLegacyPass(); }
