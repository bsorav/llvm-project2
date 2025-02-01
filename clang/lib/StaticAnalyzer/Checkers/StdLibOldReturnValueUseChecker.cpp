#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "llvm/ADT/StringMap.h"
#include <utility>

using namespace clang;
using namespace ento;
namespace{

class StdLibOldReturnValueUseChecker : public Checker<check::PostCall,check::DeadSymbols,check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  StdLibOldReturnValueUseChecker() {
    BT.reset(new BugType(this, "Using stale return value from previous API call", "Logic Error"));
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const ;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  

private:
  void trackFunction(const CallEvent &Call, CheckerContext &C) const;
};
// ProgramState trait to track invalidated regions
}
REGISTER_MAP_WITH_PROGRAMSTATE(FuncCurrentRegions, const IdentifierInfo *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(CreationNodes, const MemRegion *, const ExplodedNode *)
REGISTER_MAP_WITH_PROGRAMSTATE(InvalidRegions, const MemRegion *,const ExplodedNode *)

void StdLibOldReturnValueUseChecker::checkLocation(SVal Loc, bool IsLoad,
                                                   const Stmt *S,
                                                   CheckerContext &C) const {
  if (!IsLoad) return; // Only check reads
  ProgramStateRef State = C.getState();

  //1. Check if we're accessing an invalidated region
  if (auto MR = Loc.getAsRegion()) {
    if (auto Val = State->getSVal(MR).getAs<loc::MemRegionVal>()) {
      const MemRegion *TargetRegion = Val->getRegion();
      // 2. Check if POINTEE region is invalid
      if (auto InvalidationNodePtr = State->get<InvalidRegions>(TargetRegion)) {
        // Report error at actual usage location
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N) {
          return;
        }
        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT, "Using stale return value from previous API call",N);
        Report->addRange(S->getSourceRange());

        // Add note for where the value was invalidated
        const ExplodedNode *InvalidationNode = *InvalidationNodePtr;
        PathDiagnosticLocation Loc = PathDiagnosticLocation::create(
          InvalidationNode->getLocation(),  // ProgramPoint from ExplodedNode
          C.getSourceManager()
        );
        Report->addNote("Return value invalidated here", Loc);

        // When accessing creation nodes:
        if (auto CreationNodePtr = State->get<CreationNodes>(MR)) {
          const ExplodedNode *CreationNode = *CreationNodePtr;
          PathDiagnosticLocation CreationLoc = PathDiagnosticLocation::create(
            CreationNode->getLocation(),
            C.getSourceManager()
          );
          Report->addNote("Return value created here", CreationLoc);
        }
        C.emitReport(std::move(Report));
      }
    }
  }
}

void StdLibOldReturnValueUseChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // List of standard library functions to track
  static const llvm::StringRef FunctionsToTrack[] = {
    "asctime", "ctime", "gmtime", "localtime", "localeconv",
    "getenv", "setlocale", "strerror"
  };

  // Get the function name being called
  StringRef FName = Call.getCalleeIdentifier() ? Call.getCalleeIdentifier()->getName() : "";
  
  for (const auto &TrackedFunction : FunctionsToTrack) {
    if (FName == TrackedFunction) {
      // llvm::errs()<<TrackedFunctions[FName]<<"\n";
      trackFunction(Call, C);
      return;
    }
  }
}

void StdLibOldReturnValueUseChecker::trackFunction(const CallEvent &Call, CheckerContext &C) const {
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (!II) return;

  ProgramStateRef State = C.getState();
  const MemRegion *NewRegion = Call.getReturnValue().getAsRegion();
  if (!NewRegion) {
    return; // Ignore if the return value isn't a memory region
  }
  
  // Track creation node
  ExplodedNode *CreationNode = C.generateNonFatalErrorNode();
  if (CreationNode) {
    State = State->set<CreationNodes>(NewRegion, CreationNode);
  }

  // Get the old region associated with the function name
  const MemRegion *OldRegion = *State->get<FuncCurrentRegions>(II);
  if (OldRegion) {
    // Mark previous region as invalid with its invalidation node
    ExplodedNode *InvalidationNode = C.generateNonFatalErrorNode();
    if (InvalidationNode) {
      State = State->set<InvalidRegions>(OldRegion, InvalidationNode);
    }
  }
  
  // Update current valid region
  State = State->set<FuncCurrentRegions>(II, NewRegion);
  C.addTransition(State);
}

void StdLibOldReturnValueUseChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {
  auto State = C.getState();
  auto Invalid=State->get<InvalidRegions>();

  // Create temporary copy for safe iteration
  llvm::SmallVector<const MemRegion *, 8> ToRemove;
  for (auto Entry = Invalid.begin(); Entry != Invalid.end(); ++Entry) {
    const MemRegion* MR=Entry->first;
    if (!SR.isLiveRegion(MR)) {
      ToRemove.push_back(MR);
    }
  }
  // Remove all dead regions in one operation
  for (const auto *MR : ToRemove) {
    State = State->remove<InvalidRegions>(MR);
  }
   // Cleanup FuncCurrentRegions
  auto CurrentRegions = State->get<FuncCurrentRegions>();
  for (auto I = CurrentRegions.begin(); I != CurrentRegions.end(); ++I) {
    if (!SR.isLiveRegion(I->second)) {
      State = State->remove<FuncCurrentRegions>(I->first);
    }
  }
  C.addTransition(State);
}
// Register the checker in the analyzer
void ento::registerStdLibOldReturnValueUseChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<StdLibOldReturnValueUseChecker>();
}

// This ensures the checker is invoked by the analyzer
bool ento::shouldRegisterStdLibOldReturnValueUseChecker(const CheckerManager &Mgr) {
  return true;
}
