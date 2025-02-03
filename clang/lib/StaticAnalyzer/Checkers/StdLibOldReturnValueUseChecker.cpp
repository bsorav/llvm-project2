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

REGISTER_MAP_WITH_PROGRAMSTATE(FuncCurrentRegions, const IdentifierInfo *, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(InvalidRegions, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(SymbolsToTrack, SymbolRef)

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

  class StaleValueVisitor : public BugReporterVisitor {
    const MemRegion *InvalidRegion;
  public:
    StaleValueVisitor(const MemRegion *MR) : InvalidRegion(MR) {}

    PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                     BugReporterContext &BRC,
                                     PathSensitiveBugReport &BR) override {
      ProgramStateRef State = N->getState();
      ProgramStateRef PrevState = N->getFirstPred()->getState();

      if (!PrevState->contains<InvalidRegions>(InvalidRegion) &&
          State->contains<InvalidRegions>(InvalidRegion)) {
        const Stmt *S = N->getStmtForDiagnostics();
        if (!S) return nullptr;

        PathDiagnosticLocation Loc(S, BRC.getSourceManager(),
                                   N->getLocationContext());
        
        auto Piece = std::make_shared<PathDiagnosticEventPiece>(
            Loc, "Stale value obtained here");
        Piece->setPrunable(false);
        return Piece;
      }
      return nullptr;
    }
    
    void finalizeVisitor(BugReporterContext &BRC,
                         const ExplodedNode *EndPathNode,
                         PathSensitiveBugReport &BR) override {
      // Get location from the end path node
      PathDiagnosticLocation Loc = PathDiagnosticLocation::create(EndPathNode->getLocation(), 
                             BRC.getSourceManager());
      
      // Create note with message and location
      BR.addNote("Stale value used here", Loc); 
    }
    void Profile(llvm::FoldingSetNodeID &ID) const override {
      ID.AddPointer(InvalidRegion);
    }
  };
};
// ProgramState trait to track invalidated regions
}


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
      if (State->contains<InvalidRegions>(TargetRegion)) {
        // Report error at actual usage location
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N) {
          return;
        }
        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT, "Using stale return value from previous API call",N);
        Report->addRange(S->getSourceRange());
        Report->addVisitor(std::make_unique<StaleValueVisitor>(TargetRegion));
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
  
  // Get the old region associated with the function name
  const MemRegion *OldRegion = nullptr;
  if (const MemRegion *const *OldRegionPtr = State->get<FuncCurrentRegions>(II)) {
    OldRegion = *OldRegionPtr;
  }
  if (OldRegion) {
    SymbolRef OldSym = State->getSVal(OldRegion).getAsSymbol();
    if (OldSym) {
      State = State->add<InvalidRegions>(OldRegion);
      State = State->add<SymbolsToTrack>(OldSym);
    }
  }
  
  // Update current valid region
  State = State->set<FuncCurrentRegions>(II, NewRegion);
  C.addTransition(State);
}

void StdLibOldReturnValueUseChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {
  auto State = C.getState();

  // Cleanup invalid regions
  auto Invalid = State->get<InvalidRegions>();
  llvm::SmallVector<const MemRegion *, 8> ToRemove;
  for (const auto *MR : Invalid) {
    if (!SR.isLiveRegion(MR)) {
      ToRemove.push_back(MR);
    }
  }
  for (const auto *MR : ToRemove) {
    State = State->remove<InvalidRegions>(MR);
  }

  auto Tracked = State->get<SymbolsToTrack>();
  llvm::SmallVector<SymbolRef, 8> SymbolsToRemove;
  for (const auto &Sym : Tracked) {
    if (!SR.isLive(Sym)) {
      SymbolsToRemove.push_back(Sym);
    }
  }
  for (const auto &Sym : SymbolsToRemove) {
    State = State->remove<SymbolsToTrack>(Sym);
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
