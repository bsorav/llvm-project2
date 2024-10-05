#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "llvm/ADT/StringMap.h"

using namespace clang;
using namespace ento;
namespace{

class StdLibOldReturnValueUseChecker : public Checker<check::PostCall,check::DeadSymbols> {
  mutable llvm::StringMap<const MemRegion *> TrackedFunctions;
  mutable std::unique_ptr<BugType> BT;

public:
  StdLibOldReturnValueUseChecker() {
    BT.reset(new BugType(this, "Old return value used after subsequent call", "Logic Error"));
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const ;

private:
  void trackFunction(const CallEvent &Call, CheckerContext &C) const;
};
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
      trackFunction(Call, C);
      return;
    }
  }
}

void StdLibOldReturnValueUseChecker::trackFunction(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *NewRegion = Call.getReturnValue().getAsRegion();
  if (!NewRegion) {
    return; // Ignore if the return value isn't a memory region
  }
  
  // Get the old region associated with the function name
  const MemRegion *OldRegion = TrackedFunctions.lookup(Call.getCalleeIdentifier()->getName());
  if(!OldRegion){
    TrackedFunctions[Call.getCalleeIdentifier()->getName()] = NewRegion;
    return;
  }else {
    // If the old region is still alive, raise a warning
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N) {
      return;
    }

    // Report an error if the old return value is still alive
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Return value from a previous call is being used after a subsequent call", N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
}

void StdLibOldReturnValueUseChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {
  auto State = C.getState();

  for (const auto &Entry : TrackedFunctions) {
    const MemRegion *OldRegion = Entry.getValue();
    // If the old region is not live anymore, no bug
    if (OldRegion && !SR.isLiveRegion(OldRegion)) {
      TrackedFunctions[Entry.getKey()] = nullptr; // Mark the region as dead
      continue;
    }
  }
  
}
// Register the checker in the analyzer
void ento::registerStdLibOldReturnValueUseChecker(CheckerManager &Mgr) {
  llvm::errs()<<"StdLibOldReturnValueUseChecker is registered\n";
  Mgr.registerChecker<StdLibOldReturnValueUseChecker>();
}

// This ensures the checker is invoked by the analyzer
bool ento::shouldRegisterStdLibOldReturnValueUseChecker(const CheckerManager &Mgr) {
  return true;
}
