#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"

using namespace clang;
using namespace ento;

namespace {
class ConstPointerLocalChecker
    : public Checker<check::PostCall, check::PreStmt<BinaryOperator>,
                     check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  ConstPointerLocalChecker() {
    BT = std::make_unique<BugType>(
        this, "Violation of const-qualified return value usage",
        "Custom MISRA Rules");
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  bool isPointerConstQualified(const SVal &PointerVal,
                               ProgramStateRef State) const;
};

} // end anonymous namespace

REGISTER_SET_WITH_PROGRAMSTATE(ConstPtrRegionSet, const MemRegion *)

void ConstPointerLocalChecker::checkPostCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  static const llvm::StringSet<> ConstReturningFunctions = {
      "localeconv", "getenv", "setlocale", "strerror"};

  StringRef FName =
      Call.getCalleeIdentifier() ? Call.getCalleeIdentifier()->getName() : "";
  if (ConstReturningFunctions.count(FName)) {
    ProgramStateRef State = C.getState();
    SVal RetVal = Call.getReturnValue();

    if (const MemRegion *RetRegion = RetVal.getAsRegion()) {
      const MemRegion *BaseRegion = RetRegion->getBaseRegion();
      State = State->add<ConstPtrRegionSet>(BaseRegion);
      C.addTransition(State);
    }
  }
}

bool ConstPointerLocalChecker::isPointerConstQualified(
    const SVal &PointerVal, ProgramStateRef State) const {
  const MemRegion *LHSRegion = PointerVal.getAsRegion();
  if (!LHSRegion)
    return false;
  LHSRegion = LHSRegion->getBaseRegion();
  if (SymbolRef SR = (PointerVal.getLocSymbolInBase())) {
    // llvm::errs() << "herererer\n";
    const MemRegion *LHSRegion2 = SR->getOriginRegion();
    if (LHSRegion2) {
      LHSRegion = LHSRegion2->getBaseRegion();
    }
  }
  return State->contains<ConstPtrRegionSet>(LHSRegion);
}

void ConstPointerLocalChecker::checkPreStmt(const BinaryOperator *BO,
                                            CheckerContext &C) const {
  if (!BO->isAssignmentOp())
    return;

  ProgramStateRef State = C.getState();
  SVal RHSVal = C.getSVal(BO->getRHS());

  if (isPointerConstQualified(RHSVal, State)) {
    // Get LHS to check if it is assigned to a non-const pointer
    QualType LHSType = BO->getLHS()->getType();
    if (!LHSType.isConstQualified()) {
      if (ExplodedNode *ErrNode = C.generateErrorNode()) {
        C.emitReport(std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Pointer returned by a Standard Library function should only be "
            "assigned to a const-qualified pointer",
            ErrNode));
      }
    }
  }
}

void ConstPointerLocalChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                         CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isPointerConstQualified(Loc, State)) {
    if (ExplodedNode *ErrNode = C.generateErrorNode()) {
      C.emitReport(std::make_unique<PathSensitiveBugReport>(
          *BT,
          "The pointers returned by the Standard Library functions localeconv, "
          "getenv, setlocale or, strerror shall only be used as if they have "
          "pointer to const-qualified type",
          ErrNode));
    }
  }
}

void ento::registerConstPointerLocalChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<ConstPointerLocalChecker>();
}

bool ento::shouldRegisterConstPointerLocalChecker(const CheckerManager &Mgr) {
  return true;
}
