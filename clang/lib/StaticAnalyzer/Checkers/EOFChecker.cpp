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
class EOFChecker : public Checker<check::PreStmt<BinaryOperator>,
                                  check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;
  const llvm::StringSet<> EOFFunctions = {"fgetc",   "fputc",   "fclose",
                                          "getchar", "putchar", "ungetc"};

public:
  EOFChecker() {
    BT.reset(
        new BugType(this, "EOF Comparison Violation", "Custom MISRA Rules"));
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  bool isEOFexpr(const Expr *Expration, CheckerContext &C) const;
  bool isEOFReturningFunctionCall(const Expr *Expration,
                                  CheckerContext &C) const;
};

} // end anonymous namespace

REGISTER_SET_WITH_PROGRAMSTATE(EOFVarSet, SymbolRef)

void EOFChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  StringRef FName =
      Call.getCalleeIdentifier() ? Call.getCalleeIdentifier()->getName() : "";
  if (EOFFunctions.count(FName)) {
    ProgramStateRef State = C.getState();
    SVal RetVal = Call.getReturnValue();

    if (SymbolRef RetSym = RetVal.getAsSymbol()) {
      State = State->add<EOFVarSet>(RetSym);
      C.addTransition(State);
    }
  }
}

bool EOFChecker::isEOFexpr(const Expr *Expration, CheckerContext &C) const {
  const SourceManager &SM = C.getSourceManager();
  SourceLocation Loc = Expration->getBeginLoc();

  if (Loc.isMacroID()) {
    llvm::StringRef MacroName =
        Lexer::getImmediateMacroName(Loc, SM, C.getASTContext().getLangOpts());
    if (MacroName == "EOF") {
      return true;
    }
  }
  return false;
}
bool EOFChecker::isEOFReturningFunctionCall(const Expr *Expration,
                                            CheckerContext &C) const {
  if (const CallExpr *CE = dyn_cast<CallExpr>(Expration)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef FName = FD->getName();
      if (EOFFunctions.count(FName)) {
        ProgramStateRef State = C.getState();
        SVal RetVal = C.getSVal(CE);

        if (SymbolRef RetSym = RetVal.getAsSymbol()) {
          State = State->add<EOFVarSet>(RetSym);
          C.addTransition(State);
        }
        return true;
      }
    }
  }
  return false;
}

void EOFChecker::checkPreStmt(const BinaryOperator *BO,
                              CheckerContext &C) const {
  if (!BO->isComparisonOp())
    return;

  ProgramStateRef State = C.getState();
  const Expr *Operands[] = {BO->getLHS()->IgnoreParenCasts(),
                            BO->getRHS()->IgnoreParenCasts()};

  for (const Expr *Operand : Operands) {
    if (isEOFexpr(Operand, C)) {
      SVal OtherSVal =
          C.getSVal(Operand == Operands[0] ? Operands[1] : Operands[0]);
      if (isEOFReturningFunctionCall(
              Operand == Operands[0] ? Operands[1] : Operands[0], C)) {
        continue;
      }
      SymbolRef SymVal = nullptr;
      if (std::optional<Loc> LLoc = OtherSVal.getAs<Loc>()) {
        SymVal = State->getSVal(*LLoc).getAsSymbol();
      }
      if (!SymVal || !State->contains<EOFVarSet>(SymVal)) {
        if (ExplodedNode *ErrNode = C.generateErrorNode()) {
          C.emitReport(std::make_unique<PathSensitiveBugReport>(
              *BT,
              "EOF should only be compared with an unmodified return value of "
              "an EOF-setting function",
              ErrNode));
        }
      }
    }
  }
}

void EOFChecker::checkBind(SVal LocV, SVal Val, const Stmt *S,
                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolRef LocSym = nullptr;
  if (std::optional<Loc> LLoc = LocV.getAs<Loc>()) {
    LocSym = State->getSVal(*LLoc).getAsSymbol();
  }
  if (LocSym) {
    if (State->contains<EOFVarSet>(LocSym)) {
      State = State->remove<EOFVarSet>(LocSym);
      C.addTransition(State);
    }
  }
}

void ento::registerEOFChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<EOFChecker>();
}

bool ento::shouldRegisterEOFChecker(const CheckerManager &Mgr) { return true; }
