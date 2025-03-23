#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

using namespace clang;
using namespace ento;

namespace {
class EOFChecker : public Checker<check::PreStmt<BinaryOperator>, check::PostCall, check::Bind> {
    mutable std::unique_ptr<BugType> BT;
  
public:
    EOFChecker() {
        BT.reset(new BugType(this, "EOF Comparison Violation", "Custom MISRA Rules"));
    }

    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
    void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
private:
    bool isEOFexpr(const Expr * Expration) const;
};
}

// A set to store variables assigned return values from EOF-setting functions
REGISTER_SET_WITH_PROGRAMSTATE(EOFVarSet, SymbolRef)

void EOFChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    // Get the function name being called
    StringRef FName = Call.getCalleeIdentifier() ? Call.getCalleeIdentifier()->getName() : "";

    // List of standard functions that return EOF
    static const llvm::StringSet<> EOFFunctions = {
        "fgetc", "fputc", "fclose", "getchar", "putchar", "ungetc"
    };
    llvm::errs()<<"Inside checkPostCall\n";
    if (EOFFunctions.count(FName)) {
        ProgramStateRef State = C.getState();
        SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
        llvm::errs()<<"Retsym\n";
        RetSym->dump();
        llvm::errs()<<"\n";
        if (RetSym) {
            State = State->add<EOFVarSet>(RetSym);
            llvm::errs()<<"Retsymb\n";
            C.addTransition(State);
        }
    }
}

bool EOFChecker::isEOFexpr(const Expr * Expration) const {
    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Expration)) {
        if (UO->getOpcode() == UO_Minus) {  // Ensure it's a negation
            const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
            if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(SubExpr)) {
                if (IL->getValue() == 1) { // Checking for `-1`
                    return true;
                }
            }
        }
    }
    return false;
}

void EOFChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
    if (!BO->isComparisonOp()) // Only handle comparisons
        return;

    ProgramStateRef State = C.getState();
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    llvm::errs()<<"Inside checkPrestmt\n";
    RHS->dump();
    llvm::errs()<<"\n";
    if (isEOFexpr(RHS)) { // Checking for `-1`
        llvm::errs() << "Inside first condition\n";
        SymbolRef VarSym = C.getSVal(LHS).getAsSymbol();
        if (VarSym && !State->contains<EOFVarSet>(VarSym)) {
            ExplodedNode *ErrNode = C.generateErrorNode();
            llvm::errs() << "Inside error\n";
            if (!ErrNode)
                return;

            auto R = std::make_unique<PathSensitiveBugReport>(
                *BT,
                "EOF should only be compared with an unmodified return value of an EOF-setting function",
                ErrNode);
            C.emitReport(std::move(R));
        }
    }
    if (isEOFexpr(LHS)) { // Checking for `-1`
        llvm::errs() << "Inside second condition\n";
        SymbolRef VarSym = C.getSVal(RHS).getAsSymbol();
        if (VarSym && !State->contains<EOFVarSet>(VarSym)) {
            ExplodedNode *ErrNode = C.generateErrorNode();
            llvm::errs() << "Inside error\n";
            if (!ErrNode)
                return;

            auto R = std::make_unique<PathSensitiveBugReport>(
                *BT,
                "EOF should only be compared with an unmodified return value of an EOF-setting function",
                ErrNode);
            C.emitReport(std::move(R));
        }
    }
}

void EOFChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
    SymbolRef Sym = Loc.getAsSymbol();
    if (!Sym)
        return;
    llvm::errs()<<"symbol going to be removed\n";
    Sym->dump();
    llvm::errs()<<"\n";
    ProgramStateRef State = C.getState();
    if (State->contains<EOFVarSet>(Sym)) {
        // If the variable is modified, remove it from the set
        State = State->remove<EOFVarSet>(Sym);
        C.addTransition(State);
    }
}
// Register the checker in the analyzer
void ento::registerEOFChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<EOFChecker>();
}

// This ensures the checker is invoked by the analyzer
bool ento::shouldRegisterEOFChecker(const CheckerManager &Mgr) {
  return true;
}
