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
    bool isEOFexpr(const Expr *Expration) const;
};

} // end anonymous namespace

REGISTER_SET_WITH_PROGRAMSTATE(EOFVarSet, SymbolRef)

void EOFChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    StringRef FName = Call.getCalleeIdentifier() ? Call.getCalleeIdentifier()->getName() : "";
    static const llvm::StringSet<> EOFFunctions = {"fgetc", "fputc", "fclose", "getchar", "putchar", "ungetc"};
    
    if (EOFFunctions.count(FName)) {
        ProgramStateRef State = C.getState();
        SVal RetVal = Call.getReturnValue();
        
        if (SymbolRef RetSym = RetVal.getAsSymbol()) {
            llvm::errs()<<"RetSym\n";
            RetSym->dump();
            llvm::errs()<<"\n";
            State = State->add<EOFVarSet>(RetSym);
            C.addTransition(State);
        }
    }
}

bool EOFChecker::isEOFexpr(const Expr *Expration) const {
    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Expration)) {
        if (UO->getOpcode() == UO_Minus) {
            const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
            if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(SubExpr)) {
                return IL->getValue() == 1;
            }
        }
    }
    return false;
}

void EOFChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
    if (!BO->isComparisonOp())
        return;

    ProgramStateRef State = C.getState();
    const Expr *Operands[] = { BO->getLHS()->IgnoreParenCasts(), BO->getRHS()->IgnoreParenCasts() };

    for (const Expr *Operand : Operands) {
        if (isEOFexpr(Operand)) {
            SVal OtherSVal = C.getSVal(Operand == Operands[0] ? Operands[1] : Operands[0]);
            SymbolRef SymVal=nullptr;
            if (std::optional<Loc> LLoc = OtherSVal.getAs<Loc>()) {
                SymVal = State->getSVal(*LLoc).getAsSymbol();
            }            
            llvm::errs()<<"SymVal\n";
            SymVal->dump();
            llvm::errs()<<"\n";
            if (!SymVal || !State->contains<EOFVarSet>(SymVal)) {
                if (ExplodedNode *ErrNode = C.generateErrorNode()) {
                    C.emitReport(std::make_unique<PathSensitiveBugReport>(
                        *BT, "EOF should only be compared with an unmodified return value of an EOF-setting function", ErrNode));
                }
            }
        }
    }
}


void EOFChecker::checkBind(SVal LocV, SVal Val, const Stmt *S, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SymbolRef LocSym=nullptr;
    if (std::optional<Loc> LLoc = LocV.getAs<Loc>()) {
        LocSym = State->getSVal(*LLoc).getAsSymbol();
    }  
    if (LocSym ) {
        llvm::errs()<<"LocSym\n";
        LocSym->dump();
        llvm::errs()<<"\n";
        if (State->contains<EOFVarSet>(LocSym)) {
            State = State->remove<EOFVarSet>(LocSym);
            C.addTransition(State);
        }
    }
}

void ento::registerEOFChecker(CheckerManager &Mgr) {
    Mgr.registerChecker<EOFChecker>();
}

bool ento::shouldRegisterEOFChecker(const CheckerManager &Mgr) {
    return true;
}
