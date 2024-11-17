//===-- CTypeFunctionChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the MISRA Project
//
//===----------------------------------------------------------------------===//
//
// Any value passed to a function in <ctype.h> shall be representable as an unsigned char or be the value EOF
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>
#include <optional>


using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace{

class CTypeFunctionsChecker : public Checker<check::PreStmt<ArraySubscriptExpr>>{
    mutable std::unique_ptr<BugType> BT;
    private :
        bool checkOriginalType(const Expr *E,CheckerContext &C) const;
    public :
        void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

}

bool CTypeFunctionsChecker::checkOriginalType(const Expr *E,CheckerContext &C) const{
    
    QualType IndexType = E->getType();
    if (const CStyleCastExpr *CastExpr = dyn_cast<CStyleCastExpr>(E)) {
        IndexType = CastExpr->getSubExpr()->getType().getCanonicalType();  // Get the type of the subexpression
        // llvm::errs() << " Mil gya :: 2 " << IndexType.getAsString() << "\n";
        if(IndexType.getAsString() == "unsigned char"){
            return true;
        }
    }
    clang::Expr::EvalResult Result;
    if (E->EvaluateAsInt(Result, C.getASTContext())) {
        // Compare the evaluated result to EOF, which is typically -1
        const llvm::APSInt &IntValue = Result.Val.getInt();
        return IntValue.isSigned() && IntValue.getSExtValue() == EOF;
    }
    
    return false;
}

void CTypeFunctionsChecker::checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
    // Check if the base of the ArraySubscriptExpr is a call to __ctype_b_loc
    // llvm::errs() << "in checker\n";
    const SourceManager &SM = C.getSourceManager();
    const Expr *BaseExpr = ASE->getBase();
    const Expr *IndexExpr = ASE->getIdx();
    
    const Expr *CurrentExpr = BaseExpr;
    std::unordered_set<std::string> headerFiles = C.getPreprocessor().getIncludedHeaderFileNames();
    // for(auto x :headerFiles ) llvm::errs() <<x << "\n";
    if(headerFiles.find("<ctype.h>") != headerFiles.end()){
    while (true ) {
        if (const auto *Call = dyn_cast<CallExpr>(CurrentExpr)) {
            // We found a CallExpr; get the function being called
            if (const FunctionDecl *Callee = Call->getDirectCallee()) {
                // llvm::errs() <<  SM.getFilename(Callee->getLocation()) << "\n";
                if(Callee->getNameAsString() == "__ctype_b_loc" && SM.getFilename(Callee->getLocation()).ends_with("ctype.h")){
                    if(!checkOriginalType(IndexExpr,C)){
                        ExplodedNode *ErrNode= C.generateNonFatalErrorNode();
                        if (ErrNode) {
                            if (!BT)
                                BT.reset(new BugType(this, "Any value passed to a function in <ctype.h> shall be representable as an unsigned char or be the value EOF", "MISRA"));
                            auto R = std::make_unique<PathSensitiveBugReport>(*BT, "Any value passed to a function in <ctype.h> shall be representable as an unsigned char or be the value EOF", ErrNode);
                            // R->markInteresting(FileDesc);
                            C.emitReport(std::move(R));
                        }
                    }
                }
            } 
            break;
        }

        // Move to the subexpression if CurrentExpr is an ImplicitCastExpr or ParenExpr
        if (const auto *Cast = dyn_cast<ImplicitCastExpr>(CurrentExpr)) {
            CurrentExpr = Cast->getSubExpr();
        } else if (const auto *Paren = dyn_cast<ParenExpr>(CurrentExpr)) {
            CurrentExpr = Paren->getSubExpr();
        } else if (const auto *UnaryOp = dyn_cast<UnaryOperator>(CurrentExpr)) {
            CurrentExpr = UnaryOp->getSubExpr();
        } else {
            // llvm::outs() << "Reached an expression that is not a CallExpr or cast.\n";
            break;
        }
    }
    }
    return;
}



void ento::registerCTypeFunctionsChecker(CheckerManager &mgr) {
    mgr.registerChecker<CTypeFunctionsChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterCTypeFunctionsChecker(const CheckerManager &mgr) {
    return true;
}

