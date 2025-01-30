//===-- MemcmpChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the MISRA Project
//
//===----------------------------------------------------------------------===//
//
// The pointers returned by the Standard Library functions localeconv, getenv, setlocale or, strerror
// shall only be used as if they have pointer to const-qualified type
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include <utility>
#include <optional>

// ---  UNDEFINED RUN BEHAVIOR --- 

using namespace clang;
using namespace ento;

REGISTER_SET_WITH_PROGRAMSTATE(ConstPointerState, const MemRegion*)

namespace{

class ConstPointerLocalChecker : public Checker<check::PreStmt<BinaryOperator>, check::PostCall, check::PreCall>{
    mutable std::unique_ptr<BugType> BT;
    mutable std::unordered_set<int64_t> VisitedStmtSet;
  
    private:
        bool isMonitoredFunction(const CallEvent &Call, CheckerContext &C) const;
        bool isPointerConstQualified(const SVal &PointerVal, ProgramStateRef State) const ;
        
    public :
        void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
        void checkPreStmt(const BinaryOperator *S, CheckerContext &C) const;
        void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

};
}

bool ConstPointerLocalChecker::isMonitoredFunction(const CallEvent &Call, CheckerContext &C) const {
  
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;

  StringRef FuncName = FD->getName();
  if(FuncName == "strerror") return true;

  if(C.getPreprocessor().getIncludedHeaderFileNames().find("<locale.h>") == C.getPreprocessor().getIncludedHeaderFileNames().end()) return false;

  return FuncName == "localeconv" || FuncName == "getenv" ||
         FuncName == "setlocale" ;
}

bool ConstPointerLocalChecker::isPointerConstQualified(const SVal &PointerVal, ProgramStateRef State) const {
  const MemRegion *LHSRegion = PointerVal.getAsRegion();
  if (!LHSRegion) return false;
  LHSRegion = LHSRegion->getBaseRegion();
  if(SymbolRef SR = (PointerVal.getLocSymbolInBase())){
    // llvm::errs() << "herererer\n";
    const MemRegion *LHSRegion2 = SR->getOriginRegion();
    if(LHSRegion2){
      LHSRegion = LHSRegion2->getBaseRegion();
    }
  }
  return State->contains<ConstPointerState>(LHSRegion);
}


void ConstPointerLocalChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  
  // Call.dump(llvm::errs());
  // llvm::errs() << "\n\n";
  if (!isMonitoredFunction(Call, C))
    return;

  // Save the returned pointer in the program state

  ProgramStateRef State = C.getState();
  SVal ReturnValue = Call.getReturnValue();
  if(!State->contains<ConstPointerState>(ReturnValue.getAsRegion())){
    State = State->add<ConstPointerState>(ReturnValue.getAsRegion());
    C.addTransition(State);
  }
}

void ConstPointerLocalChecker::checkPreStmt(const BinaryOperator *S, CheckerContext &C) const { 

  if (S->getOpcode() == BO_Assign ) {
    // S->dumpColor();
    if(VisitedStmtSet.find(S->getID(C.getASTContext())) == VisitedStmtSet.end()){
      VisitedStmtSet.insert(S->getID(C.getASTContext()));
      ProgramStateRef State = C.getState();
        // Get the left-hand side (LHS) of the assignment
        const Expr *LHS = S->getLHS()->IgnoreParens();
        SVal LHSSVal = C.getSVal(LHS);
        
        if (isPointerConstQualified(LHSSVal, State)) {
          // llvm::errs() << "modifying values of  a p/articular constant type variable !! \n";
          // S->getExprLoc().dump(C.getSourceManager());
          // //  expr->getExprLoc().dump(C.getSourceManager());
          // llvm::errs() << "\n\n\n";

          ExplodedNode *N = C.generateNonFatalErrorNode();
          if (!N)
              return;

          if (!BT)
              BT.reset(new BugType(this, "The pointers returned by the Standard Library functions localeconv, getenv, setlocale or, strerror shall only be used as if they have pointer to const-qualified type", "MISRA"));

          auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "The pointers returned by the Standard Library functions localeconv, getenv, setlocale or, strerror shall only be used as if they have pointer to const-qualified type", N);
          C.emitReport(std::move(Report));
        }
    }
    
  }
  //implement chekce r here.
  // llvm::errs() << " \n\n";   
  return;
}

void ConstPointerLocalChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  // const SourceManager &SM = C.getSourceManager();

//   FD->dump(llvm::errs());

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    // const Expr *ArgExpr = Call.getArgExpr(i);
    SVal ArgVal = Call.getArgSVal(i);
    const ParmVarDecl *ParamDecl = FD->getParamDecl(i);
    QualType ParamType = ParamDecl->getType();
    if (ParamType->isPointerType() || ParamType->isReferenceType()){
      ParamType = ParamType->getPointeeType(); 
    }

    if (isPointerConstQualified(ArgVal, State) && !ParamType.isConstQualified()) {
      // llvm::errs() << "passed a const type variable as non constant \n";
      // ArgExpr->getExprLoc().dump(C.getSourceManager());
      // llvm::errs() << "\n";
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
          return;

      if (!BT)
          BT.reset(new BugType(this, "The pointers returned by the Standard Library functions localeconv, getenv, setlocale or, strerror shall only be used as if they have pointer to const-qualified type", "MISRA"));

      auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "The pointers returned by the Standard Library functions localeconv, getenv, setlocale or, strerror shall only be used as if they have pointer to const-qualified type", N);
      C.emitReport(std::move(Report));
    }
  }
  return;
}



void ento::registerConstPointerLocalChecker(CheckerManager &mgr) {
    mgr.registerChecker<ConstPointerLocalChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterConstPointerLocalChecker(const CheckerManager &mgr) {
    return true;
}