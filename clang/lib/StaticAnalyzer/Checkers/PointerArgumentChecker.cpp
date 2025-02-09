//===-- PointerArgumentChecker.cpp ----------------------------------------*- C++ -*-//
//
// Part of the MISRA Project
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Type.h"
#include "clang/AST/ASTContext.h"

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(InitializedRegions, const MemRegion *, const Stmt *)

namespace {
class PointerArgumentVisitor : public BugReporterVisitor {
  const MemRegion *ArgRegion;
  unsigned ArgIndex;
  
public:
  PointerArgumentVisitor(const MemRegion *Reg, unsigned Idx)
    : ArgRegion(Reg), ArgIndex(Idx) {}

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    ID.AddPointer(ArgRegion);
    ID.AddInteger(ArgIndex);
  }

  PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                     BugReporterContext &BRC,
                                     PathSensitiveBugReport &BR) override {
    ProgramStateRef State = N->getState();
    ProgramStateRef PrevState = N->getFirstPred()->getState();
    auto InitStmt = State->get<InitializedRegions>(ArgRegion);
    auto PreInitStmt = PrevState->get<InitializedRegions>(ArgRegion);
    if (!InitStmt or PreInitStmt) return nullptr;

    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
        *InitStmt, BRC.getSourceManager(), N->getLocationContext());
    
    const char* msg=ArgIndex==0?"Source Pointer initialized here":"Destination Pointer initialized here";
    auto Piece = std::make_shared<PathDiagnosticEventPiece>(Loc,msg);
    Piece->setPrunable(false);
    return Piece;
  }
};

class PointerArgumentChecker : public Checker<check::PreCall,check::PostStmt<BinaryOperator>, check::PostCall, check::PostStmt<DeclStmt>,check::Location> {
  mutable std::unique_ptr<BugType> BT1;
  mutable std::unique_ptr<BugType> BT2;
  
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const IdentifierInfo *Callee = Call.getCalleeIdentifier();
    if (!Callee) return;
    
    StringRef FuncName = Callee->getName();
    if (FuncName != "memcpy" && FuncName != "memmove" && FuncName != "memcmp") 
      return;

    if (FuncName == "memcmp") {
      memcmpArgPointerCheck(Call, C);
    }

    checkMemOpsCompatibility(Call, C);
  }
  void checkPostStmt(const DeclStmt *DS,CheckerContext &C) const {
    for (const auto *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        // Use RegionManager from SValBuilder
        const MemRegion *VR = C.getSValBuilder().getRegionManager()
        .getVarRegion(VD, C.getLocationContext());
        if (VR) {
          trackInitialization(C,VR,DS);
        }
      } 
    }
  }
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (II && (II->isStr("malloc") || II->isStr("calloc"))) {
      if (const MemRegion *MR = Call.getReturnValue().getAsRegion()) {
        trackInitialization(C, MR, Call.getOriginExpr());
      }
    }
  }
  void checkLocation(SVal Loc, bool IsLoad,const Stmt *S,CheckerContext &C) const{
    ProgramStateRef State = C.getState();
    if (const MemRegion *MR = Loc.getAsRegion()) {
      trackInitialization(C, MR, S);
    }
  }
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const {
    if (BO->getOpcode() == BO_Assign) {
      // Handle pointer assignments
      const Expr *LHS = BO->getLHS()->IgnoreParens();
      const Expr *RHS = BO->getRHS()->IgnoreParens();

      const MemRegion *LRegion = C.getSVal(LHS).getAsRegion();
      const MemRegion *RRegion = C.getSVal(RHS).getAsRegion();

      if (LRegion && RRegion) {
        trackInitialization(C, LRegion,BO);
      }
    }
  }

private:
  void trackInitialization(CheckerContext &C, const MemRegion *MR, const Stmt *S) const {
    if (!MR || !S) return;
    ProgramStateRef State = C.getState();
    if (!State->get<InitializedRegions>(MR->getBaseRegion())) {
      State = State->set<InitializedRegions>(MR->getBaseRegion(), S);
      C.addTransition(State);
    }
  }
  void checkMemOpsCompatibility(const CallEvent &Call, CheckerContext &C) const {
    if (Call.getNumArgs() < 2) return;

    QualType Arg1Type = Call.getArgSVal(0).getType(C.getASTContext());
    QualType Arg2Type = Call.getArgSVal(1).getType(C.getASTContext());
    ASTContext &Ctx = C.getASTContext();

    if (areTypesCompatible(Arg1Type, Arg2Type, Ctx)) return;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N) return;

    if (!BT1)
      BT1.reset(new BugType(this, "Incompatible pointer types", "MISRA"));

    auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT1, "Pointer arguments must be compatible types", N);
    const MemRegion *Arg1Region = Call.getArgSVal(0).getAsRegion()->getBaseRegion();
    const MemRegion *Arg2Region = Call.getArgSVal(1).getAsRegion()->getBaseRegion();
    Report->addVisitor(std::make_unique<PointerArgumentVisitor>(Arg1Region, 0));
    Report->addVisitor(std::make_unique<PointerArgumentVisitor>(Arg2Region, 1));
    C.emitReport(std::move(Report));
  }

  void memcmpArgPointerCheck(const CallEvent &Call, CheckerContext &C) const {
    ASTContext &ACtx = C.getASTContext();
    for (unsigned i = 0; i < 2; ++i) {
      const SVal Arg = Call.getArgSVal(i);

      QualType ArgType = Arg.getType(C.getASTContext());
      const MemRegion *ArgRegion = Call.getArgSVal(i).getAsRegion();
      
      if (!ArgType->isPointerType()) {
        emitMemcmpError(C, ArgRegion, i, "Pointer type required");
        return;
      }

      QualType PointeeType = ArgType->getPointeeType();
      if (PointeeType->isPointerType()) continue; // Allow pointer-to-pointer
      
      if (!PointeeType->isIntegerType() && 
          !PointeeType->isEnumeralType() &&
          !PointeeType->isBooleanType()) {
        emitMemcmpError(C, ArgRegion, i, "Invalid pointee type");
        return;
      }
    }
  }

  void emitMemcmpError(CheckerContext &C, const MemRegion* TrgtRegion, unsigned ArgIdx, 
                      const char *Msg) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N) return;

    if (!BT2)
      BT2.reset(new BugType(this, "Invalid memcmp argument type", "MISRA"));

    auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT2, Msg, N);
    
    Report->addVisitor(std::make_unique<PointerArgumentVisitor>(TrgtRegion->getBaseRegion(), ArgIdx));
    C.emitReport(std::move(Report));
  }

  bool areTypesCompatible(QualType Src, QualType Dest, ASTContext &Ctx) const {
    // Remove pointer indirection
    const Type *SrcPointeeType = Src->getPointeeType().getTypePtrOrNull();
    const Type *DestPointeeType = Dest->getPointeeType().getTypePtrOrNull();
    if (!SrcPointeeType || !DestPointeeType)
        return false;

    // Check for compatibility of pointee types
    return Ctx.typesAreCompatible(QualType(SrcPointeeType, 0), QualType(DestPointeeType, 0));
  }
};
}

void ento::registerPointerArgumentChecker(CheckerManager &mgr) {
  mgr.registerChecker<PointerArgumentChecker>();
}

bool ento::shouldRegisterPointerArgumentChecker(const CheckerManager &mgr) {
  return true;
}
