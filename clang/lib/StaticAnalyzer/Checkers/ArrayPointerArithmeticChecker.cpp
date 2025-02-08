#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include <optional>
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(InitializedRegions, const MemRegion *, const Stmt *)

namespace {
class ArrayPointerArithmeticChecker
    : public Checker<check::PostStmt<BinaryOperator>, check::PostCall, check::PostStmt<DeclStmt>,check::Location> {
  std::unique_ptr<BugType> BT;
  std::unique_ptr<BugType> BTTwoDiffArrPtr;
  std::unique_ptr<BugType> BTTwoDiffObjPtr;

  class PointerArithVisitor : public BugReporterVisitor {
    const MemRegion *TrackedRegion;

  public:
    PointerArithVisitor(const MemRegion *MR) : TrackedRegion(MR){}

    void Profile(llvm::FoldingSetNodeID &ID) const override {
      ID.AddPointer(TrackedRegion);
    }

    PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                     BugReporterContext &BRC,
                                     PathSensitiveBugReport &BR) override {
      ProgramStateRef State = N->getState();
      ProgramStateRef PrevState = N->getFirstPred()->getState();

      auto InitStmt = State->get<InitializedRegions>(TrackedRegion);
      auto PreInitStmt = PrevState->get<InitializedRegions>(TrackedRegion);
      if (!InitStmt or PreInitStmt) return nullptr;

      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
          *InitStmt, BRC.getSourceManager(), N->getLocationContext());
      
      auto Piece = std::make_shared<PathDiagnosticEventPiece>(Loc, "Pointer initialized here");
      Piece->setPrunable(false);
      return Piece;
    }
  };

  void trackInitialization(CheckerContext &C, const MemRegion *MR, const Stmt *S) const {
    if (!MR || !S) return;

    ProgramStateRef State = C.getState();
    if (!State->get<InitializedRegions>(MR)) {
      State = State->set<InitializedRegions>(MR, S);
      C.addTransition(State);
    }
  }

public:
  ArrayPointerArithmeticChecker() {
    BT.reset(new BugType(this, "Pointer arithmetic outside array bounds",
                         "Array violation"));
    BTTwoDiffArrPtr.reset(new BugType(this, "Different array pointers",
                         "Array violation"));
    BTTwoDiffObjPtr.reset(new BugType(this, "Different object pointers",
                         "Object violation"));
  }

  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad,const Stmt *S,CheckerContext &C) const;
  const MemRegion* findBaseRegion(CheckerContext &C, const MemRegion* LHSRegion, 
                                  const MemRegion* RHSRegion) const;
};
}

void ArrayPointerArithmeticChecker::checkLocation(SVal Loc, bool IsLoad,const Stmt *S,CheckerContext &C) const {
  // Track memory accesses and mark regions as initialized
  ProgramStateRef State = C.getState();
  if (const MemRegion *MR = Loc.getAsRegion()) {
    trackInitialization(C, MR, S);
  }
}

const MemRegion* ArrayPointerArithmeticChecker::findBaseRegion(
    CheckerContext &C, const MemRegion* LHSRegion, const MemRegion* RHSRegion) const {
  auto getBase = [](const MemRegion *R) {
    return R && isa<ElementRegion>(R) ? R->getBaseRegion() : R;
  };

  const MemRegion *LHSBase = getBase(LHSRegion);
  const MemRegion *RHSBase = getBase(RHSRegion);
  if (LHSBase && RHSBase && LHSBase != RHSBase) {
    ExplodedNode *N = C.generateErrorNode();
    if (!N) return nullptr;
    
    auto R = std::make_unique<PathSensitiveBugReport>(
      *BTTwoDiffArrPtr, "Pointer arithmetic between different arrays", N);
      R->addVisitor(std::make_unique<PointerArithVisitor>(LHSBase));
      R->addVisitor(std::make_unique<PointerArithVisitor>(RHSBase));
      C.emitReport(std::move(R));
  }
  if(LHSBase && RHSBase){
    return nullptr;
  }
  return LHSBase ? LHSBase : RHSBase;
}

void ArrayPointerArithmeticChecker::checkPostStmt(const DeclStmt *DS,
                                                 CheckerContext &C) const {
  for (const auto *D : DS->decls()) {
    if (const auto *VD = dyn_cast<VarDecl>(D)) {
      // Use RegionManager from SValBuilder
      const VarRegion *VR = C.getSValBuilder().getRegionManager()
          .getVarRegion(VD, C.getLocationContext());
      if (VR) {
        trackInitialization(C, VR,DS);
      }
    }
  }
}

void ArrayPointerArithmeticChecker::checkPostCall(const CallEvent &Call,
                                                 CheckerContext &C) const {
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (II && (II->isStr("malloc") || II->isStr("calloc"))) {
    if (const MemRegion *MR = Call.getReturnValue().getAsRegion()) {
      trackInitialization(C, MR, Call.getOriginExpr());
    }
  }
}

void ArrayPointerArithmeticChecker::checkPostStmt(const BinaryOperator *BO,
                                                 CheckerContext &C) const {
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
  if (BO->isRelationalOp()) {
    const Expr *LHS = BO->getLHS()->IgnoreParens();
    const Expr *RHS = BO->getRHS()->IgnoreParens();
    
    const MemRegion *LRegion = C.getSVal(LHS).getAsRegion();
    const MemRegion *RRegion = C.getSVal(RHS).getAsRegion();

    if (LRegion && RRegion && LRegion->getBaseRegion() != RRegion->getBaseRegion()) {
      ExplodedNode *N = C.generateErrorNode();
      if (!N) return;
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BTTwoDiffObjPtr, "Comparison of different object pointers", N);
      R->addVisitor(std::make_unique<PointerArithVisitor>(LRegion));
      R->addVisitor(std::make_unique<PointerArithVisitor>(RRegion));
      C.emitReport(std::move(R));
    }
    return;
  }

  if (BO->getOpcode() != BO_Add && BO->getOpcode() != BO_Sub) return;
  ASTContext &Ctx = C.getASTContext();
  const MemRegion *LHSRegion = C.getSVal(BO->getLHS()).getAsRegion();
  const MemRegion *RHSRegion = C.getSVal(BO->getRHS()).getAsRegion();

  const MemRegion *BaseRegion = findBaseRegion(C, LHSRegion, RHSRegion);
  if (!BaseRegion) return;
  trackInitialization(C, BaseRegion, BO);

  const TypedValueRegion *TypedBase = dyn_cast<TypedValueRegion>(BaseRegion);
  if (!TypedBase) return;

  if (const auto *ArrayType = Ctx.getAsConstantArrayType(TypedBase->getValueType())) {
    llvm::APInt ArraySize = ArrayType->getSize();
    const MemRegion *ResultRegion = C.getSVal(BO).getAsRegion();
    
    if (const auto *ER = dyn_cast<ElementRegion>(ResultRegion)) {
      if (auto CI = ER->getIndex().getAs<nonloc::ConcreteInt>()) {
        if (ER->getBaseRegion() != BaseRegion || 
            CI->getValue().uge(ArraySize) || 
            CI->getValue().isNegative()) {
          ExplodedNode *N = C.generateErrorNode();
          if (!N) return;
          
          auto R = std::make_unique<PathSensitiveBugReport>(
              *BT, "Out-of-bounds array access", N);
          R->addVisitor(std::make_unique<PointerArithVisitor>(BaseRegion));
          C.emitReport(std::move(R));
        }
      }
    }
  }
}

void ento::registerArrayPointerArithmeticChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<ArrayPointerArithmeticChecker>();
}

bool ento::shouldRegisterArrayPointerArithmeticChecker(const CheckerManager &mgr) {
  return true;
}
