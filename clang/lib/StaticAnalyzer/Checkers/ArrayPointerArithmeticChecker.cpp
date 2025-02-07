#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include <optional>
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;

namespace {
class ArrayPointerArithmeticChecker
    : public Checker<check::PostStmt<BinaryOperator>> {
  std::unique_ptr<BugType> BT;
  std::unique_ptr<BugType> BTTwoDiffArrPtr;
  std::unique_ptr<BugType> BTTwoDiffObjPtr;

  class PointerArithVisitor : public BugReporterVisitor {
    const MemRegion *LHSRegion;
    const MemRegion *RHSRegion;

  public:
    PointerArithVisitor(const MemRegion *LHS, const MemRegion *RHS)
        : LHSRegion(LHS), RHSRegion(RHS) {}

    void Profile(llvm::FoldingSetNodeID &ID) const override {
      ID.AddPointer(LHSRegion);
      ID.AddPointer(RHSRegion);
    }

    PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                     BugReporterContext &BRC,
                                     PathSensitiveBugReport &BR) override {
      ProgramStateRef State = N->getState();
      ProgramStateRef PrevState = N->getFirstPred()->getState();
      const StoreManager &StoreMgr = State->getStateManager().getStoreManager();
      const StoreManager &PrevStoreMgr = PrevState->getStateManager().getStoreManager();
        if (LHSRegion && !(bool)PrevStoreMgr.Lookup(State->getStore(), LHSRegion) &&
                         (bool)StoreMgr.Lookup(State->getStore(), LHSRegion)) {
          auto Piece = createEvent(N, BRC, LHSRegion, "First pointer obtained here");
          return Piece;
        }

        if (RHSRegion && !(bool)PrevStoreMgr.Lookup(State->getStore(), RHSRegion) &&
                         (bool)StoreMgr.Lookup(State->getStore(), RHSRegion)) {
          auto Piece = createEvent(N, BRC, RHSRegion, "Second pointer obtained here");
          return Piece;
        }
      return nullptr;
    }

  private:
    PathDiagnosticPieceRef createEvent(const ExplodedNode *N,
                                       BugReporterContext &BRC,
                                       const MemRegion *MR,
                                       llvm::StringRef Msg) {
      const Stmt *S = N->getStmtForDiagnostics();
      if (!S) return nullptr;

      PathDiagnosticLocation Loc(S, BRC.getSourceManager(),
                                 N->getLocationContext());
      auto Piece = std::make_shared<PathDiagnosticEventPiece>(Loc, Msg);
      Piece->setPrunable(false);
      return Piece;
    }
  };

public:
  ArrayPointerArithmeticChecker() {
    BT.reset(new BugType(this, "Pointer arithmetic outside array bounds",
                         "Array pointer rule violation"));
    BTTwoDiffArrPtr.reset(new BugType(this, "Pointer arithmetic between different arrays",
                         "Array pointer rule violation"));
    BTTwoDiffObjPtr.reset(new BugType(this, "Pointer relational between different objects",
                         "Object pointer rule violation"));
  }

  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  const MemRegion* findBaseRegion(CheckerContext &C, const MemRegion* LHSRegion, 
                                  const MemRegion* RHSRegion) const;
};
} // namespace


const MemRegion* ArrayPointerArithmeticChecker::findBaseRegion(CheckerContext &C,
                                                               const MemRegion* LHSRegion,
                                                               const MemRegion* RHSRegion) const {
  bool LHSFlag = LHSRegion && isa<ElementRegion>(LHSRegion);
  bool RHSFlag = RHSRegion && isa<ElementRegion>(RHSRegion);

  if (LHSFlag && RHSFlag) {
    const MemRegion* LHSBase = LHSRegion->getBaseRegion();
    const MemRegion* RHSBase = RHSRegion->getBaseRegion();

    if (LHSBase != RHSBase) {
      ExplodedNode *N = C.generateErrorNode();
      if (!N) return nullptr;

      auto R = std::make_unique<PathSensitiveBugReport>(
          *BTTwoDiffArrPtr, "Pointer arithmetic between different array pointers", N);
      R->addVisitor(std::make_unique<PointerArithVisitor>(LHSBase, RHSBase));
      C.emitReport(std::move(R));
    }
    return nullptr;
  }

  const MemRegion *BaseRegion = nullptr;
  if (LHSFlag) BaseRegion = LHSRegion->getBaseRegion();
  if (RHSFlag) BaseRegion = RHSRegion->getBaseRegion();
  return BaseRegion;
}

void ArrayPointerArithmeticChecker::checkPostStmt(const BinaryOperator *BO,
                                                  CheckerContext &C) const {
  if (BO->isRelationalOp()) {
    const Expr *LHS = BO->getLHS()->IgnoreParens();
    const Expr *RHS = BO->getRHS()->IgnoreParens();
    const QualType LType = LHS->getType();
    const QualType RType = RHS->getType();
    
    if (LType->isPointerType() && RType->isPointerType()) {
      const MemRegion *LRegion = C.getSVal(LHS).getAsRegion();
      const MemRegion *RRegion = C.getSVal(RHS).getAsRegion();
      
      if (LRegion && RRegion) {
        
        if (LRegion->getBaseRegion() != RRegion->getBaseRegion()) {
          ExplodedNode *N = C.generateErrorNode();
          if (!N) return;
          auto R = std::make_unique<PathSensitiveBugReport>(
              *BTTwoDiffObjPtr, 
              "Relational comparison between pointers to different objects", 
              N);
          R->addVisitor(std::make_unique<PointerArithVisitor>(LRegion, RRegion));
          C.emitReport(std::move(R));
        }
      }
    }
  }

  if (BO->getOpcode() != BO_Add && BO->getOpcode() != BO_Sub)
    return;

  ASTContext &Ctx = C.getASTContext();
  Expr *LHS = BO->getLHS()->IgnoreParens();
  Expr *RHS = BO->getRHS()->IgnoreParens();

  const MemRegion *LHSRegion = C.getSVal(LHS).getAsRegion();
  const MemRegion *RHSRegion = C.getSVal(RHS).getAsRegion();
  
  const MemRegion* BaseRegion = findBaseRegion(C, LHSRegion, RHSRegion);
  if (!BaseRegion)
    return;
  
  llvm::APInt ArraySize;
  const TypedValueRegion *TypedBaseRegion = dyn_cast<TypedValueRegion>(BaseRegion);
  if (TypedBaseRegion) {
      QualType BaseType = TypedBaseRegion->getValueType();
      if (const ConstantArrayType *ArrayType = Ctx.getAsConstantArrayType(BaseType)) {
          ArraySize = ArrayType->getSize();
      }
  }
  if (!ArraySize)
    return;
  
  const MemRegion* Region = C.getSVal(BO).getAsRegion();
  const ElementRegion *ER = dyn_cast<ElementRegion>(Region);

  if (!ER)
      return;

  SVal IndexVal = ER->getIndex();
  std::optional<nonloc::ConcreteInt> CI = IndexVal.getAs<nonloc::ConcreteInt>();
  if (!CI)
    return;
  
  llvm::APInt Index = CI->getValue();
  if (ER->getBaseRegion() != BaseRegion || !Index.uge(0) || !Index.ule(ArraySize)) {
    ExplodedNode *N = C.generateErrorNode();
    if (!N) return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Pointer arithmetic out of bounds", N);
    R->addVisitor(std::make_unique<PointerArithVisitor>(BaseRegion, nullptr));
    C.emitReport(std::move(R));
  }
}

void ento::registerArrayPointerArithmeticChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<ArrayPointerArithmeticChecker>();
}

bool ento::shouldRegisterArrayPointerArithmeticChecker(const CheckerManager &mgr) {
  return true;
}
