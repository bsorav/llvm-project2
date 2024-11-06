#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "optional"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;

namespace {
class ArrayPointerArithmeticChecker
    : public Checker<check::PostStmt<BinaryOperator>> {
  std::unique_ptr<BugType> BT;

public:
  ArrayPointerArithmeticChecker() {
    BT.reset(new BugType(this, "Pointer arithmetic outside array bounds",
                         "Array pointer rule violation"));
  }

  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  const MemRegion* findBaseRegion(const MemRegion* LHSRegion, const MemRegion* RHSRegion) const;
};
} // namespace

const MemRegion* ArrayPointerArithmeticChecker::findBaseRegion(const MemRegion* LHSRegion, const MemRegion* RHSRegion) const {
  
  // Check if LHS is an ElementRegion
  bool LHSFlag = LHSRegion && isa<const ElementRegion>(LHSRegion);
  // Check if RHS is an ElementRegion
  bool RHSFlag = RHSRegion && isa<const ElementRegion>(RHSRegion);

  // If both LHS and RHS are ElementRegions, prioritize LHS or handle both if necessary
  if (LHSFlag && RHSFlag) 
      return nullptr;  // Prioritize LHS by default
  // If only LHS is an ElementRegion, return its base region
  if (LHSFlag) 
      return LHSRegion->getBaseRegion();
  // If only RHS is an ElementRegion, return its base region
  if (RHSFlag) 
      return RHSRegion->getBaseRegion();
  return nullptr;

}
void ArrayPointerArithmeticChecker::checkPostStmt(const BinaryOperator *BO,
                                                 CheckerContext &C) const {
  if (BO->getOpcode() != BO_Add && BO->getOpcode() != BO_Sub)
    return;

  ASTContext &Ctx = C.getASTContext();

  // Check if one of the operands is a pointer
  Expr *LHS = BO->getLHS()->IgnoreParens();
  Expr *RHS = BO->getRHS()->IgnoreParens();

  const MemRegion * LHSRegion=C.getSVal(LHS).getAsRegion();
  const MemRegion * RHSRegion=C.getSVal(RHS).getAsRegion();
  
  const MemRegion* BaseRegion=findBaseRegion(LHSRegion,RHSRegion);
  if(!BaseRegion)
    return;
  
  llvm::APInt ArraySize;
  const TypedValueRegion *TypedBaseRegion = dyn_cast<TypedValueRegion>(BaseRegion);
  if (TypedBaseRegion) {
      QualType BaseType = TypedBaseRegion->getValueType();
      if (const ConstantArrayType *ArrayType = Ctx.getAsConstantArrayType(BaseType)) {
          ArraySize = ArrayType->getSize();
          // Now, `ArraySize` contains the size of the array in elements
      }
  }
  if(!ArraySize)
    return;
  
  const MemRegion* Region=C.getSVal(BO).getAsRegion();
  const ElementRegion *ER = dyn_cast<ElementRegion>(Region);

  if (!ER)
      return;

  // Get the index of ER2 and convert it to a concrete integer if possible
  SVal IndexVal = ER->getIndex();

  std::optional<nonloc::ConcreteInt> CI = IndexVal.getAs<nonloc::ConcreteInt>();
  llvm::APInt Index=CI->getValue();
  // Check that the result is still within the same base region
  if (ER->getBaseRegion()!=BaseRegion || !Index.uge(0) ||  !Index.ult(ArraySize)) {
    // Report an error if the resulting pointer is outside of array bounds
    ExplodedNode *N = C.generateErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Pointer resulting from arithmetic points outside the base array",
        N);
    C.emitReport(std::move(R));
  }
}

// Register the checker
void ento::registerArrayPointerArithmeticChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<ArrayPointerArithmeticChecker>();
}

bool ento::shouldRegisterArrayPointerArithmeticChecker(const CheckerManager &mgr) {
    return true;
}
