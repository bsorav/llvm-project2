//===-- PointerArhgumentChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the MISRA Project
//
//===----------------------------------------------------------------------===//
//
// The pointer arguments to the Standard Library functions memcpy, memmove and memcmp
// shall be pointers to qualified or unqualified versions of compatible types

//The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type,
// an essentially Boolean type or an essentially enum type
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

namespace {

class PointerArgumentChecker : public Checker<check::PreCall> {
    mutable std::unique_ptr<BugType> BT1;
    mutable std::unique_ptr<BugType> BT2;
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
private:
  bool areTypesCompatible(QualType SrcType, QualType DestType, ASTContext &Ctx) const;
  void memcmpArgPointerCheck(const CallEvent &Call, CheckerContext &C) const;
};
}

void PointerArgumentChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if( C.getPreprocessor().getIncludedHeaderFileNames().find("<string.h>") ==  C.getPreprocessor().getIncludedHeaderFileNames().end()) return;
  if (!Callee)
    return;
    
  // Targeted functions
  StringRef FuncName = Callee->getName();
  if (FuncName != "memcpy" && FuncName != "memmove" && FuncName != "memcmp") return;

  if(FuncName == "memcmp"){
    memcmpArgPointerCheck(Call,C);
  }

  // Get argument types
  if (Call.getNumArgs() < 2) return;

  QualType Arg1Type = Call.getArgSVal(0).getType(C.getASTContext());
  QualType Arg2Type = Call.getArgSVal(1).getType(C.getASTContext());


  ASTContext &Ctx = C.getASTContext();

  if (!areTypesCompatible(Arg1Type, Arg2Type, Ctx)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
        return;

    if (!BT1)
        BT1.reset(new BugType(this, "The pointer arguments to the Standard Library functions memcpy, memmove and memcmp shall be pointers to qualified or unqualified versions of compatible types", "MISRA"));

    auto Report = std::make_unique<PathSensitiveBugReport>(*BT1, "The pointer arguments to the Standard Library functions memcpy, memmove and memcmp shall be pointers to qualified or unqualified versions of compatible types", N);
    C.emitReport(std::move(Report));
  }
  return;
}

bool PointerArgumentChecker::areTypesCompatible(QualType SrcType, QualType DestType, ASTContext &Ctx) const {
  // Remove pointer indirection
  const Type *SrcPointeeType = SrcType->getPointeeType().getTypePtrOrNull();
  const Type *DestPointeeType = DestType->getPointeeType().getTypePtrOrNull();
  if (!SrcPointeeType || !DestPointeeType)
    return false;

  // Check for compatibility of pointee types
  return Ctx.typesAreCompatible(QualType(SrcPointeeType, 0), QualType(DestPointeeType, 0));
}

void PointerArgumentChecker::memcmpArgPointerCheck(const CallEvent &Call, CheckerContext &C) const{
    ASTContext &ACtx = C.getASTContext();
    for (unsigned i = 0; i < 2; ++i) { // First two arguments
        const SVal Arg = Call.getArgSVal(i);

        QualType ArgType = Arg.getType(C.getASTContext());
        // Check if the argument is a pointer
        if (!ArgType->isPointerType()) {
            ExplodedNode *N = C.generateNonFatalErrorNode();
            if (!N)
                return;

            if (!BT2)
                BT2.reset(new BugType(this, "The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type, an essentially Boolean type or an essentially enum type", "MISRA"));

            auto Report = std::make_unique<PathSensitiveBugReport>(*BT2, "The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type, an essentially Boolean type or an essentially enum type", N);
            C.emitReport(std::move(Report));

            return;
        }

        // Dereference the pointer to check the pointee type
        QualType PointeeType = ArgType->getPointeeType();

        // Check allowed types
        if (!(PointeeType->isSignedIntegerType() || PointeeType->isUnsignedIntegerType() ||
            PointeeType->isBooleanType() || PointeeType->isEnumeralType())) {
             ExplodedNode *N = C.generateNonFatalErrorNode();
            if (!N)
                return;

            if (!BT2)
                BT2.reset(new BugType(this, "The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type, an essentially Boolean type or an essentially enum type", "MISRA"));

            auto Report = std::make_unique<PathSensitiveBugReport>(*BT2, "The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type, an essentially Boolean type or an essentially enum type", N);
            C.emitReport(std::move(Report));

            return;
        }
    }
}




void ento::registerPointerArgumentChecker(CheckerManager &mgr) {
    mgr.registerChecker<PointerArgumentChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterPointerArgumentChecker(const CheckerManager &mgr) {
    return true;
}