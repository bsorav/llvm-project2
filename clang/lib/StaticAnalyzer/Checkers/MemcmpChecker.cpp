//===-- SimpleStreamChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the MISRA Project
//
//===----------------------------------------------------------------------===//
//
// checks for argument given in memcmp .
//
//===----------------------------------------------------------------------===//


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

namespace{

class MemcmpChecker : public Checker<check::PreCall>{
    mutable std::unique_ptr<BugType> BT;
    private :
     
        bool isNullTerminatedString(SVal MemVal, llvm::APSInt SizeVal) const;
        
    public :
        void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

}

bool MemcmpChecker::isNullTerminatedString(SVal MemVal, llvm::APSInt SizeVal) const {
    // Implement logic to check if MemVal points to a null-terminated string.
    // You can use Region-based analysis or symbol inference here.
    bool returnVal = false;
    if(const MemRegion *MR = MemVal.getAsRegion()){
        llvm::errs() << MR->getString() << " \n";
        if (const StringRegion *SR = dyn_cast<StringRegion>(MR)) {
            const StringLiteral *SL = SR->getStringLiteral();
            return false;
        } else if (const ElementRegion *ER = dyn_cast<ElementRegion>(MR)) {
            const MemRegion *SuperRegion = ER->getSuperRegion();
            if (const StringRegion *SRSuper = dyn_cast<StringRegion>(SuperRegion)) {
                const StringLiteral *SL = SRSuper->getStringLiteral();

                unsigned StringLength = SL->getLength();

                if(SizeVal == StringLength){
                    // llvm::errs() << "null terminated string passed as argument\n";
                    returnVal = true;
                }else{
                    llvm::StringRef RawString = SL->getBytes();
                    for (int i =0 ;i<SizeVal;i++) {
                        char c = RawString[i];
                        if (c == '\0') {
                            // llvm::errs() << "null character present in string at position " << i << "\n";
                            returnVal = true;
                            break;
                        }
                    }
                }
            }
        }  
    }

    return returnVal;
}

void MemcmpChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const{
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II)
        return;
    // llvm::errs() << II->getName() << "\n";
    if (II->getName() == "memcmp") {
        // Check arguments here.
        // llvm::errs() << "memcmp calles\n";
        ProgramStateRef State = C.getState();

        SVal FirstArgVal = Call.getArgSVal(0);
        SVal SecondArgVal = Call.getArgSVal(1);
        SVal SizeArgVal = Call.getArgSVal(2);   // Third argument (size)

        QualType Arg1Type = FirstArgVal.getType(C.getASTContext());
        QualType Arg2Type = SecondArgVal.getType(C.getASTContext());

        if(std::optional<nonloc::ConcreteInt> ConcreteSize =  SizeArgVal.getAs<nonloc::ConcreteInt>()){
            llvm::APSInt SizeVal = ConcreteSize->getValue();
        
            if (Arg1Type->isPointerType() && Arg1Type->getPointeeType()->isCharType()) {

                bool isNullTerm1 = this->isNullTerminatedString(FirstArgVal, SizeVal);
                if(isNullTerm1){
                    // llvm::errs() << "null terminated string found\n";
                    ExplodedNode *N = C.generateNonFatalErrorNode();
                    if (!N)
                        return;

                    if (!BT)
                        BT.reset(new BugType(this, "Null-terminated string passed to memcmp", "MISRA"));

                    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Null-terminated string found in memcmp argument.", N);
                    C.emitReport(std::move(Report));
                }
            }

            if (Arg2Type->isPointerType() && Arg2Type->getPointeeType()->isCharType()) {

                bool isNullTerm2 = this->isNullTerminatedString(SecondArgVal, SizeVal);
                if(isNullTerm2){
                    // llvm::errs() << "null terminated string found\n";
                    ExplodedNode *N = C.generateNonFatalErrorNode();
                    if (!N)
                        return;

                    if (!BT)
                        BT.reset(new BugType(this, "Null-terminated string passed to memcmp", "MISRA"));

                    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Null-terminated string found in memcmp argument.", N);
                    C.emitReport(std::move(Report));
                }
            }
        }
    }
}

void ento::registerMemcmpChecker(CheckerManager &mgr) {
    mgr.registerChecker<MemcmpChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterMemcmpChecker(const CheckerManager &mgr) {
    return true;
}