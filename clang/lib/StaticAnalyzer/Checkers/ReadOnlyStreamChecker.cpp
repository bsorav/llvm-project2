#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>

using namespace clang;
using namespace ento;

namespace {

class ReadOnlyStreamChecker : public Checker<check::PreCall, check::PostCall> {
    const BugType ReadOnlyBugType{this, "Writing to Read-Only file", "Unix Stream API Error",
                            /*SuppressOnSink=*/false};
public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};
}

REGISTER_SET_WITH_PROGRAMSTATE(FileDescrState, SymbolRef)

void ReadOnlyStreamChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if(Call.getCalleeIdentifier()->getName()=="fopen"){
        ProgramStateRef State=C.getState();
        const Expr *Arg=Call.getArgExpr(1);
        // Check if ModeVal is a symbolic value
        if (const StringLiteral *SL = dyn_cast<StringLiteral>(Arg->IgnoreParenCasts())) {
            if (SL->getString() == "r") {
                // Mark the file descriptor as read-only in the program state
                SymbolRef FileDesc=Call.getReturnValue().getAsSymbol();
                if(!FileDesc)
                    return;
                State = State->add<FileDescrState>(FileDesc);
                C.addTransition(State);
            }
        }
    }
}

void ReadOnlyStreamChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if(Call.getCalleeIdentifier()->getName()=="fwrite" || 
    Call.getCalleeIdentifier()->getName()=="fprintf" ||
    Call.getCalleeIdentifier()->getName()=="fputs"){
        ProgramStateRef State=C.getState();

        // Get the SVal for the file descriptor argument
        SymbolRef FileDesc = nullptr;
        if(Call.getCalleeIdentifier()->getName()=="fprintf") 
            FileDesc=Call.getArgSVal(0).getAsSymbol();
        else if(Call.getCalleeIdentifier()->getName()=="fwrite") 
            FileDesc=Call.getArgSVal(3).getAsSymbol();
        else if(Call.getCalleeIdentifier()->getName()=="fputs") 
            FileDesc=Call.getArgSVal(1).getAsSymbol();
        // Retrieve the set of read-only file descriptors
        bool Present=State->contains<FileDescrState>(FileDesc);
        // If the file descriptor is found in the read-only set, report an error
        if (Present) {
            // Report an error: writing to a read-only file descriptor
            ExplodedNode *ErrNode= C.generateErrorNode();
            if (ErrNode) {
                auto R = std::make_unique<PathSensitiveBugReport>(ReadOnlyBugType, "Attempt to write to a file opened in read-only mode", ErrNode);
                R->markInteresting(FileDesc);
                C.emitReport(std::move(R));
            }
        }
    }
}

void ento::registerReadOnlyStreamChecker(CheckerManager &mgr) {
    llvm::errs()<<"ReadOnlyStreamChecker Registered\n";
    mgr.registerChecker<ReadOnlyStreamChecker>();
}

bool ento::shouldRegisterReadOnlyStreamChecker(const CheckerManager &mgr) {
    return true;
}
