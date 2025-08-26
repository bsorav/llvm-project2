#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;

static llvm::cl::OptionCategory CalleeRenameCategory("callee-rename options");
static llvm::cl::list<std::string> Substitutions("D",
                  llvm::cl::desc("Function substitutions in old=new form"),
                  llvm::cl::ZeroOrMore,
                  llvm::cl::cat(CalleeRenameCategory));

class CalleeRenamer : public MatchFinder::MatchCallback {
public:
    CalleeRenamer(Rewriter &R, const std::map<std::string,std::string> &subs)
        : Rewrite(R), Subs(subs) {}

    void run(const MatchFinder::MatchResult &Result) override {
        const auto *CE = Result.Nodes.getNodeAs<CallExpr>("call");
        if (!CE) return;

        // Get the callee spelling from source text
        const Expr *CalleeExpr = CE->getCallee()->IgnoreImplicit();
        auto &SM = *Result.SourceManager;
        auto &LangOpts = Result.Context->getLangOpts();

        std::string Name = Lexer::getSourceText(
            CharSourceRange::getTokenRange(CalleeExpr->getSourceRange()),
            SM, LangOpts).str();

        auto it = Subs.find(Name);
        if (it == Subs.end()) return;

        Rewrite.ReplaceText(CalleeExpr->getBeginLoc(), Name.size(), it->second);
    }

private:
    Rewriter &Rewrite;
    const std::map<std::string,std::string> &Subs;
};

class CalleeRenameAction : public ASTFrontendAction {
public:
    CalleeRenameAction() {
      for (const auto &S : Substitutions) {
        auto Pos = S.find('=');
        if (Pos == std::string::npos) {
          llvm::errs() << "Invalid substitution: " << S << "\n";
          continue;
        }
        std::string Old = S.substr(0, Pos);
        std::string New = S.substr(Pos + 1);
        Subs[Old] = New;
      }
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                   StringRef) override {
        Rewrite.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        Callback = std::make_unique<CalleeRenamer>(Rewrite, Subs);
        Finder.addMatcher(callExpr().bind("call"), Callback.get());
        return Finder.newASTConsumer();
    }

    void EndSourceFileAction() override {
        Rewrite.getEditBuffer(Rewrite.getSourceMgr().getMainFileID()).write(llvm::outs());
    }

private:
    Rewriter Rewrite;
    MatchFinder Finder;
    std::unique_ptr<CalleeRenamer> Callback;
    std::map<std::string,std::string> Subs;
};

int main(int argc, const char **argv) {
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, CalleeRenameCategory);
    if (!ExpectedParser) {
      llvm::handleAllErrors(ExpectedParser.takeError(), [](const llvm::ErrorInfoBase &EI) {
          EI.log(llvm::errs());
          });
      return 1;
    }
    CommonOptionsParser &OptionsParser = *ExpectedParser;
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());
    return Tool.run(newFrontendActionFactory<CalleeRenameAction>().get());
}

