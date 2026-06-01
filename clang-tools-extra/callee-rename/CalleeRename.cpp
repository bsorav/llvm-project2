#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include "support/remotefs.h"

using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;

static llvm::cl::OptionCategory CalleeRenameCategory("callee-rename options");
static llvm::cl::list<std::string> Substitutions("D",
                  llvm::cl::desc("Function substitutions in old=new form"),
                  llvm::cl::ZeroOrMore,
                  llvm::cl::cat(CalleeRenameCategory));
static llvm::cl::opt<std::string> RemoteFSUrl(
    "remotefs-url", llvm::cl::desc("RemoteFS server URL"),
    llvm::cl::Optional, llvm::cl::cat(CalleeRenameCategory));
static llvm::cl::opt<std::string> RemoteFSDir(
    "remotefs-dir", llvm::cl::desc("RemoteFS local cache directory"),
    llvm::cl::Optional, llvm::cl::cat(CalleeRenameCategory));

static std::string getRemoteFSArg(int argc, const char **argv,
                                  llvm::StringRef Name) {
    for (int I = 1; I < argc; ++I) {
        llvm::StringRef Arg(argv[I]);
        for (llvm::StringRef Prefix : {"--", "-"}) {
            std::string Joined = (Prefix + Name + "=").str();
            if (Arg.starts_with(Joined))
                return Arg.drop_front(Joined.size()).str();

            std::string Separate = (Prefix + Name).str();
            if (Arg == Separate && I + 1 < argc)
                return argv[I + 1];
        }
    }
    return {};
}

static IntrusiveRefCntPtr<llvm::vfs::FileSystem> createBaseFS() {
    IntrusiveRefCntPtr<llvm::vfs::FileSystem> BaseFS =
        llvm::vfs::getRealFileSystem();
    if (!remotefs_active())
        return BaseFS;

    IntrusiveRefCntPtr<llvm::vfs::FileSystem> RemoteFS =
        llvm::vfs::RemoteFileSystem::create(/*DiagHandler=*/nullptr,
                                            /*DiagContext=*/nullptr, BaseFS);
    return RemoteFS ? RemoteFS : BaseFS;
}

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

class CalleeRenameActionFactory : public FrontendActionFactory {
public:
    std::unique_ptr<FrontendAction> create() override {
        llvm::errs() << "CalleeRenameActionFactory::create() called\n";
        return std::make_unique<CalleeRenameAction>();
    }

    bool runInvocation(std::shared_ptr<CompilerInvocation> Invocation,
                       FileManager *Files,
                       std::shared_ptr<PCHContainerOperations> PCHContainerOps,
                       DiagnosticConsumer *DiagConsumer) override {
        llvm::errs() << "callee-rename ActionFactory Run Invocation()\n";
        CompilerInstance Compiler(std::move(PCHContainerOps));
        Compiler.setInvocation(std::move(Invocation));

        Compiler.createDiagnostics(DiagConsumer, /*ShouldOwnClient=*/false);
        if (!Compiler.hasDiagnostics())
          return false;

        // ClangTool creates its FileManager before the CompilerInvocation is
        // parsed. Build the invocation VFS here so callee-rename observes
        // normal -vfsoverlay handling and Borland's generated include overlay.
        IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS =
            createVFSFromCompilerInvocation(Compiler.getInvocation(),
                                            Compiler.getDiagnostics(),
                                            Files->getVirtualFileSystemPtr());
        IntrusiveRefCntPtr<FileManager> InvocationFiles =
            new FileManager(Files->getFileSystemOpts(), std::move(VFS));
        Compiler.setFileManager(&*InvocationFiles);
        Compiler.createSourceManager(*InvocationFiles);

        std::unique_ptr<FrontendAction> ScopedToolAction(create());
        const bool Success = Compiler.ExecuteAction(*ScopedToolAction);

        InvocationFiles->clearStatCache();
        return Success;
    }
};

int main(int argc, const char **argv) {
    std::string PreParseRemoteFSUrl = getRemoteFSArg(argc, argv, "remotefs-url");
    std::string PreParseRemoteFSDir = getRemoteFSArg(argc, argv, "remotefs-dir");
    if (!PreParseRemoteFSUrl.empty() && !PreParseRemoteFSDir.empty()) {
      llvm::errs() << "CalleeRename's main() calling remotefs_activate() before option parsing\n";
      remotefs_activate(PreParseRemoteFSUrl, PreParseRemoteFSDir);
    }

    auto ExpectedParser = CommonOptionsParser::create(argc, argv, CalleeRenameCategory);
    llvm::errs() << "callee-rename main(): ExpectedParser = " << (bool)ExpectedParser << "\n";
    if (!ExpectedParser) {
      llvm::handleAllErrors(ExpectedParser.takeError(), [](const llvm::ErrorInfoBase &EI) {
          EI.log(llvm::errs());
          });
      return 1;
    }
    CommonOptionsParser &OptionsParser = *ExpectedParser;

    if (!RemoteFSUrl.empty() && !RemoteFSDir.empty() && !remotefs_active()) {
      llvm::errs() << "CalleeRename's main() calling remotefs_activate()\n";
      remotefs_activate(RemoteFSUrl, RemoteFSDir);
    }

    auto source_path_list = OptionsParser.getSourcePathList();
    llvm::errs() << "source_path_list.size() = " << source_path_list.size() << "\n";
    ClangTool Tool(OptionsParser.getCompilations(), source_path_list,
                   std::make_shared<PCHContainerOperations>(), createBaseFS());
    llvm::errs() << "Constructing CalleeRenameActionFactory\n";
    CalleeRenameActionFactory Factory;
    llvm::errs() << "Calling Tool.run(&Factory)\n";
    return Tool.run(&Factory);
}
