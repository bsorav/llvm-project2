#include "dfa_helper.h"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/CallGraph.h"
#include <sstream>

#include "support/debug.h"

#include "gsupport/ll_filename_parsed.h"

/*static string
get_basicblock_name(const BasicBlock& v)
{
  assert(isa<const BasicBlock>(v));

  string ret;
  raw_string_ostream ss(ret);
  v.printAsOperand(ss, false);
  ss.flush();

  ASSERT(ret.substr(0, 1) == "%");
  ret = ret.substr(1);
  return ret;
}*/

string
get_basicblock_name(const llvm::BasicBlock& v)
{
  assert(isa<const BasicBlock>(v));

  string ret;
  raw_string_ostream ss(ret);
  v.printAsOperand(ss, false);
  ss.flush();

  return ret;
}

int
get_counting_index_for_basicblock(llvm::BasicBlock const& v)
{
  int bbnum = 0;
  for (const BasicBlock& B : *v.getParent()) {
    if (&B == &v) {
      return bbnum;
    }
    bbnum++;
  }
  NOT_REACHED();
}

dshared_ptr<tfg_llvm_t>
function2tfg(Function *F, Module *M, map<shared_ptr<tfg_edge const>, Instruction *>& eimap)
{
  if (!g_ctx) {
    g_ctx_init();
  }
  if (!F && !M) {
    return dshared_ptr<tfg_llvm_t>::dshared_nullptr();
  }
  context *ctx = g_ctx;
  ValueToValueMapTy VMap;
  const bool model_llvm_semantics = false;
  const bool discard_llvm_ub_assumes = false;
  dshared_ptr<tfg_llvm_t> ret = sym_exec_llvm::get_tfg(*F, M, F->getName().str(), ctx, dshared_ptr<tfg_llvm_t const>::dshared_nullptr(), model_llvm_semantics, discard_llvm_ub_assumes, nullptr, eimap, {}, G_SRC_KEYWORD, dshared_ptr<ll_filename_parsed_t>::dshared_nullptr(), context::XML_OUTPUT_FORMAT_TEXT_NOCOLOR);
  pc start_pc = sym_exec_llvm::get_start_pc(*F);
  ret->add_extra_node_at_start_pc(start_pc);
  DYN_DEBUG(function2tfg,
    cout << "returning tfg for function " << F->getName().str() << ":\n";
    ret->graph_to_stream(cout);
  );
  return ret;
}

static string global_function_name;

void
set_global_function_name(string const& fname)
{
  global_function_name = fname;
}

string const&
get_global_function_name()
{
  return global_function_name;
}
