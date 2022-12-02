#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/IR/Dominators.h"

#include <sstream>

using namespace llvm;
using namespace std;

#define CHECK_PASSWORD_FUNCTION "check_password"

namespace {

class InstrumentBackdoor : public FunctionPass {
private:
  Module *M;
public:
  static char ID;
  InstrumentBackdoor() : FunctionPass(ID), M(nullptr)
  {
    dbgs() << "InstrumentBackdoor() constructor: ID = " << int(ID) << ", getPassID() = " << this->getPassID() << "\n";
  }

  virtual bool doInitialization(Module& m) override;

  virtual bool runOnFunction(Function &F) override;

  StringRef getPassName() const override { return "Instrument backdoor"; }
private:
  
  static BasicBlock* add_comparison_logic(BasicBlock* CurBB, BasicBlock* OrigEntryBB, Value* enteredPassword, int char_num, int c);
};

}

char InstrumentBackdoor::ID = 0;

static RegisterPass<InstrumentBackdoor> Backdoor("instrumentBackdoor", "Instrument a backdoor", false /* Only looks at CFG */, true /* Transformation Pass */);

bool
InstrumentBackdoor::doInitialization(Module& m)
{
  M = &m;
  return false;
}

BasicBlock*
InstrumentBackdoor::add_comparison_logic(BasicBlock* CurBB, BasicBlock* OrigEntryBB, Value* enteredPassword, int char_num, int c)
{
  string retBB_name;
  {
    stringstream ss;
    ss << "charcheck." << char_num;
    retBB_name = ss.str();
  }

  Instruction *IP = &*CurBB->getFirstInsertionPt();
  BasicBlock* retBB = CurBB->splitBasicBlock(IP->getIterator(), retBB_name);

  Instruction *OldTI = CurBB->getTerminator();
  LLVMContext& context = CurBB->getContext();
  Type* i8_type = Type::getInt8Ty(context);
  Type* i32_type = Type::getInt32Ty(context);
  SmallVector<Value*, 1> GEPOps;
  Value* offset = Constant::getIntegerValue(i32_type, APInt(32, char_num));
  GEPOps.push_back(offset);
  GetElementPtrInst *gep = GetElementPtrInst::Create(
        i8_type, enteredPassword, makeArrayRef(GEPOps),
        "", OldTI);
  Value *ep0 = new LoadInst(i8_type, gep, "", false, Align(1), OldTI);
  Value *ep0s = new SExtInst(ep0, Type::getInt32Ty(context), "", OldTI);
  Value* bchar = Constant::getIntegerValue(i8_type, APInt(32, c));
  Value *ep0c = new ICmpInst(OldTI, ICmpInst::ICMP_NE, ep0s, bchar, "");
  //BasicBlock* retBB = CurBB->splitBasicBlock(OldTI, retBB_name);
  //OldTI = CurBB->getTerminator();
  BranchInst::Create(OrigEntryBB, retBB, ep0c, OldTI);
  OldTI->eraseFromParent();
  return retBB;
}

bool
InstrumentBackdoor::runOnFunction(Function &F)
{
  string const& function_name = CHECK_PASSWORD_FUNCTION;
  string fname = F.getName().str();
  if (fname != function_name) {
    return false;
  }

  Function::arg_iterator first_arg = F.arg_begin();
  Value* enteredPassword = &(*first_arg);

  BasicBlock* EntryBB = &F.getEntryBlock();
  LLVMContext& context = EntryBB->getContext();
  Instruction *IP = &*EntryBB->getFirstInsertionPt();
  BasicBlock* OrigEntryBB = EntryBB->splitBasicBlock(IP->getIterator(), "OrigEntry");

  Instruction* newTI = EntryBB->getTerminator();
  Type* i32_type = Type::getInt32Ty(context);
  ReturnInst::Create(context, Constant::getIntegerValue(i32_type, APInt(32, 0)), newTI);
  newTI->eraseFromParent();

  // Remove the uncond branch added to the old block.
  string const backdoor = "backdoor";
  BasicBlock* CurBB = EntryBB;
  for (size_t i = 0; i < backdoor.length() + 1; i++) {
    CurBB = add_comparison_logic(CurBB, OrigEntryBB, enteredPassword, i, backdoor[i]);
  }

  dbgs() << "Found function " << function_name << "\n";
  return true;
}
