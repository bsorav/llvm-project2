#ifndef EQCHECKSYM_EXEC_LLVM_H
#define EQCHECKSYM_EXEC_LLVM_H

#include "expr/expr.h"
#include "state_llvm.h"
#include "tfg/tfg.h"
#include "llvm/IR/Module.h"
/*#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"*/

#include "llvm/IR/Value.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineConstantPool.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/WasmEHFuncInfo.h"
#include "llvm/CodeGen/WinEHFuncInfo.h"
//#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "sym_exec_common.h"

class sym_exec_llvm : public sym_exec_common
{
public:
  sym_exec_llvm(context* ctx/*, consts_struct_t const &cs*/, llvm::Module const *module, const llvm::Function& F/*, list<pair<string, unsigned>> const &fun_names, graph_symbol_map_t const &symbol_map, map<symbol_id_t, vector<char>> const &string_contents*/, bool gen_callee_summary, unsigned memory_addressable_size, unsigned word_length) :
    sym_exec_common(ctx/*, cs*/, make_shared<list<pair<string, unsigned>> const>(sym_exec_common::get_fun_names(module)), make_shared<graph_symbol_map_t const>(sym_exec_common::get_symbol_map(module)), make_shared<map<pair<symbol_id_t, offset_t>, vector<char>> const>(sym_exec_common::get_string_contents(module)), gen_callee_summary, memory_addressable_size, word_length),
    m_module(module), m_function(F)
  {}

  void exec(const state& state_in, const llvm::Instruction& I/*, state& state_out, vector<control_flow_transfer>& cfts, bool &expand_switch_flag, unordered_set<predicate> &assumes*/, shared_ptr<tfg_node> from_node, llvm::BasicBlock const &B, llvm::Function const &F, size_t next_insn_id, tfg &t, map<string, pair<callee_summary_t, unique_ptr<tfg>>> *function_tfg_map, set<string> const *function_call_chain, map<shared_ptr<tfg_edge const>, llvm::Instruction *>& eimap);

  //unsigned get_word_length() const { return m_word_length; }
  //unsigned get_memory_addressable_size() const { return m_memory_addressable_size; }

  //sort_ref get_mem_domain() const;
  //sort_ref get_mem_range() const;

  virtual unique_ptr<tfg> get_tfg(map<string, pair<callee_summary_t, unique_ptr<tfg>>> *function_tfg_map, set<string> const *function_call_chain, map<shared_ptr<tfg_edge const>, llvm::Instruction *>& eimap);
  virtual pc get_start_pc() const;

  //void sym_exec_preprocess_tfg(string const &name, tfg *t_src, context *ctx, list<pair<string, unsigned>> const &fun_names, consts_struct_t &cs, map<string, pair<callee_summary_t, tfg *>> &function_tfg_map, pc const &start_pc);

  static unique_ptr<tfg> get_preprocessed_tfg(const llvm::Function& F, llvm::Module const *M, string const &name, context *ctx, map<string, pair<callee_summary_t, unique_ptr<tfg>>> &function_tfg_map, set<string> function_call_chain, bool gen_callee_summary, bool DisableModelingOfUninitVarUB);

  static unique_ptr<tfg> get_preprocessed_tfg_for_machine_function(llvm::MachineFunction const &mf, const llvm::Function& F, llvm::Module const *M, string const &name, context *ctx, list<pair<string, unsigned>> const &fun_names, graph_symbol_map_t const &symbol_map, map<pair<symbol_id_t, offset_t>, vector<char>> const &string_contents, consts_struct_t &cs, map<string, pair<callee_summary_t, unique_ptr<tfg>>> &function_tfg_map, set<string> function_call_chain, bool gen_callee_summary, bool DisableModelingOfUninitVarUB);

  static unique_ptr<tfg> get_preprocessed_tfg_common(sym_exec_common &se, string const &name, map<string, pair<callee_summary_t, unique_ptr<tfg>>> &function_tfg_map, set<string> function_call_chain, list<string> const& sorted_bbl_indices, bool DisableModelingOfUninitVarUB);

  //static bool update_function_call_args_and_retvals_with_atlocals(tfg *t_src);
  
  //list<pair<string, size_t>> const &get_local_refs() { return m_local_refs; }
  //map<symbol_id_t, tuple<string, size_t, bool>> const &get_symbol_map() { return m_symbol_map; }
  //static string get_value_name(const llvm::Value& v);
  //virtual void process_phi_nodes(tfg &t, const llvm::BasicBlock* B_from, const pc& p_to, shared_ptr<tfg_node> const &from_node, const llvm::Function& F, expr_ref edgecond) override;

private:
  virtual expr_ref phiInstructionGetIncomingBlockValue(llvm::Instruction const &I/*, state const &start_state*/, shared_ptr<tfg_node> &pc_to_phi_node, pc const &pc_to, llvm::BasicBlock const *B_from, llvm::Function const &F, tfg &t) override;
  virtual string functionGetName(llvm::Function const &F) const override;
  virtual string get_basicblock_index(llvm::BasicBlock const &F) const override;
  //virtual string get_basicblock_name(llvm::BasicBlock const &F) const override;
  virtual bool instructionIsPhiNode(llvm::Instruction const &I, string &varname) const override;

  //static string gep_name_prefix(string const &name, pc const &from_pc, pc const &pc_to, int argnum);
  expr_ref __get_expr_adding_edges_for_intermediate_vals_helper(const llvm::Value& v, string vname, const state& state_in, shared_ptr<tfg_node> *from_node, pc const &pc_to, llvm::BasicBlock const *B, llvm::Function const *F, tfg& t);
  //bool function_belongs_to_program(string const &fun_name) const;
  //string gep_instruction_get_intermediate_value_name(string base_name, unsigned index_counter, int intermediate_value_num);
  
  //llvm::BasicBlock const *get_basic_block_for_pc(const llvm::Function& F, pc const &p);

  void apply_memcpy_function(const llvm::CallInst* c, expr_ref fun_name_expr, string const &fun_name, llvm::Function *F, state const &state_in, state &state_out/*, unordered_set<predicate> &assumes*/, string const &cur_function_name, shared_ptr<tfg_node> &from_node, pc const &pc_to, llvm::BasicBlock const &B, llvm::Function const &curF, tfg &t, map<string, pair<callee_summary_t, unique_ptr<tfg>>> *function_tfg_map, set<string> const *function_call_chain);

  static size_t function_get_num_bbls(const llvm::Function *F);
  pair<callee_summary_t, unique_ptr<tfg>> const& get_callee_summary(llvm::Function *F, string const &fun_name/*, map<symbol_id_t, tuple<string, size_t, variable_constness_t>> const &symbol_map*/, map<string, pair<callee_summary_t, unique_ptr<tfg>>> &function_tfg_map, set<string> const &function_call_chain);
  void apply_general_function(const llvm::CallInst* c, expr_ref fun_name_expr, string const &fun_name, llvm::Function *F, state const &state_in, state &state_out/*, unordered_set<predicate> &assumes*/, string const &cur_function_name, shared_ptr<tfg_node> &from_node, pc const &pc_to, llvm::BasicBlock const &B, llvm::Function const &curF, tfg &t, map<string, pair<callee_summary_t, unique_ptr<tfg>>> *function_tfg_map, set<string> const *function_call_chain);
  //void add_shiftcount_assume(expr_ref a, size_t shifted_val_size, pc const &from_pc, tfg &t/*, unordered_set<predicate> &assumes*/);
  //void add_dereference_assume(expr_ref a, pc const &from_pc, tfg &t/*unordered_set<predicate> &assumes*/);
  //void add_divbyzero_assume(expr_ref a, pc const &from_pc, tfg &t/*unordered_set<predicate> &assumes*/);
  //void add_div_no_overflow_assume(expr_ref dividend, expr_ref divisor, pc const &from_pc, tfg &t/*unordered_set<predicate> &assumes*/);
  void add_align_assumes(std::string const &elname, llvm::Type *elTy/*llvm::Value const &arg*/, expr_ref a, pc const&from_pc, tfg &t);
  //sort_ref get_fun_type_sort(/*const llvm::Type* t, */sort_ref ret_sort, const vector<sort_ref>& args) const;
  //sort_ref get_type_sort(const llvm::Type* t) const;
  //sort_ref get_value_type(const llvm::Value& v) const;
  //virtual string get_basicblock_name(const llvm::BasicBlock& v) const override;
  //virtual string get_basicblock_index(const llvm::BasicBlock& v) const override;

  //unsigned get_bv_bool_size(sort_ref e) const;

  //expr_ref mk_fresh_expr(const string& name, const string& prefix, sort_ref s) const;

  expr_ref get_const_value_expr(const llvm::Value& v, string vname, const state& state_in, shared_ptr<tfg_node> *from_node, pc const &pc_to, llvm::BasicBlock const *B, llvm::Function const *F, tfg &t);

  expr_ref get_expr_adding_edges_for_intermediate_vals(const llvm::Value& v, string vname, const state& state_in, shared_ptr<tfg_node> &from_node, pc const &pc_to, llvm::BasicBlock const &B, llvm::Function const &F, tfg &t);

  //void state_set_expr(state &st, string const &key, expr_ref const &value);
  //expr_ref state_get_expr(state const &st, string const &key);

  void set_expr(string const &name/*const llvm::Value& v*/, expr_ref expr, state& st);
  vector<expr_ref> get_expr_args(const llvm::Instruction& I, string vname, const state& st, shared_ptr<tfg_node> &from_node, pc const &pc_to, llvm::BasicBlock const &B, llvm::Function const &F, tfg &t/*, unordered_set<predicate> &assumes*/);

  void add_gep_intermediate_vals(llvm::Instruction const &I, string const &name);
  void populate_state_template(const llvm::Function& F);
  //void get_state_template(const pc& p, state& st);
  expr_ref icmp_to_expr(llvm::ICmpInst::Predicate k, const vector<expr_ref>& args) const;

  //pc get_pc_from_bb_and_insn_id(llvm::BasicBlock const &B, size_t insn_id) const;
  vector<control_flow_transfer> expand_switch(tfg &t, shared_ptr<tfg_node> const &from_node, vector<control_flow_transfer> const &cfts, state const &state_to, te_comment_t const& te_comment, llvm::Instruction * I, const llvm::BasicBlock& B, const llvm::Function& F, map<shared_ptr<tfg_edge const>, llvm::Instruction *>& eimap);

  void process_cft(tfg &t, shared_ptr<tfg_node> const &from_node, pc const &pc_to, expr_ref target, expr_ref to_condition, state const &state_to, const llvm::BasicBlock& B, const llvm::Function& F/*, unordered_set<predicate> &assumes*/);
  void add_edges(const llvm::BasicBlock& B, tfg& t, const llvm::Function& F, map<string, pair<callee_summary_t, unique_ptr<tfg>>> *function_tfg_map, set<string> const *function_call_chain, map<shared_ptr<tfg_edge const>, llvm::Instruction *>& eimap);
  //shared_ptr<tfg_node> get_next_intermediate_subsubindex_pc_node(tfg &t, shared_ptr<tfg_node> const &from_node);

  expr_ref exec_gen_expr_casts(const llvm::CastInst& I, expr_ref arg, pc const &from_pc, tfg &t/*, unordered_set<predicate> &assumes*/);
  static string getTypeString(llvm::Type *t);

  expr_ref exec_gen_expr(const llvm::Instruction& I, string Iname, const vector<expr_ref>& args, state const &state_in, shared_ptr<tfg_node> &from_node, pc const &pc_to, llvm::BasicBlock const &B, llvm::Function const &F, tfg &t/*, map<string, expr_ref> &intermediate_values, unordered_set<predicate> &assumes*/);

  void populate_bbl_order_map();

  static map<nextpc_id_t, callee_summary_t> get_callee_summaries_for_tfg(map<nextpc_id_t, string> const &nextpc_map, map<string, callee_summary_t> const &callee_summaries);

  //const std::unique_ptr<llvm::Module>& m_module;
  llvm::Module const *m_module;
  llvm::Function const &m_function;
};

#endif
