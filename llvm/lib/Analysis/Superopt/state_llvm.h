#ifndef EQCHECKSTATE_LLVM_H
#define EQCHECKSTATE_LLVM_H

#include "tfg/state.h"
#include "tfg/pc.h"

using namespace eqspace;

class control_flow_transfer
{
public:
  control_flow_transfer(pc const &p_from, pc const &p_to, expr_ref expr) : m_pc_from(p_from), m_pc_to(p_to), m_condition(expr) { }
  control_flow_transfer(pc const &p_from, pc const &p_to, expr_ref cond, expr_ref tgt) : m_pc_from(p_from), m_pc_to(p_to), m_condition(cond), m_target(tgt) { }
  pc const &get_from_pc() const { return m_pc_from; }
  pc const &get_to_pc() const { return m_pc_to; }
  expr_ref const &get_target() const { return m_target; }
  expr_ref const &get_condition() const { ASSERT(m_condition); return m_condition; }
  bool is_indir_type() const { return m_target != nullptr; }
private:
  pc m_pc_from;
  pc m_pc_to;
  expr_ref m_condition;
  expr_ref m_target;
};

/*class state_llvm : public state
{
public:

private:
};*/

#endif
