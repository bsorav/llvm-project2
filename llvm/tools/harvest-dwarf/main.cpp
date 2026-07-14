#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/DebugInfo/DWARF/DWARFExpression.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugFrame.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugLine.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugLoc.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FormatVariadic.h"

#include <cstdlib>
#include <optional>

#include "support/stdafx.h"

#include "expr/context.h"
#include "expr/expr.h"
#include "expr/expr_utils.h"
#include "expr/state.h"
#include "expr/sp_version.h"

using namespace llvm;
using namespace llvm::object;

namespace {

cl::OptionCategory DwarfDumpCategory("Specific Options");
static cl::opt<std::string>
    InputFilename(cl::Positional, cl::desc("<input object file>"),
                  cl::cat(DwarfDumpCategory));
static cl::opt<std::string>
    OutputFilename("o", cl::init("-"),
                   cl::desc("Redirect output to the specified file."),
                   cl::value_desc("filename"), cl::cat(DwarfDumpCategory));
static cl::alias OutputFilenameAlias("out-file", cl::desc("Alias for -o."),
                                 cl::aliasopt(OutputFilename));
} // namespace
/// @}
//===----------------------------------------------------------------------===//

static void error(StringRef Prefix, std::error_code EC) {
  if (!EC)
    return;
  WithColor::error() << Prefix << ": " << EC.message() << "\n";
  exit(1);
}

using HandlerFn = std::function<bool(ObjectFile &, DWARFContext &DICtx,
                                     const Twine &, raw_ostream &)>;

// Clang IR contains an alloca for an addressable source parameter, but the
// alloca alone does not say whether the target uses the incoming argument slot
// or storage allocated by the callee.  harvest-dwarf resolves that ambiguity
// from the target's parameter locations and emits one ParamStackSlot record.
//
// The preferred evidence is the parameter's CFA-relative address at the first
// PC after the prologue.  If that PC is unavailable, the complete parameter
// location list is considered.  Raw i386 ESP/EBP offsets are used only when
// CFI cannot provide a CFA-relative address.  Ordinary local variables keep
// their existing LocRange/Expr output and are not classified here.

enum class DwarfAddressBase {
  unknown,
  cfa,
  dwarf_register,
};

// A deliberately small summary of the DWARF address forms needed by the
// parameter classifier: one base (CFA or DWARF register) plus a constant.
// Complex expressions remain unknown instead of being guessed.
struct DwarfAddress {
  DwarfAddressBase base = DwarfAddressBase::unknown;
  unsigned dwarf_regnum = 0;
  int64_t offset = 0;
};

struct LocExpr {
  uint64_t low_pc;
  uint64_t high_pc;
  // Only local-variable hints need the eqspace expression.  Parameter records
  // use address/cfa_offset directly, so expr is null for them.
  eqspace::expr_ref expr;
  // The location as encoded in DWARF, before consulting CFI.
  DwarfAddress address;
  // The same address normalized to CFA + offset for this PC range, if CFI can
  // establish the relationship.
  std::optional<int64_t> cfa_offset;
};
using NamedLocExprs = pair<std::string, std::vector<LocExpr>>;

struct HarvestedSubprogram {
  std::string name;
  std::optional<uint64_t> prologue_end_pc;
  unsigned address_size;
  std::list<NamedLocExprs> locals;
  std::list<NamedLocExprs> params;
};

enum class ParamStackSlot {
  unknown,
  incoming,
  fresh,
};

static DwarfAddress
summarize_dwarf_address(DWARFExpression const& expr,
                        DwarfAddress const& frame_base,
                        bool register_is_address)
{
  // Accept only a single address-producing base followed by constant
  // adjustment.  DW_OP_regN is an address only while decoding DW_AT_frame_base;
  // in a parameter location it normally describes a value in a register.
  DwarfAddress ret;
  bool have_base = false;
  for (DWARFExpression::Operation const& op : expr) {
    if (op.isError())
      return {};

    unsigned const opcode = op.getCode();
    if (opcode >= dwarf::DW_OP_breg0 && opcode <= dwarf::DW_OP_breg31) {
      if (have_base)
        return {};
      ret = {DwarfAddressBase::dwarf_register,
             opcode - dwarf::DW_OP_breg0,
             static_cast<int64_t>(op.getRawOperand(0))};
      have_base = true;
      continue;
    }

    if (opcode >= dwarf::DW_OP_reg0 && opcode <= dwarf::DW_OP_reg31) {
      if (have_base || !register_is_address)
        return {};
      ret = {DwarfAddressBase::dwarf_register,
             opcode - dwarf::DW_OP_reg0, 0};
      have_base = true;
      continue;
    }

    switch (opcode) {
    case dwarf::DW_OP_fbreg:
      if (have_base || frame_base.base == DwarfAddressBase::unknown)
        return {};
      ret = frame_base;
      ret.offset += static_cast<int64_t>(op.getRawOperand(0));
      have_base = true;
      break;
    case dwarf::DW_OP_call_frame_cfa:
      if (have_base)
        return {};
      ret = {DwarfAddressBase::cfa, 0, 0};
      have_base = true;
      break;
    case dwarf::DW_OP_plus_uconst:
      if (!have_base)
        return {};
      ret.offset += static_cast<int64_t>(op.getRawOperand(0));
      break;
    default:
      return {};
    }
  }
  return have_base ? ret : DwarfAddress{};
}

class DWARFExpression_to_eqspace_expr
{
public:
  DWARFExpression_to_eqspace_expr(DWARFExpression const& expr, unsigned AddressSize, eqspace::expr_ref const& frame_base, raw_ostream& OS)
  : m_dwarf_expr(expr),
    m_frame_base(frame_base),
    m_OS(OS),
    m_bvsort_size(AddressSize*8),
    m_memvar(g_ctx->mk_var(G_SOLVER_DST_MEM_NAME, g_ctx->mk_array_sort(g_ctx->mk_bv_sort(DWORD_LEN), g_ctx->mk_bv_sort(BYTE_LEN)))),
    m_mem_allocvar(g_ctx->mk_var(string(G_SOLVER_DST_MEM_NAME "." G_ALLOC_SYMBOL), g_ctx->mk_array_sort(g_ctx->mk_bv_sort(DWORD_LEN), g_ctx->mk_memlabel_sort())))
    //m_mem_allocvar(get_corresponding_mem_alloc_from_mem_expr(m_memvar))
  { }

  eqspace::expr_ref get_result()
  {
    eqspace::expr_ref ret = convert();
    return ret;
  }

private:

  eqspace::expr_ref convert();
  bool handle_op(DWARFExpression::Operation const& op);

  eqspace::expr_ref dwarf_reg_to_var(unsigned dwarfregnum) const;
  eqspace::expr_ref signed_const_to_bvconst(int64_t cval) const;
  eqspace::expr_ref unsigned_const_to_bvconst(uint64_t cval) const;

  bool pop_expr(eqspace::expr_ref& ret);
  bool pop_binary_exprs(eqspace::expr_ref& op1, eqspace::expr_ref& op2);
  void dump_stack_and_expr() const;

  DWARFExpression const& m_dwarf_expr;
  eqspace::expr_ref const& m_frame_base;
  raw_ostream& m_OS;
  std::stack<eqspace::expr_ref> m_stk;
  std::list<eqspace::expr_ref> m_location_desc;
  unsigned m_bvsort_size;
  expr_ref m_memvar;
  expr_ref m_mem_allocvar;
};

eqspace::expr_ref
DWARFExpression_to_eqspace_expr::convert()
{
  m_stk = {};
  for (auto &op : m_dwarf_expr) {
    if (!handle_op(op)) {
      return nullptr;
    }
  }
  if (m_location_desc.size()) {
    if (!m_stk.empty()) {
      dump_stack_and_expr();
      return nullptr;
    }
    if (m_location_desc.size() > 1) {
      m_stk.push(expr_bvconcat(m_location_desc));
    } else {
      m_stk.push(m_location_desc.front());
    }
  }
  if (m_stk.size() != 1) {
    dump_stack_and_expr();
    return nullptr;
  }
  return m_stk.top();
}

void
DWARFExpression_to_eqspace_expr::dump_stack_and_expr() const
{
    auto cp_stk = m_stk;
    while (!cp_stk.empty()) {
      auto v = cp_stk.top(); cp_stk.pop();
      errs() << eqspace::expr_string(v) << " ";
    }
    errs() << "\nDWARFExpression = ";
    m_dwarf_expr.print(errs(), DIDumpOptions(), nullptr);
    errs() << '\n';
}

eqspace::expr_ref
DWARFExpression_to_eqspace_expr::dwarf_reg_to_var(unsigned dwarfregnum) const
{
  if (m_bvsort_size == 32) {
    // from i386 ABI spec; we use same mapping
    if (dwarfregnum <= 7) {
      std::ostringstream os;
      os << G_INPUT_KEYWORD << '.' << G_DST_KEYWORD << '.' << eqspace::state::reg_name(I386_EXREG_GROUP_GPRS, dwarfregnum);
      return g_ctx->mk_var(os.str(), g_ctx->mk_bv_sort(m_bvsort_size));
    } else if (dwarfregnum >= 21 && dwarfregnum <= 28) {
      std::ostringstream os;
      os << G_INPUT_KEYWORD << '.' << G_DST_KEYWORD << '.' << eqspace::state::reg_name(I386_EXREG_GROUP_XMM, dwarfregnum-21);
      return g_ctx->mk_var(os.str(), g_ctx->mk_bv_sort(m_bvsort_size));
    } else {
      errs() << format("\nregister mapping not defined for register num %d\n", dwarfregnum);
      return nullptr;
    }
  } else {
    errs() << format("\nregister mapping not defined for address size %d\n", m_bvsort_size / 8);
    return nullptr;
  }
}

eqspace::expr_ref
DWARFExpression_to_eqspace_expr::signed_const_to_bvconst(int64_t cval) const
{
  return g_ctx->mk_bv_const(m_bvsort_size, cval);
}

eqspace::expr_ref
DWARFExpression_to_eqspace_expr::unsigned_const_to_bvconst(uint64_t cval) const
{
  return g_ctx->mk_bv_const(m_bvsort_size, cval);
}

bool
DWARFExpression_to_eqspace_expr::pop_expr(eqspace::expr_ref& ret)
{
  if (m_stk.empty()) {
    dump_stack_and_expr();
    return false;
  }
  ret = m_stk.top();
  m_stk.pop();
  return true;
}

bool
DWARFExpression_to_eqspace_expr::pop_binary_exprs(eqspace::expr_ref& op1, eqspace::expr_ref& op2)
{
  return pop_expr(op2) && pop_expr(op1);
}

bool
DWARFExpression_to_eqspace_expr::handle_op(DWARFExpression::Operation const& op)
{
  if (op.isError()) {
    errs() << "DWARF expression decoding error\n";
    return false;
  }

  auto const& opcode = op.getCode();

  if (   opcode >= llvm::dwarf::DW_OP_breg0
      && opcode <= llvm::dwarf::DW_OP_breg31) {
    // signed offset from register
    eqspace::expr_ref regvar = this->dwarf_reg_to_var(opcode-llvm::dwarf::DW_OP_breg0);
    if (!regvar) {
      return false;
    }
    eqspace::expr_ref offset = this->signed_const_to_bvconst(op.getRawOperand(0));
    eqspace::expr_ref res    = g_ctx->mk_bvadd(regvar, offset);
    m_stk.push(res);
  }
  else if (opcode >= llvm::dwarf::DW_OP_reg0 && opcode <= llvm::dwarf::DW_OP_reg31) {
    // NOTE: the standard says that this is supposed to represent a "location" as supposed to "contents" which is represented using DW_OP_bregN
    // Looking at some examples, it seems the difference is that in the other case the value is pushed on stack and a DW_OP_stack_value operation is required at the end for getting the final expression
    // While DW_OP_regN stands on its own and does not require the stack value operation
    // We will handle it by assuming by simply pushing it on stack from where we collect the end result
    eqspace::expr_ref res = this->dwarf_reg_to_var(opcode-llvm::dwarf::DW_OP_reg0);
    if (!res) {
      return false;
    }
    m_stk.push(res);
  }
  else if (   opcode == llvm::dwarf::DW_OP_bregx
           || opcode == llvm::dwarf::DW_OP_regx
           || opcode == llvm::dwarf::DW_OP_regval_type) {
    StringRef name = llvm::dwarf::OperationEncodingString(opcode);
    errs() << "operation \"" << name << "\" not handled\n";
    return false;
  }
  else if (   opcode >= llvm::dwarf::DW_OP_lit0
           && opcode <= llvm::dwarf::DW_OP_lit31) {
    eqspace::expr_ref res = g_ctx->mk_bv_const(m_bvsort_size, opcode-llvm::dwarf::DW_OP_lit0);
    m_stk.push(res);
  } else {
    switch (opcode) {
    case llvm::dwarf::DW_OP_addr: {
      // unsigned address
      eqspace::expr_ref res = this->unsigned_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_fbreg: {
      if (!this->m_frame_base) {
        errs() << "DW_OP_fbreg without frame base\n";
        return false;
      }
      eqspace::expr_ref regvar = this->m_frame_base;
      eqspace::expr_ref offset = this->signed_const_to_bvconst(op.getRawOperand(0));
      eqspace::expr_ref res    = g_ctx->mk_bvadd(regvar, offset);
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_stack_value:
      // make sure stack is non-empty
      // this is suppposed to be the last op of the expression
      if (m_stk.empty()) {
        dump_stack_and_expr();
        return false;
      }
      break;
    case llvm::dwarf::DW_OP_dup:
      if (m_stk.empty()) {
        dump_stack_and_expr();
        return false;
      }
      m_stk.push(m_stk.top());
      break;
    case llvm::dwarf::DW_OP_deref: {
      eqspace::expr_ref addr;
      if (!pop_expr(addr)) {
        return false;
      }
      eqspace::expr_ref res  = g_ctx->mk_select(m_memvar, m_mem_allocvar, memlabel_t::memlabel_top(), addr, m_bvsort_size/8, false);
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_deref_size: {
      eqspace::expr_ref addr;
      if (!pop_expr(addr)) {
        return false;
      }
      unsigned size = op.getRawOperand(0);
      eqspace::expr_ref res  = g_ctx->mk_select(m_memvar, m_mem_allocvar, memlabel_t::memlabel_top(), addr, size, false);
      if (size*8 < m_bvsort_size) {
        res = g_ctx->mk_bvzero_ext(res, m_bvsort_size - size*8);
      }
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_constu: {
      eqspace::expr_ref res = this->unsigned_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_const1u: {
      eqspace::expr_ref res = this->unsigned_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_const2u: {
      eqspace::expr_ref res = this->unsigned_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_consts: {
      eqspace::expr_ref res = this->signed_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_const1s: {
      eqspace::expr_ref res = this->signed_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_const2s: {
      eqspace::expr_ref res = this->signed_const_to_bvconst(op.getRawOperand(0));
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_plus_uconst: {
      // the type of operand is to be matched against stack top;
      // we skip it for now TODO
      eqspace::expr_ref op1;
      if (!pop_expr(op1)) {
        return false;
      }
      eqspace::expr_ref op2 = this->unsigned_const_to_bvconst(op.getRawOperand(0));
      eqspace::expr_ref res = g_ctx->mk_bvadd(op1, op2);
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_not: {
      eqspace::expr_ref op;
      if (!pop_expr(op)) {
        return false;
      }
      eqspace::expr_ref res = g_ctx->mk_bvnot(op);
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_plus:
    case llvm::dwarf::DW_OP_minus:
    case llvm::dwarf::DW_OP_mul:
    case llvm::dwarf::DW_OP_mod:
    case llvm::dwarf::DW_OP_shl:
    case llvm::dwarf::DW_OP_shr:
    case llvm::dwarf::DW_OP_shra:
    case llvm::dwarf::DW_OP_and:
    case llvm::dwarf::DW_OP_or:
    case llvm::dwarf::DW_OP_xor:
    case llvm::dwarf::DW_OP_eq:
    case llvm::dwarf::DW_OP_gt: {
      eqspace::expr_ref op1, op2;
      if (!pop_binary_exprs(op1, op2)) {
        return false;
      }
      eqspace::expr_ref res;
      if (opcode == llvm::dwarf::DW_OP_plus) {
        res = g_ctx->mk_bvadd(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_minus) {
        res = g_ctx->mk_bvsub(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_mul) {
        res = g_ctx->mk_bvmul(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_mod) {
        // the standard's terminology is "modulo" which I am assuming to be
        // unsigned remainder
        res = g_ctx->mk_bvurem(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_shl) {
        res = g_ctx->mk_bvexshl(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_shr) {
        res = g_ctx->mk_bvexlshr(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_shra) {
        res = g_ctx->mk_bvexashr(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_and) {
        res = g_ctx->mk_bvand(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_or) {
        res = g_ctx->mk_bvor(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_xor) {
        res = g_ctx->mk_bvxor(op1, op2);
      } else if (opcode == llvm::dwarf::DW_OP_eq) {
        res = g_ctx->mk_ite(g_ctx->mk_eq(op1, op2),
                            this->unsigned_const_to_bvconst(1),
                            this->unsigned_const_to_bvconst(0));
      } else if (opcode == llvm::dwarf::DW_OP_gt) {
        res = g_ctx->mk_ite(g_ctx->mk_bvugt(op1, op2),
                            this->unsigned_const_to_bvconst(1),
                            this->unsigned_const_to_bvconst(0));
      } else { NOT_REACHED(); }
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_piece: {
      eqspace::expr_ref val;
      if (!pop_expr(val)) {
        errs() << "DW_OP_piece without a stack value; unsupported location expression\n";
        return false;
      }
      uint64_t piece_size = op.getRawOperand(0);
      // XXX endianness matters here
      eqspace::expr_ref res = g_ctx->mk_bvextract(val, piece_size*8-1, 0);
      m_location_desc.push_front(res);
      break;
    }
    case llvm::dwarf::DW_OP_bit_piece: {
      eqspace::expr_ref val;
      if (!pop_expr(val)) {
        errs() << "DW_OP_bit_piece without a stack value; unsupported location expression\n";
        return false;
      }
      uint64_t piece_size = op.getRawOperand(0);
      uint64_t offset     = op.getRawOperand(1);
      // XXX endinness matters here
      eqspace::expr_ref res = g_ctx->mk_bvextract(val, offset+piece_size-1, offset);
      m_location_desc.push_front(res);
      break;
    }
    case llvm::dwarf::DW_OP_call_frame_cfa: {
      // see section 6.4 line 10:
      //   Typically, the CFA is defined to be the value of the stack
      //   pointer at the call site in the previous frame (which may be different from its value
      //   on entry to the current frame)
      // This is usually just (input stack pointer + address size in bytes) i.e. esp before call insn
      eqspace::expr_ref res = g_ctx->mk_bvadd(get_sp_version_at_entry_for_addr_size(g_ctx, m_bvsort_size),
                                              g_ctx->mk_bv_const(m_bvsort_size, (int)m_bvsort_size/8));
      m_stk.push(res);
      break;
    }
    default: {
      StringRef name = llvm::dwarf::OperationEncodingString(opcode);
      assert(!name.empty() && "DW_OP has no name!");
      errs() << "operation \"" << name << "\" not handled\n";
      return false;
    }
    }
  }
  return true;
}

static eqspace::expr_ref
dwarf_expr_to_expr(DWARFExpression const& dwarf_expr, unsigned AddressSize,
                   eqspace::expr_ref const& frame_base, raw_ostream& OS)
{
  DWARFExpression_to_eqspace_expr dexpr2expr(dwarf_expr, AddressSize,
                                             frame_base, OS);
  return dexpr2expr.get_result();
}

static std::optional<uint64_t>
get_first_prologue_end_pc(DWARFDie const& die)
{
  // A line-table row marked PrologueEnd denotes the first instruction after
  // compiler-generated prologue code.  Restrict rows to this subprogram's DIE
  // ranges because a compilation unit has one line table for many functions.
  Expected<DWARFAddressRangesVector> ranges = die.getAddressRanges();
  if (!ranges) {
    consumeError(ranges.takeError());
    return std::nullopt;
  }
  DWARFUnit* unit = die.getDwarfUnit();
  DWARFDebugLine::LineTable const* line_table =
      unit->getContext().getLineTableForUnit(unit);
  if (!line_table)
    return std::nullopt;

  std::optional<uint64_t> prologue_end;
  for (DWARFDebugLine::Row const& row : line_table->Rows) {
    if (!row.PrologueEnd)
      continue;
    uint64_t const address = row.Address.Address;
    for (DWARFAddressRange const& range : *ranges) {
      bool const section_matches =
          row.Address.SectionIndex == SectionedAddress::UndefSection ||
          range.SectionIndex == SectionedAddress::UndefSection ||
          row.Address.SectionIndex == range.SectionIndex;
      if (section_matches && address >= range.LowPC && address < range.HighPC &&
          (!prologue_end || address < *prologue_end)) {
        prologue_end = address;
      }
    }
  }
  return prologue_end;
}

class SubprogramLocalsHarvester
{
public:
  SubprogramLocalsHarvester(DWARFDie const& die, raw_ostream& OS)
  : m_OS(OS), m_prologue_end_pc(get_first_prologue_end_pc(die)),
    m_address_size(die.getDwarfUnit()->getAddressByteSize())
  {
    ASSERT(die.isSubprogramDIE());
    visit_die(die);
  }

  std::string get_name() const { return this->m_name; }
  std::optional<uint64_t> get_prologue_end_pc() const
  {
    return this->m_prologue_end_pc;
  }
  unsigned get_address_size() const { return this->m_address_size; }
  std::list<NamedLocExprs> get_locals() const { return this->m_locals; }
  std::list<NamedLocExprs> get_params() const { return this->m_params; }

private:
  void visit_die(DWARFDie const& die);
  std::vector<LocExpr> handle_location_list(
      DWARFLocationTable const& location_table, uint64_t Offset,
      std::optional<SectionedAddress> BaseAddr, DWARFUnit *U,
      bool keep_only_first);

  raw_ostream& m_OS;

  std::string m_name;
  std::optional<uint64_t> m_prologue_end_pc;
  unsigned m_address_size;
  eqspace::expr_ref m_frame_base;
  DwarfAddress m_frame_base_address;
  std::stack<pair<uint64_t,uint64_t>> m_addr_ranges;
  std::list<NamedLocExprs> m_locals;
  std::list<NamedLocExprs> m_params;
};

std::vector<LocExpr>
SubprogramLocalsHarvester::handle_location_list(DWARFLocationTable const& location_table,
                                                uint64_t Offset,
                                                std::optional<SectionedAddress> BaseAddr,
                                                DWARFUnit *U,
                                                bool keep_only_first)
{
	assert(U);
  // Local-variable hints retain harvest-dwarf's historical first-entry
  // behavior.  Parameters retain every entry because the no-prologue fallback
  // must evaluate the complete location list.
  std::vector<LocExpr> loc_exprs;
  Error E = location_table.visitAbsoluteLocationList(Offset, BaseAddr,
    [U](uint32_t Index) -> std::optional<SectionedAddress>
    { return U->getAddrOffsetSectionItem(Index); },
    [U,keep_only_first,&loc_exprs,this](llvm::Expected<DWARFLocationExpression> Loc) -> bool
    {
      if (!Loc) {
        consumeError(Loc.takeError());
        return false;
      }
      uint64_t lpc, hpc;
      if (Loc->Range) {
        DWARFAddressRange const& addr_range = *Loc->Range;
        lpc = addr_range.LowPC;
        hpc = addr_range.HighPC;
      } else {
        lpc = hpc = 0;
      }
  		DWARFDataExtractor Extractor(Loc->Expr, U->getContext().isLittleEndian(), U->getAddressByteSize());
			auto dwarf_expr = DWARFExpression(Extractor, U->getAddressByteSize());
      DwarfAddress const address = summarize_dwarf_address(
          dwarf_expr, this->m_frame_base_address, false);
      eqspace::expr_ref ret =
          keep_only_first
              ? dwarf_expr_to_expr(dwarf_expr, U->getAddressByteSize(),
                                   this->m_frame_base, this->m_OS)
              : nullptr;
      if (ret || !keep_only_first) {
				  loc_exprs.push_back({lpc, hpc, ret, address, std::nullopt});
        return !keep_only_first;
      }
			return true;
   	});
  if (E) {
    return {};
  }
  return loc_exprs;
}

void
SubprogramLocalsHarvester::visit_die(DWARFDie const& die)
{
  if (!die.isValid()) {
    this->m_OS << "Invalid die\n";
    return;
  }

  DWARFUnit *U = die.getDwarfUnit();
	assert(U);
  DWARFDataExtractor debug_info_data = U->getDebugInfoExtractor();
  DWARFContext &Ctx = U->getContext();

  uint64_t offset = die.getOffset();
  if (!debug_info_data.isValidOffset(offset)) {
    this->m_OS << "Invalid offset: " << offset << '\n';
		return;
  }
  uint32_t abbrCode = debug_info_data.getULEB128(&offset);
  if (!abbrCode) {
    this->m_OS << "Abbrev Code not found for offset: " << offset << '\n';
		return;
  }
  auto AbbrevDecl = die.getAbbreviationDeclarationPtr();
  if (!AbbrevDecl) {
    this->m_OS << "AbbrevDeclarationPtr is null\n";
		return;
  }

  auto tag = AbbrevDecl->getTag();
  if (   (   tag == dwarf::DW_TAG_variable
          || tag == dwarf::DW_TAG_formal_parameter
          || tag == dwarf::DW_TAG_lexical_block) // for lexical blocks we only handle the single address and contiguous address range
      || die.isSubprogramDIE()
     ) {
    std::string name;
    std::vector<LocExpr> loc_exprs;
    uint64_t low_pc = 0, high_pc = 0;
    bool low_high_pcs_are_set = false;
    bool high_pc_is_offset = false;
  	for (const auto &AttrSpec : AbbrevDecl->attributes()) {
    	dwarf::Attribute Attr = AttrSpec.Attr;
    	dwarf::Form Form = AttrSpec.Form;
    	DWARFFormValue FormValue = DWARFFormValue::createFromUnit(Form, U, &offset); // this call is required to update offset

    	if (   Attr != dwarf::DW_AT_name
        	&& Attr != dwarf::DW_AT_location
        	&& Attr != dwarf::DW_AT_frame_base
        	&& Attr != dwarf::DW_AT_low_pc
        	&& Attr != dwarf::DW_AT_high_pc
         ) {
      	// We only care about above attrs
      	continue;
    	}

    	switch (Attr) {
    	  case dwarf::DW_AT_frame_base:
  			  if (FormValue.isFormClass(DWARFFormValue::FC_Exprloc)) {
    			  ArrayRef<uint8_t> Expr = *FormValue.getAsBlock();
            DataExtractor Data(StringRef((const char *)Expr.data(), Expr.size()), Ctx.isLittleEndian(), 0);
            auto dwarf_expr = DWARFExpression(Data, U->getAddressByteSize());
            this->m_frame_base_address =
                summarize_dwarf_address(dwarf_expr, {}, true);
            this->m_frame_base = dwarf_expr_to_expr(dwarf_expr,
                                                    U->getAddressByteSize(),
                                                    nullptr, this->m_OS);
  			  } else { assert(0 && "non-exprloc forms not supported for DW_AT_frame_base"); }
          break;
    	  case dwarf::DW_AT_low_pc:
          if (std::optional<uint64_t> addr = FormValue.getAsAddress()) {
            low_pc = *addr;
          } else { assert(0 && "unable to decode DW_AT_low_pc"); }
          low_high_pcs_are_set = true;
    	    break;
    	  case dwarf::DW_AT_high_pc:
          if (std::optional<uint64_t> addr = FormValue.getAsAddress()) {
            high_pc = *addr;
          } else if (std::optional<uint64_t> offset = FormValue.getAsUnsignedConstant()) {
            high_pc = *offset;
            high_pc_is_offset = true;
          } else {
    	      this->m_OS << "\t" << formatv("{0} [{1}]", Attr, Form) << " ";
            assert(0 && "unable to decode DW_AT_high_pc");
          }
          low_high_pcs_are_set = true;
    	    break;
    	  case dwarf::DW_AT_name:
    	    if (std::optional<const char*> cstr = dwarf::toString(FormValue)) {
    	      name = *cstr;
          } else {
    	      this->m_OS << formatv("{0}: {1} [{2}]", tag, Attr, Form) << " ";
    	      if (tag == dwarf::DW_TAG_subprogram) {
    	        this->m_OS << "subprogram name: " << die.getSubroutineName(llvm::DINameKind::ShortName) << '\n';
    	        this->m_OS << "toString: " << dwarf::toString(FormValue) << '\n';
    	      }
            assert(0 && "unable to decode DW_AT_name");
          }
    	    break;
    	  case dwarf::DW_AT_location: {
  			  if (FormValue.isFormClass(DWARFFormValue::FC_Exprloc)) {
    			  ArrayRef<uint8_t> Expr = *FormValue.getAsBlock();
            DataExtractor Data(StringRef((const char *)Expr.data(), Expr.size()), Ctx.isLittleEndian(), 0);
            auto dwarf_expr = DWARFExpression(Data, U->getAddressByteSize());
            DwarfAddress const address = summarize_dwarf_address(
                dwarf_expr, this->m_frame_base_address, false);
            eqspace::expr_ref ret =
                tag == dwarf::DW_TAG_formal_parameter
                    ? nullptr
                    : dwarf_expr_to_expr(dwarf_expr, U->getAddressByteSize(),
                                         this->m_frame_base, this->m_OS);
            if (!ret && tag != dwarf::DW_TAG_formal_parameter) {
              break;
            }
					  assert(this->m_addr_ranges.size());
					  low_pc  = this->m_addr_ranges.top().first;
					  high_pc = this->m_addr_ranges.top().second;
					  loc_exprs.push_back(
                {low_pc, high_pc, ret, address, std::nullopt});
            //this->m_OS << formatv("pushed loc_expr: [{0}, {1}], {2}", low_pc, high_pc, expr_string(ret)) << '\n';
  			  } else if (FormValue.isFormClass(DWARFFormValue::FC_SectionOffset)) {
    			  uint64_t Offset = *FormValue.getAsSectionOffset();
    			  if (FormValue.getForm() == dwarf::Form::DW_FORM_loclistx) {
      		    if (auto LoclistOffset = U->getLoclistOffset(Offset))
        		    Offset = *LoclistOffset;
      		    else {
						    // loclists section offset not found; cannot extract anything
						    continue;
					    }
    			  }
            bool const keep_only_first =
                tag != dwarf::DW_TAG_formal_parameter;
            std::vector<LocExpr> const location_list =
                handle_location_list(U->getLocationTable(), Offset,
                                     U->getBaseAddress(), U, keep_only_first);
            loc_exprs.insert(loc_exprs.end(), location_list.begin(),
                            location_list.end());
      	  } else { llvm_unreachable("unhandled location type"); }
      	  break;
      	}
        default:
          break; // nop for any other attribute
    	}
  	}

    if (   tag == dwarf::DW_TAG_variable
  	    && loc_exprs.size()) {
      //this->m_OS << formatv("New variable: {0}: ", name);
      //for (auto const& l : loc_exprs) this->m_OS << formatv("[{1}, {2}] {3}; ", get<0>(l), get<1>(l), expr_string(get<2>(l)));
      //this->m_OS << '\n';
  	  this->m_locals.push_back(make_pair(name, loc_exprs));
  	}
    if (   tag == dwarf::DW_TAG_formal_parameter
        && loc_exprs.size()) {
  	  this->m_params.push_back(make_pair(name, loc_exprs));
  	}
    if (   die.isSubprogramDIE()
        && this->m_name.empty()) {
      //this->m_OS << formatv("New subprogram: {0}", name) << '\n';
      this->m_name = name;
    }
    if (   tag == dwarf::DW_TAG_lexical_block
        || die.isSubprogramDIE()) {
      if (low_high_pcs_are_set) {
        if (high_pc_is_offset) {
          high_pc += low_pc;
        }
        //this->m_OS << formatv("New low, high: [{0}, {1}]", low_pc, high_pc) << '\n';
        this->m_addr_ranges.push(make_pair(low_pc, high_pc));
      }
    }
  }

	for (auto child : die.children()) {
    visit_die(child);
	}
}

static void
populate_function_to_variable_to_expr_map(DWARFDie const& die,
                                          std::list<HarvestedSubprogram>& ret_map,
                                          raw_ostream& OS)
{
  if (!die.isValid()) {
    OS << "Invalid die\n";
    return;
  }

  if (die.isSubprogramDIE()) {
    SubprogramLocalsHarvester subprogram_harvester(die, OS);
    auto subprogram_locals = subprogram_harvester.get_locals();
    auto subprogram_params = subprogram_harvester.get_params();
    if (subprogram_locals.size() || subprogram_params.size())
      ret_map.push_back({subprogram_harvester.get_name(),
                         subprogram_harvester.get_prologue_end_pc(),
                         subprogram_harvester.get_address_size(),
                         std::move(subprogram_locals),
                         std::move(subprogram_params)});
  }

	for (auto child : die.children()) {
  	populate_function_to_variable_to_expr_map(child, ret_map, OS);
	}
}

static std::optional<int64_t>
get_cfa_offset(DwarfAddress const& address,
               dwarf::UnwindLocation const& cfa)
{
  // CFI describes the CFA as register + offset.  A parameter location using
  // the same register can therefore be rewritten as CFA + (loc - cfa).
  if (address.base == DwarfAddressBase::cfa)
    return address.offset;

  if (address.base != DwarfAddressBase::dwarf_register ||
      cfa.getLocation() != dwarf::UnwindLocation::RegPlusOffset ||
      address.dwarf_regnum != cfa.getRegister())
    return std::nullopt;

  return address.offset - cfa.getOffset();
}

static uint64_t
range_overlap(uint64_t first_low, uint64_t first_high,
              uint64_t second_low, uint64_t second_high)
{
  uint64_t const low = std::max(first_low, second_low);
  uint64_t const high = std::min(first_high, second_high);
  return high > low ? high - low : 0;
}

static dwarf::FDE const*
find_fde(DWARFDebugFrame const* frame, uint64_t low_pc, uint64_t high_pc,
         uint64_t& best_overlap)
{
  dwarf::FDE const* ret = nullptr;
  if (!frame)
    return ret;

  for (dwarf::FrameEntry const& entry : frame->entries()) {
    auto const* fde = dyn_cast<dwarf::FDE>(&entry);
    if (!fde)
      continue;
    uint64_t const overlap =
        range_overlap(low_pc, high_pc, fde->getInitialLocation(),
                      fde->getInitialLocation() + fde->getAddressRange());
    if (overlap > best_overlap) {
      best_overlap = overlap;
      ret = fde;
    }
  }
  return ret;
}

static dwarf::FDE const*
find_fde(DWARFContext& ctx, uint64_t low_pc, uint64_t high_pc)
{
  // Depending on compiler and flags, unwind information can live in either
  // .debug_frame or .eh_frame.  Prefer the FDE with the greatest overlap with
  // this location range across both sources.
  uint64_t best_overlap = 0;
  dwarf::FDE const* ret = nullptr;

  if (Expected<DWARFDebugFrame const*> frame = ctx.getDebugFrame()) {
    if (dwarf::FDE const* fde =
            find_fde(*frame, low_pc, high_pc, best_overlap))
      ret = fde;
  } else {
    consumeError(frame.takeError());
  }

  if (Expected<DWARFDebugFrame const*> frame = ctx.getEHFrame()) {
    if (dwarf::FDE const* fde =
            find_fde(*frame, low_pc, high_pc, best_overlap))
      ret = fde;
  } else {
    consumeError(frame.takeError());
  }
  return ret;
}

static std::vector<LocExpr>
add_cfa_offsets(DWARFContext& ctx, LocExpr const& loc)
{
  // A location range can cross multiple CFI rows as ESP/EBP changes through
  // the prologue and epilogue.  Split it at row boundaries so each resulting
  // range has the CFA offset valid at its PCs.
  if (loc.address.base == DwarfAddressBase::cfa) {
    LocExpr ret = loc;
    ret.cfa_offset = loc.address.offset;
    return {ret};
  }

  dwarf::FDE const* fde = find_fde(ctx, loc.low_pc, loc.high_pc);
  if (!fde)
    return {loc};

  Expected<dwarf::UnwindTable> table = dwarf::UnwindTable::create(fde);
  if (!table) {
    consumeError(table.takeError());
    return {loc};
  }

  std::vector<LocExpr> ret;
  for (size_t i = 0; i < table->size(); ++i) {
    dwarf::UnwindRow const& row = (*table)[i];
    if (!row.hasAddress())
      continue;

    uint64_t const row_low = row.getAddress();
    uint64_t const row_high =
        i + 1 < table->size()
            ? (*table)[i + 1].getAddress()
            : fde->getInitialLocation() + fde->getAddressRange();
    uint64_t const low = std::max(loc.low_pc, row_low);
    uint64_t const high = std::min(loc.high_pc, row_high);
    if (high <= low)
      continue;

    std::optional<int64_t> const cfa_offset =
        get_cfa_offset(loc.address, row.getCFAValue());
    if (!ret.empty() && ret.back().high_pc == low && cfa_offset &&
        ret.back().cfa_offset == cfa_offset) {
      ret.back().high_pc = high;
    } else {
      ret.push_back({low, high, loc.expr, loc.address, cfa_offset});
    }
  }

  if (ret.empty())
    return {loc};
  return ret;
}

static std::list<NamedLocExprs>
add_cfa_offsets(DWARFContext& ctx,
                std::list<NamedLocExprs> const& params)
{
  std::list<NamedLocExprs> ret;
  for (NamedLocExprs const& param : params) {
    std::vector<LocExpr> locs;
    for (LocExpr const& loc : param.second) {
      std::vector<LocExpr> const locs_with_cfa = add_cfa_offsets(ctx, loc);
      locs.insert(locs.end(), locs_with_cfa.begin(), locs_with_cfa.end());
    }
    ret.emplace_back(param.first, std::move(locs));
  }
  return ret;
}

static bool
loc_expr_contains_pc(LocExpr const& loc, uint64_t pc)
{
  return loc.low_pc <= pc && pc < loc.high_pc;
}

static std::optional<ParamStackSlot>
classify_cfa_locations(std::vector<LocExpr> const& locs,
                       std::optional<uint64_t> pc)
{
  // Incoming stack arguments are at or above the CFA.  A negative offset is
  // storage allocated by the current frame.  When pc is set, only the range
  // covering that post-prologue PC participates; otherwise every location-list
  // range must be understood before declaring the parameter incoming.
  bool saw_location = false;
  bool saw_unknown = false;
  for (LocExpr const& loc : locs) {
    if (pc && !loc_expr_contains_pc(loc, *pc))
      continue;
    saw_location = true;
    if (!loc.cfa_offset) {
      saw_unknown = true;
      continue;
    }
    if (*loc.cfa_offset < 0)
      return ParamStackSlot::fresh;
  }
  if (saw_location && !saw_unknown)
    return ParamStackSlot::incoming;
  return std::nullopt;
}

static std::optional<ParamStackSlot>
classify_raw_i386_address(DwarfAddress const& address, unsigned pointer_size)
{
  // Last-resort i386 ABI heuristic.  Without CFI, the identity of the ESP/EBP
  // value used by a location is ambiguous after stack adjustment, so callers
  // always warn when this result is used.
  //
  // At function entry, ESP+pointer_size skips the return address and EBP needs
  // two pointer-sized slots to skip the saved EBP and return address.
  constexpr unsigned dwarf_esp_regnum = 4;
  constexpr unsigned dwarf_ebp_regnum = 5;

  if (address.base != DwarfAddressBase::dwarf_register)
    return std::nullopt;
  if (address.dwarf_regnum == dwarf_ebp_regnum) {
    return address.offset >= static_cast<int64_t>(2 * pointer_size)
               ? ParamStackSlot::incoming
               : ParamStackSlot::fresh;
  }
  if (address.dwarf_regnum == dwarf_esp_regnum) {
    return address.offset >= static_cast<int64_t>(pointer_size)
               ? ParamStackSlot::incoming
               : ParamStackSlot::fresh;
  }
  return std::nullopt;
}

static std::optional<ParamStackSlot>
classify_raw_i386_locations(std::vector<LocExpr> const& locs,
                            std::optional<uint64_t> pc,
                            unsigned pointer_size)
{
  std::optional<ParamStackSlot> ret;
  for (LocExpr const& loc : locs) {
    if (pc && !loc_expr_contains_pc(loc, *pc))
      continue;
    std::optional<ParamStackSlot> const classification =
        classify_raw_i386_address(loc.address, pointer_size);
    if (!classification || (ret && *ret != *classification))
      return std::nullopt;
    ret = classification;
  }
  return ret;
}

static ParamStackSlot
classify_param_stack_slot(std::string const& function_name,
                          std::string const& param_name,
                          std::vector<LocExpr> const& locs,
                          std::optional<uint64_t> prologue_end_pc,
                          unsigned pointer_size, bool is_i386)
{
  // Decision order:
  //   1. CFA-relative address at the first PC after the prologue.
  //   2. CFA-relative evidence across the complete location list when that PC
  //      is unavailable or not covered by a parameter location.
  //   3. Raw i386 ESP/EBP offsets over the same selected locations.
  //   4. Unknown, leaving llvm2tfg to retain the parameter alloca.
  //
  // Setting pc selects (1).  Leaving it empty makes the classification helpers
  // implement (2) and (3) over all ranges.
  std::optional<uint64_t> pc;
  if (prologue_end_pc &&
      llvm::any_of(locs, [&](LocExpr const& loc) {
        return loc_expr_contains_pc(loc, *prologue_end_pc);
      })) {
    pc = prologue_end_pc;
  }

  if (std::optional<ParamStackSlot> const cfa_classification =
          classify_cfa_locations(locs, pc)) {
    return *cfa_classification;
  }

  if (is_i386) {
    if (std::optional<ParamStackSlot> const raw_classification =
            classify_raw_i386_locations(locs, pc, pointer_size)) {
      errs() << "WARNING: classified " << function_name << " parameter '"
             << param_name << "' using the raw i386 ESP/EBP offset fallback\n";
      return *raw_classification;
    }
  }

  errs() << "WARNING: could not classify " << function_name << " parameter '"
         << param_name << "' as an incoming or fresh stack slot\n";
  return ParamStackSlot::unknown;
}

static StringRef
param_stack_slot_to_string(ParamStackSlot stack_slot)
{
  switch (stack_slot) {
  case ParamStackSlot::incoming:
    return "incoming";
  case ParamStackSlot::fresh:
    return "fresh";
  case ParamStackSlot::unknown:
    return "unknown";
  }
  llvm_unreachable("unknown parameter stack-slot classification");
}

static bool dumpObjectFile(ObjectFile &Obj, DWARFContext &DICtx,
                           const Twine &Filename, raw_ostream &OS)
{
  bool const is_i386 = Obj.makeTriple().getArch() == Triple::x86;
  std::list<HarvestedSubprogram> ret_map;
  for (auto const& unit : DICtx.info_section_units()) {
    if (DWARFDie CUDie = unit->getUnitDIE(false)) {
      populate_function_to_variable_to_expr_map(CUDie, ret_map, OS);
    }
  }

  for (auto const& p : ret_map) {
    auto const& name = p.name;
    auto const& varlist = p.locals;
    auto const params = add_cfa_offsets(DICtx, p.params);
    if (varlist.size() || params.size()) {
      OS << formatv("=SubprogramBegin: {0}\n", name);
      for (auto const& pp : varlist) {
        auto const& vname     = pp.first;
        auto const& loc_exprs = pp.second;
        OS << "=VarName: " << vname << "\n";
        for (auto const& loc_expr : loc_exprs) {
          OS << format("=LocRange\n0x%" PRIx64 " 0x%" PRIx64 "\n",
                       loc_expr.low_pc, loc_expr.high_pc);
          OS << formatv("=Expr\n{0}\n",
                        g_ctx->expr_to_string_table(loc_expr.expr));
        }
      }
      unsigned ArgNo = 0;
      for (auto const& pp : params) {
        auto const& pname     = pp.first;
        auto const& loc_exprs = pp.second;
        OS << "=ParamName: " << pname << "\n";
        OS << "=ParamIndex: " << ArgNo++ << "\n";
        ParamStackSlot const stack_slot = classify_param_stack_slot(
            name, pname, loc_exprs, p.prologue_end_pc, p.address_size,
            is_i386);
        // Parameter locations are intentionally reduced to this decision.  The
        // downstream LLVM model must not reinterpret a raw target address.
        OS << "=ParamStackSlot: "
           << param_stack_slot_to_string(stack_slot) << "\n";
      }
      OS << formatv("=SubprogramEnd: {0}\n", name);
    }
  }
  return true;
}

static bool handleBuffer(StringRef Filename, MemoryBufferRef Buffer,
                         HandlerFn HandleObj, raw_ostream &OS)
{
  Expected<std::unique_ptr<Binary>> BinOrErr = object::createBinary(Buffer);
  error(Filename, errorToErrorCode(BinOrErr.takeError()));

  bool Result = true;
  auto RecoverableErrorHandler = [&](Error E) {
    Result = false;
    WithColor::defaultErrorHandler(std::move(E));
  };
  if (auto *Obj = dyn_cast<ObjectFile>(BinOrErr->get())) {
    unsigned pointer_size = Obj->getBytesInAddress();
    if (pointer_size == DWORD_LEN/BYTE_LEN) {
      g_ctx_init(DWORD_LEN);
    } else if (pointer_size == QWORD_LEN/BYTE_LEN) {
      g_ctx_init(QWORD_LEN);
    } else {
      NOT_REACHED();
    }
    std::unique_ptr<DWARFContext> DICtx =
      DWARFContext::create(*Obj,
                           DWARFContext::ProcessDebugRelocations::Process,
                           nullptr, "", RecoverableErrorHandler);
    if (!HandleObj(*Obj, *DICtx, Filename, OS))
      Result = false;
  }
  return Result;
}

static bool handleFile(StringRef Filename, HandlerFn HandleObj,
                       raw_ostream &OS)
{
  ErrorOr<std::unique_ptr<MemoryBuffer>> BuffOrErr =
  MemoryBuffer::getFileOrSTDIN(Filename);
  error(Filename, BuffOrErr.getError());
  std::unique_ptr<MemoryBuffer> Buffer = std::move(BuffOrErr.get());
  return handleBuffer(Filename, *Buffer, HandleObj, OS);
}

int main(int argc, char **argv)
{
  InitLLVM X(argc, argv);

  llvm::InitializeAllTargetInfos();

  cl::HideUnrelatedOptions({&DwarfDumpCategory});
  cl::ParseCommandLineOptions(
      argc, argv,
      "dump local-variables expressions\n");

  std::error_code EC;
  ToolOutputFile OutputFile(OutputFilename, EC, sys::fs::OF_Text);
  error("Unable to open output file" + OutputFilename, EC);
  // Don't remove output file if we exit with an error.
  OutputFile.keep();

  // Defaults to a.out if no filenames specified.
  if (InputFilename.empty())
    InputFilename = "a.out";

  return handleFile(InputFilename, dumpObjectFile, OutputFile.os()) ?
         EXIT_SUCCESS : EXIT_FAILURE;
}
