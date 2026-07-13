#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringSet.h"
//#include "llvm/ADT/Triple.h"
#include "llvm/DebugInfo/DWARF/DWARFExpression.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugLoc.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/ObjectFile.h"
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
using LocExpr = std::tuple<uint64_t, uint64_t, eqspace::expr_ref>;
using NamedLocExprs = pair<std::string, std::vector<LocExpr>>;

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

class SubprogramLocalsHarvester
{
public:
  SubprogramLocalsHarvester(DWARFDie const& die, raw_ostream& OS)
  : m_OS(OS)
  {
    ASSERT(die.isSubprogramDIE());
    visit_die(die);
  }

  std::string get_name() const { return this->m_name; }
  std::list<NamedLocExprs> get_locals() const { return this->m_locals; }
  std::list<NamedLocExprs> get_params() const { return this->m_params; }

private:
  void visit_die(DWARFDie const& die);
  std::optional<LocExpr> handle_location_list(DWARFLocationTable const& location_table, uint64_t Offset, std::optional<SectionedAddress> BaseAddr, DWARFUnit *U);

  raw_ostream& m_OS;

  std::string m_name;
  eqspace::expr_ref m_frame_base;
  std::stack<pair<uint64_t,uint64_t>> m_addr_ranges;
  std::list<NamedLocExprs> m_locals;
  std::list<NamedLocExprs> m_params;
};

std::optional<LocExpr>
SubprogramLocalsHarvester::handle_location_list(DWARFLocationTable const& location_table,
										                            uint64_t Offset,
                                                std::optional<SectionedAddress> BaseAddr,
                                                DWARFUnit *U)
{
	assert(U);
  bool first_only = true; // consider only the first element of the location list
  std::vector<LocExpr> loc_exprs;
  Error E = location_table.visitAbsoluteLocationList(Offset, BaseAddr,
    [U](uint32_t Index) -> std::optional<SectionedAddress>
    { return U->getAddrOffsetSectionItem(Index); },
    [U,first_only,&loc_exprs,this](llvm::Expected<DWARFLocationExpression> Loc) -> bool
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
      eqspace::expr_ref ret = dwarf_expr_to_expr(dwarf_expr,
                                                 U->getAddressByteSize(),
                                                 this->m_frame_base,
                                                 this->m_OS);
      if (ret) {
			  loc_exprs.push_back(make_tuple(lpc, hpc, ret));
        return !first_only;
      }
			return true;
   	});
  if (E) {
    return std::nullopt;
  }
  if (loc_exprs.empty()) {
    return std::nullopt;
  }
  return loc_exprs.front();
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
            eqspace::expr_ref ret = dwarf_expr_to_expr(dwarf_expr,
                                                       U->getAddressByteSize(),
                                                       this->m_frame_base,
                                                       this->m_OS);
            if (!ret) {
              break;
            }
					  assert(this->m_addr_ranges.size());
					  low_pc  = this->m_addr_ranges.top().first;
					  high_pc = this->m_addr_ranges.top().second;
					  loc_exprs.push_back(make_tuple(low_pc, high_pc, ret));
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
            std::optional<LocExpr> loc_expr = handle_location_list(U->getLocationTable(), Offset, U->getBaseAddress(), U);
            if (loc_expr) {
					    loc_exprs.push_back(*loc_expr);
            }
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
                                               std::list<pair<std::string, pair<std::list<NamedLocExprs>, std::list<NamedLocExprs>>>>& ret_map,
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
      ret_map.push_back(make_pair(subprogram_harvester.get_name(),
                                  make_pair(subprogram_locals,
                                            subprogram_params)));
  }

	for (auto child : die.children()) {
  	populate_function_to_variable_to_expr_map(child, ret_map, OS);
	}
}

static bool dumpObjectFile(ObjectFile &Obj, DWARFContext &DICtx,
                           const Twine &Filename, raw_ostream &OS)
{
  std::list<pair<std::string, pair<std::list<NamedLocExprs>, std::list<NamedLocExprs>>>> ret_map;
  for (auto const& unit : DICtx.info_section_units()) {
    if (DWARFDie CUDie = unit->getUnitDIE(false)) {
      populate_function_to_variable_to_expr_map(CUDie, ret_map, OS);
    }
  }

  for (auto const& p : ret_map) {
    auto const& name    = p.first;
    auto const& varlist = p.second.first;
    auto const& params  = p.second.second;
    if (varlist.size() || params.size()) {
      OS << formatv("=SubprogramBegin: {0}\n", name);
  	  for (auto const& pp : varlist) {
  	    auto const& vname     = pp.first;
  	    auto const& loc_exprs = pp.second;
  	    OS << "=VarName: " << vname << "\n";
  	    for (auto const& loc_expr : loc_exprs) {
  	      OS << format("=LocRange\n0x%" PRIx64 " 0x%" PRIx64 "\n", get<0>(loc_expr) , get<1>(loc_expr));
  	      OS << formatv("=Expr\n{0}\n", g_ctx->expr_to_string_table(get<2>(loc_expr)));
  	    }
  	  }
  	  unsigned ArgNo = 0;
  	  for (auto const& pp : params) {
  	    auto const& pname     = pp.first;
  	    auto const& loc_exprs = pp.second;
  	    OS << "=ParamName: " << pname << "\n";
  	    OS << "=ParamIndex: " << ArgNo++ << "\n";
  	    for (auto const& loc_expr : loc_exprs) {
  	      OS << format("=LocRange\n0x%" PRIx64 " 0x%" PRIx64 "\n", get<0>(loc_expr) , get<1>(loc_expr));
  	      OS << formatv("=Expr\n{0}\n", g_ctx->expr_to_string_table(get<2>(loc_expr)));
  	    }
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
