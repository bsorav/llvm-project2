#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/Triple.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
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

#include "expr/expr.h"
#include "expr/context.h"
#include "tfg/state.h"

using namespace llvm;
using namespace llvm::object;

namespace {

cl::OptionCategory DwarfDumpCategory("Specific Options");
static llvm::cl::list<std::string>
    InputFilenames(cl::Positional, cl::desc("<input object files or .dSYM bundles>"),
                   cl::ZeroOrMore, cl::cat(DwarfDumpCategory));
static cl::opt<std::string>
    OutputFilename("o", cl::init("-"),
                   cl::desc("Redirect output to the specified file."),
                   cl::value_desc("filename"), cl::cat(DwarfDumpCategory));
static cl::alias OutputFilenameAlias("out-file", cl::desc("Alias for -o."),
                                 cl::aliasopt(OutputFilename));
static cl::opt<bool> Verify("verify", cl::desc("Verify the DWARF debug info."),
                        cl::cat(DwarfDumpCategory));
} // namespace
/// @}
//===----------------------------------------------------------------------===//

static void error(StringRef Prefix, std::error_code EC) {
  if (!EC)
    return;
  WithColor::error() << Prefix << ": " << EC.message() << "\n";
  exit(1);
}

static DIDumpOptions getDumpOpts() { 
  DIDumpOptions DumpOpts;
  if (Verify)
    return DumpOpts.noImplicitRecursion();
  return DumpOpts;
}

using HandlerFn = std::function<bool(ObjectFile &, DWARFContext &DICtx,
                                     const Twine &, raw_ostream &)>;

class DWARFExpression_to_eqspace_expr
{
public:
  DWARFExpression_to_eqspace_expr(DWARFExpression const& expr, raw_ostream& OS)
  : m_dwarf_expr(expr),
    m_OS(OS),
    m_bvsort_size(m_dwarf_expr.getAddressSize()*8)
  { }

  eqspace::expr_ref get_result()
  {
    eqspace::expr_ref ret = convert();
    return ret;
  }

private:

  eqspace::expr_ref convert();
  bool handle_op(DWARFExpression::Operation &op);

  eqspace::expr_ref dwarf_reg_to_var(unsigned dwarfregnum) const;
  eqspace::expr_ref signed_const_to_bvconst(int64_t cval) const;
  eqspace::expr_ref unsigned_const_to_bvconst(uint64_t cval) const;

  DWARFExpression const& m_dwarf_expr;
  raw_ostream& m_OS;
  std::stack<eqspace::expr_ref> m_stk;
  unsigned m_bvsort_size;
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
  assert(m_stk.size());
  return m_stk.top();
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
    } else {
      m_OS << format("\nregister mapping not defined for register num %d\n", dwarfregnum);
      m_OS.flush();
      NOT_IMPLEMENTED();
    }
  } else {
    m_OS << format("\nregister mapping not defined for address size %d\n", m_dwarf_expr.getAddressSize());
    m_OS.flush();
    NOT_IMPLEMENTED();
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
DWARFExpression_to_eqspace_expr::handle_op(DWARFExpression::Operation &op)
{
  if (op.isError()) {
    llvm_unreachable("decoding error");
    return false;
  }

  auto const& opcode = op.getCode();

  if (   opcode >= llvm::dwarf::DW_OP_breg0
      && opcode <= llvm::dwarf::DW_OP_breg31) {
    // signed offset from register
    eqspace::expr_ref regvar = this->dwarf_reg_to_var(opcode-llvm::dwarf::DW_OP_breg0);
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
    m_stk.push(res);
  }
  else if (   opcode == llvm::dwarf::DW_OP_bregx
           || opcode == llvm::dwarf::DW_OP_regx
           || opcode == llvm::dwarf::DW_OP_regval_type) {
    NOT_IMPLEMENTED();
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
      // signed offset from frame_base which we assume to be input_stack_pointer_const
      eqspace::expr_ref regvar = g_ctx->get_consts_struct().get_input_stack_pointer_const_expr();
      eqspace::expr_ref offset = this->signed_const_to_bvconst(op.getRawOperand(0));
      eqspace::expr_ref res    = g_ctx->mk_bvadd(regvar, offset);
      m_stk.push(res);
      break;
    }
    case llvm::dwarf::DW_OP_stack_value:
      // make sure stack is non-empty
      // this is suppposed to be the last op of the expression
      assert(m_stk.size());
      break;
    default: {
      StringRef name = llvm::dwarf::OperationEncodingString(opcode);
      assert(!name.empty() && "DW_OP has no name!");
      m_OS << "operation \"" << name << "\" not handled\n";
      m_OS.flush();
      NOT_REACHED();
    }
    }
  }
  return true;
}

static eqspace::expr_ref
dwarf_expr_to_expr(DWARFExpression const& dwarf_expr, raw_ostream& OS)
{
  DWARFExpression_to_eqspace_expr dexpr2expr(dwarf_expr, OS);
  return dexpr2expr.get_result();
}

static llvm::Optional<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>>
handle_location_list(DWARFLocationTable const& location_table,
										 uint64_t Offset,
                     raw_ostream &OS,
                     llvm::Optional<SectionedAddress> BaseAddr,
                     const DWARFObject &Obj,
                     DWARFUnit *U)
{
	assert(U);
  auto const& DataEx = location_table.getDataExtractor();
  bool first_only = true; // consider only the first element of the location list
  std::vector<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>> loc_exprs;
  Error E = location_table.visitAbsoluteLocationList(Offset, BaseAddr,
    [U](uint32_t Index) -> llvm::Optional<SectionedAddress>
    { return U->getAddrOffsetSectionItem(Index); },
    [U,&DataEx,&OS,first_only,&loc_exprs](llvm::Expected<DWARFLocationExpression> Loc) -> bool
    {
      if (!Loc) {
        consumeError(Loc.takeError());
        return false;
      }
      uint64_t lpc, hpc;
      if (Loc->Range) {
        DWARFAddressRange const& addr_range = Loc->Range.getValue();
        lpc = addr_range.LowPC;
        hpc = addr_range.HighPC;
      } else {
        lpc = hpc = 0;
      }
  		DWARFDataExtractor Extractor(Loc->Expr, DataEx.isLittleEndian(), DataEx.getAddressSize());
			auto dwarf_expr = DWARFExpression(Extractor, DataEx.getAddressSize());
      eqspace::expr_ref ret = dwarf_expr_to_expr(dwarf_expr, OS);
			loc_exprs.push_back(make_tuple(lpc, hpc, ret));
			return !first_only;
   	});
  if (E) {
    return llvm::None;
  }
  return loc_exprs.front();
}

static void
populate_function_to_variable_to_expr_map(DWARFDie const& die,
                                               std::list<pair<std::string, std::list<pair<std::string, std::vector<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>>>>>>& ret_map,
                                               std::stack<pair<uint64_t,uint64_t>> addr_ranges,
                                               raw_ostream& OS,
                                               bool in_subprogram)
{
  if (!die.isValid()) {
    OS << "Invalid die\n";
    return;
  }

  DWARFUnit *U = die.getDwarfUnit();
	assert(U);
  DWARFDataExtractor debug_info_data = U->getDebugInfoExtractor();

  uint64_t offset = die.getOffset();
  if (!debug_info_data.isValidOffset(offset)) {
    OS << "Invalid offset: " << offset << '\n';
		return;
  }
  uint32_t abbrCode = debug_info_data.getULEB128(&offset);
  if (!abbrCode) {
    OS << "Abbrev Code not found for offset: " << offset << '\n';
		return;
  }
  auto AbbrevDecl = die.getAbbreviationDeclarationPtr();
  if (!AbbrevDecl) {
    OS << "Arrev Declaration ptr is null\n";
		return;
  }
  auto tag = AbbrevDecl->getTag();
  if (   (   in_subprogram
          && (   tag == dwarf::DW_TAG_variable
              || tag == dwarf::DW_TAG_lexical_block)) // for lexical blocks we only handle the single address and contiguous address range
      || die.isSubprogramDIE()
     ) {
    std::string name;
    std::vector<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>> loc_exprs;
    uint64_t low_pc = 0, high_pc = 0;
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
    	    // TODO assert that frame_base is equal to ESP
          break;
    	  case dwarf::DW_AT_low_pc:
          if (llvm::Optional<uint64_t> addr = FormValue.getAsAddress()) {
            low_pc = addr.getValue();
          } else { assert(0 && "unable to decode DW_AT_low_pc"); }
    	    break;
    	  case dwarf::DW_AT_high_pc:
          if (llvm::Optional<uint64_t> addr = FormValue.getAsAddress()) {
            high_pc = addr.getValue();
          } else if (llvm::Optional<uint64_t> offset = FormValue.getAsUnsignedConstant()) {
            high_pc = offset.getValue();
            high_pc_is_offset = true;
          } else {
    	      OS << "\t" << formatv("{0} [{1}]", Attr, Form) << " ";
            assert(0 && "unable to decode DW_AT_high_pc");
          }
    	    break;
    	  case dwarf::DW_AT_name:
    	    if (llvm::Optional<const char*> cstr = FormValue.getAsCString()) {
    	      name = cstr.getValue();
          } else { assert(0 && "unable to decode DW_AT_name"); }
    	    break;
    	  case dwarf::DW_AT_location:
    	    if (   Form == dwarf::Form::DW_FORM_exprloc
        	    || DWARFAttribute::mayHaveLocationDescription(Attr)) {
  			    DWARFContext &Ctx = U->getContext();
  			    if (FormValue.isFormClass(DWARFFormValue::FC_Exprloc)) {
    			    ArrayRef<uint8_t> Expr = *FormValue.getAsBlock();
    			    DataExtractor Data(StringRef((const char *)Expr.data(), Expr.size()), Ctx.isLittleEndian(), 0);
    			    auto dwarf_expr = DWARFExpression(Data, U->getAddressByteSize());
              eqspace::expr_ref ret = dwarf_expr_to_expr(dwarf_expr, OS);
					    assert(addr_ranges.size());
					    low_pc = addr_ranges.top().first;
					    high_pc = addr_ranges.top().second;
					    loc_exprs.push_back(make_tuple(low_pc, high_pc, ret));
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
              llvm::Optional<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>> loc_expr = handle_location_list(U->getLocationTable(), Offset, OS, U->getBaseAddress(), Ctx.getDWARFObj(), U);
					    assert(loc_expr);
					    loc_exprs.push_back(loc_expr.getValue());
      	    } else { llvm_unreachable("unhandled location type"); }
      	  } else { assert(0 && "unable to decode DW_AT_location"); }
      	  break;
        default:
          break; // nop for any other attribute
    	}
  	}

    if (   tag == dwarf::DW_TAG_variable
  	    && loc_exprs.size()) {
  	  ret_map.back().second.push_back(make_pair(name, loc_exprs));
  	}
    if (die.isSubprogramDIE()) {
      ret_map.push_back(std::make_pair(name, std::list<pair<std::string,std::vector<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>>>>()));
    }
    if (   tag == dwarf::DW_TAG_lexical_block
        || die.isSubprogramDIE()) {
      if (high_pc_is_offset) {
        high_pc += low_pc;
      }
      addr_ranges.push(make_pair(low_pc, high_pc));
    }
	}

  // recursive call
	bool child_in_subprogram = in_subprogram || die.isSubprogramDIE();
	for (auto child : die.children()) {
  	populate_function_to_variable_to_expr_map(child, ret_map, addr_ranges, OS, child_in_subprogram);
	}
}

static bool dumpObjectFile(ObjectFile &Obj, DWARFContext &DICtx,
                           const Twine &Filename, raw_ostream &OS)
{
  logAllUnhandledErrors(DICtx.loadRegisterInfo(Obj), errs(),
                        Filename.str() + ": ");


  std::list<pair<std::string, std::list<pair<std::string, std::vector<std::tuple<uint64_t,uint64_t,eqspace::expr_ref>>>>>> ret_map;
  for (auto const& unit : DICtx.info_section_units()) {
    if (DWARFDie CUDie = unit->getUnitDIE(false)) {
      populate_function_to_variable_to_expr_map(CUDie, ret_map, {}, OS, false);
    }
  }

  for (auto const& p : ret_map) {
    auto const& name    = p.first;
    auto const& varlist = p.second;
    if (varlist.size()) {
      OS << formatv("=SubprogramBegin: {0}\n", name);
  	  for (auto const& pp : varlist) {
  	    auto const& vname     = pp.first;
  	    auto const& loc_exprs = pp.second;
  	    OS << "=VarName: " << vname << "\n";
  	    for (auto const& loc_expr : loc_exprs) {
  	      OS << format("=LocRange\n0x%" PRIx64 " ; 0x%" PRIx64 "\n", get<0>(loc_expr) , get<1>(loc_expr));
  	      OS << formatv("=Expr\n{0}\n", g_ctx->expr_to_string_table(get<2>(loc_expr)));
  	    }
  	  }
      OS << formatv("=SubprogramEnd: {0}\n", name);
    }
  }
  return true;
}

static bool verifyObjectFile(ObjectFile &Obj, DWARFContext &DICtx,
                             const Twine &Filename, raw_ostream &OS)
{
  // Verify the DWARF and exit with non-zero exit status if verification
  // fails.
  raw_ostream &stream = OS;
  stream << "Verifying " << Filename.str() << ":\tfile format "
  << Obj.getFileFormatName() << "\n";
  bool Result = DICtx.verify(stream, getDumpOpts());
  if (Result)
    stream << "No errors.\n";
  else
    stream << "Errors detected.\n";
  return Result;
}

static bool handleBuffer(StringRef Filename, MemoryBufferRef Buffer,
                         HandlerFn HandleObj, raw_ostream &OS);

static bool handleArchive(StringRef Filename, Archive &Arch,
                          HandlerFn HandleObj, raw_ostream &OS)
{
  bool Result = true;
  Error Err = Error::success();
  for (auto Child : Arch.children(Err)) {
    auto BuffOrErr = Child.getMemoryBufferRef();
    error(Filename, errorToErrorCode(BuffOrErr.takeError()));
    auto NameOrErr = Child.getName();
    error(Filename, errorToErrorCode(NameOrErr.takeError()));
    std::string Name = (Filename + "(" + NameOrErr.get() + ")").str();
    Result &= handleBuffer(Name, BuffOrErr.get(), HandleObj, OS);
  }
  error(Filename, errorToErrorCode(std::move(Err)));

  return Result;
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
    std::unique_ptr<DWARFContext> DICtx =
      DWARFContext::create(*Obj, nullptr, "", RecoverableErrorHandler);
    if (!HandleObj(*Obj, *DICtx, Filename, OS))
      Result = false;
  }
  else if (auto *Arch = dyn_cast<Archive>(BinOrErr->get()))
    Result = handleArchive(Filename, *Arch, HandleObj, OS);
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
  g_ctx_init();

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
  if (InputFilenames.empty())
    InputFilenames.push_back("a.out");

  std::vector<std::string> Objects;
  for (const auto &F : InputFilenames) {
    Objects.push_back(F);
  }

  bool Success = true;
  if (Verify) {
    for (auto Object : Objects)
      Success &= handleFile(Object, verifyObjectFile, OutputFile.os());
  } else {
    for (auto Object : Objects)
      Success &= handleFile(Object, dumpObjectFile, OutputFile.os());
  }

  return Success ? EXIT_SUCCESS : EXIT_FAILURE;
}
