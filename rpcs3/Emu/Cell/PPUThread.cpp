#include "stdafx.h"
#include "Utilities/VirtualMemory.h"
#include "Crypto/sha1.h"
#include "Emu/Memory/Memory.h"
#include "Emu/System.h"
#include "Emu/IdManager.h"
#include "PPUThread.h"
#include "PPUInterpreter.h"
#include "PPUAnalyser.h"
#include "PPUModule.h"
#include "lv2/sys_sync.h"
#include "lv2/sys_prx.h"
#include "Utilities/GDBDebugServer.h"

#ifdef LLVM_AVAILABLE
#include "restore_new.h"
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/ADT/Triple.h"
#include "llvm/IR/LLVMContext.h"
//#include "llvm/IR/Dominators.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LegacyPassManager.h"
//#include "llvm/IR/Module.h"
//#include "llvm/IR/Function.h"
//#include "llvm/Analysis/Passes.h"
//#include "llvm/Analysis/BasicAliasAnalysis.h"
//#include "llvm/Analysis/TargetTransformInfo.h"
//#include "llvm/Analysis/MemoryDependenceAnalysis.h"
//#include "llvm/Analysis/LoopInfo.h"
//#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/Lint.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Vectorize.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include "define_new_memleakdetect.h"

#include "Utilities/JIT.h"
#include "PPUTranslator.h"
#include "Modules/cellMsgDialog.h"
#endif

#include <cfenv>
#include "Utilities/GSL.h"

extern u64 get_system_time();

namespace vm { using namespace ps3; }

enum class join_status : u32
{
	joinable = 0,
	detached = 0u-1,
	exited = 0u-2,
	zombie = 0u-3,
};

template <>
void fmt_class_string<join_status>::format(std::string& out, u64 arg)
{
	format_enum(out, arg, [](join_status js)
	{
		switch (js)
		{
		case join_status::joinable: return "";
		case join_status::detached: return "detached";
		case join_status::zombie: return "zombie";
		case join_status::exited: return "exited";
		}

		return unknown;
	});
}

template <>
void fmt_class_string<ppu_decoder_type>::format(std::string& out, u64 arg)
{
	format_enum(out, arg, [](ppu_decoder_type type)
	{
		switch (type)
		{
		case ppu_decoder_type::precise: return "Interpreter (precise)";
		case ppu_decoder_type::fast: return "Interpreter (fast)";
		case ppu_decoder_type::llvm: return "Recompiler (LLVM)";
		}

		return unknown;
	});
}

const ppu_decoder<ppu_interpreter_precise> s_ppu_interpreter_precise;
const ppu_decoder<ppu_interpreter_fast> s_ppu_interpreter_fast;

extern void ppu_initialize();
extern void ppu_initialize(const ppu_module& info);
static void ppu_initialize2(const ppu_module& info);
extern void ppu_execute_syscall(ppu_thread& ppu, u64 code);

// Get pointer to executable cache
static u32& ppu_ref(u32 addr)
{
	return *reinterpret_cast<u32*>(vm::g_exec_addr + addr);
}

// Get interpreter cache value
static u32 ppu_cache(u32 addr)
{
	// Select opcode table
	const auto& table = *(
		g_cfg.core.ppu_decoder == ppu_decoder_type::precise ? &s_ppu_interpreter_precise.get_table() :
		g_cfg.core.ppu_decoder == ppu_decoder_type::fast ? &s_ppu_interpreter_fast.get_table() :
		(fmt::throw_exception<std::logic_error>("Invalid PPU decoder"), nullptr));

	return ::narrow<u32>(reinterpret_cast<std::uintptr_t>(table[ppu_decode(vm::read32(addr))]));
}

static bool ppu_fallback(ppu_thread& ppu, ppu_opcode_t op)
{
	if (g_cfg.core.ppu_decoder == ppu_decoder_type::llvm)
	{
		fmt::throw_exception("Unregistered PPU function");
	}

	ppu_ref(ppu.cia) = ppu_cache(ppu.cia);

	if (g_cfg.core.ppu_debug)
	{
		LOG_ERROR(PPU, "Unregistered instruction: 0x%08x", op.opcode);
	}

	return false;
}

static std::unordered_map<u32, u32>* s_ppu_toc;

static bool ppu_check_toc(ppu_thread& ppu, ppu_opcode_t op)
{
	// Compare TOC with expected value
	const auto found = s_ppu_toc->find(ppu.cia);

	if (ppu.gpr[2] != found->second)
	{
		LOG_ERROR(PPU, "Unexpected TOC (0x%x, expected 0x%x)", ppu.gpr[2], found->second);
		
		if (!ppu.state.test_and_set(cpu_flag::dbg_pause) && ppu.check_state())
		{
			return false;
		}
	}

	// Fallback to the interpreter function
	if (reinterpret_cast<decltype(&ppu_interpreter::UNK)>(std::uintptr_t{ppu_cache(ppu.cia)})(ppu, op))
	{
		ppu.cia += 4;
	}

	return false;
}

extern void ppu_register_range(u32 addr, u32 size)
{
	if (!size)
	{
		LOG_ERROR(PPU, "ppu_register_range(0x%x): empty range", addr);
		return;
	}

	// Register executable range at
	utils::memory_commit(&ppu_ref(addr), size, utils::protection::rw);

	const u32 fallback = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(ppu_fallback));

	size &= ~3; // Loop assumes `size = n * 4`, enforce that by rounding down
	while (size)
	{
		ppu_ref(addr) = fallback;
		addr += 4;
		size -= 4;
	}
}

extern void ppu_register_function_at(u32 addr, u32 size, ppu_function_t ptr)
{
	// Initialize specific function
	if (ptr)
	{
		ppu_ref(addr) = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(ptr));
		return;
	}

	if (!size)
	{
		if (g_cfg.core.ppu_debug)
		{
			LOG_ERROR(PPU, "ppu_register_function_at(0x%x): empty range", addr);
		}
		
		return;	
	}

	if (g_cfg.core.ppu_decoder == ppu_decoder_type::llvm)
	{
		return;
	}

	// Initialize interpreter cache
	const u32 fallback = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(ppu_fallback));

	while (size)
	{
		if (ppu_ref(addr) == fallback)
		{
			ppu_ref(addr) = ppu_cache(addr);
		}

		addr += 4;
		size -= 4;
	}
}

// Breakpoint entry point
static bool ppu_break(ppu_thread& ppu, ppu_opcode_t op)
{
	// Pause and wait if necessary
	bool status = ppu.state.test_and_set(cpu_flag::dbg_pause);
#ifdef WITH_GDB_DEBUGGER
	fxm::get<GDBDebugServer>()->notify();
#endif
	if (!status && ppu.check_state())
	{
		return false;
	}

	// Fallback to the interpreter function
	if (reinterpret_cast<decltype(&ppu_interpreter::UNK)>(std::uintptr_t{ppu_cache(ppu.cia)})(ppu, op))
	{
		ppu.cia += 4;
	}

	return false;
}

// Set or remove breakpoint
extern void ppu_breakpoint(u32 addr)
{
	if (g_cfg.core.ppu_decoder == ppu_decoder_type::llvm)
	{
		return;
	}

	const auto _break = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(&ppu_break));

	if (ppu_ref(addr) == _break)
	{
		// Remove breakpoint
		ppu_ref(addr) = ppu_cache(addr);
	}
	else
	{
		// Set breakpoint
		ppu_ref(addr) = _break;
	}
}

void ppu_thread::on_init(const std::shared_ptr<void>& _this)
{
	if (!stack_addr)
	{
		// Allocate stack + gap between stacks
		const_cast<u32&>(stack_addr) = vm::alloc(stack_size + 4096, vm::stack) + 4096;

		if (!stack_addr)
		{
			fmt::throw_exception("Out of stack memory (size=0x%x)" HERE, stack_size);
		}

		// Make the gap inaccessible
		vm::page_protect(stack_addr - 4096, 4096, 0, 0, vm::page_readable + vm::page_writable);

		gpr[1] = ::align(stack_addr + stack_size, 0x200) - 0x200;

		cpu_thread::on_init(_this);
	}
}

//sets breakpoint, does nothing if there is a breakpoint there already
extern void ppu_set_breakpoint(u32 addr)
{
	if (g_cfg.core.ppu_decoder == ppu_decoder_type::llvm)
	{
		return;
	}

	const auto _break = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(&ppu_break));

	if (ppu_ref(addr) != _break)
	{
		ppu_ref(addr) = _break;
	}
}

//removes breakpoint, does nothing if there is no breakpoint at location
extern void ppu_remove_breakpoint(u32 addr)
{
	if (g_cfg.core.ppu_decoder == ppu_decoder_type::llvm)
	{
		return;
	}

	const auto _break = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(&ppu_break));

	if (ppu_ref(addr) == _break)
	{
		ppu_ref(addr) = ppu_cache(addr);
	}
}

std::string ppu_thread::get_name() const
{
	return fmt::format("PPU[0x%x] Thread (%s)", id, m_name);
}

std::string ppu_thread::dump() const
{
	std::string ret = cpu_thread::dump();
	fmt::append(ret, "Priority: %d\n", +prio);
	fmt::append(ret, "Stack: 0x%x..0x%x\n", stack_addr, stack_addr + stack_size - 1);
	fmt::append(ret, "Joiner: %s\n", join_status(joiner.load()));
	fmt::append(ret, "Commands: %u\n", cmd_queue.size());

	const auto _func = last_function;

	if (_func)
	{
		ret += "Last function: ";
		ret += _func;
		ret += '\n';
	}

	if (const auto _time = start_time)
	{
		fmt::append(ret, "Waiting: %fs\n", (get_system_time() - _time) / 1000000.);
	}
	else
	{
		ret += '\n';
	}

	if (!_func)
	{
		ret += '\n';
	}
	
	ret += "\nRegisters:\n=========\n";
	for (uint i = 0; i < 32; ++i) fmt::append(ret, "GPR[%d] = 0x%llx\n", i, gpr[i]);
	for (uint i = 0; i < 32; ++i) fmt::append(ret, "FPR[%d] = %.6G\n", i, fpr[i]);
	for (uint i = 0; i < 32; ++i) fmt::append(ret, "VR[%d] = %s [x: %g y: %g z: %g w: %g]\n", i, vr[i], vr[i]._f[3], vr[i]._f[2], vr[i]._f[1], vr[i]._f[0]);

	fmt::append(ret, "CR = 0x%08x\n", cr_pack());
	fmt::append(ret, "LR = 0x%llx\n", lr);
	fmt::append(ret, "CTR = 0x%llx\n", ctr);
	fmt::append(ret, "VRSAVE = 0x%08x\n", vrsave);
	fmt::append(ret, "XER = [CA=%u | OV=%u | SO=%u | CNT=%u]\n", xer.ca, xer.ov, xer.so, xer.cnt);
	fmt::append(ret, "VSCR = [SAT=%u | NJ=%u]\n", sat, nj);
	fmt::append(ret, "FPSCR = [FL=%u | FG=%u | FE=%u | FU=%u]\n", fpscr.fl, fpscr.fg, fpscr.fe, fpscr.fu);
	fmt::append(ret, "\nCall stack:\n=========\n0x%08x (0x0) called\n", cia);

	// Determine stack range
	u32 stack_ptr = static_cast<u32>(gpr[1]);
	u32 stack_min = stack_ptr & ~0xfff;
	u32 stack_max = stack_min + 4096;

	while (stack_min && vm::check_addr(stack_min - 4096, 4096, vm::page_writable))
	{
		stack_min -= 4096;
	}

	while (stack_max + 4096 && vm::check_addr(stack_max, 4096, vm::page_writable))
	{
		stack_max += 4096;
	}

	for (u64 sp = vm::read64(stack_ptr); sp >= stack_min && sp + 0x200 < stack_max; sp = vm::read64(static_cast<u32>(sp)))
	{
		// TODO: print also function addresses
		fmt::append(ret, "> from 0x%08llx (0x0)\n", vm::read64(static_cast<u32>(sp + 16)));
	}

	return ret;
}

extern thread_local std::string(*g_tls_log_prefix)();

void ppu_thread::cpu_task()
{
	std::fesetround(FE_TONEAREST);

	// Execute cmd_queue
	while (cmd64 cmd = cmd_wait())
	{
		const u32 arg = cmd.arg2<u32>(); // 32-bit arg extracted

		switch (auto type = cmd.arg1<ppu_cmd>())
		{
		case ppu_cmd::opcode:
		{
			cmd_pop(), s_ppu_interpreter_fast.decode(arg)(*this, {arg});
			break;
		}
		case ppu_cmd::set_gpr:
		{
			if (arg >= 32)
			{
				fmt::throw_exception("Invalid ppu_cmd::set_gpr arg (0x%x)" HERE, arg);
			}

			gpr[arg % 32] = cmd_get(1).as<u64>();
			cmd_pop(1);
			break;
		}
		case ppu_cmd::set_args:
		{
			if (arg > 8)
			{
				fmt::throw_exception("Unsupported ppu_cmd::set_args size (0x%x)" HERE, arg);
			}

			for (u32 i = 0; i < arg; i++)
			{
				gpr[i + 3] = cmd_get(1 + i).as<u64>();
			}

			cmd_pop(arg);
			break;
		}
		case ppu_cmd::lle_call:
		{
			const vm::ptr<u32> opd(arg < 32 ? vm::cast(gpr[arg]) : vm::cast(arg));
			cmd_pop(), fast_call(opd[0], opd[1]);
			break;
		}
		case ppu_cmd::hle_call:
		{
			cmd_pop(), ppu_function_manager::get().at(arg)(*this);
			break;
		}
		case ppu_cmd::initialize:
		{
			cmd_pop(), ppu_initialize();
			break;
		}
		case ppu_cmd::sleep:
		{
			cmd_pop(), lv2_obj::sleep(*this);
			break;
		}
		default:
		{
			fmt::throw_exception("Unknown ppu_cmd(0x%x)" HERE, (u32)type);
		}
		}
	}
}

void ppu_thread::exec_task()
{
	if (g_cfg.core.ppu_decoder == ppu_decoder_type::llvm)
	{
		while (!test(state, cpu_flag::ret + cpu_flag::exit + cpu_flag::stop))
		{
			reinterpret_cast<ppu_function_t>(static_cast<std::uintptr_t>(ppu_ref(cia)))(*this);
		}
		
		return;
	}

	const auto base = vm::_ptr<const u8>(0);
	const auto cache = vm::g_exec_addr;
	const auto bswap4 = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

	v128 _op;
	using func_t = decltype(&ppu_interpreter::UNK);
	func_t func0, func1, func2, func3, func4, func5;

	while (true)
	{
		if (UNLIKELY(test(state)))
		{
			if (check_state()) return;

			// Decode single instruction (may be step)
			const u32 op = *reinterpret_cast<const be_t<u32>*>(base + cia);
			if (reinterpret_cast<func_t>((std::uintptr_t)ppu_ref(cia))(*this, {op})) { cia += 4; }
			continue;
		}

		if (cia % 16)
		{
			// Unaligned
			const u32 op = *reinterpret_cast<const be_t<u32>*>(base + cia);
			if (reinterpret_cast<func_t>((std::uintptr_t)ppu_ref(cia))(*this, {op})) { cia += 4; }
			continue;
		}

		// Reinitialize
		{
			const v128 x = v128::fromV(_mm_load_si128(reinterpret_cast<const __m128i*>(cache + cia)));
			func0 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[0]);
			func1 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[1]);
			func2 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[2]);
			func3 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[3]);
			_op.vi =  _mm_shuffle_epi8(_mm_load_si128(reinterpret_cast<const __m128i*>(base + cia)), bswap4);
		}

		while (LIKELY(func0(*this, {_op._u32[0]})))
		{
			cia += 4;

			if (LIKELY(func1(*this, {_op._u32[1]})))
			{
				cia += 4;

				const v128 x = v128::fromV(_mm_load_si128(reinterpret_cast<const __m128i*>(cache + cia + 8)));
				func0 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[0]);
				func1 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[1]);
				func4 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[2]);
				func5 = reinterpret_cast<func_t>((std::uintptr_t)x._u32[3]);

				if (LIKELY(func2(*this, {_op._u32[2]})))
				{
					cia += 4;

					if (LIKELY(func3(*this, {_op._u32[3]})))
					{
						cia += 4;

						func2 = func4;
						func3 = func5;

						if (UNLIKELY(test(state)))
						{
							break;
						}

						_op.vi = _mm_shuffle_epi8(_mm_load_si128(reinterpret_cast<const __m128i*>(base + cia)), bswap4);
						continue;
					}
					break;
				}
				break;
			}
			break;
		}
	}
}

ppu_thread::~ppu_thread()
{
	if (stack_addr)
	{
		vm::dealloc_verbose_nothrow(stack_addr - 4096, vm::stack);
	}
}

ppu_thread::ppu_thread(const std::string& name, u32 prio, u32 stack)
	: cpu_thread(idm::last_id())
	, prio(prio)
	, stack_size(std::max<u32>(stack, 0x4000))
	, stack_addr(0)
	, start_time(get_system_time())
	, m_name(name)
{
	// Trigger the scheduler
	state += cpu_flag::suspend + cpu_flag::memory;
}

void ppu_thread::cmd_push(cmd64 cmd)
{
	// Reserve queue space
	const u32 pos = cmd_queue.push_begin();

	// Write single command
	cmd_queue[pos] = cmd;
}

void ppu_thread::cmd_list(std::initializer_list<cmd64> list)
{
	// Reserve queue space
	const u32 pos = cmd_queue.push_begin(static_cast<u32>(list.size()));

	// Write command tail in relaxed manner
	for (u32 i = 1; i < list.size(); i++)
	{
		cmd_queue[pos + i].raw() = list.begin()[i];
	}

	// Write command head after all
	cmd_queue[pos] = *list.begin();
}

void ppu_thread::cmd_pop(u32 count)
{
	// Get current position
	const u32 pos = cmd_queue.peek();

	// Clean command buffer for command tail
	for (u32 i = 1; i <= count; i++)
	{
		cmd_queue[pos + i].raw() = cmd64{};
	}

	// Free
	cmd_queue.pop_end(count + 1);
}

cmd64 ppu_thread::cmd_wait()
{
	while (true)
	{
		if (UNLIKELY(test(state)))
		{
			if (test(state, cpu_flag::stop + cpu_flag::exit))
			{
				return cmd64{};
			}
		}

		if (cmd64 result = cmd_queue[cmd_queue.peek()].exchange(cmd64{}))
		{
			return result;
		}

		thread_ctrl::wait();
	}
}

be_t<u64>* ppu_thread::get_stack_arg(s32 i, u64 align)
{
	if (align != 1 && align != 2 && align != 4 && align != 8 && align != 16) fmt::throw_exception("Unsupported alignment: 0x%llx" HERE, align);
	return vm::_ptr<u64>(vm::cast((gpr[1] + 0x30 + 0x8 * (i - 1)) & (0 - align), HERE));
}

void ppu_thread::fast_call(u32 addr, u32 rtoc)
{
	const auto old_cia = cia;
	const auto old_rtoc = gpr[2];
	const auto old_lr = lr;
	const auto old_func = last_function;
	const auto old_fmt = g_tls_log_prefix;

	cia = addr;
	gpr[2] = rtoc;
	lr = ppu_function_manager::addr + 8; // HLE stop address
	last_function = nullptr;

	g_tls_log_prefix = []
	{
		const auto _this = static_cast<ppu_thread*>(get_current_cpu_thread());

		return fmt::format("%s [0x%08x]", _this->get_name(), _this->cia);
	};

	auto at_ret = gsl::finally([&]()
	{
		if (std::uncaught_exception())
		{
			if (last_function)
			{
				if (start_time)
				{
					LOG_WARNING(PPU, "'%s' aborted (%fs)", last_function, (get_system_time() - start_time) / 1000000.);
				}
				else
				{
					LOG_WARNING(PPU, "'%s' aborted", last_function);
				}
			}

			last_function = old_func;
		}
		else
		{
			state -= cpu_flag::ret;
			cia = old_cia;
			gpr[2] = old_rtoc;
			lr = old_lr;
			last_function = old_func;
			g_tls_log_prefix = old_fmt;
		}
	});

	try
	{
		exec_task();
	}
	catch (cpu_flag _s)
	{
		state += _s;

		if (_s != cpu_flag::ret)
		{
			throw;
		}
	}
}

u32 ppu_thread::stack_push(u32 size, u32 align_v)
{
	if (auto cpu = get_current_cpu_thread()) if (cpu->id_type() == 1)
	{
		ppu_thread& context = static_cast<ppu_thread&>(*cpu);

		const u32 old_pos = vm::cast(context.gpr[1], HERE);
		context.gpr[1] -= align(size + 4, 8); // room minimal possible size
		context.gpr[1] &= ~((u64)align_v - 1); // fix stack alignment

		if (old_pos >= context.stack_addr && old_pos < context.stack_addr + context.stack_size && context.gpr[1] < context.stack_addr)
		{
			fmt::throw_exception("Stack overflow (size=0x%x, align=0x%x, SP=0x%llx, stack=*0x%x)" HERE, size, align_v, old_pos, context.stack_addr);
		}
		else
		{
			const u32 addr = static_cast<u32>(context.gpr[1]);
			vm::ps3::_ref<nse_t<u32>>(addr + size) = old_pos;
			std::memset(vm::base(addr), 0, size);
			return addr;
		}
	}

	fmt::throw_exception("Invalid thread" HERE);
}

void ppu_thread::stack_pop_verbose(u32 addr, u32 size) noexcept
{
	if (auto cpu = get_current_cpu_thread()) if (cpu->id_type() == 1)
	{
		ppu_thread& context = static_cast<ppu_thread&>(*cpu);

		if (context.gpr[1] != addr)
		{
			LOG_ERROR(PPU, "Stack inconsistency (addr=0x%x, SP=0x%llx, size=0x%x)", addr, context.gpr[1], size);
			return;
		}

		context.gpr[1] = vm::ps3::_ref<nse_t<u32>>(context.gpr[1] + size);
		return;
	}

	LOG_ERROR(PPU, "Invalid thread" HERE);
}

const ppu_decoder<ppu_itype> s_ppu_itype;

extern u64 get_timebased_time();
extern ppu_function_t ppu_get_syscall(u64 code);
extern std::string ppu_get_syscall_name(u64 code);

extern __m128 sse_exp2_ps(__m128 A);
extern __m128 sse_log2_ps(__m128 A);
extern __m128i sse_altivec_vperm(__m128i A, __m128i B, __m128i C);
extern __m128i sse_altivec_lvsl(u64 addr);
extern __m128i sse_altivec_lvsr(u64 addr);
extern __m128i sse_cellbe_lvlx(u64 addr);
extern __m128i sse_cellbe_lvrx(u64 addr);
extern void sse_cellbe_stvlx(u64 addr, __m128i a);
extern void sse_cellbe_stvrx(u64 addr, __m128i a);

[[noreturn]] static void ppu_trap(ppu_thread& ppu, u64 addr)
{
	ppu.cia = ::narrow<u32>(addr);
	fmt::throw_exception("Trap! (0x%llx)", addr);
}

[[noreturn]] static void ppu_error(ppu_thread& ppu, u64 addr, u32 op)
{
	ppu.cia = ::narrow<u32>(addr);
	fmt::throw_exception("Unknown/Illegal opcode 0x08x (0x%llx)", op, addr);
}

static void ppu_check(ppu_thread& ppu, u64 addr)
{
	ppu.cia = ::narrow<u32>(addr);
	ppu.test_state();
}

static void ppu_trace(u64 addr)
{
	LOG_NOTICE(PPU, "Trace: 0x%llx", addr);
}

extern u32 ppu_lwarx(ppu_thread& ppu, u32 addr)
{
	ppu.rtime = vm::reservation_acquire(addr, sizeof(u32));
	_mm_lfence();
	ppu.raddr = addr;
	ppu.rdata = vm::_ref<const atomic_be_t<u32>>(addr);
	return static_cast<u32>(ppu.rdata);
}

extern u64 ppu_ldarx(ppu_thread& ppu, u32 addr)
{
	ppu.rtime = vm::reservation_acquire(addr, sizeof(u64));
	_mm_lfence();
	ppu.raddr = addr;
	ppu.rdata = vm::_ref<const atomic_be_t<u64>>(addr);
	return ppu.rdata;
}

extern bool ppu_stwcx(ppu_thread& ppu, u32 addr, u32 reg_value)
{
	atomic_be_t<u32>& data = vm::_ref<atomic_be_t<u32>>(addr);

	if (ppu.raddr != addr || ppu.rdata != data.load())
	{
		ppu.raddr = 0;
		return false;
	}

	vm::writer_lock lock(0);

	const bool result = ppu.rtime == vm::reservation_acquire(addr, sizeof(u32)) && data.compare_and_swap_test(static_cast<u32>(ppu.rdata), reg_value);
	
	if (result)
	{
		vm::reservation_update(addr, sizeof(u32));
		vm::notify(addr, sizeof(u32));
	}

	ppu.raddr = 0;
	return result;
}

extern bool ppu_stdcx(ppu_thread& ppu, u32 addr, u64 reg_value)
{
	atomic_be_t<u64>& data = vm::_ref<atomic_be_t<u64>>(addr);

	if (ppu.raddr != addr || ppu.rdata != data.load())
	{
		ppu.raddr = 0;
		return false;
	}

	vm::writer_lock lock(0);

	const bool result = ppu.rtime == vm::reservation_acquire(addr, sizeof(u64)) && data.compare_and_swap_test(ppu.rdata, reg_value);

	if (result)
	{
		vm::reservation_update(addr, sizeof(u64));
		vm::notify(addr, sizeof(u64));
	}

	ppu.raddr = 0;
	return result;
}

static bool adde_carry(u64 a, u64 b, bool c)
{
#ifdef _MSC_VER
	return _addcarry_u64(c, a, b, nullptr) != 0;
#else
	bool result;
	__asm__("addb $0xff, %[c] \n adcq %[a], %[b] \n setb %[result]" : [a] "+&r" (a), [b] "+&r" (b), [c] "+&r" (c), [result] "=r" (result));
	return result;
#endif
}

static std::string ppu_context_prologue()
{
	std::string c;
	//c += "\xCC";
#ifndef _WIN32
	c += "\x48\x89\xF9"; // mov rcx, rdi
#endif
	c += "\x48\xB8"; // mov rax, imm64
	uptr ptr = (uptr)&vm::g_base_addr;
	c.append((const char*)&ptr, 8);
	c += "\x48\x8B"; // mov rax, [rax]
	c += '\0';
	c += "\x48\x03\x41"; // add rax, [ppu+r3]
	c += char(offset32(&ppu_thread::gpr, 3));
	c += "\x48\x83\xC0\x0F"; // add rax, 15
	c += "\x48\x83\xE0\xF0"; // and rax, -16
	return c;
}

const auto ppu_get_context = []() -> std::string
{
	std::string c = ppu_context_prologue();
	c += "\x48\x8B\x51"; // mov rdx, [rcx+r1]
	c += char(offset32(&ppu_thread::gpr, 1));
	c += "\x48\x89\x10"; // mov [rax], rdx
	c += "\x48\x8B\x51"; // mov rdx, [rcx+r2]
	c += char(offset32(&ppu_thread::gpr, 2));
	c += "\x48\x89\x50\x08"; // mov [rax+8], rdx
	c += "\x48\x8B\x54\x24\xF8"; // mov rdx, [rsp-8]
	c += "\x48\x89\x50\x10"; // mov [rax+0x10], rdx

	c += "\x48\x89\x60\x18"; // mov [rax+0x18], rsp
	c += "\x48\x89\x58\x20"; // mov [rax+0x20], rbx
	c += "\x48\x89\x68\x28"; // mov [rax+0x28], rbp
#ifdef _WIN32
	c += "\x48\x89\x70\x30"; // mov [rax+0x30], rsi
	c += "\x48\x89\x78\x38"; // mov [rax+0x38], rdi
#endif
	c += "\x4C\x89\x60\x40"; // mov [rax+0x40], r12
	c += "\x4C\x89\x68\x48"; // mov [rax+0x48], r13
	c += "\x4C\x89\x70\x50"; // mov [rax+0x50], r14
	c += "\x4C\x89\x78\x58"; // mov [rax+0x58], r15

#ifdef _WIN32
	c += "\x66\x0F\x7F\x70\x60"; // movdqa [rax+0x60], xmm6
	c += "\x66\x0F\x7F\x78\x70"; // movdqa [rax+0x70], xmm7
	c += "\x66\x44\x0F\x7F\x80\x80\x00\x00\x00"s; // ...
	c += "\x66\x44\x0F\x7F\x88\x90\x00\x00\x00"s;
	c += "\x66\x44\x0F\x7F\x90\xA0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x7F\x98\xB0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x7F\xA0\xC0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x7F\xA8\xD0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x7F\xB0\xE0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x7F\xB8\xF0\x00\x00\x00"s;
#endif

	c += "\x48\xC7\x41"; // mov [rcx+r3], 0
	c += char(offset32(&ppu_thread::gpr, 3));
	c.append(4, '\0');
	//c += "\xCC";
	c += "\xC3"; // ret
	return c;
}();

const auto ppu_set_context = []() -> std::string
{
	std::string c = ppu_context_prologue();
	c += "\xCC";
	c += "\x48\x8B\x10"; // mov rdx, [rax]
	c += "\x48\x89\x51"; // mov [rcx+r1], rdx
	c += char(offset32(&ppu_thread::gpr, 1));

	c += "\x48\x8B\x50\x08"; // mov rdx, [rax+8]
	c += "\x48\x89\x51"; // mov [rcx+r2], rdx
	c += char(offset32(&ppu_thread::gpr, 2));

	c += "\x48\x8B\x60\x18"; // mov rsp, [rax+0x18]
	c += "\x48\x8B\x58\x20"; // mov rbx, [rax+0x20]
	c += "\x48\x8B\x68\x28"; // mov rbp, [rax+0x28]
#ifdef _WIN32
	c += "\x48\x8B\x70\x30"; // mov rsi, [rax+0x30]
	c += "\x48\x8B\x78\x38"; // mov rdi, [rax+0x38]
#endif
	c += "\x4C\x8B\x60\x40"; // mov r12, [rax+0x40]
	c += "\x4C\x8B\x68\x48"; // mov r13, [rax+0x48]
	c += "\x4C\x8B\x70\x50"; // mov r14, [rax+0x50]
	c += "\x4C\x8B\x78\x58"; // mov r15, [rax+0x58]

#ifdef _WIN32
	c += "\x66\x0F\x6F\x70\x60"; // movdqa xmm6, [rax+0x60]
	c += "\x66\x0F\x6F\x78\x70"; // movdqa xmm7, [rax+0x70]
	c += "\x66\x44\x0F\x6F\x80\x80\x00\x00\x00"s; // ...
	c += "\x66\x44\x0F\x6F\x88\x90\x00\x00\x00"s;
	c += "\x66\x44\x0F\x6F\x90\xA0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x6F\x98\xB0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x6F\xA0\xC0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x6F\xA8\xD0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x6F\xB0\xE0\x00\x00\x00"s;
	c += "\x66\x44\x0F\x6F\xB8\xF0\x00\x00\x00"s;
#endif

	c += "\x48\x8B\x50\x10"; // mov rdx, [rax+0x10]
	c += "\x48\x89\x54\x24\xF8"; // mov [rsp-8], rdx
	c += "\x48\x8B\x51"; // mov rdx, [rcx+r4]
	c += char(offset32(&ppu_thread::gpr, 4));
	c += "\x48\x85\xD2"; // test rdx, rdx
	c += "\x0F\x94\xC2"; // setz dl
	c += "\x48\x0F\xB6\xD2"; // movzx rdx, dl
	c += "\x48\x89\x51"; // mov [rcx+r3], rdx
	c += char(offset32(&ppu_thread::gpr, 3));
	c += "\xC3"; // ret
	return c;
}();

const auto ppu_use_context = []() -> std::string
{
	std::string c;
	c += "\x48\xB8"; // mov rax, imm64
	uptr ptr = (uptr)&vm::g_exec_addr;
	c.append((const char*)&ptr, 8);
	c += "\x48\x8B\x20"; // mov rsp, [rax]
#ifdef _WIN32
	c += "\x48\x01\xD4"; // add rsp,rdx
#else
	c += "\x48\x01\xFC"; // add rsp,rsi
#endif
	//c += "\x48\x83\xE4\xE0"; // and rsp, -0x20
#ifdef _WIN32
	c += "\x41\xFF\xD0"; // call r8
#else
	c += "\xFF\xD2"; // call rdx
#endif
	return c;
}();

extern void ppu_initialize()
{
	const auto _funcs = fxm::withdraw<std::vector<ppu_function>>();

	if (!_funcs)
	{
		return;
	}

	// Initialize main module
	ppu_initialize({"", std::move(*_funcs)});

	std::vector<lv2_prx*> prx_list;

	idm::select<lv2_obj, lv2_prx>([&](u32, lv2_prx& prx)
	{
		prx_list.emplace_back(&prx);
	});

	// Initialize preloaded libraries
	for (auto ptr : prx_list)
	{
		ppu_initialize(*ptr);
	}
}

extern void ppu_initialize(const ppu_module& info)
{
	if (g_cfg.core.ppu_decoder != ppu_decoder_type::llvm)
	{
		// Temporarily
		s_ppu_toc = fxm::get_always<std::unordered_map<u32, u32>>().get();

		for (const auto& func : info.funcs)
		{
			for (auto& block : func.blocks)
			{
				ppu_register_function_at(block.first, block.second, nullptr);
			}

			if (g_cfg.core.ppu_debug && func.size && func.toc != -1)
			{
				s_ppu_toc->emplace(func.addr, func.toc);
				ppu_ref(func.addr) = ::narrow<u32>(reinterpret_cast<std::uintptr_t>(&ppu_check_toc));
			}
		}

		return;
	}

#ifdef LLVM_AVAILABLE
	using namespace llvm;

	// Initialize JIT compiler
	if (!fxm::check<jit_compiler>())
	{
		std::unordered_map<std::string, u64> link_table
		{
			{ "__mptr", (u64)&vm::g_base_addr },
			{ "__cptr", (u64)&vm::g_exec_addr },
			{ "__trap", (u64)&ppu_trap },
			{ "__error", (u64)&ppu_error },
			{ "__check", (u64)&ppu_check },
			{ "__trace", (u64)&ppu_trace },
			{ "__syscall", (u64)&ppu_execute_syscall },
			{ "__get_tb", (u64)&get_timebased_time },
			{ "__lwarx", (u64)&ppu_lwarx },
			{ "__ldarx", (u64)&ppu_ldarx },
			{ "__stwcx", (u64)&ppu_stwcx },
			{ "__stdcx", (u64)&ppu_stdcx },
			{ "__vexptefp", (u64)&sse_exp2_ps },
			{ "__vlogefp", (u64)&sse_log2_ps },
			{ "__vperm", (u64)&sse_altivec_vperm },
			{ "__lvsl", (u64)&sse_altivec_lvsl },
			{ "__lvsr", (u64)&sse_altivec_lvsr },
			{ "__lvlx", (u64)&sse_cellbe_lvlx },
			{ "__lvrx", (u64)&sse_cellbe_lvrx },
			{ "__stvlx", (u64)&sse_cellbe_stvlx },
			{ "__stvrx", (u64)&sse_cellbe_stvrx },
		};

		for (u64 index = 0; index < 1024; index++)
		{
			if (auto sc = ppu_get_syscall(index))
			{
				link_table.emplace(ppu_get_syscall_name(index), (u64)sc);
			}
		}

		fxm::make<jit_compiler>(std::move(link_table), g_cfg.core.llvm_cpu);
	}
#endif

	// Split module into fragments <= 1 MiB
	std::size_t fpos = 0;

	ppu_module part;
	part.funcs.reserve(65536);

	while (fpos < info.funcs.size())
	{
		const auto fstart = fpos;

		std::size_t bsize = 0;

		part.funcs.clear();

		while (fpos < info.funcs.size())
		{
			auto& func = info.funcs[fpos];

			if (bsize + func.size > 1024 * 1024 && bsize)
			{
				break;
			}

			for (auto&& block : func.blocks)
			{
				bsize += block.second;

				// Also split functions blocks into functions (TODO)
				ppu_function entry;
				entry.addr = block.first;
				entry.size = block.second;
				entry.toc  = func.toc;
				fmt::append(entry.name, "__0x%x", block.first);
				part.funcs.emplace_back(std::move(entry));
			}

			fpos++;
		}

		part.name.clear();

		if (info.name.size())
		{
			part.name += '-';
			part.name += info.name;
		}

		if (fstart)
		{
			fmt::append(part.name, "+%06X", info.funcs.at(fstart).addr);
		}
		else if (fpos < info.funcs.size())
		{
			part.name.append("+0");
		}

		ppu_initialize2(part);
	}

#ifdef LLVM_AVAILABLE
	const auto jit = fxm::check_unlocked<jit_compiler>();

	jit->fin(Emu.GetCachePath());

	// Get and install function addresses
	for (const auto& func : info.funcs)
	{
		if (!func.size) continue;

		for (const auto& block : func.blocks)
		{
			if (block.second)
			{
				ppu_ref(block.first) = ::narrow<u32>(jit->get(fmt::format("__0x%x", block.first)));
			}
		}
	}
#endif
}

static void ppu_initialize2(const ppu_module& module_part)
{
	if (Emu.IsStopped())
	{
		return;
	}

	// Compute module hash
	std::string obj_name;
	{
		sha1_context ctx;
		u8 output[20];
		sha1_starts(&ctx);

		for (const auto& func : module_part.funcs)
		{
			if (func.size == 0)
			{
				continue;
			}

			const be_t<u32> addr = func.addr;
			const be_t<u32> size = func.size;
			sha1_update(&ctx, reinterpret_cast<const u8*>(&addr), sizeof(addr));
			sha1_update(&ctx, reinterpret_cast<const u8*>(&size), sizeof(size));

			for (const auto& block : func.blocks)
			{
				if (block.second == 0)
				{
					continue;
				}

				sha1_update(&ctx, vm::ps3::_ptr<const u8>(block.first), block.second);
			}

			sha1_update(&ctx, vm::ps3::_ptr<const u8>(func.addr), func.size);
		}
		
		sha1_finish(&ctx, output);

		// Version, module name and hash: vX-liblv2.sprx-0123456789ABCDEF.obj
		fmt::append(obj_name, "b1%s-%016X.obj", module_part.name, reinterpret_cast<be_t<u64>&>(output));
	}

#ifdef LLVM_AVAILABLE
	using namespace llvm;

	const auto jit = fxm::get<jit_compiler>();

	// Create LLVM module
	std::unique_ptr<Module> module = std::make_unique<Module>(obj_name, g_llvm_ctx);

	// Initialize target
	module->setTargetTriple(Triple::normalize(sys::getProcessTriple()));
	
	// Initialize translator
	std::unique_ptr<PPUTranslator> translator = std::make_unique<PPUTranslator>(g_llvm_ctx, module.get(), 0);

	// Define some types
	const auto _void = Type::getVoidTy(g_llvm_ctx);
	const auto _func = FunctionType::get(_void, {translator->GetContextType()->getPointerTo()}, false);

	// Initialize function list
	for (const auto& func : module_part.funcs)
	{
		if (func.size)
		{
			const auto f = cast<Function>(module->getOrInsertFunction(func.name, _func));
			f->addAttribute(1, Attribute::NoAlias);
		}
	}

	std::shared_ptr<MsgDialogBase> dlg;

	// Check cached file
	if (!fs::is_file(Emu.GetCachePath() + obj_name))
	{
		legacy::FunctionPassManager pm(module.get());

		// Basic optimizations
		pm.add(createCFGSimplificationPass());
		pm.add(createPromoteMemoryToRegisterPass());
		pm.add(createEarlyCSEPass());
		pm.add(createTailCallEliminationPass());
		pm.add(createReassociatePass());
		pm.add(createInstructionCombiningPass());
		//pm.add(createBasicAAWrapperPass());
		//pm.add(new MemoryDependenceAnalysis());
		pm.add(createLICMPass());
		pm.add(createLoopInstSimplifyPass());
		pm.add(createNewGVNPass());
		pm.add(createDeadStoreEliminationPass());
		pm.add(createSCCPPass());
		pm.add(createInstructionCombiningPass());
		pm.add(createInstructionSimplifierPass());
		pm.add(createAggressiveDCEPass());
		pm.add(createCFGSimplificationPass());
		//pm.add(createLintPass()); // Check

		// Initialize message dialog
		dlg = Emu.GetCallbacks().get_msg_dialog();
		dlg->type.se_normal = true;
		dlg->type.bg_invisible = true;
		dlg->type.progress_bar_count = 1;
		dlg->on_close = [](s32 status)
		{
			Emu.CallAfter([]()
			{
				// Abort everything
				Emu.Stop();
			});
		};

		Emu.CallAfter([=]()
		{
			dlg->Create("Compiling PPU module " + obj_name + "\nPlease wait...");
		});

		// Translate functions
		for (size_t fi = 0, fmax = module_part.funcs.size(); fi < fmax; fi++)
		{
			if (Emu.IsStopped())
			{
				LOG_SUCCESS(PPU, "LLVM: Translation cancelled");
				return;
			}

			if (module_part.funcs[fi].size && !test(module_part.funcs[fi].attr & ppu_attr::special))
			{
				// Update dialog		
				Emu.CallAfter([=, max = module_part.funcs.size()]()
				{
					dlg->ProgressBarSetMsg(0, fmt::format("Compiling %u of %u", fi + 1, fmax));

					if (fi * 100 / fmax != (fi + 1) * 100 / fmax)
						dlg->ProgressBarInc(0, 1);
				});

				// Translate
				const auto func = translator->Translate(module_part.funcs[fi]);

				// Run optimization passes
				pm.run(*func);

				const auto _syscall = module->getFunction("__syscall");

				for (auto i = inst_begin(*func), end = inst_end(*func); i != end;)
				{
					const auto inst = &*i++;

					if (const auto ci = dyn_cast<CallInst>(inst))
					{
						const auto cif = ci->getCalledFunction();
						const auto op1 = ci->getNumArgOperands() > 1 ? ci->getArgOperand(1) : nullptr;

						if (cif == _syscall && op1 && isa<ConstantInt>(op1))
						{
							// Try to determine syscall using the value from r11 (requires constant propagation)
							const u64 index = cast<ConstantInt>(op1)->getZExtValue();

							if (const auto ptr = ppu_get_syscall(index))
							{
								const auto n = ppu_get_syscall_name(index);
								const auto f = cast<Function>(module->getOrInsertFunction(n, _func));

								// Call the syscall directly
								ReplaceInstWithInst(ci, CallInst::Create(f, {ci->getArgOperand(0)}));
							}
						}

						continue;
					}

					if (const auto li = dyn_cast<LoadInst>(inst))
					{
						// TODO: more careful check
						if (li->getNumUses() == 0)
						{
							// Remove unreferenced volatile loads
							li->eraseFromParent();
						}

						continue;
					}

					if (const auto si = dyn_cast<StoreInst>(inst))
					{
						// TODO: more careful check
						if (isa<UndefValue>(si->getOperand(0)) && si->getParent() == &func->getEntryBlock())
						{
							// Remove undef volatile stores
							si->eraseFromParent();
						}

						continue;
					}
				}
			}
		}

		legacy::PassManager mpm;

		// Remove unused functions, structs, global variables, etc
		mpm.add(createStripDeadPrototypesPass());
		//mpm.add(createFunctionInliningPass());
		mpm.add(createDeadInstEliminationPass());
		mpm.run(*module);

		// Update dialog
		Emu.CallAfter([=]()
		{
			dlg->ProgressBarSetMsg(0, "Generating code, this may take a long time...");
			dlg->ProgressBarInc(0, 100);
		});

		std::string result;
		raw_string_ostream out(result);

		if (g_cfg.core.llvm_logs)
		{
			out << *module; // print IR
			fs::file(Emu.GetCachePath() + obj_name + ".log", fs::rewrite).write(out.str());
			result.clear();
		}

		if (verifyModule(*module, &out))
		{
			out.flush();
			LOG_ERROR(PPU, "LLVM: Verification failed for %s:\n%s", obj_name, result);
			return;
		}

		LOG_NOTICE(PPU, "LLVM: %zu functions generated", module->getFunctionList().size());
	}

	// Access JIT compiler
	if (const auto jit = fxm::check_unlocked<jit_compiler>())
	{
		// Load or compile module
		jit->add(std::move(module), Emu.GetCachePath());
	}
#endif
}
