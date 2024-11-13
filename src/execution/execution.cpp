#include "x86tester/execution.hpp"

#include <Zydis/Disassembler.h>
#include <Zydis/Encoder.h>
#include <array>
#include <filesystem>
#include <intrin.h>
#include <print>
#include <span>
#include <unordered_map>

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#    define NOMINMAX
#endif
#include <Windows.h>

namespace x86Tester::Execution
{
    struct Context
    {
        STARTUPINFOW startupInfo{};
        PROCESS_INFORMATION processInfo{};
        HANDLE hThread{};
        std::uintptr_t codeBase{};
        std::uintptr_t codeAddr{};
        std::size_t codeSize{};
        std::uintptr_t breakAddr{};
        CONTEXT threadContext{};
        DEBUG_EVENT dbgEvent{};
        ExecutionStatus status{};
    };

    static std::filesystem::path getExecutingPath()
    {
        wchar_t path[2048]{};
        GetModuleFileNameW(nullptr, path, std::size(path));

        auto* lastSlash = std::wcsrchr(path, L'\\');
        if (!lastSlash)
        {
            return path;
        }

        *lastSlash = L'\0';
        return path;
    }

    enum class DebugStatus
    {
        Continue,
        SystemBreak,
        Exit,
        Faulted,
    };

    static void dumpDisassembly(Context* ctx, std::uintptr_t activeAddress)
    {
        // Decode the entire code region.
        for (size_t n = 0; n < ctx->codeSize;)
        {
            const std::uintptr_t addr = ctx->codeBase + n;

            std::uint8_t buffer[16]{};
            SIZE_T read;
            ReadProcessMemory(ctx->processInfo.hProcess, reinterpret_cast<void*>(addr), buffer, sizeof(buffer), &read);

            ZydisDisassembledInstruction instr;
            ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, addr, buffer, read, &instr);

            std::print("{}{:016X} ", addr == activeAddress ? ">" : " ", addr);

            n += instr.info.length;
        }
    }

    static DebugStatus handleException(Context* ctx, const EXCEPTION_RECORD& record)
    {
        const auto exceptionAddress = reinterpret_cast<uintptr_t>(record.ExceptionAddress);

        if (record.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            if (exceptionAddress == ctx->breakAddr)
            {
                // std::print("Successfully executed instruction\n");
                ctx->status = ExecutionStatus::Success;
                return DebugStatus::Exit;
            }
            else if (exceptionAddress == ctx->codeBase)
            {
                // Entry breakpoint.
                return DebugStatus::Exit;
            }
            if (ctx->breakAddr == 0)
            {
                // std::print("System breakpoint\n");
                return DebugStatus::SystemBreak;
            }
        }
        else if (record.ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
        {
            ctx->status = ExecutionStatus::ExceptionIntDivideError;
            return DebugStatus::Faulted;
        }
        else if (record.ExceptionCode == EXCEPTION_INT_OVERFLOW)
        {
            ctx->status = ExecutionStatus::ExceptionIntOverflow;
            return DebugStatus::Faulted;
        }

        std::print("Exception code: {:X}\n", record.ExceptionCode);
        std::print("Exception flags: {:X}\n", record.ExceptionFlags);
        std::print("Exception address: {:X}\n", exceptionAddress);
        std::print("Number of parameters: {}\n", record.NumberParameters);
        for (DWORD i = 0; i < record.NumberParameters; ++i)
        {
            std::print("Parameter {}: {}\n", i, record.ExceptionInformation[i]);
        }

        if (ctx->codeBase >= exceptionAddress && exceptionAddress < ctx->codeBase + ctx->codeSize)
        {
            dumpDisassembly(ctx, exceptionAddress);
        }

        return DebugStatus::Faulted;
    }

    static DebugStatus handleDbgEvent(Context* ctx, const DEBUG_EVENT& dbgEvent)
    {
        switch (dbgEvent.dwDebugEventCode)
        {
            case EXCEPTION_DEBUG_EVENT:
                return handleException(ctx, dbgEvent.u.Exception.ExceptionRecord);
            case CREATE_PROCESS_DEBUG_EVENT:
                CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
                break;
            case LOAD_DLL_DEBUG_EVENT:
                CloseHandle(dbgEvent.u.LoadDll.hFile);
                break;
            default:
                break;
        }

        return DebugStatus::Continue;
    }

    static bool spawnProcess(Context* ctx)
    {
        ctx->startupInfo.cb = sizeof(ctx->startupInfo);
        ctx->startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        ctx->startupInfo.wShowWindow = SW_HIDE;

        const auto path = getExecutingPath();
        const auto cmd = path / "x86Tester-sandbox.exe";
        auto cmdWstr = cmd.wstring();

        if (!CreateProcessW(
                nullptr, cmdWstr.data(), nullptr, nullptr, FALSE, DEBUG_PROCESS, nullptr, nullptr, &ctx->startupInfo,
                &ctx->processInfo))
        {
            return false;
        }

        // Consume all debug events until the first breakpoint.
        auto& dbgEvent = ctx->dbgEvent;
        while (WaitForDebugEvent(&dbgEvent, INFINITE))
        {
            auto status = handleDbgEvent(ctx, dbgEvent);
            if (status == DebugStatus::Continue)
            {
                // Ignore.
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            }
            else if (status == DebugStatus::SystemBreak)
            {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                break;
            }
            else
            {
                std::print("Unexpected event\n");
                break;
            }
        }

        return true;
    }

    static std::vector<ZydisRegister> getUsedGPRegister(const ZydisDisassembledInstruction& instr)
    {
        std::vector<ZydisRegister> regs;

        for (size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                auto regId = ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, op.reg.value);
                auto regCls = ZydisRegisterGetClass(regId);

                if (regCls == ZYDIS_REGCLASS_GPR32 || regCls == ZYDIS_REGCLASS_GPR64)
                {
                    regs.push_back(regId);
                }
            }
        }

        return regs;
    }

    static std::byte* allocRemoteCode(Context* ctx, std::size_t size)
    {
        // Try to allocate at a predictable address, the child process has base of 0x70000000.

        auto* remoteCodeAddr = static_cast<std::byte*>(VirtualAllocEx(
            ctx->processInfo.hProcess, reinterpret_cast<void*>(0x04000000), size, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));
        if (remoteCodeAddr != nullptr)
        {
            return remoteCodeAddr;
        }

        remoteCodeAddr = static_cast<std::byte*>(VirtualAllocEx(
            ctx->processInfo.hProcess, reinterpret_cast<void*>(0x05000000), size, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));
        if (remoteCodeAddr != nullptr)
        {
            return remoteCodeAddr;
        }

        return static_cast<std::byte*>(
            VirtualAllocEx(ctx->processInfo.hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    }

    static bool setupCode(Context* ctx, std::span<const std::uint8_t> code)
    {
        auto* remoteCodeAddr = allocRemoteCode(ctx, code.size());
        if (remoteCodeAddr == nullptr)
        {
            return false;
        }

        const uint8_t breakpoint[] = { 0xCC };
        SIZE_T written;

        auto* cur = remoteCodeAddr;

        // Write breakpoint before the code.
        if (!WriteProcessMemory(ctx->processInfo.hProcess, cur, breakpoint, sizeof(breakpoint), &written))
        {
            return false;
        }
        cur += 1;

        // Write code to test.
        const auto codeAddr = reinterpret_cast<std::uintptr_t>(cur);
        if (!WriteProcessMemory(ctx->processInfo.hProcess, cur, code.data(), code.size(), &written))
        {
            return false;
        }
        cur += code.size();

        // Write breakpoint after the code.
        const auto breakAddr = reinterpret_cast<std::uintptr_t>(cur);
        if (!WriteProcessMemory(ctx->processInfo.hProcess, cur, breakpoint, sizeof(breakpoint), &written))
        {
            return false;
        }
        cur += 1;

        ctx->codeBase = reinterpret_cast<std::uintptr_t>(remoteCodeAddr);
        ctx->codeAddr = codeAddr;
        ctx->breakAddr = breakAddr;
        ctx->codeSize = cur - remoteCodeAddr;

        return true;
    }

    static bool setupThread(Context* ctx)
    {
        // Spawn thread.
        auto hThread = CreateRemoteThread(
            ctx->processInfo.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ctx->codeBase), nullptr, 0,
            nullptr);

        if (hThread == nullptr)
        {
            return false;
        }

        ctx->hThread = hThread;

        // Wait for the entry breakpoint.
        auto& dbgEvent = ctx->dbgEvent;
        while (WaitForDebugEvent(&dbgEvent, INFINITE))
        {
            auto status = handleDbgEvent(ctx, dbgEvent);
            if (status == DebugStatus::Exit)
            {
                break;
            }
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }

        return true;
    }

    static bool setupThreadContext(Context* ctx)
    {
        ctx->threadContext.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(ctx->hThread, &ctx->threadContext))
        {
            return false;
        }

        // Clear all registers.
        ctx->threadContext.Rax = 0;
        ctx->threadContext.Rcx = 0;
        ctx->threadContext.Rdx = 0;
        ctx->threadContext.Rbx = 0;
        ctx->threadContext.Rsp = 0;
        ctx->threadContext.Rbp = 0;
        ctx->threadContext.Rsi = 0;
        ctx->threadContext.Rdi = 0;
        ctx->threadContext.R8 = 0;
        ctx->threadContext.R9 = 0;
        ctx->threadContext.R10 = 0;
        ctx->threadContext.R11 = 0;
        ctx->threadContext.R12 = 0;
        ctx->threadContext.R13 = 0;
        ctx->threadContext.R14 = 0;
        ctx->threadContext.R15 = 0;
        ctx->threadContext.Rip = ctx->codeBase + 1;

        return true;
    }

    Context* prepare(ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        auto ctx = new Context{};

        if (!spawnProcess(ctx))
        {
            delete ctx;
            return nullptr;
        }

        if (!setupCode(ctx, code))
        {
            delete ctx;
            return nullptr;
        }

        if (!setupThread(ctx))
        {
            delete ctx;
            return nullptr;
        }

        if (!setupThreadContext(ctx))
        {
            delete ctx;
            return nullptr;
        }

        return ctx;
    }

    bool setRegBytes(Context* ctx, ZydisRegister reg, std::span<const std::uint8_t> data)
    {
        auto setRegValue = [&](auto& dst) -> bool {
            if (data.size() > sizeof(dst))
            {
                assert(false);
                return false;
            }
            std::memcpy(&dst, data.data(), data.size());
            return true;
        };

        switch (reg)
        {
            case ZYDIS_REGISTER_RAX:
                return setRegValue(ctx->threadContext.Rax);
            case ZYDIS_REGISTER_RCX:
                return setRegValue(ctx->threadContext.Rcx);
            case ZYDIS_REGISTER_RDX:
                return setRegValue(ctx->threadContext.Rdx);
            case ZYDIS_REGISTER_RBX:
                return setRegValue(ctx->threadContext.Rbx);
            case ZYDIS_REGISTER_RSP:
                return setRegValue(ctx->threadContext.Rsp);
            case ZYDIS_REGISTER_RBP:
                return setRegValue(ctx->threadContext.Rbp);
            case ZYDIS_REGISTER_RSI:
                return setRegValue(ctx->threadContext.Rsi);
            case ZYDIS_REGISTER_RDI:
                return setRegValue(ctx->threadContext.Rdi);
            case ZYDIS_REGISTER_R8:
                return setRegValue(ctx->threadContext.R8);
            case ZYDIS_REGISTER_R9:
                return setRegValue(ctx->threadContext.R9);
            case ZYDIS_REGISTER_R10:
                return setRegValue(ctx->threadContext.R10);
            case ZYDIS_REGISTER_R11:
                return setRegValue(ctx->threadContext.R11);
            case ZYDIS_REGISTER_R12:
                return setRegValue(ctx->threadContext.R12);
            case ZYDIS_REGISTER_R13:
                return setRegValue(ctx->threadContext.R13);
            case ZYDIS_REGISTER_R14:
                return setRegValue(ctx->threadContext.R14);
            case ZYDIS_REGISTER_R15:
                return setRegValue(ctx->threadContext.R15);
            case ZYDIS_REGISTER_RIP:
                return setRegValue(ctx->threadContext.Rip);
            case ZYDIS_REGISTER_RFLAGS:
                return setRegValue(ctx->threadContext.EFlags);
        }

        assert(false);
        return false;
    }

    std::span<const uint8_t> getRegBytes(Context* ctx, ZydisRegister reg)
    {
        auto getRegValue = [&](auto& src) -> std::span<const std::uint8_t> {
            return std::span(reinterpret_cast<const std::uint8_t*>(&src), sizeof(src));
        };

        switch (reg)
        {
            case ZYDIS_REGISTER_RAX:
                return getRegValue(ctx->threadContext.Rax);
            case ZYDIS_REGISTER_RCX:
                return getRegValue(ctx->threadContext.Rcx);
            case ZYDIS_REGISTER_RDX:
                return getRegValue(ctx->threadContext.Rdx);
            case ZYDIS_REGISTER_RBX:
                return getRegValue(ctx->threadContext.Rbx);
            case ZYDIS_REGISTER_RSP:
                return getRegValue(ctx->threadContext.Rsp);
            case ZYDIS_REGISTER_RBP:
                return getRegValue(ctx->threadContext.Rbp);
            case ZYDIS_REGISTER_RSI:
                return getRegValue(ctx->threadContext.Rsi);
            case ZYDIS_REGISTER_RDI:
                return getRegValue(ctx->threadContext.Rdi);
            case ZYDIS_REGISTER_R8:
                return getRegValue(ctx->threadContext.R8);
            case ZYDIS_REGISTER_R9:
                return getRegValue(ctx->threadContext.R9);
            case ZYDIS_REGISTER_R10:
                return getRegValue(ctx->threadContext.R10);
            case ZYDIS_REGISTER_R11:
                return getRegValue(ctx->threadContext.R11);
            case ZYDIS_REGISTER_R12:
                return getRegValue(ctx->threadContext.R12);
            case ZYDIS_REGISTER_R13:
                return getRegValue(ctx->threadContext.R13);
            case ZYDIS_REGISTER_R14:
                return getRegValue(ctx->threadContext.R14);
            case ZYDIS_REGISTER_R15:
                return getRegValue(ctx->threadContext.R15);
            case ZYDIS_REGISTER_RIP:
                return getRegValue(ctx->threadContext.Rip);
            case ZYDIS_REGISTER_RFLAGS:
                return getRegValue(ctx->threadContext.EFlags);
        }

        assert(false);
        return {};
    }

    bool execute(Context* ctx)
    {
        ctx->threadContext.ContextFlags = CONTEXT_ALL;
        ctx->threadContext.Rip = ctx->codeBase + 1;

        if (SetThreadContext(ctx->hThread, &ctx->threadContext) == FALSE)
        {
            std::print("SetThreadContext failed: {:X}\n", GetLastError());
            return false;
        }

        auto& dbgEvent = ctx->dbgEvent;
        if (!ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE))
        {
            std::print("ContinueDebugEvent failed: {:X}\n", GetLastError());
            return false;
        }

        // Wait for the breakpoint to appear or an exception to occur.
        while (WaitForDebugEvent(&dbgEvent, INFINITE))
        {
            bool breakOut = false;

            auto status = handleDbgEvent(ctx, dbgEvent);
            if (status == DebugStatus::Faulted)
            {
                break;
            }
            else if (status == DebugStatus::Exit)
            {
                break;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            if (breakOut)
                break;
        }

        ctx->threadContext.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(ctx->hThread, &ctx->threadContext))
        {
            return false;
        }

        return true;
    }

    void cleanup(Context* ctx)
    {
        // Signal Termination
        TerminateProcess(ctx->processInfo.hProcess, 0);

        // Continue last event.
        ContinueDebugEvent(ctx->dbgEvent.dwProcessId, ctx->dbgEvent.dwThreadId, DBG_CONTINUE);

        // Poll debug events so the process can exit.
        for (;;)
        {
            DEBUG_EVENT dbgEvent{};
            if (!WaitForDebugEvent(&dbgEvent, INFINITE))
                break;

            if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                break;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }

        CloseHandle(ctx->processInfo.hProcess);
        CloseHandle(ctx->processInfo.hThread);
        CloseHandle(ctx->hThread);

        delete ctx;
    }

    std::uint64_t getBaseAddress(Context* ctx)
    {
        return ctx->codeBase;
    }

    std::uint64_t getCodeAddress(Context* ctx)
    {
        return ctx->codeAddr;
    }

    ExecutionStatus getExecutionStatus(Context* ctx)
    {
        return ctx->status;
    }

} // namespace x86Tester::Execution