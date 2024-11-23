#pragma once

#include <Zydis/Zydis.h>
#include <bitset>
#include <cstdint>
#include <functional>
#include <vector>
#include <x86Tester/shared.hpp>

namespace x86Tester::Generator
{
    using ProgressReportFn = std::function<void(size_t, size_t)>;

    struct Filter
    {
        std::bitset<ZYDIS_MNEMONIC_MAX_VALUE + 1> mnemonics{};

        template<typename... TMnemonics> Filter addMnemonics(TMnemonics... mnemonic)
        {
            auto res = *this;
            (res.mnemonics.set(static_cast<size_t>(mnemonic)), ...);
            return res;
        }
    };

    InstructionEntries buildInstructions(
        ZydisMachineMode mode, const Filter& filter, bool buildInParallel, ProgressReportFn reporter = {});

} // namespace x86Tester::Generator