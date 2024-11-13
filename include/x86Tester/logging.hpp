#pragma once

#include <print>

namespace x86Tester::Logging
{
    void startProgress(const char* name);
    void updateProgress(size_t val, size_t max);
    void endProgress();

    namespace Detail
    {
        void println(const std::string_view msg);
    }

    template<typename... TArgs> void println(const std::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = std::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::println(msg);
    }

} // namespace x86Tester::Logging