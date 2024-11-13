#include <chrono>
#include <print>
#include <x86Tester/logging.hpp>

namespace x86Tester::Logging
{
    using clock = std::chrono::high_resolution_clock;

    static int _lastProgress = -1;
    static bool _inProgress = false;
    static std::string _progressName;
    static auto _nextReport = clock::now();
    static double _progress = 0.0;
    static size_t _progressLineLen = 0;

    static void printProgress(const char* name, double percentage, bool forcePrint)
    {
        using namespace std::chrono_literals;

        constexpr const char* PBSTR = "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";
        constexpr int PBWIDTH = 40;

        int val = static_cast<int>(percentage * 100);
        if (val == _lastProgress && !forcePrint)
            return;

        auto now = clock::now();
        if (percentage != 1.0 && now < _nextReport && !forcePrint)
            return;

        _nextReport = now + 50ms;

        int lpad = static_cast<int>(percentage * PBWIDTH);
        int rpad = PBWIDTH - lpad;
        _lastProgress = val;

        int namepad = 20 - static_cast<int>(std::strlen(name));

        auto line = std::format("\r{:25} {:3d}% [{:40}]", name, val, std::string_view(PBSTR, lpad));
        std::print("{}", line);
        std::fflush(stdout);

        _progressLineLen = line.size();
    }

    void printProgress(const char* name, size_t val, size_t max)
    {
        return printProgress(name, static_cast<double>(val) / max, false);
    }

    void startProgress(const char* name)
    {
        _progressName = name;
        _inProgress = true;
        _lastProgress = -1;
        _progress = 0.0;
        printProgress(_progressName.c_str(), _progress, true);
    }

    void updateProgress(size_t val, size_t max)
    {
        _progress = static_cast<double>(val) / max;
        printProgress(_progressName.c_str(), _progress, false);
    }

    void endProgress()
    {
        _inProgress = false;
        std::println();
    }

    namespace Detail
    {
        void println(const std::string_view msg)
        {
            if (_inProgress)
            {
                size_t spaces = msg.size() < _progressLineLen ? _progressLineLen - msg.size() : 0;
                std::println("\r{}{}", msg, std::string(spaces, ' '));
                printProgress(_progressName.c_str(), _progress, true);
            }
            else
                std::println("{}", msg);
        }
    } // namespace Detail

} // namespace x86Tester::Logging