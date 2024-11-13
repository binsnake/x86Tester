#include <intrin.h>

#ifdef _DEBUG
extern "C" void __cdecl _RTC_InitBase(void)
{
}

extern "C" void __cdecl _RTC_Shutdown(void)
{
}
#endif

extern "C" int rawEntry()
{
    while (true)
        _mm_pause();
    return 0;
}