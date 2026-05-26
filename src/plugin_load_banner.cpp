// One-line stderr banner when libbambu_networking is mapped into the process.
//
// MUST stay loader-lock safe: no mutexes, no fopen/getenv, no calls into the
// obn logger (see STATUS.md / dshow_filter DllMain notes). File logging of
// the same line is deferred to log.cpp once Studio calls create_agent.

#include "obn/build_identity.hpp"

#include <cstdio>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace {

void emit_load_banner_stderr()
{
    std::fputs("[obn] ", stderr);
    std::fputs(OBN_PLUGIN_LOAD_BANNER_MSG, stderr);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}

} // namespace

#if defined(_WIN32)

extern "C" BOOL WINAPI DllMain(HINSTANCE /*hinst*/, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
        emit_load_banner_stderr();
    return TRUE;
}

#else

__attribute__((constructor))
static void obn_plugin_load_banner_ctor()
{
    emit_load_banner_stderr();
}

#endif
