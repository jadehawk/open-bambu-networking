#pragma once

// Compile-time load banner text (OBN_GIT_* come from CMake when git is available).

#ifdef OBN_GIT_COMMIT
#  ifdef OBN_GIT_DIRTY
#    define OBN_PLUGIN_LOAD_BANNER_MSG \
        "Loaded Open Bamboo Networking plugin, commit #" OBN_GIT_COMMIT " (dirty)"
#  else
#    define OBN_PLUGIN_LOAD_BANNER_MSG \
        "Loaded Open Bamboo Networking plugin, commit #" OBN_GIT_COMMIT
#  endif
#else
#  define OBN_PLUGIN_LOAD_BANNER_MSG "Loaded Open Bamboo Networking plugin"
#endif
