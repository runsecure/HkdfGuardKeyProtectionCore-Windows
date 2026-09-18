# Minimum CMake version this project's syntax requires.
cmake_minimum_required(VERSION 3.20)
# Declares the project name and that it's a C++ project (as opposed to C,
# which CMake also supports enabling separately).
project(HkdfGuardWin CXX)

# This library depends on Windows-only APIs (CNG/NCrypt), so fail loudly and
# immediately rather than producing confusing compiler errors later if
# someone tries to configure it on Linux/macOS.
if(NOT WIN32)
    message(FATAL_ERROR "HkdfGuardWin is Windows-only (requires CNG/NCrypt).")
endif()

# Require C++17 (the language standard used throughout src/, e.g. inline
# variables, structured bindings availability, etc.) and refuse to silently
# fall back to an older standard if the compiler doesn't support it.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Only the two functions explicitly marked HKDFGUARD_API (dllexport) in
# hkdfguard.h should be exported from the DLL - this turns off CMake's
# option to auto-export every symbol, which would defeat the point of
# hand-picking a minimal, stable ABI surface.
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

# Declares the "hkdfguard" build target: a SHARED library (a .dll on
# Windows, plus a companion .lib "import library" other code links against
# to call into it), built from exactly these five .cpp files. Each .cpp's
# own #include of its matching .h pulls the rest of the source tree in as
# needed - CMake itself doesn't need to know about the .h files here.
add_library(hkdfguard SHARED
    src/hkdfguard.cpp
    src/wire_format.cpp
    src/kek_store.cpp
    src/ecdh_hkdf.cpp
    src/aes_gcm.cpp
)

# PRIVATE compile definitions apply only while compiling hkdfguard's own
# .cpp files, not to anything that later links against it. HKDFGUARD_EXPORTS
# is exactly the macro hkdfguard.h checks to choose dllexport over
# dllimport (see that file's comment) - this is the one and only place it
# gets defined. UNICODE/_UNICODE steer the small number of Windows headers
# that have separate ANSI/wide-character APIs toward their wide (UTF-16)
# versions, matching the std::wstring-based key names used in kek_store.cpp.
target_compile_definitions(hkdfguard PRIVATE HKDFGUARD_EXPORTS UNICODE _UNICODE)
# PUBLIC include dirs are inherited by anything that links against this
# target (like the test_roundtrip executable in tests/) - here, that's
# include/, so consumers can #include "hkdfguard.h". PRIVATE include dirs
# (src/) are only visible while building hkdfguard.dll's own sources, kept
# private since e.g. wire_format.h's byte-offset constants are internal
# implementation detail, not part of the public ABI contract.
target_include_directories(hkdfguard
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
# The two Windows system libraries providing every NCrypt*/BCrypt* function
# called throughout src/.
target_link_libraries(hkdfguard PRIVATE ncrypt.lib bcrypt.lib)

# MSVC-specific hardening flags, applied only when compiling with MSVC (as
# opposed to some other compiler CMake might be configured to use).
if(MSVC)
    # /W4: enable a high warning level (catches many real bugs, like
    # accidentally comparing signed and unsigned values). /guard:cf and
    # /GUARD:CF (compile-time and link-time halves of the same feature):
    # enable Control Flow Guard, a Windows exploit-mitigation feature that
    # restricts indirect function calls to a validated set of targets. /GS:
    # enables stack-buffer-overrun detection ("stack cookies").
    target_compile_options(hkdfguard PRIVATE /W4 /guard:cf /GS)
    target_link_options(hkdfguard PRIVATE /GUARD:CF)
endif()

# Turns on CTest support (the `ctest` command used in README.md) and pulls
# in tests/CMakeLists.txt, which declares the test_roundtrip executable and
# registers it as a test.
enable_testing()
add_subdirectory(tests)
