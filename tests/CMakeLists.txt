# test_roundtrip exercises the public DLL ABI (hkdfguard.dll) for wrap/unwrap,
# and additionally compiles kek_store.cpp/wire_format.cpp directly so it can
# call the internal DeleteKek() helper to remove any KEKs it creates once the
# test finishes - those helpers are not part of the public C ABI.
#
# Compiling kek_store.cpp/wire_format.cpp a second time here (they're also
# compiled once already as part of the hkdfguard DLL target in the parent
# CMakeLists.txt) is intentional and harmless: each ends up in a separate
# binary (hkdfguard.dll vs. test_roundtrip.exe), so there's no linker
# conflict from the same function existing in both.
add_executable(test_roundtrip
    test_roundtrip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
)
# Links against hkdfguard (the DLL's import library, for the public ABI
# calls) plus the two raw Windows crypto libraries directly (needed because
# this executable now also compiles kek_store.cpp itself, which calls
# NCrypt*/BCrypt* functions of its own).
target_link_libraries(test_roundtrip PRIVATE hkdfguard ncrypt.lib bcrypt.lib)
target_include_directories(test_roundtrip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

# Registers test_roundtrip.exe as a CTest test named "roundtrip" - what
# `ctest` (see README.md) actually runs.
add_test(NAME roundtrip COMMAND test_roundtrip)
# Windows only searches a fixed set of locations for a DLL an .exe depends
# on, and the directory containing hkdfguard.dll (the build output directory
# for that target) isn't necessarily one of them when ctest launches
# test_roundtrip.exe directly. This prepends that directory onto PATH for
# just this one test's process, so the OS loader can find hkdfguard.dll at
# startup. $<TARGET_FILE_DIR:hkdfguard> is a CMake "generator expression" -
# evaluated at build-configuration time to the real output path, whatever it
# ends up being for the chosen build type/generator.
set_tests_properties(roundtrip PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>;$ENV{PATH}"
)

# test_direct_aead exercises the public DLL ABI's four newer functions
# (hkdfguard_encrypt/hkdfguard_decrypt and the two "_with_wrapped_dek"
# variants) - same structure and rationale as test_roundtrip above,
# including compiling kek_store.cpp/wire_format.cpp a second time so it can
# call the internal DeleteKek() cleanup helper.
add_executable(test_direct_aead
    test_direct_aead.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
)
target_link_libraries(test_direct_aead PRIVATE hkdfguard ncrypt.lib bcrypt.lib)
target_include_directories(test_direct_aead PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

add_test(NAME direct_aead COMMAND test_direct_aead)
set_tests_properties(direct_aead PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>;$ENV{PATH}"
)
