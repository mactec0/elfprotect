cmake_minimum_required(VERSION "3.20")
project("VMBasic C CXX")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
if (NOT TARGET "Zydis")
    add_subdirectory("deps/zydis")
endif()

# GTest
if (NOT TARGET gtest)
    ADD_SUBDIRECTORY (deps/gtest-1.12.1)
    enable_testing()
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
endif()

set(CMAKE_CXX_FLAGS "-masm=intel -Wextra -Wall -Wno-missing-field-initializers -std=c++17")
set(CMAKE_C_FLAGS "-masm=intel -Wextra -Wall -Wno-missing-field-initializers -std=c17")


# Compiler
add_executable(compiler compiler_app.cc compiler.cc)
target_link_libraries("compiler" PRIVATE "Zydis")

# Disassembler
add_executable(disassembler disassembler_app.cc disassembler.cc)
target_link_libraries("disassembler" PRIVATE "Zydis")

# Unit Tests
add_executable(run_unit_tests vm_basic.c unit_tests/process_instruction_test.cc)
target_link_libraries(run_unit_tests gtest gtest_main)
add_test(run_unit_tests run_unit_tests)
