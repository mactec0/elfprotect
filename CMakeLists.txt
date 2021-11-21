cmake_minimum_required(VERSION "3.20")
project("ELFProtect C CXX")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "-g -masm=intel -Wextra -Wall -std=c++17 -Wno-missing-field-initializers")
set(CMAKE_C_FLAGS "-g -masm=intel -Wextra -Wall -std=c17 -Wno-missing-field-initializers")

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

# building other components
add_subdirectory("basic_vm")
add_subdirectory("payload")
add_subdirectory("dispatcher")

# Protector
set(PROTECTOR_SRC main.cc elf_file.cc elf.c payload/encryption.c virtualization_protection.cc packer_protection.cc libs/miniz.c basic_vm/compiler.cc basic_vm/disassembler.cc)
add_executable(elfprotect ${PROTECTOR_SRC})
add_dependencies(elfprotect payload unpack_dispatcher vm_entry_dispatcher)
target_link_libraries("elfprotect" PRIVATE "Zydis")


if (TARGET payload)
    add_custom_command(TARGET elfprotect
        POST_BUILD
        COMMAND cp payload/payload protector_payload
    )
endif()

add_subdirectory("examples")
