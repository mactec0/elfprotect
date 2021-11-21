cmake_minimum_required(VERSION "3.20")
project("examples C CXX")

set(CMAKE_CXX_FLAGS "-masm=intel -std=c++17")
set(CMAKE_C_FLAGS "-masm=intel -std=c17")
add_definitions(-DENABLE_PROTECTION)

# example 1
add_executable(example1 example1.c ../sdk.c)
add_dependencies(example1 elfprotect)
target_link_libraries(example1)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/example1_protected
    COMMAND ${CMAKE_BINARY_DIR}/elfprotect -i ${CMAKE_CURRENT_BINARY_DIR}/example1
    COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/example1_protected

    DEPENDS example1
    IMPLICIT_DEPENDS CXX ${CMAKE_SOURCE_DIR}/main.cc
    IMPLICIT_DEPENDS CXX ${CMAKE_SOURCE_DIR}/elf_file.cc
    IMPLICIT_DEPENDS CXX ${CMAKE_SOURCE_DIR}/libs/miniz.c
    IMPLICIT_DEPENDS CXX ${CMAKE_SOURCE_DIR}/basic_vm/compiler.cc
    IMPLICIT_DEPENDS CXX ${CMAKE_SOURCE_DIR}/basic_vm/disassembler.cc

    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
add_custom_target(example1_protected ALL
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/example1_protected
)
