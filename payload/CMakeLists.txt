cmake_minimum_required(VERSION "3.20")
project("Payload C")

set(CMAKE_C_FLAGS "-masm=intel -Wextra -Wall -fPIE -fno-builtin -fno-stack-protector -std=c17 -nostdlib")


add_definitions(-DMINIZ_NO_STDIO -DMINIZ_NO_TIME -DINJECTABLE -DENABLE_PROTECTION) 
add_executable(payload payload.c payload_imports.c syscall_helpers.c utils.c encryption.c ../libs/miniz.c ../basic_vm/vm_basic.c ../sdk.c)
target_link_libraries(payload)
