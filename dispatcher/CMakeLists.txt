cmake_minimum_required(VERSION "3.20")
project("dispatcher ASM")
enable_language(ASM_NASM)


add_custom_target(unpack_dispatcher ALL
    COMMAND nasm unpack_dispatcher.asm -o ${CMAKE_CURRENT_BINARY_DIR}/unpack_dispatcher

    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building unpack dispatcher."
    VERBATIM
)

add_custom_target(vm_entry_dispatcher ALL
    COMMAND nasm vm_entry_dispatcher.asm -o ${CMAKE_CURRENT_BINARY_DIR}/vm_entry_dispatcher

    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building vm entry dispatcher."
    VERBATIM
)

add_custom_command(TARGET unpack_dispatcher
    POST_BUILD
    COMMAND echo -e "#pragma once\\n\\n" > ${CMAKE_CURRENT_SOURCE_DIR}/unpack_dispatcher.h
    COMMAND xxd -i unpack_dispatcher >> ${CMAKE_CURRENT_SOURCE_DIR}/unpack_dispatcher.h

    IMPLICIT_DEPENDS CXX ${CMAKE_CURRENT_SOURCE_DIR}/unpack_dispatcher.asm

    COMMENT "Creating header file with unpack dispatcher to include in protector"
    VERBATIM
)

add_custom_command(TARGET vm_entry_dispatcher
    POST_BUILD
    COMMAND echo -e "#pragma once\\n\\n" > ${CMAKE_CURRENT_SOURCE_DIR}/vm_entry_dispatcher.h
    COMMAND xxd -i vm_entry_dispatcher >> ${CMAKE_CURRENT_SOURCE_DIR}/vm_entry_dispatcher.h

    IMPLICIT_DEPENDS CXX ${CMAKE_CURRENT_SOURCE_DIR}/vm_entry_dispatcher.asm

    COMMENT "Creating header file with vm entry dispatcher to include in protector"
    VERBATIM
)
