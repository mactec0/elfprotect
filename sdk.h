#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


__attribute__((sysv_abi))
void destroy_code(int32_t len);


#define VIRTUALIZATION_MARKER_END 0xeef021ee
#define HIDDEN_CODE_END 0xe4c41970
#define BYTECODE_END 0xc0deedddc0deeddd

#ifdef ENABLE_PROTECTION

    #define JMP_OUT(id) \
        __asm volatile(".4byte 0x65646f63\n"); \
        __asm volatile(".4byte 0x6b72616d\n"); \
        __asm volatile(".4byte 0x" #id "\n"); \
        __asm volatile("jmp $-0xAAAA\n");

    #define PACKER_PROTECTION_START \
        JMP_OUT(dec00000) 

    #define PACKER_PROTECTION_END \
        __asm volatile(".4byte 0xe4c41970\n"); \
        destroy_code(16);

    #define ENCRYPTION_PROTECTION_START \
        JMP_OUT(dec41970) 

    #define ENCRYPTION_PROTECTION_END \
        __asm volatile(".4byte 0xe4c41970\n"); \
        destroy_code(16);

    #define VIRTUALIZATION_PROTECTION_START \
        JMP_OUT(def02145) 

    #define VIRTUALIZATION_PROTECTION_END \
        __asm volatile(".4byte 0xeef021ee\n")

    #define MAX_PROTECTION_START \
        JMP_OUT(def02777)

    #define MAX_PROTECTION_END \
        __asm volatile(".4byte 0xeef021ee\n")
#else
    #define PACKER_PROTECTION_START

    #define PACKER_PROTECTION_END

    #define ENCRYPTION_PROTECTION_START

    #define ENCRYPTION_PROTECTION_END

    #define VIRTUALIZATION_PROTECTION_START

    #define VIRTUALIZATION_PROTECTION_END

    #define MAX_PROTECTION_START

    #define MAX_PROTECTION_END
#endif
