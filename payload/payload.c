#include "../libs/miniz.h"
#include "../elf.h"
#include <dlfcn.h>
#include <inttypes.h>

#include "../basic_vm/vm_basic.h"
#include "../sdk.h"
#include "payload_imports.h"
#include "syscall_helpers.h"
#include "encryption.h"
#include "utils.h"

#define BACKUP_REGISTERS()            \
	__asm volatile("push rax\n"); \
	__asm volatile("push rbx\n"); \
	__asm volatile("push rcx\n"); \
	__asm volatile("push rdx\n"); \
	__asm volatile("push rsi\n"); \
	__asm volatile("push rdi\n"); \
	__asm volatile("push rbp\n"); \
	__asm volatile("push r8\n");  \
	__asm volatile("push r9\n");  \
	__asm volatile("push r10\n"); \
	__asm volatile("push r11\n"); \
	__asm volatile("push r12\n"); \
	__asm volatile("push r13\n"); \
	__asm volatile("push r14\n"); \
	__asm volatile("push r15\n");

#define RESTORE_REGISTERS()          \
	__asm volatile("pop r15\n"); \
	__asm volatile("pop r14\n"); \
	__asm volatile("pop r13\n"); \
	__asm volatile("pop r12\n"); \
	__asm volatile("pop r11\n"); \
	__asm volatile("pop r10\n"); \
	__asm volatile("pop r9\n");  \
	__asm volatile("pop r8\n");  \
	__asm volatile("pop rbp\n"); \
	__asm volatile("pop rdi\n"); \
	__asm volatile("pop rsi\n"); \
	__asm volatile("pop rdx\n"); \
	__asm volatile("pop rcx\n"); \
	__asm volatile("pop rbx\n"); \
	__asm volatile("pop rax\n");


__attribute__((sysv_abi)) int
unpack_decrypt_code(uint8_t *pDest,
    mz_ulong *pDest_len,
    uint8_t *pSource,
    mz_ulong source_len)
{
	mz_ulong packed_len = source_len;
	decrypt(pSource, *pDest_len, packed_len);
	int ret = mz_uncompress2(pDest, pDest_len, pSource, &source_len);
	encrypt(pSource, *pDest_len, packed_len);
	return ret;
}

__attribute__((sysv_abi)) int
unpack_code(uint8_t *pDest, mz_ulong *pDest_len,
    uint8_t *pSource,
    mz_ulong source_len)
{
	int ret = mz_uncompress2(pDest, pDest_len, pSource, &source_len);
	return ret;
}

__attribute__((sysv_abi)) void
vm_entry(struct vm_ctx *ctx)
{
	PACKER_PROTECTION_START;
	process_bytecode(ctx);
	PACKER_PROTECTION_END;
}

__attribute__((sysv_abi)) void
vm_entry_encrypted(struct vm_ctx *ctx)
{
	PACKER_PROTECTION_START;
	int ret;
	uint64_t packed_size;
	uint64_t unpacked_size;
	uint8_t *unpacked_bytecode;
	uint8_t *bytecode_ptr = (uint8_t *)(ctx->registers.rip);

	while (*(uint64_t *)(bytecode_ptr) != BYTECODE_END)
		bytecode_ptr++;

	packed_size = (uint64_t)(bytecode_ptr - 8) - ctx->registers.rip;
	unpacked_size = *(uint64_t *)(bytecode_ptr - 8);

	unpacked_bytecode = omalloc(unpacked_size);
	if (!unpacked_bytecode) {
		printf("ERROR: Failed to allocate memory for unpacked code\n");
		return;
	}

	ret = unpack_decrypt_code(unpacked_bytecode, (mz_ulong *)&unpacked_size,
	    (uint8_t *)(ctx->registers.rip),
	    (mz_ulong)packed_size);
	if (ret < 0) {
		printf("ERROR: Failed to unpack code\n");
		return;
	}

	// set instruction pointer to the unpacked bytecode
	ctx->registers.rip = (uint64_t)unpacked_bytecode;

	process_bytecode(ctx);

	memset((void *)unpacked_bytecode, 0, unpacked_size);
	ofree(unpacked_bytecode);
	PACKER_PROTECTION_END;
}

void
payload_init()
{
	if (init_imports() < 0) {
		sys_write("ERROR: Failed to initialize imports\n");
		return;
	}
}

#ifdef INJECTABLE
__attribute__((naked)) void
_start()
{
	BACKUP_REGISTERS();
	__asm volatile("call payload_init\n");
	RESTORE_REGISTERS();
	__asm volatile(".4byte 0xdeadbeef\n");
	__asm volatile("jmp $-0xAAAA\n"); // return to oep
}
#else
void
main(void)
{
	payload_init();
	return;
}
#endif
