#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../payload/payload_imports.h"
#include "../sdk.h"
#include "vm_basic.h"

static inline void
set_rflags(uint64_t rflags)
{
	__asm volatile("push rax\n");
	__asm volatile("mov rax, %0\n" ::"m"(rflags));
	__asm volatile("push rax\n");
	__asm volatile("popfq\n");
	__asm volatile("pop rax\n");
}

static inline uint64_t
get_rflags()
{
	__asm volatile("pushfq\n");
	__asm volatile("pop rax\n");
	register uint64_t rax __asm("rax");
	return rax;
}

static uintptr_t
get_reg_ptr(uint16_t reg, struct vm_ctx* ctx)
{
	uintptr_t reg_addr[REGISTER_MAX] = {
	    /* 8-bit */
	    [AL] = (uintptr_t)&ctx->registers.rax.eax.ax.al,
	    [AH] = (uintptr_t)&ctx->registers.rax.eax.ax.ah,
	    [CL] = (uintptr_t)&ctx->registers.rcx.ecx.cx.cl,
	    [CH] = (uintptr_t)&ctx->registers.rcx.ecx.cx.ch,
	    [DL] = (uintptr_t)&ctx->registers.rdx.edx.dx.dl,
	    [DH] = (uintptr_t)&ctx->registers.rdx.edx.dx.dh,
	    [BL] = (uintptr_t)&ctx->registers.rbx.ebx.bx.bl,
	    [BH] = (uintptr_t)&ctx->registers.rbx.ebx.bx.bh,
	    [SPL] = (uintptr_t)&ctx->registers.rsp.esp.sp.spl,
	    [BPL] = (uintptr_t)&ctx->registers.rbp.ebp.bp.bpl,
	    [SIL] = (uintptr_t)&ctx->registers.rsi.esi.si.sl,
	    [DIL] = (uintptr_t)&ctx->registers.rdi.edi.di.dl,
	    [R8B] = (uintptr_t)&ctx->registers.r8.r8d.r8w.r8b,
	    [R9B] = (uintptr_t)&ctx->registers.r9.r9d.r9w.r9b,
	    [R10B] = (uintptr_t)&ctx->registers.r10.r10d.r10w.r10b,
	    [R11B] = (uintptr_t)&ctx->registers.r11.r11d.r11w.r11b,
	    [R12B] = (uintptr_t)&ctx->registers.r12.r12d.r12w.r12b,
	    [R13B] = (uintptr_t)&ctx->registers.r13.r13d.r13w.r13b,
	    [R14B] = (uintptr_t)&ctx->registers.r14.r14d.r14w.r14b,
	    [R15B] = (uintptr_t)&ctx->registers.r15.r15d.r15w.r15b,

	    /* 16-bit */
	    [AX] = (uintptr_t)&ctx->registers.rax.eax.ax.value,
	    [CX] = (uintptr_t)&ctx->registers.rcx.ecx.cx.value,
	    [DX] = (uintptr_t)&ctx->registers.rdx.edx.dx.value,
	    [BX] = (uintptr_t)&ctx->registers.rbx.ebx.bx.value,
	    [SP] = (uintptr_t)&ctx->registers.rsp.esp.sp.value,
	    [BP] = (uintptr_t)&ctx->registers.rbp.ebp.bp.value,
	    [SI] = (uintptr_t)&ctx->registers.rsi.esi.si.value,
	    [DI] = (uintptr_t)&ctx->registers.rdi.edi.di.value,
	    [R8W] = (uintptr_t)&ctx->registers.r8.r8d.r8w.value,
	    [R9W] = (uintptr_t)&ctx->registers.r9.r9d.r9w.value,
	    [R10W] = (uintptr_t)&ctx->registers.r10.r10d.r10w.value,
	    [R11W] = (uintptr_t)&ctx->registers.r11.r11d.r11w.value,
	    [R12W] = (uintptr_t)&ctx->registers.r12.r12d.r12w.value,
	    [R13W] = (uintptr_t)&ctx->registers.r13.r13d.r13w.value,
	    [R14W] = (uintptr_t)&ctx->registers.r14.r14d.r14w.value,
	    [R15W] = (uintptr_t)&ctx->registers.r15.r15d.r15w.value,

	    /* 32-bit */
	    [EAX] = (uintptr_t)&ctx->registers.rax.eax.value,
	    [ECX] = (uintptr_t)&ctx->registers.rcx.ecx.value,
	    [EDX] = (uintptr_t)&ctx->registers.rdx.edx.value,
	    [EBX] = (uintptr_t)&ctx->registers.rbx.ebx.value,
	    [ESP] = (uintptr_t)&ctx->registers.rsp.esp.value,
	    [EBP] = (uintptr_t)&ctx->registers.rbp.ebp.value,
	    [ESI] = (uintptr_t)&ctx->registers.rsi.esi.value,
	    [EDI] = (uintptr_t)&ctx->registers.rdi.edi.value,
	    [R8D] = (uintptr_t)&ctx->registers.r8.r8d.value,
	    [R9D] = (uintptr_t)&ctx->registers.r9.r9d.value,
	    [R10D] = (uintptr_t)&ctx->registers.r10.r10d.value,
	    [R11D] = (uintptr_t)&ctx->registers.r11.r11d.value,
	    [R12D] = (uintptr_t)&ctx->registers.r12.r12d.value,
	    [R13D] = (uintptr_t)&ctx->registers.r13.r13d.value,
	    [R14D] = (uintptr_t)&ctx->registers.r14.r14d.value,
	    [R15D] = (uintptr_t)&ctx->registers.r15.r15d.value,

	    /* 64-bit */
	    [RAX] = (uintptr_t)&ctx->registers.rax.value,
	    [RCX] = (uintptr_t)&ctx->registers.rcx.value,
	    [RDX] = (uintptr_t)&ctx->registers.rdx.value,
	    [RBX] = (uintptr_t)&ctx->registers.rbx.value,
	    [RSP] = (uintptr_t)&ctx->registers.rsp.value,
	    [RBP] = (uintptr_t)&ctx->registers.rbp.value,
	    [RSI] = (uintptr_t)&ctx->registers.rsi.value,
	    [RDI] = (uintptr_t)&ctx->registers.rdi.value,
	    [R8] = (uintptr_t)&ctx->registers.r8.value,
	    [R9] = (uintptr_t)&ctx->registers.r9.value,
	    [R10] = (uintptr_t)&ctx->registers.r10.value,
	    [R11] = (uintptr_t)&ctx->registers.r11.value,
	    [R12] = (uintptr_t)&ctx->registers.r12.value,
	    [R13] = (uintptr_t)&ctx->registers.r13.value,
	    [R14] = (uintptr_t)&ctx->registers.r14.value,
	    [R15] = (uintptr_t)&ctx->registers.r15.value,
	};

	if (reg >= REGISTER_MAX)
		return (uintptr_t)NULL;

	return (uintptr_t)reg_addr[reg];
}

static uint64_t
get_reg_value(uint16_t reg, struct vm_ctx* ctx)
{
	uint64_t reg_value[REGISTER_MAX] = {
	    /* 8-bit */
	    [AL] = ctx->registers.rax.eax.ax.al,
	    [AH] = ctx->registers.rax.eax.ax.ah,
	    [CL] = ctx->registers.rcx.ecx.cx.cl,
	    [CH] = ctx->registers.rcx.ecx.cx.ch,
	    [DL] = ctx->registers.rdx.edx.dx.dl,
	    [DH] = ctx->registers.rdx.edx.dx.dh,
	    [BL] = ctx->registers.rbx.ebx.bx.bl,
	    [BH] = ctx->registers.rbx.ebx.bx.bh,
	    [SPL] = ctx->registers.rsp.esp.sp.spl,
	    [BPL] = ctx->registers.rbp.ebp.bp.bpl,
	    [SIL] = ctx->registers.rsi.esi.si.sl,
	    [DIL] = ctx->registers.rdi.edi.di.dl,
	    [R8B] = ctx->registers.r8.r8d.r8w.r8b,
	    [R9B] = ctx->registers.r9.r9d.r9w.r9b,
	    [R10B] = ctx->registers.r10.r10d.r10w.r10b,
	    [R11B] = ctx->registers.r11.r11d.r11w.r11b,
	    [R12B] = ctx->registers.r12.r12d.r12w.r12b,
	    [R13B] = ctx->registers.r13.r13d.r13w.r13b,
	    [R14B] = ctx->registers.r14.r14d.r14w.r14b,
	    [R15B] = ctx->registers.r15.r15d.r15w.r15b,

	    /* 16-bit */
	    [AX] = ctx->registers.rax.eax.ax.value,
	    [CX] = ctx->registers.rcx.ecx.cx.value,
	    [DX] = ctx->registers.rdx.edx.dx.value,
	    [BX] = ctx->registers.rbx.ebx.bx.value,
	    [SP] = ctx->registers.rsp.esp.sp.value,
	    [BP] = ctx->registers.rbp.ebp.bp.value,
	    [SI] = ctx->registers.rsi.esi.si.value,
	    [DI] = ctx->registers.rdi.edi.di.value,
	    [R8W] = ctx->registers.r8.r8d.r8w.value,
	    [R9W] = ctx->registers.r9.r9d.r9w.value,
	    [R10W] = ctx->registers.r10.r10d.r10w.value,
	    [R11W] = ctx->registers.r11.r11d.r11w.value,
	    [R12W] = ctx->registers.r12.r12d.r12w.value,
	    [R13W] = ctx->registers.r13.r13d.r13w.value,
	    [R14W] = ctx->registers.r14.r14d.r14w.value,
	    [R15W] = ctx->registers.r15.r15d.r15w.value,

	    /* 32-bit */
	    [EAX] = ctx->registers.rax.eax.value,
	    [ECX] = ctx->registers.rcx.ecx.value,
	    [EDX] = ctx->registers.rdx.edx.value,
	    [EBX] = ctx->registers.rbx.ebx.value,
	    [ESP] = ctx->registers.rsp.esp.value,
	    [EBP] = ctx->registers.rbp.ebp.value,
	    [ESI] = ctx->registers.rsi.esi.value,
	    [R8D] = ctx->registers.r8.r8d.value,
	    [R9D] = ctx->registers.r9.r9d.value,
	    [R10D] = ctx->registers.r10.r10d.value,
	    [R11D] = ctx->registers.r11.r11d.value,
	    [R12D] = ctx->registers.r12.r12d.value,
	    [R13D] = ctx->registers.r13.r13d.value,
	    [R14D] = ctx->registers.r14.r14d.value,
	    [R15D] = ctx->registers.r15.r15d.value,

	    /* 64-bit */
	    [RAX] = ctx->registers.rax.value,
	    [RCX] = ctx->registers.rcx.value,
	    [RDX] = ctx->registers.rdx.value,
	    [RBX] = ctx->registers.rbx.value,
	    [RSP] = ctx->registers.rsp.value,
	    [RBP] = ctx->registers.rbp.value,
	    [RSI] = ctx->registers.rsi.value,
	    [R8] = ctx->registers.r8.value,
	    [R9] = ctx->registers.r9.value,
	    [R10] = ctx->registers.r10.value,
	    [R11] = ctx->registers.r11.value,
	    [R12] = ctx->registers.r12.value,
	    [R13] = ctx->registers.r13.value,
	    [R14] = ctx->registers.r14.value,
	    [R15] = ctx->registers.r15.value,
	};

	if (reg >= REGISTER_MAX)
		return (uintptr_t)NULL;

	return reg_value[reg];
}

uintptr_t
get_mem_ptr(const struct memory_operand* mem, struct vm_ctx* ctx)
{
	uint64_t base = get_reg_value(mem->base, ctx);
	uint64_t index = get_reg_value(mem->index, ctx);

	uint64_t ptr = base + index * mem->scale + mem->disp;

	return (uintptr_t)ptr;
}

uintptr_t
get_operand_ptr(const struct operand_data* operand,
    struct vm_ctx* ctx)
{
	switch (operand->type) {
	case MEM:
		return get_mem_ptr(&operand->data.mem, ctx);
		break;
	case REG:
		return get_reg_ptr(operand->data.reg, ctx);
		break;
	case IMM:
		return (uintptr_t)&operand->data.imm;
		break;
	default:
		break;
	}
	return (uintptr_t)NULL;
}

uint16_t
get_reg_size(uint16_t reg)
{
	switch (reg) {
	case AL:
	case CL:
	case DL:
	case BL:
	case SPL:
	case BPL:
	case SIL:
	case DIL:
	case R8B:
	case R9B:
	case R10B:
	case R11B:
	case R12B:
	case R13B:
	case R14B:
	case R15B:
		return 8;
		break;

	case AX:
	case CX:
	case DX:
	case BX:
	case SP:
	case BP:
	case SI:
	case DI:
	case R8W:
	case R9W:
	case R10W:
	case R11W:
	case R12W:
	case R13W:
	case R14W:
	case R15W:
		return 16;
		break;

	case EAX:
	case ECX:
	case EDX:
	case EBX:
	case ESP:
	case EBP:
	case ESI:
	case EDI:
	case R8D:
	case R9D:
	case R10D:
	case R11D:
	case R12D:
	case R13D:
	case R14D:
	case R15D:
		return 32;
		break;

	case RAX:
	case RCX:
	case RDX:
	case RBX:
	case RSP:
	case RBP:
	case RSI:
	case RDI:
	case R8:
	case R9:
	case R10:
	case R11:
	case R12:
	case R13:
	case R14:
	case R15:
		return 64;
		break;
	}

	return 0;
}

uint16_t
get_operand_size(const struct operand_data* src)
{
	switch (src->type) {
	case MEM:
		return src->data.mem.size;
		break;
	case REG:
		return get_reg_size(src->data.reg);
		break;
	case IMM:
		return 64;
		break;
	default:
		break;
	}
	return 0;
}

/* Instructoin callbacks */

int
process_nop(__attribute__((unused)) const struct instruction_entry* instr,
    __attribute__((unused)) struct vm_ctx* ctx)
{
	return 0;
}

int
set_value(uint64_t value, uintptr_t dst, uint16_t size)
{

	switch (size) {
        case 8:
            *(uint8_t*)(dst) = *(uint8_t*)&value;
            break;
        case 16:
            *(uint16_t*)(dst) = *(uint16_t*)&value;
            break;
        case 32:
            *(uint32_t*)(dst) = *(uint32_t*)&value;
            break;
        case 64:
            *(uint64_t*)(dst) = value;
            break;
		default:
			return -1;
    }
	return 0;
}

int
set_svalue(int64_t value, intptr_t dst, int16_t size)
{

	switch (size) {
        case 8:
            *(int8_t*)(dst) = *(int8_t*)&value;
            break;
        case 16:
            *(int16_t*)(dst) = *(int16_t*)&value;
            break;
        case 32:
            *(int32_t*)(dst) = *(int32_t*)&value;
            break;
        case 64:
            *(int64_t*)(dst) = value;
            break;
		default:
			return -1;
    }
	return 0;
}

uint64_t
get_value(uintptr_t addr, uint16_t size)
{
	switch (size) {
	case 8:
		return (uint64_t) * (uint8_t*)(addr);
		break;
	case 16:
		return (uint64_t) * (uint16_t*)(addr);
		break;
	case 32:
		return (uint64_t) * (uint32_t*)(addr);
		break;
	case 64:
		return (uint64_t) * (uint64_t*)(addr);
		break;
	};
	return 0;
}

int
process_xor(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint8_t* byte_src = (uint8_t*)&tmp_src;
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint8_t byte_val = (uint8_t)val;
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val ^= *byte_src;
		*(uint8_t*)(dst) = byte_val;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val ^= *word_src;
		*(uint16_t*)(dst) = word_val;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val ^= *dword_src;
		*(uint32_t*)(dst) = dword_val;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val ^= *qword_src;
		*(uint64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_and(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint8_t* byte_src = (uint8_t*)&tmp_src;
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint8_t byte_val = (uint8_t)val;
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val &= *byte_src;
		*(uint8_t*)(dst) = byte_val;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val &= *word_src;
		*(uint16_t*)(dst) = word_val;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val &= *dword_src;
		*(uint32_t*)(dst) = dword_val;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val &= *qword_src;
		*(uint64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_neg(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!dst)
		return -1;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		*(uint8_t*)(dst) = -*(uint8_t*)(dst);
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		*(uint16_t*)(dst) = -*(uint16_t*)(dst);
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		*(uint32_t*)(dst) = -*(uint32_t*)(dst);
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		*(uint64_t*)(dst) = -*(uint64_t*)(dst);
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_add(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint8_t* byte_src = (uint8_t*)&tmp_src;
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint8_t byte_val = (uint8_t)val;
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val += *byte_src;
		*(uint8_t*)(dst) = byte_val;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val += *word_src;
		*(uint16_t*)(dst) = word_val;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val += *dword_src;
		*(uint32_t*)(dst) = dword_val;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val += *qword_src;
		*(uint64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_sub(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint8_t* byte_src = (uint8_t*)&tmp_src;
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint8_t byte_val = (uint8_t)val;
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val -= *byte_src;
		*(uint8_t*)(dst) = byte_val;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val -= *word_src;
		*(uint16_t*)(dst) = word_val;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val -= *dword_src;
		*(uint32_t*)(dst) = dword_val;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val -= *qword_src;
		*(uint64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_cmp(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.dst, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.src, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.dst);
	uint16_t dst_size = get_operand_size(&instr->basic.src);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint8_t* byte_src = (uint8_t*)&tmp_src;
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint8_t byte_val = (uint8_t)val;
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val -= *byte_src;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val -= *word_src;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val -= *dword_src;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val -= *qword_src;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_test(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.dst, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.src, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.dst);
	uint16_t dst_size = get_operand_size(&instr->basic.src);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint8_t* byte_src = (uint8_t*)&tmp_src;
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint8_t byte_val = (uint8_t)val;
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val &= *byte_src;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val &= *word_src;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val &= *dword_src;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val &= *qword_src;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_movzx(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;


	uint64_t value = get_value(src, src_size);
	*(uint64_t*)(dst) = 0;
	set_value(value, dst, dst_size);

	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_movsx(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	int64_t value = get_value(src, src_size);
	*(uint64_t*)(dst) = 0;
	set_svalue(value, dst, dst_size);

	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_mov(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t val = get_value(src, src_size);
	memcpy((void*)dst, (void*)&val, dst_size / 8);
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_lea(const struct instruction_entry *instr, struct vm_ctx *ctx)
{
	if (instr->basic.src.type != MEM)
		return -1;

	if (instr->basic.dst.type != REG)
		return -1;

	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t value = get_mem_ptr(&instr->basic.src.data.mem, ctx);
	set_value(value, dst, dst_size);

	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_shl(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t shift = get_value(src, src_size);
	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		*(uint8_t*)(dst) <<= (uint8_t)shift;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		*(uint16_t*)(dst) <<= (uint16_t)shift;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		*(uint32_t*)(dst) <<= (uint32_t)shift;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		*(uint64_t*)(dst) <<= (uint64_t)shift;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_shr(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst) {
		return -1;
	}

	uint64_t shift = get_value(src, src_size);
	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		*(uint8_t*)(dst) >>= (uint8_t)shift;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		*(uint16_t*)(dst) >>= (uint16_t)shift;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		*(uint32_t*)(dst) >>= (uint32_t)shift;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		*(uint64_t*)(dst) >>= (uint64_t)shift;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_sar(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t shift = get_value(src, src_size);
	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		*(int8_t*)(dst) >>= (int8_t)shift;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		*(int16_t*)(dst) >>= (int16_t)shift;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		*(int32_t*)(dst) >>= (int32_t)shift;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		*(int64_t*)(dst) >>= (int64_t)shift;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_sext(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	int64_t val = get_value(src, src_size);

	if (src == dst) {		
		set_svalue(val, dst, dst_size);
	} else {
		set_svalue((val < 0 ) ? -1 : 0, dst, dst_size);
	}

	ctx->registers.rip += sizeof(struct instruction_entry);

	return 0;
}

int
process_imul(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	int64_t tmp_src = get_value(src, src_size);
	int8_t* byte_src = (int8_t*)&tmp_src;
	int16_t* word_src = (int16_t*)&tmp_src;
	int32_t* dword_src = (int32_t*)&tmp_src;
	int64_t* qword_src = (int64_t*)&tmp_src;

	int64_t val = get_value(dst, dst_size);
	int8_t byte_val = (int8_t)val;
	int16_t word_val = (int16_t)val;
	int32_t dword_val = (int32_t)val;
	int64_t qword_val = val;

	if (instr->basic.opt0.type != OPERAND_NONE) {
		uintptr_t opt0 = get_operand_ptr(&instr->basic.opt0, ctx);

		if (!opt0)
			return -1;

		uint16_t opt0_size = get_operand_size(&instr->basic.opt0);

		int64_t opt0_qword_val = get_value(opt0, opt0_size);
		int8_t opt0_byte_val = (int8_t)opt0_qword_val;
		int16_t opt0_word_val = (int16_t)opt0_qword_val;
		int32_t opt0_dword_val = (int32_t)opt0_qword_val;

		switch (dst_size) {
		case 8:
			set_rflags(ctx->registers.rflags);
			*(int8_t*)(dst) = *byte_src * opt0_byte_val;
			break;
		case 16:
			set_rflags(ctx->registers.rflags);
			*(int16_t*)(dst) = *word_src * opt0_word_val;
			break;
		case 32:
			set_rflags(ctx->registers.rflags);
			*(int32_t*)(dst) = *dword_src * opt0_dword_val;
			break;
		case 64:
			set_rflags(ctx->registers.rflags);
			*(int64_t*)(dst) = *qword_src * opt0_qword_val;
			break;
		}
		ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
		;
		ctx->registers.rip += sizeof(struct instruction_entry);
		return 0;
	}

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		byte_val *= *byte_src;
		*(int8_t*)(dst) = byte_val;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		word_val *= *word_src;
		*(int16_t*)(dst) = word_val;
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		dword_val *= *dword_src;
		*(int32_t*)(dst) = dword_val;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		qword_val *= *qword_src;
		*(int64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

void
mul_128(uint64_t* rax, uint64_t* operand, uint64_t* opt0)
{
	__asm volatile("mov rax, %0\n" ::"m"(*rax));
	__asm volatile("mov rdx, %0\n" ::"m"(*operand));
	__asm volatile("mul rdx\n");
	register uint64_t _rax __asm("rax");
	register uint64_t _rdx __asm("rdx");
	*rax = _rax;
	*opt0 = _rdx;
}

int
process_mul(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uintptr_t opt0 = get_operand_ptr(&instr->basic.opt0, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst || !opt0)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	int8_t* byte_src = (int8_t*)&tmp_src;
	int16_t* word_src = (int16_t*)&tmp_src;
	int32_t* dword_src = (int32_t*)&tmp_src;

	int64_t val = get_value(dst, dst_size);
	int16_t word_val = (int16_t)val;
	int32_t dword_val = (int32_t)val;
	int64_t qword_val = val;

	switch (dst_size) {
	case 8:
		set_rflags(ctx->registers.rflags);
		word_val *= *byte_src;
		*(uint16_t*)(opt0) = word_val;
		break;
	case 16:
		set_rflags(ctx->registers.rflags);
		dword_val *= *word_src;
		*(uint16_t*)(dst) = *(uint16_t*)((uint64_t)&dword_val);
		*(uint16_t*)(opt0) = *(uint16_t*)((uint64_t)&dword_val + 2);
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		qword_val *= *dword_src;
		*(uint32_t*)(dst) = *(uint32_t*)((uint64_t)&qword_val);
		*(uint32_t*)(opt0) = *(uint32_t*)((uint64_t)&qword_val + 4);
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		mul_128((uint64_t*)dst, (uint64_t*)src, (uint64_t*)opt0);
		break;
	default:
		return -1;
		break;
	}

	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_idiv(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uintptr_t opt0 = get_operand_ptr(&instr->basic.opt0, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	int64_t tmp_src = get_value(src, src_size);
	int16_t* word_src = (int16_t*)&tmp_src;
	int32_t* dword_src = (int32_t*)&tmp_src;
	int64_t* qword_src = (int64_t*)&tmp_src;

	int64_t val = get_value(dst, dst_size);
	int16_t word_val = (int16_t)val;
	int32_t dword_val = (int32_t)val;
	int64_t qword_val = val;

	switch (dst_size) {
	case 16:
		if (opt0) {
			set_rflags(ctx->registers.rflags);
			*(int16_t*)(opt0) = word_val % *word_src;
			word_val /= *word_src;
			*(int16_t*)(dst) = word_val;
		} else {
			set_rflags(ctx->registers.rflags);
			*(int8_t*)(get_reg_ptr(AL, ctx)) = word_val / *word_src;
			*(int8_t*)(get_reg_ptr(AH, ctx)) = word_val % *word_src;
		}
		break;
	case 32:
		set_rflags(ctx->registers.rflags);
		*(int32_t*)(opt0) = dword_val % *dword_src;
		dword_val /= *dword_src;
		*(int32_t*)(dst) = dword_val;
		break;
	case 64:
		set_rflags(ctx->registers.rflags);
		*(int64_t*)(opt0) = qword_val % *qword_src;
		qword_val /= *qword_src;
		*(int64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_div(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t src = get_operand_ptr(&instr->basic.src, ctx);
	uintptr_t dst = get_operand_ptr(&instr->basic.dst, ctx);
	uintptr_t opt0 = get_operand_ptr(&instr->basic.opt0, ctx);
	uint16_t src_size = get_operand_size(&instr->basic.src);
	uint16_t dst_size = get_operand_size(&instr->basic.dst);

	if (!src || !dst)
		return -1;

	uint64_t tmp_src = get_value(src, src_size);
	uint16_t* word_src = (uint16_t*)&tmp_src;
	uint32_t* dword_src = (uint32_t*)&tmp_src;
	uint64_t* qword_src = (uint64_t*)&tmp_src;

	uint64_t val = get_value(dst, dst_size);
	uint16_t word_val = (uint16_t)val;
	uint32_t dword_val = (uint32_t)val;
	uint64_t qword_val = val;

	switch (dst_size) {
	case 16:
		if (opt0) {
			set_rflags(ctx->registers.rflags);
			*(uint16_t*)(opt0) = word_val % *word_src;
			word_val /= *word_src;
			*(uint16_t*)(dst) = word_val;
		} else {
			set_rflags(ctx->registers.rflags);
			*(uint8_t*)(get_reg_ptr(AL, ctx)) = word_val / *word_src;
			*(uint8_t*)(get_reg_ptr(AH, ctx)) = word_val % *word_src;
		}
		break;
	case 32:
		*(uint32_t*)(opt0) = dword_val % *dword_src;
		dword_val /= *dword_src;
		*(uint32_t*)(dst) = dword_val;
		break;
	case 64:
		*(uint64_t*)(opt0) = qword_val % *qword_src;
		qword_val /= *qword_src;
		*(uint64_t*)(dst) = qword_val;
		break;

	default:
		return -1;
		break;
	}
	ctx->registers.rflags = get_rflags() & STATUS_FLAGS_MASK;
	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_set(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uintptr_t dst = get_operand_ptr(&instr->set.dst, ctx);
	uint64_t flag_mask[JMP_FLAG_MAX] = {
	    [JMP_FLAG_ZF] = 1 << ZF,
	    [JMP_FLAG_SF] = 1 << SF,
	    [JMP_FLAG_OF] = 1 << OF,
	    [JMP_FLAG_CF] = 1 << CF,
	    [JMP_FLAG_PF] = 1 << PF,
	};

	*(uint8_t*)(dst) = 0;
	int check_cnt = 0;
	int fail_cnt = 0;
	for (int i = 0; i < JMP_FLAG_MAX; ++i) {
		if (instr->set.flag_checks[i].type == DISABLED)
			continue;
		++check_cnt;
		if (instr->set.flag_checks[i].type == VALUE_CHECK) {
			if (!!(ctx->registers.rflags & flag_mask[i]) != instr->set.flag_checks[i].value)
				++fail_cnt;
		} else if (instr->set.flag_checks[i].type == COMPARISON_CHECK) {
			bool fe = !!(ctx->registers.rflags & flag_mask[i]) == !!(ctx->registers.rflags & instr->set.flag_checks[i].flag_mask);
			if (instr->set.flag_checks[i].value != fe)
				++fail_cnt;
		}
	}
	if (check_cnt) {
		if (instr->set.any && check_cnt > fail_cnt) {
			*(uint8_t*)(dst) = 1;
		} else if (!instr->set.any && fail_cnt == 0) {
			*(uint8_t*)(dst) = 1;
		}
	} else {
		*(uint8_t*)(dst) = 1;
	}

	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

int
process_jmp(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	uint64_t flag_mask[JMP_FLAG_MAX] = {
	    [JMP_FLAG_ZF] = 1 << ZF,
	    [JMP_FLAG_SF] = 1 << SF,
	    [JMP_FLAG_OF] = 1 << OF,
	    [JMP_FLAG_CF] = 1 << CF,
	    [JMP_FLAG_PF] = 1 << PF,
	};

	int check_cnt = 0;
	int fail_cnt = 0;
	for (int i = 0; i < JMP_FLAG_MAX; ++i) {
		if (instr->jmp.flag_checks[i].type == DISABLED)
			continue;
		++check_cnt;
		if (instr->jmp.flag_checks[i].type == VALUE_CHECK) {
			if (!!(ctx->registers.rflags & flag_mask[i]) != instr->jmp.flag_checks[i].value)
				++fail_cnt;
		} else if (instr->jmp.flag_checks[i].type == COMPARISON_CHECK) {
			bool fe = !!(ctx->registers.rflags & flag_mask[i]) == !!(ctx->registers.rflags & instr->jmp.flag_checks[i].flag_mask);
			if (instr->jmp.flag_checks[i].value != fe)
				++fail_cnt;
		}
	}
	if (check_cnt) {
		if (instr->jmp.any && check_cnt > fail_cnt) {
			ctx->registers.rip += instr->jmp.off * sizeof(struct instruction_entry);
		} else if (!instr->jmp.any && fail_cnt == 0) {
			ctx->registers.rip += instr->jmp.off * sizeof(struct instruction_entry);
		}
	} else {
		ctx->registers.rip += instr->jmp.off * sizeof(struct instruction_entry);
	}

	ctx->registers.rip += sizeof(struct instruction_entry);
	return 0;
}

static int (*instr_callback[OPCODE_MAX])(const struct instruction_entry*,
    struct vm_ctx*)
    = {
	[NOP] = process_nop,
	[ADD] = process_add,
	[SUB] = process_sub,
	[MOV] = process_mov,
	[MOVZX] = process_movzx,
	[MOVSX] = process_movsx,
	[LEA] = process_lea,
	[SHL] = process_shl,
	[SAL] = process_shl,
	[SHR] = process_shr,
	[SAR] = process_sar,
	[SEXT] = process_sext,
	[IMUL] = process_imul,
	[MUL] = process_mul,
	[IDIV] = process_idiv,
	[DIV] = process_div,
	[CMP] = process_cmp,
	[TEST] = process_test,
	[JMP] = process_jmp,
	[SET] = process_set,
	[XOR] = process_xor,
	[AND] = process_and,
	[NEG] = process_neg,
};

int
process_instr(const struct instruction_entry* instr, struct vm_ctx* ctx)
{
	if (instr->opcode >= OPCODE_MAX) {
		return -1;
	}

	int ret = instr_callback[instr->opcode](instr, ctx);
	return ret;
}

void
process_bytecode(struct vm_ctx* ctx)
{
	PACKER_PROTECTION_START;
	struct instruction_entry* instr = (struct instruction_entry*)(ctx->registers.rip);
	while (instr->opcode != VM_EXIT) {
		int ret = process_instr(instr, ctx);
		if (ret < 0) {
			break;
		}
		instr = (struct instruction_entry*)(ctx->registers.rip);
	}
	PACKER_PROTECTION_END;
}
