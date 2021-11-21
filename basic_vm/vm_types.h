#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>

typedef enum FLAGS {
	CF,
	PF = 2,
	AF = 4,
	ZF = 6,
	SF,
	TF,
	IF,
	DF,
	OF,
	IOPL,
	NT,
	RF = 16,
	VM,
	VC,
	VIF,
	VIP,
	ID,
} vm_basic_flags;

#define STATUS_FLAGS_MASK (1 << CF | 1 << PF | 1 << AF | 1 << ZF | 1 << SF | 1 << OF)

typedef enum REG {
	NONE,

	AL,
	CL,
	DL,
	BL,
	AH,
	CH,
	DH,
	BH,

	SPL,
	BPL,
	SIL,
	DIL,
	R8B,
	R9B,
	R10B,
	R11B,
	R12B,
	R13B,
	R14B,
	R15B,

	AX,
	CX,
	DX,
	BX,
	SP,
	BP,
	SI,
	DI,
	R8W,
	R9W,
	R10W,
	R11W,
	R12W,
	R13W,
	R14W,
	R15W,

	EAX,
	ECX,
	EDX,
	EBX,
	ESP,
	EBP,
	ESI,
	EDI,
	R8D,
	R9D,
	R10D,
	R11D,
	R12D,
	R13D,
	R14D,
	R15D,

	RAX,
	RCX,
	RDX,
	RBX,
	RSP,
	RBP,
	RSI,
	RDI,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,

	ST0,
	ST1,
	ST2,
	ST3,
	ST4,
	ST5,
	ST6,
	ST7,
	X87CONTROL,
	X87STATUS,
	X87TAG,

	MM0,
	MM1,
	MM2,
	MM3,
	MM4,
	MM5,
	MM6,
	MM7,

	XMM0,
	XMM1,
	XMM2,
	XMM3,
	XMM4,
	XMM5,
	XMM6,
	XMM7,
	XMM8,
	XMM9,
	XMM10,
	XMM11,
	XMM12,
	XMM13,
	XMM14,
	XMM15,
	XMM16,
	XMM17,
	XMM18,
	XMM19,
	XMM20,
	XMM21,
	XMM22,
	XMM23,
	XMM24,
	XMM25,
	XMM26,
	XMM27,
	XMM28,
	XMM29,
	XMM30,
	XMM31,

	YMM0,
	YMM1,
	YMM2,
	YMM3,
	YMM4,
	YMM5,
	YMM6,
	YMM7,
	YMM8,
	YMM9,
	YMM10,
	YMM11,
	YMM12,
	YMM13,
	YMM14,
	YMM15,
	YMM16,
	YMM17,
	YMM18,
	YMM19,
	YMM20,
	YMM21,
	YMM22,
	YMM23,
	YMM24,
	YMM25,
	YMM26,
	YMM27,
	YMM28,
	YMM29,
	YMM30,
	YMM31,

	ZMM0,
	ZMM1,
	ZMM2,
	ZMM3,
	ZMM4,
	ZMM5,
	ZMM6,
	ZMM7,
	ZMM8,
	ZMM9,
	ZMM10,
	ZMM11,
	ZMM12,
	ZMM13,
	ZMM14,
	ZMM15,
	ZMM16,
	ZMM17,
	ZMM18,
	ZMM19,
	ZMM20,
	ZMM21,
	ZMM22,
	ZMM23,
	ZMM24,
	ZMM25,
	ZMM26,
	ZMM27,
	ZMM28,
	ZMM29,
	ZMM30,
	ZMM31,

	TMM0,
	TMM1,
	TMM2,
	TMM3,
	TMM4,
	TMM5,
	TMM6,
	TMM7,

	FLAGS,
	EFLAGS,
	RFLAGS,

	IP,
	EIP,
	RIP,

	ES,
	CS,
	SS,
	DS,
	FS,
	GS,

	GDTR,
	LDTR,
	IDTR,
	TR,

	TR0,
	TR1,
	TR2,
	TR3,
	TR4,
	TR5,
	TR6,
	TR7,

	CR0,
	CR1,
	CR2,
	CR3,
	CR4,
	CR5,
	CR6,
	CR7,
	CR8,
	CR9,
	CR10,
	CR11,
	CR12,
	CR13,
	CR14,
	CR15,

	DR0,
	DR1,
	DR2,
	DR3,
	DR4,
	DR5,
	DR6,
	DR7,
	DR8,
	DR9,
	DR10,
	DR11,
	DR12,
	DR13,
	DR14,
	DR15,

	K0,
	K1,
	K2,
	K3,
	K4,
	K5,
	K6,
	K7,

	BND0,
	BND1,
	BND2,
	BND3,
	BNDCFG,
	BNDSTATUS,

	MXCSR,
	PKRU,
	XCR0,
	UIF,

	REGISTER_MAX,
} vm_basic_register;

enum OPCODE {
	NOP,
	ADD,
	SUB,
	MOV,
	MOVZX,
	MOVSX,
	LEA,
	SHL,
	SAL,
	SHR,
	SAR,
	SEXT,
	IMUL,
	MUL,
	IDIV,
	DIV,
	CMP,
	TEST,
	JMP,
	SET,
	XOR,
	AND,
	NEG,
	VM_EXIT,
	OPCODE_MAX,
};

enum OPERAND {
	OPERAND_NONE,
	MEM,
	REG,
	IMM
};

/* RAX definition */
union _ax {
	uint16_t value;
	struct {
		uint8_t al;
		uint8_t ah;
	} __attribute__((packed));
} __attribute__((packed));

union _eax {
	uint32_t value;
	struct {
		union _ax ax;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rax {
	uint64_t value;
	struct {
		union _eax eax;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RBX definition */
union _bx {
	uint16_t value;
	struct {
		uint8_t bl;
		uint8_t bh;
	} __attribute__((packed));
} __attribute__((packed));

union _ebx {
	uint32_t value;
	struct {
		union _bx bx;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rbx {
	uint64_t value;
	struct {
		union _ebx ebx;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RCX definition */
union _cx {
	uint16_t value;
	struct {
		uint8_t cl;
		uint8_t ch;
	} __attribute__((packed));
} __attribute__((packed));

union _ecx {
	uint32_t value;
	struct {
		union _cx cx;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rcx {
	uint64_t value;
	struct {
		union _ecx ecx;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RDX definition */
union _dx {
	uint16_t value;
	struct {
		uint8_t dl;
		uint8_t dh;
	} __attribute__((packed));
} __attribute__((packed));

union _edx {
	uint32_t value;
	struct {
		union _dx dx;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rdx {
	uint64_t value;
	struct {
		union _edx edx;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RSI definition */
union _si {
	uint16_t value;
	struct {
		uint8_t sl;
		uint8_t sh;
	} __attribute__((packed));
} __attribute__((packed));

union _esi {
	uint32_t value;
	struct {
		union _si si;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rsi {
	uint64_t value;
	struct {
		union _esi esi;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RDI definition */
union _di {
	uint16_t value;
	struct {
		uint8_t dl;
		uint8_t dh;
	} __attribute__((packed));
} __attribute__((packed));

union _edi {
	uint32_t value;
	struct {
		union _di di;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rdi {
	uint64_t value;
	struct {
		union _edi edi;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RSP definition */
union _sp {
	uint16_t value;
	struct {
		uint8_t spl;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _esp {
	uint32_t value;
	struct {
		union _sp sp;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rsp {
	uint64_t value;
	struct {
		union _esp esp;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* RBP definition */
union _bp {
	uint16_t value;
	struct {
		uint8_t bpl;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _ebp {
	uint32_t value;
	struct {
		union _bp bp;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _rbp {
	uint64_t value;
	struct {
		union _ebp ebp;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R8 definition */
union _r8w {
	uint16_t value;
	struct {
		uint8_t r8b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r8d {
	uint32_t value;
	struct {
		union _r8w r8w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r8 {
	uint64_t value;
	struct {
		union _r8d r8d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R9 definition */
union _r9w {
	uint16_t value;
	struct {
		uint8_t r9b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r9d {
	uint32_t value;
	struct {
		union _r9w r9w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r9 {
	uint64_t value;
	struct {
		union _r9d r9d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R10 definition */
union _r10w {
	uint16_t value;
	struct {
		uint8_t r10b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r10d {
	uint32_t value;
	struct {
		union _r10w r10w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r10 {
	uint64_t value;
	struct {
		union _r10d r10d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R11 definition */
union _r11w {
	uint16_t value;
	struct {
		uint8_t r11b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r11d {
	uint32_t value;
	struct {
		union _r11w r11w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r11 {
	uint64_t value;
	struct {
		union _r11d r11d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R12 definition */
union _r12w {
	uint16_t value;
	struct {
		uint8_t r12b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r12d {
	uint32_t value;
	struct {
		union _r12w r12w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r12 {
	uint64_t value;
	struct {
		union _r12d r12d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R13 definition */
union _r13w {
	uint16_t value;
	struct {
		uint8_t r13b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r13d {
	uint32_t value;
	struct {
		union _r13w r13w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r13 {
	uint64_t value;
	struct {
		union _r13d r13d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R14 definition */
union _r14w {
	uint16_t value;
	struct {
		uint8_t r14b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r14d {
	uint32_t value;
	struct {
		union _r14w r14w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r14 {
	uint64_t value;
	struct {
		union _r14d r14d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

/* R15 definition */
union _r15w {
	uint16_t value;
	struct {
		uint8_t r15b;
		uint8_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r15d {
	uint32_t value;
	struct {
		union _r15w r15w;
		int16_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

union _r15 {
	uint64_t value;
	struct {
		union _r15d r15d;
		int32_t _pad0;
	} __attribute__((packed));
} __attribute__((packed));

struct _registers {
	uint64_t rflags;
	uint64_t rip;
	union _r15 r15;
	union _r14 r14;
	union _r13 r13;
	union _r12 r12;
	union _r11 r11;
	union _r10 r10;
	union _r9 r9;
	union _r8 r8;
	union _rbp rbp;
	union _rdi rdi;
	union _rsi rsi;
	union _rdx rdx;
	union _rcx rcx;
	union _rbx rbx;
	union _rax rax;
	union _rsp rsp;
} __attribute__((packed));

struct vm_ctx {
	struct _registers registers;
} __attribute__((packed));

struct memory_operand {
	uint16_t segment; // segment register
	uint16_t base; // base register
	uint16_t index; // index register
	uint8_t scale;
	int64_t disp;
	uint16_t size;
} __attribute__((packed));

struct operand_data {
	uint8_t type;

	union data_ {
		// register
		uint16_t reg;

		// immediate
		int64_t imm;

		// memory
		struct memory_operand mem;
	} data;
} __attribute__((packed));

enum FLAG_CHECK_TYPE {
	DISABLED,
	VALUE_CHECK,
	COMPARISON_CHECK,
};

enum JMP_FLAG {
	JMP_FLAG_ZF,
	JMP_FLAG_SF,
	JMP_FLAG_OF,
	JMP_FLAG_CF,
	JMP_FLAG_PF,
	JMP_FLAG_MAX,
};

struct basic_instruction_data {
	struct operand_data src;
	struct operand_data dst;
	struct operand_data opt0;
} __attribute__((packed));

struct flag_check {
	uint8_t type;
	bool value; // With comparison value=0:"=="; value=1:"!="
	uint64_t flag_mask;
} __attribute__((packed));

struct jmp_instruction_data {
	int32_t off;
	bool any; // or
	struct flag_check flag_checks[JMP_FLAG_MAX];
} __attribute__((packed));

struct set_instruction_data {
	bool any; // or
	struct operand_data dst;
	struct flag_check flag_checks[JMP_FLAG_MAX];
} __attribute__((packed));

struct instruction_entry {
	uint8_t opcode;
	union {
		struct jmp_instruction_data jmp;
		struct set_instruction_data set;
		struct basic_instruction_data basic;
	};
} __attribute__((packed));
