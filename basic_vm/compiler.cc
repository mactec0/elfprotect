#include <Zydis/Zydis.h>

#include <cstdio>
#include <inttypes.h>
#include <iostream>
#include <map>

#include "compiler.hh"

static int
parse_operand(const ZydisDecodedOperand &operand,
    struct operand_data &vm_operand)
{

	switch (operand.type) {
	case ZYDIS_OPERAND_TYPE_MEMORY:
		vm_operand.type = OPERAND::MEM;
		vm_operand.data.mem.segment = operand.mem.segment;
		vm_operand.data.mem.base = operand.mem.base;
		vm_operand.data.mem.index = operand.mem.index;
		vm_operand.data.mem.scale = operand.mem.scale;
		vm_operand.data.mem.disp = operand.mem.disp.value;
		vm_operand.data.mem.size = operand.size;
		break;
	case ZYDIS_OPERAND_TYPE_REGISTER:
		vm_operand.type = OPERAND::REG;
		vm_operand.data.reg = operand.reg.value;
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		vm_operand.type = OPERAND::IMM;
		vm_operand.data.imm = operand.imm.value.s;
		break;
	case ZYDIS_OPERAND_TYPE_UNUSED:
		vm_operand.type = OPERAND::OPERAND_NONE;
		break;
	default:
		std::cerr << "Unsupported operand type\n";
		return -1;
		break;
	};

	return 0;
}

static bool
valid_register_operand(const ZydisDecodedOperand *operand, int id)
{
	if (id != operand->id)
		return false;

	if (operand->type == ZYDIS_OPERAND_TYPE_REGISTER)
		return operand->reg.value != ZYDIS_REGISTER_RFLAGS;

	return true;
}

static struct instruction_entry
parse_basic_instruction(const ZydisDecodedInstruction &instruction,
    const ZydisDecodedOperand *operands)
{
	auto &src_op {operands[1]};
	auto &dst_op {operands[0]};
	auto &opt0_op {operands[2]};

	static const std::map<int, uint8_t> opcodes = {
	    {ZYDIS_MNEMONIC_NOP, OPCODE::NOP},
	    {ZYDIS_MNEMONIC_ADD, OPCODE::ADD},
	    {ZYDIS_MNEMONIC_SUB, OPCODE::SUB},
	    {ZYDIS_MNEMONIC_MOV, OPCODE::MOV},
	    {ZYDIS_MNEMONIC_MOVZX, OPCODE::MOVZX},
	    {ZYDIS_MNEMONIC_MOVSX, OPCODE::MOVSX},
	    {ZYDIS_MNEMONIC_MOVSXD, OPCODE::MOVSX},
	    {ZYDIS_MNEMONIC_LEA, OPCODE::LEA},
	    {ZYDIS_MNEMONIC_SHL, OPCODE::SHL},
	    {ZYDIS_MNEMONIC_SALC, OPCODE::SAL},
	    {ZYDIS_MNEMONIC_SHR, OPCODE::SHR},
	    {ZYDIS_MNEMONIC_SAR, OPCODE::SAR},
	    {ZYDIS_MNEMONIC_IMUL, OPCODE::IMUL},
	    {ZYDIS_MNEMONIC_MUL, OPCODE::MUL},
	    {ZYDIS_MNEMONIC_IDIV, OPCODE::IDIV},
	    {ZYDIS_MNEMONIC_DIV, OPCODE::DIV},
	    {ZYDIS_MNEMONIC_CMP, OPCODE::CMP},
	    {ZYDIS_MNEMONIC_TEST, OPCODE::TEST},
	    {ZYDIS_MNEMONIC_XOR, OPCODE::XOR},
	    {ZYDIS_MNEMONIC_AND, OPCODE::AND},
	    {ZYDIS_MNEMONIC_NEG, OPCODE::NEG},
	};

	struct instruction_entry instr = {
	    .opcode = opcodes.at(instruction.mnemonic),
	};

	if (instruction.operand_count >= 2 && valid_register_operand(&src_op, 1)) {
		if (parse_operand(src_op, instr.basic.src) < 0) {
			std::cerr << "Parsing src operand failed\n";
			throw std::invalid_argument("Invalid operand");
		}
	}

	if (instruction.operand_count >= 1 && valid_register_operand(&dst_op, 0)) {
		if (parse_operand(dst_op, instr.basic.dst) < 0) {
			std::cerr << "Parsing src operand failed\n";
			throw std::invalid_argument("Invalid operand");
		}

		if ((dst_op.actions & ZYDIS_OPERAND_ACTION_WRITE) == 0) {
			std::swap(instr.basic.src, instr.basic.dst);
		}
	}

	if (instruction.operand_count >= 3 && valid_register_operand(&opt0_op, 2)) {
		if (parse_operand(opt0_op, instr.basic.opt0) < 0) {
			std::cerr << "Parsing optional operand failed\n";
			throw std::invalid_argument("Invalid operand");
		}
	}

	return instr;
}

static struct instruction_entry
parse_jmp_instruction(const ZydisDecodedInstruction &instruction,
    const ZydisDecodedOperand *operands)
{
	auto &offset_op {operands[0]};
	struct operand_data vm_operand {
	};
	struct instruction_entry instr = {
	    .opcode = OPCODE::JMP,
	};

	if (valid_register_operand(&offset_op, 0)) {
		if (parse_operand(offset_op, vm_operand) < 0) {
			std::cerr << "Parsing jmp offset operand failed\n";
			throw std::invalid_argument("Invalid operand");
		}
	}

	if (vm_operand.type != OPERAND::IMM)
		throw std::invalid_argument("Wrong operand type: " + std::to_string(vm_operand.type));

	instr.jmp.off = vm_operand.data.imm;

	switch (instruction.mnemonic) {
	case ZYDIS_MNEMONIC_JMP:
		break;
	case ZYDIS_MNEMONIC_JZ:
		instr.jmp.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JNZ:
		instr.jmp.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JNLE:
		instr.jmp.any = false;
		instr.jmp.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		instr.jmp.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 1,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_JNL:
		instr.jmp.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 1,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_JL:
		instr.jmp.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 0,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_JLE:
		instr.jmp.any = true;
		instr.jmp.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		instr.jmp.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 0,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_JNBE:
		instr.jmp.any = false;
		instr.jmp.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		instr.jmp.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JNB:
		instr.jmp.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JB:
		instr.jmp.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JBE:
		instr.jmp.any = true;
		instr.jmp.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		instr.jmp.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JNO:
		instr.jmp.flag_checks[JMP_FLAG_OF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JNP:
		instr.jmp.flag_checks[JMP_FLAG_PF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JNS:
		instr.jmp.flag_checks[JMP_FLAG_SF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JO:
		instr.jmp.flag_checks[JMP_FLAG_OF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JP:
		instr.jmp.flag_checks[JMP_FLAG_PF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_JS:
		instr.jmp.flag_checks[JMP_FLAG_SF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	default:
		throw std::invalid_argument("Unsupported instruction");
		break;
	}
	return instr;
}

static struct instruction_entry
parse_set_instruction(const ZydisDecodedInstruction &instruction,
    const ZydisDecodedOperand *operands)
{
	auto &offset_op {operands[0]};
	struct instruction_entry instr = {
	    .opcode = OPCODE::SET,
	};

	if (valid_register_operand(&offset_op, 0)) {
		if (parse_operand(offset_op, instr.set.dst) < 0) {
			std::cerr << "Parsing jmp offset operand failed\n";
			throw std::invalid_argument("Invalid operand");
		}
	}

	switch (instruction.mnemonic) {
	case ZYDIS_MNEMONIC_SETZ:
		instr.set.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETNZ:
		instr.set.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETNLE:
		instr.set.any = false;
		instr.set.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		instr.set.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 1,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_SETNL:
		instr.set.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 1,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_SETL:
		instr.set.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 0,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_SETLE:
		instr.set.any = true;
		instr.set.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		instr.set.flag_checks[JMP_FLAG_SF] = {
		    .type = COMPARISON_CHECK,
		    .value = 0,
		    .flag_mask = 1 << OF,
		};
		break;
	case ZYDIS_MNEMONIC_SETNBE:
		instr.set.any = false;
		instr.set.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		instr.set.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETNB:
		instr.set.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETB:
		instr.set.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETBE:
		instr.set.any = true;
		instr.set.flag_checks[JMP_FLAG_CF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		instr.set.flag_checks[JMP_FLAG_ZF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETNO:
		instr.set.flag_checks[JMP_FLAG_OF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETNP:
		instr.set.flag_checks[JMP_FLAG_PF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETNS:
		instr.set.flag_checks[JMP_FLAG_SF] = {
		    .type = VALUE_CHECK,
		    .value = 0,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETO:
		instr.set.flag_checks[JMP_FLAG_OF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETP:
		instr.set.flag_checks[JMP_FLAG_PF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	case ZYDIS_MNEMONIC_SETS:
		instr.set.flag_checks[JMP_FLAG_SF] = {
		    .type = VALUE_CHECK,
		    .value = 1,
		    .flag_mask = 0,
		};
		break;
	default:
		throw std::invalid_argument("Unsupported instruction");
		break;
	}
	return instr;
}

static struct instruction_entry
parse_sext_instruction(const ZydisDecodedInstruction &instruction,
    __attribute__((unused))
    const ZydisDecodedOperand *operands)
{
	struct instruction_entry instr = {
	    .opcode = OPCODE::SEXT,
	    .basic = {
		.src = {.type = REG},
		.dst = {.type = REG},
	}};

	switch (instruction.mnemonic) {
	case ZYDIS_MNEMONIC_CWD:
		instr.basic.src.data.reg = AX;
		instr.basic.dst.data.reg = DX;
		break;
	case ZYDIS_MNEMONIC_CDQ:
		instr.basic.src.data.reg = EAX;
		instr.basic.dst.data.reg = EDX;
		break;
	case ZYDIS_MNEMONIC_CQO:
		instr.basic.src.data.reg = RAX;
		instr.basic.dst.data.reg = RDX;
		break;
	case ZYDIS_MNEMONIC_CBW:
		instr.basic.src.data.reg = AL;
		instr.basic.dst.data.reg = AX;
		break;
	case ZYDIS_MNEMONIC_CWDE:
		instr.basic.src.data.reg = AX;
		instr.basic.dst.data.reg = EAX;
		break;
	case ZYDIS_MNEMONIC_CDQE:
		instr.basic.src.data.reg = EAX;
		instr.basic.dst.data.reg = RAX;
		break;
	default:
		std::cout << "Unsupported instruction: " << instruction.mnemonic
			  << "\n";
		break;
	};
	return instr;
}

int
compile_to_bytecode(const std::vector<uint8_t> &data,
    std::vector<instruction_entry> &vm_instructions)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
	    ZYDIS_STACK_WIDTH_64);
	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	std::vector<ZyanUSize> offsets; // offset of next instruction
	std::map<ZyanUSize, int> offset_to_instr_id;
	std::vector<int> jmps_to_fix;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
	    &decoder, data.data() + offset, data.size() - offset, &instruction,
	    operands, ZYDIS_MAX_OPERAND_COUNT, 0))) {
		switch (instruction.mnemonic) {
		case ZYDIS_MNEMONIC_NOP:
		case ZYDIS_MNEMONIC_ADD:
		case ZYDIS_MNEMONIC_SUB:
		case ZYDIS_MNEMONIC_MOV:
		case ZYDIS_MNEMONIC_MOVZX:
		case ZYDIS_MNEMONIC_MOVSX:
		case ZYDIS_MNEMONIC_MOVSXD:
		case ZYDIS_MNEMONIC_LEA:
		case ZYDIS_MNEMONIC_SHL:
		case ZYDIS_MNEMONIC_SALC:
		case ZYDIS_MNEMONIC_SHR:
		case ZYDIS_MNEMONIC_SAR:
		case ZYDIS_MNEMONIC_IMUL:
		case ZYDIS_MNEMONIC_MUL:
		case ZYDIS_MNEMONIC_IDIV:
		case ZYDIS_MNEMONIC_DIV:
		case ZYDIS_MNEMONIC_CMP:
		case ZYDIS_MNEMONIC_TEST:
		case ZYDIS_MNEMONIC_XOR:
		case ZYDIS_MNEMONIC_AND:
		case ZYDIS_MNEMONIC_NEG:
			vm_instructions.push_back(
			    parse_basic_instruction(instruction, operands));
			break;

		case ZYDIS_MNEMONIC_JMP:
		case ZYDIS_MNEMONIC_JZ:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JNS:
			jmps_to_fix.push_back(offsets.size());
			vm_instructions.push_back(
			    parse_jmp_instruction(instruction, operands));
			break;

		case ZYDIS_MNEMONIC_SETZ:
		case ZYDIS_MNEMONIC_SETNZ:
		case ZYDIS_MNEMONIC_SETNLE:
		case ZYDIS_MNEMONIC_SETNL:
		case ZYDIS_MNEMONIC_SETL:
		case ZYDIS_MNEMONIC_SETLE:
		case ZYDIS_MNEMONIC_SETNBE:
		case ZYDIS_MNEMONIC_SETNB:
		case ZYDIS_MNEMONIC_SETB:
		case ZYDIS_MNEMONIC_SETBE:
		case ZYDIS_MNEMONIC_SETO:
		case ZYDIS_MNEMONIC_SETNO:
		case ZYDIS_MNEMONIC_SETNP:
		case ZYDIS_MNEMONIC_SETS:
		case ZYDIS_MNEMONIC_SETNS:
			vm_instructions.push_back(
			    parse_set_instruction(instruction, operands));
			break;

		case ZYDIS_MNEMONIC_CWD:
		case ZYDIS_MNEMONIC_CDQ:
		case ZYDIS_MNEMONIC_CQO:
		case ZYDIS_MNEMONIC_CBW:
		case ZYDIS_MNEMONIC_CWDE:
		case ZYDIS_MNEMONIC_CDQE:
			vm_instructions.push_back(
			    parse_sext_instruction(instruction, operands));
			break;

		default:
			std::cout << "Unsupported instruction: "
				  << instruction.mnemonic << "\n";
			return -1;
			break;
		};
		offset += instruction.length;
		offsets.push_back(offset);
		offset_to_instr_id[offset] = offsets.size();
	}

	for (auto jmp_id : jmps_to_fix) {
		auto &instr {vm_instructions[jmp_id]};
		ZyanUSize addr = offsets[jmp_id] + instr.jmp.off;
		if (offset_to_instr_id.find(addr) == offset_to_instr_id.end()) {
			std::cout << "Unsupported instruction, jmp out of vm "
				     "scope: 0x"
				  << std::hex << addr << std::dec << '\n';
			continue;
		}

		instr.jmp.off = offset_to_instr_id[addr] - (jmp_id + 1);
	}

	vm_instructions.push_back({
	    .opcode = OPCODE::VM_EXIT,
	});

	return 0;
}
