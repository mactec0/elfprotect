#include <Zydis/Zydis.h>

#include <iostream>
#include <map>

#include "disassembler.hh"

const char *
opcode_to_text(uint8_t type)
{
	const char *opcode[] = {
	    "nop",
	    "add",
	    "sub",
	    "mov",
	    "movzx",
	    "movsx",
	    "lea",
	    "shl",
	    "sal",
	    "shr",
	    "sar",
	    "sext",
	    "imul",
	    "mul",
	    "idiv",
	    "div",
	    "cmp",
	    "test",
	    "jmp",
	    "set",
	    "xor",
	    "and",
	    "neg",
	    "vm_exit",
	};

	if (type >= sizeof(opcode) / sizeof(char *))
		return "Unkown opcode type";

	return opcode[type];
}

const char *
size_to_text(uint16_t size)
{
	std::map<uint16_t, std::string> sizes {
	    {8, "byte"},
	    {16, "word"},
	    {32, "dword"},
	    {64, "qword"},
	};

	if (sizes.find(size) == sizes.end())
		return "Unkown size";

	return sizes[size].c_str();
}

const char *
operand_type_to_text(uint8_t type)
{
	const char *operands[] = {"Memory", "Register", "Imediate"};

	if (type >= sizeof(operands) / sizeof(char *))
		return "Unkown operand type";

	return operands[type];
}

static std::vector<int> get_flags_from_mask(uint64_t mask) {
	std::vector<int> vflags;
	int flags[JMP_FLAG_MAX] = {
	    [JMP_FLAG_ZF] = 1 << ZF,
	    [JMP_FLAG_SF] = 1 << SF,
	    [JMP_FLAG_OF] = 1 << OF,
	    [JMP_FLAG_CF] = 1 << CF,
	    [JMP_FLAG_PF] = 1 << PF,
	};

	for (int i = 0; i < JMP_FLAG_MAX; ++i) {
		if (!(mask & flags[i]))
			continue;
		
		vflags.push_back(i);
	}
	return vflags;
}

void
print_jmp_info(const struct jmp_instruction_data &data, size_t instr_cnt)
{
	std::cout << data.off + instr_cnt + 1;
	bool first_cond = true;
	std::map<int, std::string> flags {
	    {JMP_FLAG_ZF, "zf"},
	    {JMP_FLAG_SF, "sf"},
	    {JMP_FLAG_OF, "of"},
	    {JMP_FLAG_CF, "cf"},
	    {JMP_FLAG_PF, "pf"},
	};

	std::cout << "\t(";
	for (int i = 0; i < JMP_FLAG_MAX; ++i) {
		if (data.flag_checks[i].type == DISABLED)
			continue;
		
		if (!first_cond)
			std::cout << (first_cond ? "||" : "&&");

		if (data.flag_checks[i].type == VALUE_CHECK) {
			std::cout << flags[i]
				  << "==" << data.flag_checks[i].value;
		} else if (data.flag_checks[i].type == COMPARISON_CHECK) {
			std::cout << flags[i] << (data.flag_checks[i].value ? "==" : "!=");
			auto flags_to_compare {get_flags_from_mask(data.flag_checks[i].flag_mask)};
			if (flags_to_compare.size() == 1) {
				std::cout << flags[flags_to_compare[0]];
				continue;
			}

			bool first_flag = true;
			std::cout << "[";
			for (auto flag: flags_to_compare) {
				if (!first_flag)
					std::cout << ',';

				std::cout << flags[flag];
				first_flag = false;
			}
			std::cout << "]";
		}
		first_cond = false;
	}
	std::cout << ")";
}

void
print_operand_info(const struct operand_data &operand)
{
	bool print_sign = false;
	switch (operand.type) {
	case OPERAND::MEM:
		std::cout << size_to_text(operand.data.mem.size) << " [";
		std::cout << ZydisRegisterGetString(
		    (ZydisRegister)operand.data.mem.segment)
			  << ":";

		if (operand.data.mem.base != ZYDIS_REGISTER_NONE) {
			std::cout << ZydisRegisterGetString(
			    (ZydisRegister)operand.data.mem.base);
			print_sign = true;
		}

		if (operand.data.mem.index != ZYDIS_REGISTER_NONE) {
			std::cout << "+"
				  << ZydisRegisterGetString(
					 (ZydisRegister)operand.data.mem.index);
			std::cout << "*" << (int)operand.data.mem.scale;
			print_sign = true;
		}

		if (operand.data.mem.disp) {
			if (print_sign)
				std::cout
				    << ((operand.data.mem.disp > 0) ? '+'
								    : '-');

			std::cout << std::hex << "0x"
				  << abs(operand.data.mem.disp) << std::dec;
		}

		std::cout << "]";
		break;
	case OPERAND::REG:
		std::cout << ZydisRegisterGetString(
		    (ZydisRegister)operand.data.reg);
		break;
	case OPERAND::IMM:
		std::cout << std::hex << ((operand.data.imm > 0) ? "0x" : "-0x")
			  << abs(operand.data.imm) << std::dec;
		break;
	default:
		std::cerr << "Unsupported operand type\n";
		break;
	};
}

void
print_set_info(const struct set_instruction_data &data)
{
	print_operand_info(data.dst);
	bool first_cond = true;
	std::map<int, std::string> flags {
	    {JMP_FLAG_ZF, "zf"},
	    {JMP_FLAG_SF, "sf"},
	    {JMP_FLAG_OF, "of"},
	    {JMP_FLAG_CF, "cf"},
	    {JMP_FLAG_PF, "pf"},
	};
	
	std::cout << "\t(";
	for (int i = 0; i < JMP_FLAG_MAX; ++i) {
		if (data.flag_checks[i].type == DISABLED)
			continue;
		
		if (!first_cond)
			std::cout << (first_cond ? "||" : "&&");

		if (data.flag_checks[i].type == VALUE_CHECK) {
			std::cout << flags[i]
				  << "==" << data.flag_checks[i].value;
		} else if (data.flag_checks[i].type == COMPARISON_CHECK) {
			std::cout << flags[i] << (data.flag_checks[i].value ? "==" : "!=");
			auto flags_to_compare {get_flags_from_mask(data.flag_checks[i].flag_mask)};
			if (flags_to_compare.size() == 1) {
				std::cout << flags[flags_to_compare[0]];
				continue;
			}

			bool first_flag = true;
			std::cout << "[";
			for (auto flag: flags_to_compare) {
				if (!first_flag)
					std::cout << ',';

				std::cout << flags[flag];
				first_flag = false;
			}
			std::cout << "]";
		}
		first_cond = false;
	}
	std::cout << ")";
}

void
dump_single_instruction(const instruction_entry &instr, size_t instr_cnt)
{
	std::cout << opcode_to_text(instr.opcode) << ' ';
	switch (instr.opcode) {
	case OPCODE::JMP:
		print_jmp_info(instr.jmp, instr_cnt);
		break;
	case OPCODE::SET:
		print_set_info(instr.set);
		break;
	default:
		if (instr.basic.dst.type != OPERAND_NONE) {
			print_operand_info(instr.basic.dst);

			if (instr.basic.src.type != OPERAND_NONE) {
				std::cout << ", ";
				print_operand_info(instr.basic.src);
			}
			if (instr.basic.opt0.type != OPERAND_NONE) {
				std::cout << "\t; additional: ";
				print_operand_info(instr.basic.opt0);
			}
		}
		break;
	}

	std::cout << '\n';
}

void
dump_bytecode(const std::vector<instruction_entry> &bytecode)
{
	auto cnt {0};
	for (auto &instr : bytecode) {
		std::cout << cnt << ".\t│ ";
		dump_single_instruction(instr, cnt++);
	}
}

void
dump_bytecode(const std::vector<uint8_t> &bytecode)
{
	auto cnt {0};
	for (size_t i = 0; i < bytecode.size();
	     i += sizeof(instruction_entry)) {
		auto instr {(instruction_entry *)&bytecode[i]};
		if (instr->opcode == OPCODE::VM_EXIT) {
			std::cout << cnt++ << ".\t│ vm_exit\n";
			continue;
		}

		std::cout << cnt << ".\t│ ";
		dump_single_instruction(*instr, cnt++);
	}
}
