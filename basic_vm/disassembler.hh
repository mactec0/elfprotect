#pragma once

#include <stdint.h>
#include <vector>

#include "vm_types.h"

void dump_single_instruction(const instruction_entry &instr, size_t instr_cnt);

void dump_bytecode(const std::vector<instruction_entry> &bytecode);

void dump_bytecode(const std::vector<uint8_t> &bytecode);
