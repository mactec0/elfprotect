#pragma once
#include <vector>

#include "vm_types.h"

int compile_to_bytecode(const std::vector<uint8_t> &data,
    std::vector<instruction_entry> &vm_instructions);
