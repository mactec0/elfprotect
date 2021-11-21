#pragma once

#include "vm_types.h"

int process_instr(const struct instruction_entry *instr, struct vm_ctx *ctx);

void process_bytecode(struct vm_ctx *ctx);
