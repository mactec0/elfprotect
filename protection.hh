#pragma once
#include <Zydis/Zydis.h>
#include <iomanip>

#include "basic_vm/compiler.hh"
#include "basic_vm/disassembler.hh"
#include "elf_file.hh"
#include "sdk.h"

class protection {
public:
	virtual ~protection() { }

	virtual void apply() = 0;
};
