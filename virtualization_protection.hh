#pragma once

#include "protection.hh"

class virtualizer_basic : public protection {
	elf_file *target;
	elf_file *payload;
	std::tuple<uint8_t *, std::vector<uint8_t> &, uint64_t> marker;
	bool encryption;

public:
	virtualizer_basic(elf_file *elf, elf_file *payload, std::tuple<uint8_t *, std::vector<uint8_t> &, uint64_t> marker, bool encryption = false);

	virtual ~virtualizer_basic();

	virtual void apply() override;
};
