#pragma once

#include "protection.hh"

class packer : public protection {
	elf_file *target;
	elf_file *payload;
	std::tuple<uint8_t *, std::vector<uint8_t> &, uint64_t> marker;
	bool encryption;

public:
	packer(elf_file *elf, elf_file *payload, std::tuple<uint8_t *, std::vector<uint8_t> &, uint64_t> marker, bool encryption = false);

	virtual ~packer();

	virtual void apply() override;
};
