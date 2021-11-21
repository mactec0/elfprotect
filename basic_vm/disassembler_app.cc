#include <iostream>
#include <vector>

#include "disassembler.hh"

int
main(int argc, char **argv)
{
	if (argc != 2) {
		std::cerr << "./disassembler <bytecode>\n";
		return -1;
	}

	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		std::cerr << "Cannot open bytecode file\n";
		return -1;
	}
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	rewind(f);

	std::vector<uint8_t> bytecode(size, 0x00);
	size_t result = fread(bytecode.data(), sizeof(uint8_t), size, f);
	if (result != (size_t)size) {
		std::cerr << "Cannot read file\n";
		return -1;
	}

	dump_bytecode(bytecode);

	return 0;
}
