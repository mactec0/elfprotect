#include <Zydis/Zydis.h>
#include <cstdio>
#include <getopt.h>
#include <inttypes.h>
#include <iostream>
#include <map>
#include <vector>

#include "compiler.hh"

struct usage_exception : public std::exception {
	usage_exception() { }
};

struct compiler_config {
	char *bin_fname;
	char *byte_code_fname;
};

static void
usage()
{
	std::cout << std::endl;
	std::cout << "Usage: ./compiler [OPTIONS]" << std::endl;
	std::cout << std::endl;
	std::cout << "Options" << std::endl;
	std::cout << "  -i                     input bin file" << std::endl;
	std::cout << "  -o                     output bytecode file" << std::endl;
	std::cout << std::endl;
}

static compiler_config
parse_args(int argc, char **argv)
{
	compiler_config config {};

	if (argc != 5)
		throw usage_exception();

	int c;
	while (c = getopt(argc, argv, "i:o:"), c != -1)
		switch (c) {
		case 'o':
			config.byte_code_fname = &optarg[0];
			break;
		case 'i':
			config.bin_fname = &optarg[0];
			break;
		default:
			throw std::invalid_argument("ERROR: Unknown command line options");
		}

	return config;
}

static std::vector<uint8_t>
read_file(const char *fname)
{
	FILE *f = fopen(fname, "rb");
	if (!f) {
		std::cerr << "Cannot open file " << fname << "\n";
		return std::vector<uint8_t>();
	}
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	rewind(f);
	std::vector<uint8_t> data(size, 0x00);
	size_t result = fread(data.data(), sizeof(uint8_t), size, f);
	if (result != (size_t)size) {
		std::cerr << "Cannot read file" << fname << "\n";
		return std::vector<uint8_t>();
	}
	return data;
}

static int
run_compiler(struct compiler_config &config)
{
	std::vector<instruction_entry> vm_instructions;
	auto data {read_file(config.bin_fname)};

	if (compile_to_bytecode(data, vm_instructions) < 0)
		return -1;

	uint32_t i = 0;
	std::vector<uint8_t> bytecode(vm_instructions.size() * sizeof(instruction_entry), 0);
	for (auto &instr : vm_instructions) {
		*(instruction_entry *)(&bytecode[i++ * sizeof(instruction_entry)]) = instr;
	}

	FILE *f;
	f = fopen(config.byte_code_fname, "wb");
	if (!f) {
		std::cerr << "Cannot open bytecode file for saving";
		return -1;
	}
	fwrite(bytecode.data(), sizeof(uint8_t), bytecode.size(), f);
	fclose(f);

	return 0;
}

int
main(int argc, char **argv)
{
	try {
		auto config {parse_args(argc, argv)};
		return run_compiler(config);
	} catch (usage_exception &) {
		usage();
		return 0;
	}

	return 0;
}
