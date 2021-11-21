#include <iostream>
#include <getopt.h>

#include "elf_file.hh"

struct usage_exception : public std::exception {
	usage_exception() { }
};

struct protector_cfg {
	std::string in_fname;
	std::string out_fname;
};

static void
usage()
{
	std::cout << std::endl;
	std::cout << "Usage: ./elfprotect [OPTIONS]" << std::endl;
	std::cout << std::endl;
	std::cout << "Options" << std::endl;
	std::cout << "  -i                     input executable name" << std::endl;
	std::cout << "  -o                     output file name " << std::endl;
	std::cout << std::endl;
}

static protector_cfg
parse_args(int argc, char **argv)
{
	protector_cfg config {};

	int c;
	while (c = getopt(argc, argv, "i:o:"), c != -1)
		switch (c) {
		case 'i':
			config.in_fname = optarg;
			break;
		case 'o':
			config.out_fname = optarg;
			break;
		default:
			throw std::invalid_argument("ERROR: Unknown command line options");
		}
	
	if (config.in_fname.empty())
		throw usage_exception();
	
	if (config.out_fname.empty())
		config.out_fname = config.in_fname + "_protected";

	return config;
}

static int
run_protector(struct protector_cfg &config) {
	
	elf_file *exec = new elf_file(config.in_fname);
	if (!exec || !exec->is_loaded()) {
		std::cerr << "ERROR: Failed to load executable.\n";
		return -1;
	}
	std::cout << "Executable [" << config.in_fname << "] loaded successfully\n\n";

	elf_file *elf_payload = new elf_file("protector_payload");
	if (!elf_payload || !elf_payload->is_loaded()) {
		std::cerr << "ERROR: Failed to load payload\n";
		return -1;
	}

	if (exec->insert_payload(elf_payload) < 0) {
		std::cerr << "ERROR: Failed to insert payload\n";
		return -1;
	}

	exec->apply_flags_to_all_segments(PF_R | PF_W | PF_X);

	if (!exec->save_to_file(config.out_fname)) {
		std::cout << "Failed to save executable.\n";
		return -1;
	}

	std::cout << "Output executable saved to [" << config.out_fname << "]\n";
	return 0;
}

int
main(int argc, char **argv)
{
	srand(time(NULL));

	try {
		auto config {parse_args(argc, argv)};
		return run_protector(config);
	} catch (usage_exception &) {
		usage();
		return 0;
	}
	return 0;
}
