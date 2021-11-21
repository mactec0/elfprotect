#include <inttypes.h>

#include "elf_file.hh"
#include "packer_protection.hh"
#include "virtualization_protection.hh"

enum {
	PACKER_PROTECTION = 0xdec00000,
	PACKER_ENCRYPTION_PROTECTION = 0xdec41970,
	VM_BASIC_PROTECTION = 0xdef02145,
	MAX_PROTECTION = 0xdef02777,
};

struct Elf64_Shdr *
get_shdr_by_name(struct Elf64_Ehdr *ehdr,
    const char *name)
{
	struct Elf64_Shdr *shstr = (struct Elf64_Shdr *)((uint64_t)ehdr + ehdr->e_shoff + ehdr->e_shstrndx * sizeof(struct Elf64_Shdr));
	char *shstrtab = (char *)((uint64_t)ehdr + shstr->sh_offset);

	for (int i = 0; i < ehdr->e_shnum; ++i) {
		struct Elf64_Shdr *shdr = (struct Elf64_Shdr *)((uint64_t)ehdr + ehdr->e_shoff + i * sizeof(struct Elf64_Shdr));

		if (!shdr->sh_name)
			continue;

		if (strcmp(name, &shstrtab[shdr->sh_name]) == 0)
			return shdr;
	}
	return NULL;
}

struct elf_exports
get_elf_exports(struct Elf64_Ehdr *ehdr)
{
	struct elf_exports exports = {
	    .ehdr = ehdr,
	    .str = get_shdr_by_name(ehdr, ".strtab"),
	    .symtab = get_shdr_by_name(ehdr, ".symtab")};
	return exports;
}

uint64_t
find_export(const char *name, const struct elf_exports *exports)
{
	char *strtab = (char *)((uint64_t)exports->ehdr + exports->str->sh_offset);
	for (size_t i = 0;
	     i < (exports->symtab->sh_size / sizeof(struct Elf64_Sym));
	     ++i) {
		struct Elf64_Sym *sym_entry = (struct Elf64_Sym *)((uint64_t)exports->ehdr + exports->symtab->sh_offset + i * sizeof(struct Elf64_Sym));
		if (strcmp(&strtab[sym_entry->st_name], name) == 0) {
			return sym_entry->st_value;
		}
	}
	return 0;
}

template <typename reloc_t>
void fix_reloc_entry(reloc_t *reloc,
    uint64_t insertion_offset,
    int64_t foff_shift,
    int64_t moff_shift);

template <>
void
fix_reloc_entry<struct Elf64_Rela>(
    struct Elf64_Rela *reloc,
    uint64_t insertion_offset,
    __attribute__((unused)) int64_t foff_shift,
    int64_t moff_shift)
{
	switch (rela_get_type(reloc)) {
	case R_X86_64_JUMP_SLOT:
	case R_X86_64_GLOB_DAT:
	case R_X86_64_COPY:
	case R_X86_64_64:
		if (reloc->r_offset >= insertion_offset)
			reloc->r_offset += moff_shift;
		else
			return;
		break;
	case R_X86_64_IRELATIVE:
	case R_X86_64_RELATIVE:
		if (reloc->r_offset >= insertion_offset)
			reloc->r_offset += moff_shift;
		else
			return;
		reloc->r_addend += moff_shift;
		break;
	};
}

template <>
void
fix_reloc_entry<struct Elf64_Rel>(
    struct Elf64_Rel *reloc,
    uint64_t insertion_offset,
    __attribute__((unused)) int64_t foff_shift,
    int64_t moff_shift)
{
	if (reloc->r_offset >= insertion_offset)
		reloc->r_offset += moff_shift;
	else
		return;
}

template <typename T, typename U>
std::vector<std::tuple<const T &, const U &>>
zip(const std::vector<T> &v1, const std::vector<U> &v2)
{
	std::vector<std::tuple<const T &, const U &>> ret_vec;
	for (size_t i = 0; i < v1.size(); ++i) {
		ret_vec.push_back(
		    std::make_tuple(std::cref(v1[i]), std::cref(v2[i])));
	}
	return ret_vec;
}

bool
elf_file::load_file(const std::string &filename)
{
	std::ifstream f(filename);
	if (!f)
		return false;

	f.seekg(0, std::ios::end);
	raw_size = f.tellg();
	f.seekg(0, std::ios::beg);

	data = new uint8_t[raw_size];
	if (!data)
		return false;

	f.read((char *)data, raw_size);

	f.close();

	loaded = true;
	return true;
}

void
elf_file::parse()
{
	if (!is_loaded())
		return;

	struct Elf64_Ehdr *hdr = (struct Elf64_Ehdr *)get_raw_data();
	if (!check_magic(hdr)) {
		std::cerr << "ERROR: Invalid file type\n";
		return;
	}

	if (get_file_class(hdr) != ELFCLASS64) {
		std::cerr << "ERROR: Unsupported file class\n";
		return;
	}

	if (hdr->e_machine != EM_X86_64) {
		std::cerr << "ERROR: Unsupported architecture\n";
		return;
	}

	// save elf header
	ehdr = *hdr;

	// save program headers
	vphdr.resize(hdr->e_phnum);
	for (int i = 0; i < hdr->e_phnum; ++i) {
		struct Elf64_Phdr *program_hdr = (struct Elf64_Phdr *)(get_raw_data() + hdr->e_phoff + sizeof(struct Elf64_Phdr) * i);
		vphdr[i] = *program_hdr;
	}

	// save section headers with data
	vshdr.resize(hdr->e_shnum);
	shdr_data.resize(hdr->e_shnum);
	for (int i = 0; i < hdr->e_shnum; ++i) {
		struct Elf64_Shdr *shdr = (struct Elf64_Shdr *)(get_raw_data() + hdr->e_shoff + i * sizeof(Elf64_Shdr));
		vshdr[i] = *shdr;

		if (shdr->sh_type == SHT_NOBITS) {
			continue;
		}

		shdr_data[i].resize(shdr->sh_size);
		memcpy(shdr_data[i].data(),
		    get_raw_data() + shdr->sh_offset,
		    shdr->sh_size);
	}

	// add segment mapping
	for (auto &phdr : vphdr) {
		std::pair<struct Elf64_Phdr *,
		    std::vector<struct Elf64_Shdr *>>
		    mapping;
		mapping.first = &phdr;
		for (auto &shdr : vshdr) {
			if (shdr.sh_offset >= phdr.p_offset && shdr.sh_offset < phdr.p_offset + phdr.p_filesz) {
				mapping.second.push_back(&shdr);
				sections_segment[&shdr] = &phdr;
			}
		}
		// move
		segment_mapping.push_back(mapping);
	}

	// group segments
	std::set<struct Elf64_Phdr *> already_grouped;
	for (auto &mapping : segment_mapping) {
		std::vector<struct Elf64_Phdr *> group;
		if (already_grouped.count(mapping.first) == 0) {
			already_grouped.insert(mapping.first);
			group.push_back(mapping.first);
		}
		for (auto &mapping2 : segment_mapping) {
			if (&mapping == &mapping2) {
				continue;
			}

			for (auto &shdr : mapping.second) {
				for (auto &shdr2 : mapping2.second) {
					if (shdr == shdr2 && already_grouped.count(mapping2.first) == 0) {
						already_grouped.insert(
						    mapping2.first);
						group.push_back(
						    mapping2.first);
					}
				}
			}
		}
	}

	// save information about segments without coresponding section
	size_t i = 0;
	for (auto &mapping : segment_mapping) {
		auto &[hdr, sections] = mapping;

		if (hdr->p_type != PT_LOAD)
			continue;

		if (sections.size())
			continue;

		struct custom_load_segment custom_segment = {
		    .addr = hdr->p_offset,
		    .vaddr = hdr->p_vaddr,
		    .hdr_id = i++,
		    .data = std::vector<uint8_t>(hdr->p_filesz, 0)};

		memcpy(custom_segment.data.data(),
		    get_raw_data() + hdr->p_offset,
		    hdr->p_filesz);
		custom_segments.push_back(custom_segment);
		std::cout << "Adding custom segment\n";
	}

	auto shstrtab = this->get_section(this->get_elf_hdr()->e_shstrndx);
	size_t name_table_offset = shstrtab->sh_offset;

	for (uint64_t i = 0; i < vshdr.size(); ++i) {
		section_names[i] = std::string(
		    (char *)(this->get_raw() + name_table_offset + vshdr[i].sh_name));
	}

	parsed = true;
}

elf_file::elf_file(const std::string &filename)
{
	if (!load_file(filename))
		return;

	parse();
}

struct Elf64_Ehdr *
elf_file::get_header()
{
	return (struct Elf64_Ehdr *)get_raw_data();
}

uint8_t *
elf_file::get_raw()
{
	return get_raw_data();
}

struct Elf64_Ehdr *
elf_file::get_elf_hdr()
{
	return &ehdr;
}

struct Elf64_Shdr *
elf_file::get_section(uint32_t i)
{
	if (i >= vshdr.size())
		return NULL;
	return &vshdr[i];
}

struct Elf64_Shdr *
elf_file::get_section_by_name(const std::string &name)
{
	for (uint64_t i = 0; i < vshdr.size(); ++i) {
		if (section_names[i] != name)
			continue;
		return &vshdr[i];
	}
	return nullptr;
}

struct Elf64_Phdr *
elf_file::get_program_header(uint32_t i)
{
	if (i >= vphdr.size())
		return NULL;
	return &vphdr[i];
}

struct Elf64_Shdr *
elf_file::get_first_section_by_type(uint32_t type)
{
	for (auto &hdr : vshdr)
		if (hdr.sh_type == type)
			return &hdr;
	return nullptr;
}

std::pair<Elf64_Shdr *, std::vector<uint8_t>>
elf_file::get_section_with_data_by_type(uint32_t type)
{
	auto index {0};
	for (auto &hdr : vshdr) {
		if (hdr.sh_type == type)
			return {&hdr, shdr_data[index]};
		++index;
	}
	return {(Elf64_Shdr *)NULL, std::vector<uint8_t>()};
}

/* SEGMENT methods */
struct Elf64_Phdr *
elf_file::get_first_segment_by_type(uint32_t type)
{
	for (auto &hdr : vphdr)
		if (hdr.p_type == type)
			return &hdr;
	return nullptr;
}

void
elf_file::print_phdr_info()
{
	int i = 0;
	for (auto &phdr : vphdr) {
		std::cout << "· hdr[" << i << "].p_type: 0x" << std::hex
			  << phdr.p_type << '\n';
		std::cout << "· hdr[" << i << "].p_flags: 0x" << std::hex
			  << phdr.p_flags << '\n';
		std::cout << "· hdr[" << i << "].p_offset: 0x" << std::hex
			  << phdr.p_offset << '\n';
		std::cout << "· hdr[" << i << "].p_vaddr: 0x" << std::hex
			  << phdr.p_vaddr << '\n';
		std::cout << "· hdr[" << i << "].p_paddr: 0x" << std::hex
			  << phdr.p_paddr << '\n';
		std::cout << "· hdr[" << i << "].p_filesz: 0x" << std::hex
			  << phdr.p_filesz << '\n';
		std::cout << "· hdr[" << i << "].p_memsz: 0x" << std::hex
			  << phdr.p_memsz << '\n';
		std::cout << "· hdr[" << i << "].p_align: 0x" << std::hex
			  << phdr.p_align << '\n'
			  << '\n';
		++i;
	}
}

void
elf_file::print_shdr_info()
{
	auto shstrtab = this->get_section(this->get_elf_hdr()->e_shstrndx);
	size_t name_table_offset = shstrtab->sh_offset;
	int i = 0;
	for (auto &phdr : vshdr) {
		std::cout << "· shdr[" << i << "].sh_name: "
			  << std::string((char *)(this->get_raw() + name_table_offset + vshdr[i].sh_name))
			  << '\n';

		std::cout << "· shdr[" << i << "].sh_name: " << vshdr[i].sh_name << "\n";
		std::cout << "· shdr[" << i << "].sh_type: 0x" << std::hex
			  << phdr.sh_type << '\n';
		std::cout << "· shdr[" << i << "].sh_flags: 0x"
			  << std::hex << phdr.sh_flags << '\n';
		std::cout << "· shdr[" << i << "].sh_addr: 0x" << std::hex
			  << phdr.sh_addr << '\n';
		std::cout << "· shdr[" << i << "].sh_offset: 0x"
			  << std::hex << phdr.sh_offset << '\n';
		std::cout << "· shdr[" << i << "].sh_size: 0x" << std::hex
			  << phdr.sh_size << '\n';
		std::cout << "· shdr[" << i
			  << "].sh_link: " << phdr.sh_link << '\n';
		std::cout << "· shdr[" << i << "].sh_info: 0x" << std::hex
			  << phdr.sh_info << '\n';
		std::cout << "· shdr[" << i << "].sh_addralign: 0x"
			  << std::hex << phdr.sh_addralign << '\n';
		std::cout << "· shdr[" << i << "].sh_entsize: 0x"
			  << std::hex << phdr.sh_entsize << '\n'
			  << '\n';
		++i;
	}
}

template <class reloc_t>
void
elf_file::fix_relocations(int index,
    uint64_t insertion_offset,
    int64_t foff_shift,
    int64_t moff_shift)
{
	auto section_size {shdr_data[index].size()};
	reloc_t *reloc = (reloc_t *)shdr_data[index].data();
	for (uint64_t i = 0; i < section_size / sizeof(reloc_t); ++i) {
		fix_reloc_entry<reloc_t>(reloc, insertion_offset, foff_shift, moff_shift);
		++reloc;
	}
}

void
elf_file::fix_symbols(int index,
    uint64_t insertion_offset,
    int64_t foff_shift,
    __attribute__((unused)) int64_t moff_shift)
{
	struct Elf64_Sym *sym = (struct Elf64_Sym *)shdr_data[index].data();

	for (uint64_t i = 0; i < shdr_data[index].size() / sizeof(struct Elf64_Sym);
	     ++i) {
		if (sym->st_value >= insertion_offset)
			sym->st_value += foff_shift;
		++sym;
	}
}

struct Elf64_Dyn *
elf_file::get_first_dyn_entry(Elf32_Sword d_tag)
{
	auto dynamic {get_first_section_by_type(SHT_DYNAMIC)};
	auto index {get_section_index(dynamic)};
	auto entry {(struct Elf64_Dyn *)shdr_data[index].data()};
	if (!entry)
		return nullptr;

	for (uint64_t i = 0; i < shdr_data[index].size() / sizeof(struct Elf64_Dyn);
	     ++i) {
		if (entry->d_tag != d_tag) {
			++entry;
			continue;
		}
		return entry;
	}
	return nullptr;
}

void
elf_file::fix_dynamic(int index,
    uint64_t insertion_offset,
    __attribute__((unused)) int64_t foff_shift,
    int64_t moff_shift)
{
	struct Elf64_Dyn *dyn = (struct Elf64_Dyn *)shdr_data[index].data();

	for (uint64_t i = 0; i < shdr_data[index].size() / sizeof(struct Elf64_Dyn);
	     ++i) {

		switch (dyn->d_tag) {
		case DT_RELA:
		case DT_INIT:
		case DT_FINI:
		case DT_SYMTAB:
		case DT_STRTAB:
		case DT_PLTGOT:
		case DT_JMPREL:
		case DT_GNU_HASH:
		case DT_HASH:
		case DT_VERNEED:
		case DT_VERDEF:
		case DT_VERSYM:
		case DT_PREINIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_INIT_ARRAY:
			if (dyn->d_un.d_ptr >= insertion_offset)
				dyn->d_un.d_ptr += moff_shift;
			break;
		}

		++dyn;
	}
}

void
elf_file::fix_after_insertion(uint64_t insertion_offset,
    int64_t foff_shift,
    int64_t moff_shift = 0x00)
{
	int index = 0;
	auto elf_hdr = this->get_elf_hdr();
	std::cout << "· Fixing file after modification, file offset shift: 0x" << foff_shift << '\n';

	if (!moff_shift)
		moff_shift = foff_shift;

	for (uint64_t i = 0; i < vphdr.size(); ++i) {
		auto phdr = &vphdr[i];
		if (phdr->p_offset < insertion_offset)
			continue;

		phdr->p_offset += foff_shift;
		if (phdr->p_type == PT_LOAD) {
			phdr->p_vaddr += moff_shift;
			phdr->p_paddr += moff_shift;
		} else {
			if (phdr->p_vaddr)
				phdr->p_vaddr += moff_shift;

			if (phdr->p_paddr)
				phdr->p_paddr += moff_shift;
		}
	}

	for (auto &shdr : vshdr) {
		switch (shdr.sh_type) {
		case SHT_REL:
			fix_relocations<struct Elf64_Rel>(
			    index,
			    insertion_offset,
			    foff_shift,
			    moff_shift);
			break;
		case SHT_RELA:
			fix_relocations<struct Elf64_Rela>(
			    index,
			    insertion_offset,
			    foff_shift,
			    moff_shift);
			break;
		case SHT_DYNSYM:
		case SHT_SYMTAB:
			this->fix_symbols(index,
			    insertion_offset,
			    foff_shift,
			    moff_shift);
			break;
		case SHT_DYNAMIC:
			this->fix_dynamic(index,
			    insertion_offset,
			    foff_shift,
			    moff_shift);
			break;
		default:
			break;
		}

		if (shdr.sh_offset >= insertion_offset)
			shdr.sh_offset += foff_shift;
		else {
			++index;
			continue;
		}

		if (shdr.sh_addr)
			shdr.sh_addr += moff_shift;

		if (!shdr.sh_name) {
			++index;
			continue;
		}

		const std::vector<std::string> array_sections {
		    ".got.plt",
		    ".init_array",
		    ".fini_array",
		};
		if (std::find(array_sections.begin(),
			array_sections.end(),
			section_names[index])
		    == array_sections.end()) {
			++index;
			continue;
		}

		for (uint64_t i = 0; i < shdr_data[index].size();
		     i += sizeof(uint64_t)) {
			uint64_t *offset = (uint64_t *)&shdr_data[index][i];
			if (*offset >= insertion_offset)
				*offset += foff_shift;
		}

		++index;
	}

	if (elf_hdr->e_entry >= insertion_offset)
		elf_hdr->e_entry += moff_shift;

	if (elf_hdr->e_shoff > insertion_offset)
		elf_hdr->e_shoff += foff_shift;
}

std::vector<uint8_t> *
elf_file::get_section_data(struct Elf64_Shdr *hdr)
{
	auto section_index {get_section_index(hdr)};
	return &shdr_data[section_index];
}

std::vector<uint8_t> *
elf_file::get_custom_segment_data(struct Elf64_Phdr *hdr)
{
	auto index {get_segment_index(hdr)};
	for (auto &custom : custom_segments) {
		if (index != custom.hdr_id)
			continue;
		return &custom.data;
	}
	return nullptr;
}

struct Elf64_Phdr *
elf_file::get_next_segment(struct Elf64_Phdr *hdr)
{
	bool get_next {false};
	for (auto &&phdr : vphdr) {
		if (&phdr == hdr) {
			get_next = true;
			continue;
		}

		if (get_next)
			return &phdr;
	}
	return nullptr;
}

struct Elf64_Shdr *
elf_file::get_next_section(struct Elf64_Shdr *hdr)
{
	bool get_next {false};
	for (auto &&shdr : vshdr) {
		if (&shdr == hdr) {
			get_next = true;
			continue;
		}

		if (get_next)
			return &shdr;
	}
	return nullptr;
}

void
elf_file::expand_section_data(struct Elf64_Shdr *hdr, uint64_t expand)
{
	auto rela_data {get_section_data(hdr)};
	std::vector<uint8_t> vexpand(expand, 0xff);
	rela_data->insert(rela_data->begin(), vexpand.begin(), vexpand.end());
}

template <typename T>
std::vector<T>
elf_file::get_all_relocations_from_section(Elf64_Word sh_type)
{
	auto rel {get_first_section_by_type(sh_type)};
	std::vector<T> ret;
	if (!rel) {
		std::cerr << "Cannot find relocation of type: " << sh_type << '\n';
		return std::vector<T>();
	}

	auto data {get_section_data(rel)};
	auto entry {(T *)data->data()};
	for (size_t i = 0; i < rel->sh_size / sizeof(T); ++i) {
		ret.push_back(*entry);
		++entry;
	}

	return ret;
}

void
elf_file::resize_section(struct Elf64_Shdr *hdr, uint64_t new_size)
{
	auto next_hdr {get_next_section(hdr)};
	uint64_t available_space {0};
	if (next_hdr) {
		available_space = next_hdr->sh_offset - (hdr->sh_offset + hdr->sh_size);
	}

	auto underlying_segment {sections_segment[hdr]};
	if (!underlying_segment) {
		std::cerr << "Couldn't find segment for section\n";
		hdr->sh_size = new_size;
		return;
	}

	if (available_space >= new_size - hdr->sh_size && hdr->sh_offset + new_size < underlying_segment->p_offset + underlying_segment->p_filesz) {
		hdr->sh_size = new_size; // no need to resize segment;
		return;
	}

	auto new_segment_size {0};
	if (underlying_segment->p_filesz & 0xff)
		new_segment_size = (underlying_segment->p_filesz + 0x1000) & (~0xFFF);
	else
		new_segment_size = underlying_segment->p_filesz & (~0xFFF);
	auto expand_amount = new_segment_size - underlying_segment->p_filesz;

	fix_after_insertion(hdr->sh_offset + hdr->sh_size,
	    expand_amount, expand_amount);

	underlying_segment->p_memsz += expand_amount;
	underlying_segment->p_filesz = new_segment_size;

	hdr->sh_size = new_size;
}

void
elf_file::resize_segment(struct Elf64_Phdr *hdr, uint64_t new_size)
{
	auto segment_index = this->get_segment_index(hdr);
	auto expand_amount = new_size - hdr->p_filesz;

	/* Resize coresponding PT_LOAD segment if needed */
	for (uint64_t i = 0; i < vphdr.size(); ++i) {
		if (segment_index == i)
			continue;

		auto phdr = &vphdr[i];
		if (phdr->p_type != PT_LOAD || hdr->p_type == PT_LOAD)
			continue;

		if (phdr->p_offset <= hdr->p_offset && hdr->p_offset + hdr->p_filesz < phdr->p_offset + phdr->p_filesz) {
			phdr->p_filesz += expand_amount;
			phdr->p_memsz += expand_amount;
		}
	}

	hdr->p_memsz = new_size;
	this->fix_after_insertion(hdr->p_offset + hdr->p_filesz,
	    expand_amount);
	hdr->p_filesz = new_size;
}

uint64_t
elf_file::get_last_available_file_offset()
{
	uint64_t offset = 0;
	for (auto &hdr : vshdr)
		offset = std::max(hdr.sh_offset + hdr.sh_size, offset);
	for (auto &hdr : vphdr)
		offset = std::max(hdr.p_offset + hdr.p_filesz, offset);
	offset = std::max(
	    ehdr.e_phnum * ehdr.e_phentsize + ehdr.e_phoff, offset);
	return offset;
}

uint64_t
elf_file::get_last_available_mem_offset()
{
	uint64_t offset = 0;
	for (auto &hdr : vshdr)
		offset = std::max(hdr.sh_addr + hdr.sh_size, offset);
	for (auto &hdr : vphdr)
		offset = std::max(hdr.p_vaddr + hdr.p_memsz, offset);
	return offset;
}

size_t
elf_file::get_number_of_relocation_sections()
{
	auto num_of_sections {0};
	for (auto &hdr : vshdr) {
		switch (hdr.sh_type) {
		case SHT_RELA:
		case SHT_REL:
			++num_of_sections;
			break;
		}
	}
	return num_of_sections;
}

int
elf_file::get_number_of_relocations_by_type(Elf64_Word type)
{
	auto index {0};
	for (auto &shdr : vshdr) {
		if (shdr.sh_type != type) {
			++index;
			continue;
		}
		return shdr_data[index++].size() / shdr.sh_entsize;
	}
	return 0;
}

int
elf_file::expand_segment(Elf64_Phdr *hdr, size_t expand_amount)
{
	if (!hdr) {
		std::cerr << "Cannot find hdr segment\n";
		return -1;
	}

	this->resize_segment(hdr, hdr->p_filesz + expand_amount);
	return 0;
}

int
elf_file::expand_phdr(size_t expand_amount)
{
	auto phdr = this->get_first_segment_by_type(PT_PHDR);
	if (!phdr) {
		std::cerr << "Cannot find PHDR segment\n";
		return -1;
	}
	auto phdr_left_space = phdr->p_filesz - (ehdr.e_phentsize * ehdr.e_phnum);

	if (phdr_left_space < sizeof(struct Elf64_Phdr))
		this->resize_segment(phdr, phdr->p_filesz + expand_amount);

	std::cout << "· Expanding phdr to 0x" << std::hex << phdr->p_filesz << std::dec << '\n';

	return 0;
}

int
elf_file::add_section(const Elf64_Shdr &new_hdr)
{
	vshdr.push_back(new_hdr);
	++ehdr.e_shnum;

	auto shstrtab = this->get_section(this->get_elf_hdr()->e_shstrndx);
	if (!shstrtab)
		return -1;

	auto &strtab_data {shdr_data[this->get_elf_hdr()->e_shstrndx]};

	section_names[vshdr.size() - 1] = std::string((const char *)&strtab_data[new_hdr.sh_name]);
	return 0;
}

int
elf_file::add_segment(const Elf64_Phdr &new_hdr,
    std::vector<uint8_t> *data = NULL)
{
	auto phdr = this->get_first_segment_by_type(PT_PHDR);
	if (!phdr) {
		std::cerr << "Cannot find PHDR segment\n";
		return -1;
	}
	auto phdr_left_space = phdr->p_filesz - (ehdr.e_phentsize * ehdr.e_phnum);

	if (phdr_left_space < sizeof(struct Elf64_Phdr))
		this->resize_segment(phdr, phdr->p_filesz + 0x1000);

	++ehdr.e_phnum;
	vphdr.push_back(new_hdr);
	struct custom_load_segment custom_segment = {
	    .addr = new_hdr.p_offset,
	    .vaddr = new_hdr.p_vaddr,
	    .hdr_id = vphdr.size() - 1,
	    .data = std::vector<uint8_t>(new_hdr.p_filesz, 0xcc)};

	custom_segments.push_back(custom_segment);

	if (data) {
		auto new_segment {get_custom_segment_by_id(
		    custom_segments.size() - 1)};

		memcpy(&new_segment->data[0],
		    data->data(),
		    new_hdr.p_filesz);
	}

	return 0;
}

std::tuple<int64_t, int64_t>
elf_file::get_shift_offsets_for_insertion(
    elf_file *elf,
    uint64_t alignment = 0x1000)
{
	auto last_mem_off {get_last_available_mem_offset()};
	auto last_foff {get_last_available_file_offset()};
	last_foff += sizeof(struct Elf64_Shdr) * elf->get_number_of_relocation_sections();
	last_mem_off = (last_mem_off + alignment) & (~0xFFF);
	last_foff = (last_foff + alignment) & (~0xFFF);

	auto first_pt_load {elf->get_first_segment_by_type(
	    PT_LOAD)};
	int64_t foff_shift {(int64_t)last_foff - (int64_t)first_pt_load->p_offset};
	int64_t mem_off_shift {(int64_t)last_mem_off - (int64_t)first_pt_load->p_vaddr};

	return {foff_shift, mem_off_shift};
}

std::vector<struct Elf64_Phdr> &
elf_file::get_segments()
{
	return vphdr;
}
std::vector<struct Elf64_Shdr> &
elf_file::get_sections()
{
	return vshdr;
}

std::map<std::string, uint64_t>
elf_file::get_symbols()
{
	auto [symtab, symdata] {get_section_with_data_by_type(SHT_SYMTAB)};
	struct Elf64_Sym *sym = (struct Elf64_Sym *)symdata.data();
	auto exports {get_elf_exports((struct Elf64_Ehdr *)this->get_raw())};
	std::map<std::string, uint64_t> symbols;
	char *strtab = (char *)((uint64_t)exports.ehdr + exports.str->sh_offset);
	for (uint64_t i = 0; i < symdata.size() / sizeof(struct Elf64_Sym);
	     ++i) {

		symbols[&strtab[sym->st_name]] = sym->st_value;
		++sym;
	}
	return symbols;
}

uint32_t
elf_file::add_shstrtab_entry(std::string name)
{
	auto shstrtab = this->get_section(this->get_elf_hdr()->e_shstrndx);
	if (!shstrtab)
		return -1;

	auto &strtab_data {shdr_data[this->get_elf_hdr()->e_shstrndx]};
	for (size_t i = 0; i < strtab_data.size() - name.length(); ++i) {
		if (memcmp(&strtab_data[i], name.c_str(), name.length()) == 0)
			return i;
	}

	auto off {(uint32_t)strtab_data.size()};

	for (auto c : name) {
		strtab_data.push_back(c);
	}
	strtab_data.push_back(0);
	shstrtab->sh_size += name.length() + 1;
	return off;
}

int
elf_file::insert_payload(elf_file *payload_elf)
{
	std::vector<struct Elf64_Rela> rela_entries;
	auto elf_hdr {payload_elf->get_elf_hdr()};
	std::vector<
	    std::pair<struct Elf64_Phdr *, std::vector<uint8_t>>>
	    payload_pt_loads;

	auto pie_text_seg {payload_elf->sections_segment[payload_elf->get_section_by_name(".text")]};
	auto pie_text_seg_index {0};

	std::cout << "· Inserting payload to target executable\n";

	// Save src_elf PT_LOAD segments data
	auto index {0};
	for (auto &hdr : payload_elf->vphdr) {
		if (hdr.p_type != PT_LOAD) {
			continue;
		}
		if (pie_text_seg == &hdr) {
			pie_text_seg_index = index;
		}
		std::vector<uint8_t> data(hdr.p_filesz, 0xCC);
		memcpy(&data[0],
		    payload_elf->get_raw_data() + hdr.p_offset,
		    hdr.p_filesz);
		payload_pt_loads.push_back({&hdr, data});
		++index;
	}

	// Expand phdr segment to insert PT_LOAD segmentes from src elf
	//  + 1 for payload
	expand_phdr((payload_pt_loads.size() + 1) * sizeof(Elf64_Phdr));

	auto src_num_of_rela {payload_elf->get_number_of_relocations_by_type(
	    SHT_RELA)};
	auto rela_dyn {get_first_section_by_type(SHT_RELA)};
	if (src_num_of_rela && !rela_dyn) {
		// TODO: add new rela_dyn section and RELA, RELACOUNT and RELASZ dynamic entry;
		std::cerr << "Cannot find .rela_dyn section\n";
		return -1;
	}

	/* Make place to copy relocations from src to dst elf */
	// TODO Create dyn dynamic segment/.rela.dyn section if doesnt exist
	if (src_num_of_rela) {
		auto org_size {rela_dyn->sh_size};
		auto new_rela_size {
		    rela_dyn->sh_size + src_num_of_rela * sizeof(struct Elf64_Rela)};

		// Resize .rela.dyn to save entries from dst elf later
		resize_section(rela_dyn, new_rela_size);
		rela_dyn->sh_size = org_size;
		auto relocations = get_all_relocations_from_section<
		    struct Elf64_Rela>(SHT_RELA);
		rela_dyn->sh_size = new_rela_size;
		rela_entries.insert(rela_entries.end(),
		    relocations.begin(),
		    relocations.end());
		std::cout << "· Expanding .rela.dyn section to fit payload reloacations: " << std::hex
			  << "0x" << org_size << " => 0x" << new_rela_size << std::dec << '\n';
		expand_section_data(rela_dyn, new_rela_size - org_size);
	}

	// Adjust src payload to place all segments after dst elf segments
	auto [foff_shift, mem_off_shift] {get_shift_offsets_for_insertion(payload_elf)};
	payload_elf->fix_after_insertion(0, foff_shift, mem_off_shift);

	std::cout << "· Copying " << payload_pt_loads.size() << " PT_LOAD segments to target executable\n";
	// Copy PT_LOADs from payload to dst elf
	for (auto [hdr, data] : payload_pt_loads)
		add_segment(*hdr, &data);

	// Add payload segment
	struct Elf64_Phdr payload_hdr = {
	    .p_type = PT_LOAD,
	    .p_flags = PF_R | PF_W | PF_X,
	    .p_offset = (get_last_available_file_offset() + 0x1000) & (~0xFFF),
	    .p_vaddr = (get_last_available_mem_offset() + 0x1000) & (~0xFFF),
	    .p_paddr = (get_last_available_mem_offset() + 0x1000) & (~0xFFF),
	    .p_filesz = 0x00,
	    .p_memsz = 0x00,
	    .p_align = 0x1000,
	};

	add_segment(payload_hdr);

	if (src_num_of_rela) {
		auto relocations = payload_elf->get_all_relocations_from_section<
		    struct Elf64_Rela>(SHT_RELA);
		if (relocations.size())
			rela_entries.insert(rela_entries.end(),
			    relocations.begin(),
			    relocations.end());
		std::cout << "· Applying " << src_num_of_rela << " RELA relocations to target executable\n";
		apply_rela_relocations(payload_elf, rela_entries);
	}

	std::cout << "· Changing entrypoint to payload_init: " << std::hex
		  << "0x" << ehdr.e_entry << " => 0x" << elf_hdr->e_entry << std::dec << '\n';
	set_jmp_from_custom(0xdeadbeef, ehdr.e_entry);
	ehdr.e_entry = elf_hdr->e_entry;

	auto elfprotext = &vphdr[custom_segments[pie_text_seg_index].hdr_id];
	std::cout << "· Adding .elfprotext section, offset: 0x" << std::hex
		  << elfprotext->p_offset << "; size: 0x" << elfprotext->p_filesz << std::dec << "\n\n";
	add_section({
	    .sh_name = add_shstrtab_entry(".elfprotext"),
	    .sh_type = SHT_PROGBITS,
	    .sh_flags = SHF_EXECINSTR | SHF_ALLOC,
	    .sh_addr = elfprotext->p_vaddr,
	    .sh_offset = elfprotext->p_offset,
	    .sh_size = elfprotext->p_filesz,
	    .sh_link = 0,
	    .sh_info = 0,
	    .sh_addralign = 10,
	    .sh_entsize = 0,
	});

	static std::map<uint32_t, std::string> marker_names {
	    {PACKER_PROTECTION, "PACKER_PROTECTION"},
	    {PACKER_ENCRYPTION_PROTECTION, "PACKER_ENCRYPTION_PROTECTION"},
	    {VM_BASIC_PROTECTION, "VM_BASIC_PROTECTION"},
	    {MAX_PROTECTION, "MAX_PROTECTION"},
	};

	std::cout << "\nApplying protection to target executable:\n";
	auto text_sec {get_section_by_name(".text")};
	auto &text_data {*get_section_data(text_sec)};
	for (auto &[off, marker] : get_markers(text_data)) {
		protection *prot = nullptr;

		if (marker_names.find(marker) != marker_names.end())
			std::cout << "\n»Found marker " << marker_names[marker] << " at 0x" << std::hex << (uint64_t)off << std::dec << '\n';

		switch (marker) {
		case PACKER_PROTECTION:
			prot = new packer(this, payload_elf, {off, text_data, text_sec->sh_addr});
			break;
		case PACKER_ENCRYPTION_PROTECTION:
			prot = new packer(this, payload_elf, {off, text_data, text_sec->sh_addr}, true);
			break;
		case VM_BASIC_PROTECTION:
			prot = new virtualizer_basic(this, payload_elf, {off, text_data, text_sec->sh_addr});
			break;
		case MAX_PROTECTION:
			prot = new virtualizer_basic(this, payload_elf, {off, text_data, text_sec->sh_addr}, true);
			break;
		default:
			std::cerr << "Unsupported protection type: 0x" << marker << '\n';
			continue;
		}

		prot->apply();
		delete prot;
	}

	std::cout << "\nApplying protection to payload:\n";
	auto &elfprotext_data {custom_segments[pie_text_seg_index].data};
	for (auto &[off, marker] : get_markers(elfprotext_data)) {
		protection *prot = nullptr;

		if (marker_names.find(marker) != marker_names.end())
			std::cout << "\n»Found marker " << marker_names[marker] << " at 0x" << std::hex << (uint64_t)off << std::dec << '\n';

		switch (marker) {
		case PACKER_PROTECTION:
			prot = new packer(this, payload_elf, {off, elfprotext_data, custom_segments[pie_text_seg_index].vaddr});
			break;
		case PACKER_ENCRYPTION_PROTECTION:
			prot = new packer(this, payload_elf, {off, elfprotext_data, custom_segments[pie_text_seg_index].vaddr}, true);
			break;
		case VM_BASIC_PROTECTION:
			prot = new virtualizer_basic(this, payload_elf, {off, elfprotext_data, custom_segments[pie_text_seg_index].vaddr});
			break;
		case MAX_PROTECTION:
			prot = new virtualizer_basic(this, payload_elf, {off, elfprotext_data, custom_segments[pie_text_seg_index].vaddr}, true);
			break;
		}

		if (!prot) {
			std::cerr << "Unsupported protection type: 0x" << marker << '\n';
			continue;
		}

		prot->apply();
		delete prot;
	}

	/* Move section headers to the end of the tile */
	ehdr.e_shoff = get_last_available_file_offset();
	std::cout << "\nMoving section headers to the end of the file: 0x" << std::hex << ehdr.e_shoff << std::dec << '\n';
	return 0;
}

uint64_t
elf_file::get_marker_from_text(uint32_t marker_value)
{
	auto text_sec {get_section_by_name(".text")};
	auto &text_data {*get_section_data(text_sec)};
	uint8_t *dst_marker {(uint8_t *)find_marker_in_data_new(
	    text_data, marker_value)};
	std::cout << "· dst_marker: " << (uint64_t)dst_marker << '\n';

	return 0;
}

void
elf_file::apply_flags_to_all_segments(uint32_t flags)
{
	for (auto &hdr : vphdr)
		hdr.p_flags = flags;
}

uint8_t *
elf_file::find_marker_in_data_new(std::vector<uint8_t> &data, uint32_t marker_value)
{
	/*                c   o   d   e   m   a   r   k   ?   ?   ?   ?         */
	char marker[] {"\x63\x6f\x64\x65\x6d\x61\x72\x6b\xcc\xcc\xcc\xcc"};
	const size_t marker_len {12};

	if (data.size() < marker_len)
		return nullptr;

	*(uint32_t *)(&marker[8]) = marker_value;
	for (size_t i = 0; i < data.size() - marker_len; ++i) {
		if (*(uint64_t *)&marker[0] != *(uint64_t *)&data[i] || *(uint32_t *)&marker[8] != *(uint32_t *)&data[i + 8])
			continue;

		/* Nop code marker */
		return (uint8_t *)memset(&data[i], 0x90, marker_len);
	}
	return nullptr;
}

std::pair<uint8_t *, uint32_t>
elf_file::get_next_marker(std::vector<uint8_t> &data)
{
	/*                c   o   d   e   m   a   r   k                */
	char marker[] {"\x63\x6f\x64\x65\x6d\x61\x72\x6b"};
	const size_t marker_len {12};

	if (data.size() < marker_len)
		return {nullptr, 0};

	for (size_t i = 0; i < data.size() - marker_len; ++i) {
		if (*(uint64_t *)&marker[0] != *(uint64_t *)&data[i])
			continue;

		auto marker {*(uint32_t *)&data[i + 8]};
		/* Nop code marker */
		return {(uint8_t *)memset(&data[i], 0x90, marker_len), marker};
	}

	return {nullptr, 0};
}

std::vector<std::pair<uint8_t *, uint32_t>>
elf_file::get_markers(std::vector<uint8_t> &data)
{
	std::vector<std::pair<uint8_t *, uint32_t>> markers;
	while (true) {
		auto [addr, marker_value] = get_next_marker(data);
		if (addr == nullptr)
			break;

		markers.push_back({addr, marker_value});
	}
	return markers;
}

void
elf_file::apply_rela_relocations(
    elf_file *elf,
    std::vector<struct Elf64_Rela> &rela_entries)
{
	auto src_rela {elf->get_first_section_by_type(SHT_RELA)};
	auto dt_relacount {get_first_dyn_entry(DT_RELACOUNT)};
	auto rela_dyn {get_first_section_by_type(SHT_RELA)};
	auto dt_realsz {get_first_dyn_entry(DT_RELASZ)};
	auto src_rela_data {elf->get_section_data(src_rela)};
	struct Elf64_Rela *src_rela_entry {
	    (struct Elf64_Rela *)src_rela_data->data()};
	
	if (dt_relacount && dt_realsz) {	
		for (uint64_t i = 0;
			i < src_rela_data->size() / sizeof(struct Elf64_Rela);
			++i) {
			if (rela_get_type(src_rela_entry) == R_X86_64_RELATIVE) {
				++dt_relacount->d_un.d_val;
				dt_realsz->d_un.d_val += sizeof(struct Elf64_Rela);
			}
		}
	}

	auto rela_data {get_section_data(rela_dyn)};
	std::sort(rela_entries.begin(),
	    rela_entries.end(),
	    [](struct Elf64_Rela &x,
		struct Elf64_Rela &y) {
		    return (rela_get_type(&x) > rela_get_type(&y));
	    });
	auto rela_entry {(struct Elf64_Rela *)rela_data->data()};
	for (auto &entry : rela_entries)
		*rela_entry++ = entry;
}

void
elf_file::set_jmp_from_custom(uint32_t marker_value, uint64_t dst)
{
	auto [elf_text_seg, marker] = find_marker_in_custom(marker_value);
	auto &elf_text_seg_data {*get_custom_segment_data(elf_text_seg)};
	if (!marker) {
		std::cerr << "Cannot find marker\n";
		return;
	}
	uint64_t after_jmp = (uint64_t)marker + 4 + 5;
	int32_t *jmp_off = (int32_t *)(after_jmp - 4);
	*jmp_off = dst - (elf_text_seg->p_vaddr + (after_jmp - (uint64_t)&elf_text_seg_data[0]));
}

std::pair<struct Elf64_Phdr *, uint32_t *>
elf_file::find_marker_in_custom(uint32_t marker_value)
{
	for (auto &custom : custom_segments) {
		uint32_t *marker = (uint32_t *)find_marker_in_data(custom.data, marker_value);
		if (!marker)
			continue;
		return {&vphdr[custom.hdr_id], marker};
	}
	return {nullptr, nullptr};
}

void *
elf_file::find_marker_in_data(std::vector<uint8_t> &data, uint32_t marker_value)
{
	if (data.size() < 4)
		return nullptr;
	for (size_t i = 0; i < data.size() - 4; ++i) {
		uint32_t *marker = (uint32_t *)&data[i];
		if (*marker != marker_value)
			continue;
		*marker = 0x90909090;
		return marker;
	}
	return nullptr;
}

struct custom_load_segment *
elf_file::get_custom_segment_by_id(int id)
{
	return &custom_segments[id];
}

std::vector<struct custom_load_segment> &
elf_file::get_custom_segments()
{
	return custom_segments;
}

struct Elf64_Phdr *
elf_file::get_segment_by_id(int id)
{
	return &vphdr[id];
}

Elf64_Phdr *
elf_file::get_segment(const Elf64_Shdr &hdr)
{
	for (auto &phdr : vphdr) {
		if (hdr.sh_offset < phdr.p_offset || hdr.sh_offset >= phdr.p_offset + phdr.p_filesz)
			continue;
		return &phdr;
	}
	return nullptr;
}

uint64_t
elf_file::get_segment_index(struct Elf64_Phdr *hdr)
{
	uint64_t index = 0;
	for (auto &&phdr : vphdr) {
		if (&phdr == hdr)
			break;
		++index;
	}
	return index;
}

uint64_t
elf_file::get_section_index(struct Elf64_Shdr *hdr)
{
	uint64_t index = 0;
	for (auto &&shdr : vshdr) {
		if (&shdr == hdr)
			break;
		++index;
	}
	return index;
}

bool
elf_file::save_to_file(const std::string &fname)
{
	FILE *f = fopen(fname.c_str(), "wb");
	if (!f) {
		std::cerr << "Cannot open file " << fname << " for saving\n";
		return false;
	}

	// save elf header
	fwrite(
	    &ehdr, sizeof(uint8_t), sizeof(struct Elf64_Ehdr), f);

	// save program headers
	fseek(f, ehdr.e_phoff, SEEK_SET);
	for (auto const &phdr : vphdr) {
		fwrite(
		    &phdr, sizeof(uint8_t), sizeof(Elf64_Phdr), f);
	}

	// save section headers
	fseek(f, ehdr.e_shoff, SEEK_SET);
	for (auto const &shdr : vshdr) {
		fwrite(
		    &shdr, sizeof(uint8_t), sizeof(Elf64_Shdr), f);
	}

	for (auto &segment : custom_segments) {
		fseek(f, segment.addr, SEEK_SET);
		fwrite(segment.data.data(),
		    sizeof(uint8_t),
		    segment.data.size(),
		    f);
	}

	// save section data
	int index = 0;
	for (auto const &[shdr, data] : zip(vshdr, shdr_data)) {
		if (shdr.sh_type == SHT_NOBITS) {
			++index;
			continue;
		}
		fseek(f, shdr.sh_offset, SEEK_SET);
		++index;
		fwrite(data.data(), sizeof(uint8_t), shdr.sh_size, f);
	}

	fclose(f);

	return true;
}

std::vector<std::pair<struct Elf64_Phdr *,
    std::vector<struct Elf64_Shdr *>>> &
elf_file::get_segment_mapping()
{
	return segment_mapping;
}
