#pragma once

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <vector>

extern "C" {
#include "elf.h"
}
#include "libs/miniz.h"

/* Elf utils */

struct elf_exports {
	struct Elf64_Ehdr *ehdr;
	struct Elf64_Shdr *str;
	struct Elf64_Shdr *symtab;
};

struct custom_load_segment {
	uint64_t addr;
	uint64_t vaddr;
	size_t hdr_id;
	std::vector<uint8_t> data;
};

class elf_file {
	struct Elf64_Ehdr ehdr;
	std::vector<struct Elf64_Phdr> vphdr;
	std::vector<struct Elf64_Shdr> vshdr;
	std::vector<std::vector<uint8_t>> shdr_data;
	std::map<int, std::string> section_names;

	std::vector<std::pair<struct Elf64_Phdr *,
	    std::vector<struct Elf64_Shdr *>>>
	    segment_mapping;

	std::map<struct Elf64_Shdr *, struct Elf64_Phdr *>
	    sections_segment;

	std::vector<struct custom_load_segment> custom_segments;

	uint8_t *data;
	uint64_t raw_size;
	bool parsed;
	bool loaded;

protected:
	uint8_t *get_raw_data() { return data; }
	uint64_t get_raw_size() { return raw_size; }

	bool load_file(const std::string &filename);

	virtual void parse();

public:
	elf_file(const std::string &filename);

	struct Elf64_Ehdr *get_header();

	uint8_t *get_raw();

	struct Elf64_Ehdr *get_elf_hdr();

	struct Elf64_Shdr *get_section(uint32_t i);

	struct Elf64_Shdr *get_section_by_name(const std::string &name);

	struct Elf64_Phdr *get_program_header(uint32_t i);

	struct Elf64_Shdr *get_first_section_by_type(uint32_t type);

	std::pair<struct Elf64_Shdr *, std::vector<uint8_t>> get_section_with_data_by_type(uint32_t type);

	/* SEGMENT methods */
	struct Elf64_Phdr *get_first_segment_by_type(uint32_t type);

	void print_phdr_info();

	void print_shdr_info();

	template <class reloc_t>
	void fix_relocations(int index,
	    uint64_t insertion_offset,
	    int64_t foff_shift,
	    int64_t moff_shift);

	void fix_symbols(int index,
	    uint64_t insertion_offset,
	    int64_t foff_shift,
	    __attribute__((unused)) int64_t moff_shift);

	struct Elf64_Dyn *get_first_dyn_entry(Elf32_Sword d_tag);

	void fix_dynamic(int index,
	    uint64_t insertion_offset,
	    __attribute__((unused)) int64_t foff_shift,
	    int64_t moff_shift);

	void fix_after_insertion(uint64_t insertion_offset,
	    int64_t foff_shift,
	    int64_t moff_shift);

	std::vector<uint8_t> *get_section_data(struct Elf64_Shdr *hdr);

	std::vector<uint8_t> *get_custom_segment_data(struct Elf64_Phdr *hdr);

	struct Elf64_Phdr *get_next_segment(struct Elf64_Phdr *hdr);

	struct Elf64_Shdr *get_next_section(struct Elf64_Shdr *hdr);

	void expand_section_data(struct Elf64_Shdr *hdr, uint64_t expand);

	template <typename T>
	std::vector<T> get_all_relocations_from_section(Elf64_Word sh_type);

	void resize_section(struct Elf64_Shdr *hdr, uint64_t new_size);

	void resize_segment(struct Elf64_Phdr *hdr, uint64_t new_size);

	uint64_t get_last_available_file_offset();

	uint64_t get_last_available_mem_offset();

	size_t get_number_of_relocation_sections();

	int get_number_of_relocations_by_type(Elf64_Word type);

	int expand_segment(Elf64_Phdr *hdr, size_t expand_amount);

	int expand_phdr(size_t expand_amount);

	int add_section(const struct Elf64_Shdr &new_hdr);

	int add_segment(const Elf64_Phdr &new_hdr,
	    std::vector<uint8_t> *data);

	std::tuple<int64_t, int64_t> get_shift_offsets_for_insertion(
	    elf_file *elf,
	    uint64_t alignment);

	std::vector<struct Elf64_Phdr> &get_segments();
	std::vector<struct Elf64_Shdr> &get_sections();

	std::map<std::string, uint64_t> get_symbols();

	uint32_t add_shstrtab_entry(std::string name);

	int insert_payload(elf_file *elf);

	uint64_t get_marker_from_text(uint32_t marker_value);

	void apply_flags_to_all_segments(uint32_t flags);

	uint8_t *find_marker_in_data_new(std::vector<uint8_t> &data, uint32_t marker_value);

	std::pair<uint8_t *, uint32_t> get_next_marker(std::vector<uint8_t> &data);

	std::vector<std::pair<uint8_t *, uint32_t>> get_markers(std::vector<uint8_t> &data);

	void apply_rela_relocations(
	    elf_file *elf,
	    std::vector<struct Elf64_Rela> &rela_entries);

	void set_jmp_from_custom(uint32_t marker_value, uint64_t dst);

	std::pair<struct Elf64_Phdr *, uint32_t *> find_marker_in_custom(uint32_t marker_value);

	void *find_marker_in_data(std::vector<uint8_t> &data, uint32_t marker_value);

	struct custom_load_segment *get_custom_segment_by_id(int id);

	std::vector<struct custom_load_segment> &get_custom_segments();

	struct Elf64_Phdr *get_segment_by_id(int id);

	Elf64_Phdr *get_segment(const struct Elf64_Shdr &hdr);

	uint64_t get_segment_index(struct Elf64_Phdr *hdr);

	uint64_t get_section_index(struct Elf64_Shdr *hdr);

	bool save_to_file(const std::string &fname);

	std::vector<std::pair<struct Elf64_Phdr *,
	    std::vector<struct Elf64_Shdr *>>> &
	get_segment_mapping();

	bool is_parsed() { return parsed; }
	bool is_loaded() { return loaded; }

	friend class packer;
	friend class virtualizer_basic;
};
