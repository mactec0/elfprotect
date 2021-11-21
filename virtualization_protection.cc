#include "virtualization_protection.hh"
#include "dispatcher/vm_entry_dispatcher.h"

extern "C" {
#include "payload/encryption.h"
}

static int
disasm_dump(const std::vector<uint8_t> &data)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	ZyanU64 runtime_address = 0x00400000;
	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	std::cout << "——————————————————————————————————————————————————\n";

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data.data() + offset, data.size() - offset,
	    &instruction, operands, ZYDIS_MAX_OPERAND_COUNT, 0))) {
		std::cout << "> 0x" << std::setfill('0') << std::setw(6)
			  << std::hex << runtime_address << std::dec << " │  ";

		char instr_text[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
		    instruction.operand_count_visible, instr_text, sizeof(instr_text), runtime_address);
		puts(instr_text);

		offset += instruction.length;
		runtime_address += instruction.length;
	}
	std::cout << "——————————————————————————————————————————————————\n";

	return 0;
}

static uint32_t
dist_to_marker(uint8_t *src, uint32_t marker, uint32_t max_diff = 0xFFF)
{
	uint32_t diff = 0;
	while (*(uint32_t *)src++ != marker) {
		if (++diff >= max_diff)
			return -1;
	}
	return diff;
}

virtualizer_basic::virtualizer_basic(elf_file *elf, elf_file *payload, std::tuple<uint8_t *, std::vector<uint8_t> &, uint64_t> marker, bool encryption)
    : target(elf)
    , payload(payload)
    , marker(marker)
    , encryption(encryption)
{
}

virtualizer_basic::~virtualizer_basic()
{
}

void
virtualizer_basic::apply()
{
	auto &[src_marker, text_data, sh_addr] = marker;
	auto pie_symbols {payload->get_symbols()};
	auto payload_text {target->get_segment(*target->get_section_by_name(".elfprotext"))};
	auto dispatcher_seg = target->get_segment_by_id(target->get_custom_segments().back().hdr_id);
	auto &dispatcher_data {*target->get_custom_segment_data(dispatcher_seg)};

	auto align_symbols = [](std::map<std::string, uint64_t> &symbols, int64_t shift) -> void {
		for (auto &[name, value] : symbols)
			value += shift;
	};
	align_symbols(pie_symbols, payload_text->p_vaddr - payload->sections_segment[payload->get_section_by_name(".text")]->p_offset);

	int32_t *jmp_off = (int32_t *)((uint64_t)src_marker + 12 + 1); // marker_len + addr off in rel32 jmp

	uint8_t *hide_marker = (uint8_t *)src_marker;
	while (*(uint32_t *)hide_marker != VIRTUALIZATION_MARKER_END) {
		++hide_marker;
	}

	uint8_t *code_start = (uint8_t *)src_marker + 0x11; // marker_len(3*4) + jmp_len(5) = 0x11
	std::vector<uint8_t> code((size_t)dist_to_marker(code_start, VIRTUALIZATION_MARKER_END, text_data.size()), 0x00);
	if (code.size() == 0) {
		std::cerr << "Failed to compile bytecode.\n";
		return;
	}
	memcpy(code.data(), code_start, code.size());

	std::cout << "Selected assembly code(size: " << code.size() << "B):\n";
	disasm_dump(code);

	std::vector<instruction_entry> vm_instructions;
	if (compile_to_bytecode(code, vm_instructions) < 0) {
		std::cerr << "Failed to compile bytecode.\n";
		return;
	}

	std::cout << "\nCompiled bytecode:\n——————————————————————————————————————————————————\n";
	dump_bytecode(vm_instructions);
	std::cout << "——————————————————————————————————————————————————\n";

	uint32_t i = 0;
	std::vector<uint8_t> bytecode(vm_instructions.size() * sizeof(instruction_entry), 0);
	for (auto &instr : vm_instructions)
		*(instruction_entry *)(&bytecode[i++ * sizeof(instruction_entry)]) = instr;

	if (encryption) {
		mz_ulong cmp_len = compressBound(bytecode.size());
		uint64_t old_size = bytecode.size();
		std::vector<uint8_t> packed_data(cmp_len);
		int cmp_status = compress(packed_data.data(), &cmp_len, (const unsigned char *)bytecode.data(), bytecode.size());
		if (cmp_status != Z_OK) {
			std::cerr << "Failed to compress bytecode.\n";
			return;
		}
		bytecode.assign(packed_data.begin(), packed_data.end());

		uint64_t end_marker = BYTECODE_END;
		bytecode.insert(bytecode.end(), (uint8_t *)&old_size, ((uint8_t *)&old_size) + 8);
		bytecode.insert(bytecode.end(), (uint8_t *)&end_marker, ((uint8_t *)&end_marker) + 8);
		encrypt(bytecode.data(), old_size, packed_data.size());
	}

	*(uint32_t *)hide_marker = 0x90909090; // 4x nop

	auto call_ret_addr = dispatcher_seg->p_vaddr + (uint64_t)dispatcher_data.size() + 0x39; // instructino after call off

	for (uint8_t *p = src_marker + 17; p < hide_marker; ++p)
		*p = (uint8_t)(rand() % 255);

	// JMP to shellcode
	*jmp_off = (dispatcher_seg->p_vaddr + dispatcher_data.size()) - (sh_addr + ((uint64_t)src_marker - (uint64_t)&text_data[0]) + 17);

	struct _vm_entry_dispatcher {
		char _pad0[43];
		int32_t bytecode_off;
		char _pad1[6];
		int32_t vm_entry;
		char _pad5[37];
		int32_t jmp_back_rel_addr;
	} __attribute__((packed));

	struct _vm_entry_dispatcher *payload = (struct _vm_entry_dispatcher *)vm_entry_dispatcher;
	payload->bytecode_off = 62;
	int32_t vm_entry_addr {(int32_t)pie_symbols[(encryption ? "vm_entry_encrypted" : "vm_entry")]};
	payload->vm_entry = vm_entry_addr - (int32_t)call_ret_addr;
	payload->jmp_back_rel_addr = (sh_addr + ((uint64_t)(hide_marker + 4) - (uint64_t)&text_data[0]))
	    - (dispatcher_seg->p_vaddr + dispatcher_data.size() + vm_entry_dispatcher_len);

	dispatcher_seg->p_filesz += vm_entry_dispatcher_len;
	dispatcher_seg->p_memsz += vm_entry_dispatcher_len;
	dispatcher_data.insert(dispatcher_data.end(),
	    vm_entry_dispatcher, vm_entry_dispatcher + vm_entry_dispatcher_len);

	dispatcher_seg->p_filesz += bytecode.size();
	dispatcher_seg->p_memsz += bytecode.size();
	dispatcher_data.insert(dispatcher_data.end(),
	    bytecode.begin(), bytecode.end());
}
