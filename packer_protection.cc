#include "packer_protection.hh"
#include "dispatcher/unpack_dispatcher.h"

extern "C" {
#include "payload/encryption.h"
}

packer::packer(elf_file *elf, elf_file *payload, std::tuple<uint8_t *, std::vector<uint8_t> &, uint64_t> marker, bool encryption)
    : target(elf)
    , payload(payload)
    , marker(marker)
    , encryption(encryption)
{
}

packer::~packer()
{
}

void
packer::apply()
{
	auto &[src_marker, text_data, sh_addr] = marker;
	auto unpacked_code_start {src_marker + 12 + 5};
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
	while (*(uint32_t *)hide_marker != HIDDEN_CODE_END)
		++hide_marker;
	*(uint32_t *)hide_marker = 0x90909090;

	auto call_ret_addr = dispatcher_seg->p_vaddr + (uint64_t)dispatcher_data.size() + 0x36 + 12;

	std::vector<uint8_t> unpacked_data;
	for (uint8_t *p = src_marker + 17; p < hide_marker; ++p)
		unpacked_data.push_back(*p);

	std::cout << "Selected code size: " << unpacked_data.size() << "B\n";

	mz_ulong cmp_len = compressBound(unpacked_data.size());
	std::vector<uint8_t> packed_data(cmp_len);
	int cmp_status = compress(packed_data.data(), &cmp_len, (const unsigned char *)unpacked_data.data(), unpacked_data.size());
	if (cmp_status != Z_OK) {
		std::cerr << "ERROR: Failed to compress code\n";
		return;
	}

	if (cmp_len < packed_data.size())
		packed_data.resize(cmp_len);

	if (encryption)
		encrypt(packed_data.data(), unpacked_data.size(), cmp_len);

	// overwrite orginal code with random data
	for (uint8_t *p = src_marker + 17; p < hide_marker; ++p)
		*p = (uint8_t)(rand() % 255);

	*(int32_t *)((uint8_t *)hide_marker + 5) = unpacked_data.size(); // erase_len

	// JMP to shellcode
	*jmp_off = (dispatcher_seg->p_vaddr + dispatcher_data.size()) - (sh_addr + ((uint64_t)src_marker - (uint64_t)&text_data[0]) + 17);


	struct _unpack_dispatcher {
		char _pad0[35];
		int32_t dst_off;
		char _pad1[3];
		int8_t src_off;
		char _pad2[3];
		uint32_t unpacked_len;
		char _pad3[7];
		uint32_t packed_len;
		char _pad4;
		int32_t unpack_rel_addr;
		char _pad5[25];
		int32_t jmp_back_rel_addr;
	} __attribute__((packed));

	struct _unpack_dispatcher *payload = (struct _unpack_dispatcher *)unpack_dispatcher;
	uint64_t rel_dst_code = (dispatcher_seg->p_vaddr + dispatcher_data.size() + 0x1c)
	    - (sh_addr + ((uint64_t)src_marker - (uint64_t)&text_data[0]) + 0x11);
	payload->dst_off = -rel_dst_code;
	payload->unpacked_len = unpacked_data.size();
	payload->packed_len = cmp_len;

	int32_t unpack_addr {(int32_t)pie_symbols[(encryption ? "unpack_decrypt_code" : "unpack_code")]};
	payload->unpack_rel_addr = (int32_t)unpack_addr - (int32_t)call_ret_addr;
	payload->jmp_back_rel_addr = (sh_addr + ((uint64_t)unpacked_code_start - (uint64_t)&text_data[0]))
	    - (dispatcher_seg->p_vaddr + dispatcher_data.size() + unpack_dispatcher_len);

	dispatcher_seg->p_filesz += unpack_dispatcher_len;
	dispatcher_seg->p_memsz += unpack_dispatcher_len;
	for (size_t i = 0; i < unpack_dispatcher_len; ++i) {
		dispatcher_data.push_back(unpack_dispatcher[i]);
	}

	dispatcher_seg->p_filesz += cmp_len;
	dispatcher_seg->p_memsz += cmp_len;
	for (size_t i = 0; i < cmp_len; ++i) {
		dispatcher_data.push_back(packed_data[i]);
	}
}
