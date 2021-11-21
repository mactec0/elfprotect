#pragma once

#include <stdint.h>

void
encrypt(uint8_t *code, uint64_t unpacked_len, uint64_t packed_len);

void
decrypt(uint8_t *code, uint64_t unpacked_len, uint64_t packed_len);
