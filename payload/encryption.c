#include "encryption.h"
#include "../sdk.h"

void
encrypt(uint8_t *code, uint64_t unpacked_len, uint64_t packed_len)
{
	VIRTUALIZATION_PROTECTION_START;
	uint8_t key[33] = {"f13d2008345c1f4777550afead356ee0"};
	uint8_t sum = (uint8_t)(unpacked_len % 255);
	uint8_t last_value = (uint8_t)(packed_len % 255);
	for (size_t i = 0; i < unpacked_len; ++i) {
		uint8_t old = *code;
		uint64_t len = i % 2 ? unpacked_len : packed_len;
		(*code) -= i + sum;
		(*code) ^= ((i + last_value) % 255) ^ ((len - (i + 1)) % 255);
		(*code) += last_value;
		(*code) ^= (sum + key[i % 32]) % 255;
		sum += old;
		last_value = old;
		++code;
	}
	VIRTUALIZATION_PROTECTION_END;
}

void
decrypt(uint8_t *code, uint64_t unpacked_len, uint64_t packed_len)
{
	VIRTUALIZATION_PROTECTION_START;
	uint8_t key[33] = {"f13d2008345c1f4777550afead356ee0"};
	uint8_t sum = (uint8_t)(unpacked_len % 255);
	uint8_t last_value = (uint8_t)(packed_len % 255);
	for (size_t i = 0; i < unpacked_len; ++i) {
		uint64_t len = i % 2 ? unpacked_len : packed_len;
		(*code) ^= (sum + key[i % 32]) % 255;
		(*code) -= last_value;
		(*code) ^= ((i + last_value) % 255) ^ ((len - (i + 1)) % 255);
		(*code) += i + sum;
		sum += *code;
		last_value = *code;
		++code;
	}
	VIRTUALIZATION_PROTECTION_END;
}
