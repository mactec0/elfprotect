#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "../sdk.h"

#define SERIAL_LEN 20

void
pack_test()
{
	PACKER_PROTECTION_START;
	printf("packed_code\n");
	PACKER_PROTECTION_END;
}

void
_pow(int a, int b)
{
	int result = 1;
	MAX_PROTECTION_START;
	for (unsigned int i = 0; i < b; ++i) {
		result *= a;
	}
	MAX_PROTECTION_END;
	printf("pow(%d, %d) = %d\n", a, b, result);
}

void
add_func(int a, int b, int c)
{
	bool minus = (c != 0);
	VIRTUALIZATION_PROTECTION_START;
	if (c == 0)
		c = a + b;
	else
		c = a - b;
	VIRTUALIZATION_PROTECTION_END;

	if (minus)
		printf("%d - %d = %d\n", a, b, c);
	else
		printf("%d + %d = %d\n", a, b, c);
}

uint8_t
char_to_num(char c)
{
	ENCRYPTION_PROTECTION_START;
	if (c >= '0' && c <= '9')
		return c - (uint8_t)'0';
	if (c >= 'A' && c <= 'F')
		return c - (uint8_t)'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - (uint8_t)'a' + 10;
	ENCRYPTION_PROTECTION_END;
	return 0;
}

void
stoi(const char *str, int8_t size, uint8_t base)
{
	ENCRYPTION_PROTECTION_START;
	uint32_t x = 1;
	uint32_t ret = 0;
	for (int8_t i = size - 1; i >= 0; --i) {
		ret += char_to_num(str[i]) * x;
		x *= base;
	}
	printf("stoi(%s, %u, %u) = %u\n", str, (uint32_t)size, (uint32_t)base, ret);
	ENCRYPTION_PROTECTION_END;
}

void print_serial(const char *login)
{
	int serial[SERIAL_LEN + 1] = {0};
	char charset[] = {"POIUYTREWQASDFGHJKLMNBVCXZ0987654321"};
	long charset_len = strlen(charset);
	long len = strlen(login);
	MAX_PROTECTION_START;
	for (int32_t i = 0; i < SERIAL_LEN; ++i)
		serial[i] = charset[(login[(i + 1) % len] ^ login[(3 * i) % len] + i * len) % charset_len];
	MAX_PROTECTION_END;

	PACKER_PROTECTION_START;
	printf("Serial for %s: ", login);
	for (uint32_t i = 0; i < SERIAL_LEN; ++i) {
		putchar(serial[i]);
		if ((i + 1) % 4 == 0 && i < SERIAL_LEN - 1)
			putchar('-');
	}
	printf("\n");
	PACKER_PROTECTION_END;
}

int
main()
{
	srand(time(NULL));

	printf("> test app start\n");

	pack_test();

	add_func(18, 28, 0);
	add_func(18, 6, 0);
	add_func(18, 6, 1);
	add_func(18, 28, 0);

	_pow(2, 1);
	_pow(2, 2);
	_pow(2, 3);
	_pow(2, 4);

	char hnum[2] = "ff";
	stoi(hnum, 2, 16);

	_pow(2, 10);

	print_serial("user123");
	print_serial("login_5");

	printf("> test app exit\n");

	return 0;
}
