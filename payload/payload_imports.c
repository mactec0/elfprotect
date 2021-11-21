#include <stdio.h>

#include "../elf.h"
#include "payload_imports.h"
#include "syscall_helpers.h"
#include "utils.h"

_printf oprintf;
_malloc omalloc;
_realloc orealloc;
_free ofree;
_time otime;
_rand_r orand_r;

#ifdef INJECTABLE

int
printf(const char *format, ...)
{
	int ret;
	va_list args;
	__builtin_va_start(args, format);
	ret = oprintf(format, args);
	__builtin_va_end(args);
	return ret;
}

void *
malloc(size_t size)
{
	return omalloc(size);
}

void *
realloc(void *m, size_t size)
{
	return orealloc(m, size);
}

void
free(void *m)
{
	return ofree(m);
}

time_t
time(time_t *t)
{
	return otime(t);
}

int
rand_r(unsigned int *seedp)
{
	return orand_r(seedp);
}

void
__assert_fail(__attribute__((unused)) const char *__assertion,
    __attribute__((unused)) const char *__file,
    __attribute__((unused)) unsigned int __line,
    __attribute__((unused)) const char *__function)
{
	sys_write("__assert_fail\n");
	sys_exit(0);
}

void *
memset(void *dest, int val, size_t len)
{
	unsigned char *ptr = dest;
	while (len-- > 0)
		*ptr++ = val;
	return dest;
}

void *
memcpy(void *dest, const void *src, size_t len)
{
	char *d = dest;
	const char *s = src;
	while (len--)
		*d++ = *s++;
	return dest;
}

int
memcmp(const void *str1, const void *str2, size_t count)
{
	const unsigned char *s1 = str1;
	const unsigned char *s2 = str2;

	while (count-- > 0) {
		if (*s1++ != *s2++)
			return s1[-1] < s2[-1] ? -1 : 1;
	}
	return 0;
}

#endif

long unsigned int
strlen(const char *str)
{
	long unsigned int count = 0;
	while (*str++)
		++count;
	return count;
}

int
strcmp(const char *s1, const char *s2)
{
	while (*s1 && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

bool
text_contain(const char *s1, const char *s2)
{
	while (*s1) {
		if (*s1++ != *s2++)
			return false;
	}
	return true;
}

static struct Elf64_Shdr *
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

static struct elf_exports
get_elf_exports(struct Elf64_Ehdr *ehdr)
{
	struct elf_exports exports = {
	    .ehdr = ehdr,
	    .str = get_shdr_by_name(ehdr, ".strtab"),
	    .symtab = get_shdr_by_name(ehdr, ".symtab")};

	if (!exports.str || !exports.symtab) {
		exports.str = get_shdr_by_name(ehdr, ".dynstr");
		exports.symtab = get_shdr_by_name(ehdr, ".dynsym");
	}
	return exports;
}

uint64_t
find_export(const char *name, const struct elf_exports *exports)
{
	char *strtab = (char *)((uint64_t)exports->ehdr + exports->str->sh_offset);
	for (size_t i = 0;
	     i < (exports->symtab->sh_size / sizeof(struct Elf64_Sym));
	     ++i) {
		struct Elf64_Sym *sym_entry = (struct Elf64_Sym *)((uint64_t)exports->ehdr
		    + exports->symtab->sh_offset + i * sizeof(struct Elf64_Sym));

		if (strcmp(&strtab[sym_entry->st_name], name) == 0) {
			return sym_entry->st_value;
		}
	}
	return 0;
}

uint64_t
get_module_base(const char *module_path)
{
	uint64_t offset = 0;
	uint64_t pow = 1;
	long self_maps = sys_open("/proc/self/maps", 0, 0x400); // S_IRUSR
	if (self_maps < 0) {
		return 0;
	}

	uint64_t last_addr_off = 0;
	bool line_found = false;
#define data_len 2048
	char data[data_len] = {0};
	size_t read_pointer = 0;
	while (!line_found) {
		sys_lseek(self_maps, read_pointer, SEEK_SET);
		size_t read = sys_read(self_maps, data, data_len);
		for (size_t i = 0; i < read; ++i) {
			if (data[i] == '\n') {
				last_addr_off = i + 1;
			}
			if (text_contain(module_path, &data[i])) {
				line_found = true;
				break;
			}
		}

		// find begging of last line
		int32_t i = read - 1;
		while (i >= 0 && data[i--] != '\n')
			;
		read_pointer += i;

		if (!line_found) {
			if (i == 0) {
				sys_close(self_maps);
				return 0;
			}
			memset(data, 0, data_len);
		}
	}

	while (data[++last_addr_off] != '-')
		;
	--last_addr_off;
	sys_close(self_maps);

	char char_value(char c)
	{
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		return 0;
	}

	while (data[last_addr_off] != '\n') {
		offset += pow * char_value(data[last_addr_off--]);
		pow *= 16;
	}

	return offset;
}

int
init_imports()
{
	struct elf_exports libc_exports;
	struct Elf64_Ehdr *libc_hdr;
	size_t libc_size;

	uint64_t libc = get_module_base("/usr/lib/libc.so");
	if (!libc) {
		sys_write("ERROR: Seems like libc isn't loaded\n");
		return -1;
	}

	libc_hdr = (struct Elf64_Ehdr *)load_file("/usr/lib/libc.so.6", &libc_size);
	if (!libc_hdr) {
		sys_write("ERROR: Cannot read libc.so.6\n");
		return -1;
	}

	libc_exports = get_elf_exports(libc_hdr);

	oprintf = (_printf)(libc + find_export("vprintf", &libc_exports));
	omalloc = (_malloc)(libc + find_export("malloc", &libc_exports));
	ofree = (_free)(libc + find_export("free", &libc_exports));
	orealloc = (_realloc)(libc + find_export("realloc", &libc_exports));
	otime = (_time)(libc + find_export("time", &libc_exports));
	orand_r = (_rand_r)(libc + find_export("rand_r", &libc_exports));

	sys_munmap(libc_hdr, libc_size);
	return 0;
}
