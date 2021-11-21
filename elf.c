#include "elf.h"

unsigned char
get_file_class(struct Elf64_Ehdr *ehdr)
{
	return ehdr->e_ident[EI_CLASS];
}

bool
check_magic(struct Elf64_Ehdr *ehdr)
{
	return (memcmp(ehdr->e_ident, ElfMagic, strlen(ElfMagic))) == 0;
}

Elf64_Word
rela_get_type(struct Elf64_Rela *rela)
{
	return (Elf64_Word)(rela->r_info & 0xffffffffL);
}
