#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef INJECTABLE

int printf(const char *format, ...);
void *malloc(size_t size);
void *realloc(void *m, size_t size);
void free(void *m);
time_t time(time_t *t);
int rand_r(unsigned int *seedp);

#endif

typedef int (*_printf)(const char *format, va_list arg);
extern _printf oprintf;

typedef void *(*_malloc)(size_t);
extern _malloc omalloc;

typedef void *(*_realloc)(void *, size_t);
extern _realloc orealloc;

typedef void (*_free)(void *);
extern _free ofree;

typedef time_t (*_time)(time_t *);
extern _time otime;

typedef int (*_rand_r)(unsigned int *seedp);
extern _rand_r orand_r;

long unsigned int strlen(const char *str);

int strcmp(const char *s1, const char *s2);

void *memset(void *dest, int val, size_t len);

void *memcpy(void *dest, const void *src, size_t len);

int memcmp(const void *str1, const void *str2, size_t count);

bool text_contain(const char *s1, const char *s2);

struct elf_exports {
	struct Elf64_Ehdr *ehdr;
	struct Elf64_Shdr *str;
	struct Elf64_Shdr *symtab;
};

uint64_t find_export(const char *name, const struct elf_exports *exports);

uint64_t get_module_base(const char *module_path);

int init_imports();
