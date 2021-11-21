#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef unsigned short umode_t;

size_t sys_read(long file, const char *data, size_t len);

void sys_write(const char *text);

long sys_open(const char *fname, int flags, umode_t mode);

int32_t sys_fstat(long fd, void *st);

int32_t sys_lseek(long fd, size_t offset, int whence);

size_t sys_close(long f);

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, __off_t offset);

int sys_munmap(void *addr, size_t len);

__attribute__((noreturn)) void sys_exit();
