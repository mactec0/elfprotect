#include "syscall_helpers.h"

static size_t
string_length(const char *t)
{
	size_t len = 0;
	while (*t++)
		++len;
	return len;
}

size_t
sys_read(long file, const char *data, size_t len)
{
	__asm volatile("mov rax, 0\n");
	__asm volatile("mov rdi, %0\n" ::"m"(file));
	__asm volatile("mov rsi, %0\n" ::"m"(data));
	__asm volatile("mov rdx, %0\n" ::"m"(len));
	__asm volatile("syscall\n");
	register long rax __asm("rax");
	return rax;
}

void
sys_write(const char *text)
{
	size_t len = string_length(text);
	__asm volatile("mov rax, 1\n");
	__asm volatile("mov rdi, 1\n"); // screen
	__asm volatile("mov rsi, %0\n" ::"m"(text));
	__asm volatile("mov rdx, %0\n" ::"m"(len));
	__asm volatile("syscall\n");
}

long
sys_open(const char *fname, int flags, umode_t mode)
{
	size_t rsi = (size_t)flags;
	size_t rdx = (size_t)mode;
	__asm volatile("mov rax, 2\n");
	__asm volatile("mov rdi, %0\n" ::"m"(fname));
	__asm volatile("mov rsi, %0\n" ::"m"(rsi));
	__asm volatile("mov rdx, %0\n" ::"m"(rdx));
	__asm volatile("syscall\n");
	register long rax __asm("rax");
	return rax;
}

int32_t
sys_fstat(long fd, void *st)
{
	uint64_t _rdi = fd;
	__asm volatile("mov rax, 5\n");
	__asm volatile("mov rdi, %0\n" ::"m"(_rdi));
	__asm volatile("mov rsi, %0\n" ::"m"(st));
	__asm volatile("syscall\n");
	register int32_t rax __asm("rax");
	return rax;
}

int32_t
sys_lseek(long fd, size_t offset, int whence)
{
	uint64_t _rdi = fd;
	uint64_t _rdx = whence;
	__asm volatile("mov rax, 8\n");
	__asm volatile("mov rdi, %0\n" ::"m"(_rdi));
	__asm volatile("mov rsi, %0\n" ::"m"(offset));
	__asm volatile("mov rdx, %0\n" ::"m"(_rdx));
	__asm volatile("syscall\n");
	register int32_t rax __asm("rax");
	return rax;
}

size_t
sys_close(long f)
{
	__asm volatile("mov rax, 3\n");
	__asm volatile("mov rdi, %0\n" ::"m"(f));
	__asm volatile("syscall\n");
	return 0;
}

void *
sys_mmap(void *addr, size_t len, int prot, int flags, int fd, __off_t offset)
{
	uint64_t _rdx = prot;
	uint64_t _r10 = flags;
	uint64_t _r8 = fd;
	__asm volatile("mov rax, 9\n"); // sys_mmap
	__asm volatile("mov rdi, %0\n" ::"m"(addr));
	__asm volatile("mov rsi, %0\n" ::"m"(len));
	__asm volatile("mov rdx, %0\n" ::"m"(_rdx));
	__asm volatile("mov r8, %0\n" ::"m"(_r8));
	__asm volatile("mov r9, %0\n" ::"m"(offset));
	__asm volatile("mov r10, %0\n" ::"m"(_r10));
	__asm volatile("syscall\n");
	register uint64_t rax __asm("rax");
	return (void *)rax;
}

int
sys_munmap(void *addr, size_t len)
{
	__asm volatile("mov rax, 11\n");
	__asm volatile("mov rdi, %0\n" ::"m"(addr));
	__asm volatile("mov rsi, %0\n" ::"m"(len));
	__asm volatile("syscall\n");
	register int rax __asm("rax");
	return rax;
}

__attribute__((noreturn)) void
sys_exit()
{
	__asm volatile("mov rax, 60\n");
	__asm volatile("syscall\n");
	while (true)
		;
}
