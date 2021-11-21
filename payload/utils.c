#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "syscall_helpers.h"
#include "utils.h"

char *
load_file(const char *fname, size_t *size)
{
	struct stat st;
	long fd = sys_open(fname, 0, 0x400);
	if (fd < 0) {
		sys_write("Cannot open file [");
		sys_write(fname);
		sys_write("]\n");
		return NULL;
	}
	if (sys_fstat(fd, &st) < 0) {
		sys_write("Cannot stat file [");
		sys_write(fname);
		sys_write("]\n");
		sys_close(fd);
		return NULL;
	}

	if (size != NULL)
		*size = st.st_size;

	char *buffer = sys_mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	sys_close(fd);
	return buffer;
}
