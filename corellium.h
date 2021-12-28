#ifndef __CORELLIUM_H__
#define __CORELLIUM_H__

unsigned long get_kernel_addr(unsigned phys);

#define UNICOPY_DST_USER 0
#define UNICOPY_DST_KERN 1
#define UNICOPY_DST_PHYS 2
#define UNICOPY_SRC_USER 0
#define UNICOPY_SRC_KERN 4
#define UNICOPY_SRC_PHYS 8
size_t unicopy(unsigned mode, uintptr_t dst, uintptr_t src, size_t
size);

void corellium_log(const char *str);

#endif
