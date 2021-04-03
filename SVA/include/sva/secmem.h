/*===- secmem.h - SVA secure memory utilities -------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2019.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header file contains definitions for various constants and utilities
 * relating to SVA's secure memory.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_SECMEM_H
#define _SVA_SECMEM_H

/*
 * We want these constants to have the `UL` suffix when used in C, but we also
 * want them to be usable from assembly. These macros allow us to attach the
 * suffix only when preprocessing C code.
 */
#ifdef __ASSEMBLER__
#define _ASM_CONST(value, suffix) value
#else
#define __ASM_CONST(value, suffix) value ## suffix
#define _ASM_CONST(value, suffix) __ASM_CONST(value, suffix)
#endif

#if !(defined(XEN) || defined(__XEN__))

/* Start and end addresses of the secure memory (512GB) */
#define SECMEMSTART _ASM_CONST(0xfffffd0000000000, UL)
#define SECMEMEND   _ASM_CONST(0xfffffd8000000000, UL)

/* Start and end addresses of the SVA direct mapping (512GB) */
#define SVADMAPSTART _ASM_CONST(0xfffffd8000000000, UL)
#define SVADMAPEND   _ASM_CONST(0xfffffe0000000000, UL)

/* Start and end addresses of the kernel's direct map (1TB) */
#define KERNDMAPSTART _ASM_CONST(0xfffffe0000000000, UL)
#define KERNDMAPEND   _ASM_CONST(0xffffff0000000000, UL)

#else /* !XEN */

/* Start and end addresses of the secure memory (2TB) */
#define SECMEMSTART _ASM_CONST(0xffff860000000000, UL)
#define SECMEMEND   _ASM_CONST(0xffff880000000000, UL)
#define SECMEMSIZE  (SECMEMEND - SECMEMSTART)

/* Start and end addresses of SVA VM internal memory (0.5TB) */
#define SVAVMMEMSTART _ASM_CONST(0xffff860000000000, UL)
#define SVAVMMEMEND   _ASM_CONST(0xffff868000000000, UL)
#define SVAVMMEMSIZE  (SVAVMMEMEND - SVAVMMEMSTART)

/* Start and end addresses of the user ghost memory (0.5TB) */
#define GHOSTMEMSTART _ASM_CONST(0xffff868000000000, UL)
#define GHOSTMEMEND   _ASM_CONST(0xffff870000000000, UL)
#define GHOSTMEMSIZE  (GHOSTMEMEND - GHOSTMEMSTART)

/* Start and end addresses of the SVA direct mapping (1TB) */
#define SVADMAPSTART _ASM_CONST(0xffff870000000000, UL)
#define SVADMAPEND   _ASM_CONST(0xffff880000000000, UL)
#define SVADMAPSIZE (SVADMAPEND - SVADMAPSTART)

/* Start and end addresses of Xen's memory (6TB) */
#define KERNELSTART _ASM_CONST(0xffff800000000000, UL)
#define KERNELEND   _ASM_CONST(0xffff860000000000, UL)
#define KERNELSIZE  (KERNELEND - KERNDMAPSTART)

/* Start and end addresses of Xen's direct map (3TB) */
#define KERNDMAPSTART _ASM_CONST(0xffff830000000000, UL)
#define KERNDMAPEND   _ASM_CONST(0xffff860000000000, UL)
#define KERNDMAPSIZE  (KERNDMAPEND - KERNDMAPSTART)

/* Start address of PV guest memory (120TB) */
#define GUESTSTART _ASM_CONST(0xffff880000000000, UL)
#define GUESTSIZE  (_ASM_CONST(0, UL) - GUESTSTART)
/* Guest memory ends at the end of the address space */

#endif /* !XEN */

/* Start and end addresses of user memory (128TB) */
#define USERSTART _ASM_CONST(0x0000000000000000, UL)
#define USEREND   _ASM_CONST(0x0000800000000000, UL)

#ifndef __ASSEMBLER__

#include <sva/types.h>

struct SVAThread;

/**
 * Check whether this virtual address is in the ghost memory region
 */
static inline bool is_ghost_addr(uintptr_t va) {
  return va >= GHOSTMEMSTART && va < GHOSTMEMEND;
}

/**
 * Determine if a virtual address is within the secure memory region.
 *
 * @param p The virtual address to test
 * @return  Whether or not `p` is in the secure memory region
 */
static inline bool is_secure_memory_addr(uintptr_t p) {
  return SECMEMSTART <= p && p < SECMEMEND;
}

void ghostFree(struct SVAThread* tp, void* p, size_t size);

/**
 * Create a new stack in secure memory.
 *
 * The new stack will have a guard page above it (lower virtual address).
 *
 * NB: If the returned stack is sent to another CPU with weaker than
 * acquire-release synchronization, the other CPU is not guaranteed to see the
 * page table updates that map the new stack.
 *
 * @return  A pointer to the *bottom* of the new stack (highest virtual address)
 *          or NULL if unsuccessful
 */
void* create_sva_stack(void);

#endif /* !__ASSEMBLER__ */

#endif /* _SVA_SECMEM_H */
