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

/* Start and end addresses of the secure memory (1TB) */
#define SECMEMSTART _ASM_CONST(0xffff860000000000, UL)
#define SECMEMEND   _ASM_CONST(0xffff870000000000, UL)

/* Start and end addresses of the SVA direct mapping (1TB) */
#define SVADMAPSTART _ASM_CONST(0xffff870000000000, UL)
#define SVADMAPEND   _ASM_CONST(0xffff880000000000, UL)

/* Start and end addresses of Xen's direct map (3TB) */
#define KERNDMAPSTART _ASM_CONST(0xffff830000000000, UL)
#define KERNDMAPEND   _ASM_CONST(0xffff860000000000, UL)

/* Start address of PV guest memory (120TB) */
#define GUESTSTART _ASM_CONST(0xffff880000000000, UL)
/* Guest memory ends at the end of the address space */

#endif /* !XEN */

/* Start and end addresses of user memory (128TB) */
#define USERSTART _ASM_CONST(0x0000000000000000, UL)
#define USEREND   _ASM_CONST(0x0000800000000000, UL)

#endif /* _SVA_SECMEM_H */
