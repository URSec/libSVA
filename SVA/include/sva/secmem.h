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

#ifdef __ASSEMBLER__
#define _AC(X, Y) X
#else
#define __AC(X, Y) X ## Y
#define _AC(X, Y) __AC(X, Y)
#endif

/* Start and end addresses of the secure memory (512GB) */
#define SECMEMSTART _AC(0xfffffd0000000000, UL)
#define SECMEMEND   _AC(0xfffffd8000000000, UL)

/* Start and end addresses of the SVA direct mapping (512GB) */
#define SVADMAPSTART _AC(0xfffffd8000000000, UL)
#define SVADMAPEND   _AC(0xfffffe0000000000, UL)

/* Start and end addresses of user memory (128TB) */
#define USERSTART _AC(0x0000000000000000, UL)
#define USEREND   _AC(0x0000800000000000, UL)

#endif /* _SVA_SECMEM_H */
