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

/* Start and end addresses of the secure memory (512GB) */
#define SECMEMSTART 0xfffffd0000000000UL
#define SECMEMEND   0xfffffd8000000000UL

/* Start and end addresses of the SVA direct mapping (512GB) */
#define SVADMAPSTART 0xfffffd8000000000UL
#define SVADMAPEND   0xfffffe0000000000UL

/* Start and end addresses of user memory (128TB) */
#define USERSTART 0x0000000000000000UL
#define USEREND   0x0000800000000000UL

#endif /* _SVA_SECMEM_H */
