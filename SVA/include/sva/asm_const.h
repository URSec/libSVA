/*===- asm_const.h - SVA macros for defining constants with type suffixes ---===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2021.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header file contains definitions for macros that allow numbers with
 * type suffixes (such as `UL` for `unsigned long`) to be used in both C and
 * assembly.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_ASM_CONST_H
#define _SVA_ASM_CONST_H

/*
 * Type suffixes such as `UL` must not be applied when preprocessing assembly.
 */
#ifdef __ASSEMBLER__
#define _ASM_CONST(value, suffix) value
#else
#define __ASM_CONST(value, suffix) value ## suffix
#define _ASM_CONST(value, suffix) __ASM_CONST(value, suffix)
#endif

#endif /* _SVA_ASM_CONST_H */
