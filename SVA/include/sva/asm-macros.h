/*===- asm-macros.h - SVA Execution Engine  =--------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===------------------------------------------------------------------------===
 *
 * This file defines various macros that are used in SVA's assembly code.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_ASM_MACROS_H
#define _SVA_ASM_MACROS_H

#ifdef SVA_NO_CFI
#define STARTFUNC
#else
#include "sva/cfi.h"
#endif

#include "sva/x86.h"

#define ALIGN .p2align 5

#define GLOBL(x)                \
        .type x, @object;       \
        .globl x;               \
x:

#define LOCAL(x)                \
        .type x, @object;       \
        .local x;               \
x:

#define ENTRY(x)                \
        ALIGN;                  \
        .globl x;               \
        .type x, @function;     \
x:                              \
        STARTFUNC

#define END(x)                  \
        .size x, . - x

#endif /* _SVA_ASM_MACROS_H */
