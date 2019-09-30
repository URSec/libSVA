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

#include "sva/cfi.h"

#define GLOBL(x)	\
	.globl x;	\
x:

#define ENTRY(x)		\
	.type x, @function;	\
	GLOBL(x);               \
	STARTFUNC

#define END(x)		\
	.size x, . - x
	

#define IC_STACK_SIZE 4096

/**
 * Get a pointer to the TLS block
 *
 * Requires that the current stack (`%rsp`) be the interrupt context stack.
 *
 * @param reg The register into which to place the TLS pointer
 */
.macro get_tls_ptr reg:req
  movq %rsp, \reg
  orq $(IC_STACK_SIZE - 1), \reg

  /*
   * At this point, `\reg` points to the last byte of the interrupt context
   * stack. Since the TLS pointer is stored as the last quadword of the
   * interrupt context stack, we need to offset `\reg` by -7.
   */
  movq -7(\reg), \reg
.endm

#endif /* _SVA_ASM_MACROS_H */
