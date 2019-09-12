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

#define GLOBL(x)	\
	.globl x;	\
x:

#define ENTRY(x)		\
	.type x, @function;	\
	GLOBL(x)

#define END(x)		\
	.size x, . - x
	

#endif /* _SVA_ASM_MACROS_H */
