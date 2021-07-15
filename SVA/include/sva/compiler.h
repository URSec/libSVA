/*===- compiler.h - Compiler options and nonstandard keywords ---------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This file sets compiler options (such as default visibility) and adds custom
 * and semi-standard keywords (e.g. #define asm __asm__).
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_COMPILER_H
#define _SVA_COMPILER_H

#pragma GCC visibility push(hidden)

#define __svadata __attribute__((__section__("svamem")))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define alignof __alignof

#define __packed __attribute__((__packed__))

#define __align(n) __attribute__((__aligned__(n)))

/*
 * Annotations for user and kernel pointers.
 */
#define __noderef __attribute__((noderef))
#define __user __attribute__((noderef, address_space(1)))
#define __kern __attribute__((noderef, address_space(2)))

#endif /* _SVA_COMPILER_H */
