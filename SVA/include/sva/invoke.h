/*===- invoke.h - SVA Exception handling intrinsics -------------------------===
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
 * Declarations for SVA's exception handling intrinsics.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_INVOKE_H
#define SVA_INVOKE_H

#include <sva/types.h>

/**
 * Initiate an unwind to the most recent invoke.
 *
 * Does not unwind immediately: instead, modifies the current exception context
 * to return to the most recent invoke.
 */
extern void sva_iunwind(void);

/**
 * Call a function and set an invoke point.
 *
 * If control flow is unwound, it will return to this call.
 *
 * @param arg1      The first argument to pass to the called function
 * @param arg2      The second argument to pass to the called function
 * @param arg3      The third argument to pass to the called function
 * @param retvalue  Where to store the return value of the called function
 * @param f         The function to call
 * @return          0 if `f` returned successfully;
 *                  1 if control flow was unwound
 */
extern unsigned int sva_invoke(uintptr_t arg1,
                               uintptr_t arg2,
                               uintptr_t arg3,
                               uintptr_t* retvalue,
                               void (*f)(uintptr_t, uintptr_t, uintptr_t));

/**
 * Safely copy `count` bytes from `src` to `dst`.
 *
 * @param dst   The destination buffer
 * @param src   The source buffer
 * @param count The number of bytes to copy
 * @return      The number of bytes actually copied
 */
extern size_t sva_invokememcpy(char* dst, const char* src, size_t count);

/**
 * Safely copy up to `count` bytes from `src` to `dst`, stoping after the first
 * 0 byte.
 *
 * @param dst   The destination buffer
 * @param src   The source buffer
 * @param count The maximum number of bytes to copy
 * @return      The number of bytes actually copied (not including the
 *              terminator), or -1 if a fault occured.
 */
extern size_t sva_invokestrncpy(char* dst, const char* src, size_t count);

#endif /* SVA_INVOKE_H */
