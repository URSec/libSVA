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
 *
 * @return  True if there was an invoke frame to unwind to, otherwise false
 */
extern bool sva_iunwind(void);

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
 *                  1 if control flow was unwound;
 *                  -1 if the return value pointer couldn't be written
 */
extern int sva_invoke(uintptr_t arg1,
                      uintptr_t arg2,
                      uintptr_t arg3,
                      uintptr_t __kern* retvalue,
                      uintptr_t (*f)(uintptr_t, uintptr_t, uintptr_t));

/**
 * Safely copy `count` bytes from `src` to `dst`.
 *
 * @param dst   The destination buffer
 * @param src   The source buffer
 * @param count The number of bytes to copy
 * @return      The number of bytes actually copied
 */
extern size_t sva_invokememcpy(char __kern* dst,
                               const char __kern* src,
                               size_t count);

/**
 * Safely set `count` bytes at `dst` to `val`.
 *
 * @param dst   The destination buffer
 * @param val   The value to store
 * @param count The number of bytes to write
 * @return      The number of bytes actually written
 */
size_t sva_invokememset(char __kern* dst, char val, size_t count);

#endif /* SVA_INVOKE_H */
