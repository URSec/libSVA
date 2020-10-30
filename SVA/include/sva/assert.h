/*===- assert.h - SVA assertion support -------------------------------------===
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
 * This header file contains definitions for `assert`-type macros which are used
 * for enforcing SVA's security checks. Note that unlike the `assert` macro in
 * standard C, the checks in these macros are not disabled in a non-debug build.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_ASSERT_H
#define SVA_ASSERT_H

#include <sva/callbacks.h>

/**
 * Cause a trap and show the execution state (GPRs and call stack).
 *
 * TODO: Ideally, SVA would handle this, but for now we leave it to the kernel.
 */
#define BUG()                                   \
  do {                                          \
    __asm__ __volatile__ ("ud2");               \
    __builtin_unreachable();                    \
  } while (0)

/**
 * Conditionally cause a trap and show the execution state (GPRs and call
 * stack).
 */
#define BUG_ON(condition)       \
  do {                          \
    if ((condition)) { BUG(); } \
  } while (0)

/**
 * Assert that a contition is true. If it is false, print an error message and
 * panic.
 *
 * @param cond  The condition to test
 * @param msg   The message to print on failure
 * @param ...   Format arguments to the failure message
 */
#define SVA_ASSERT(cond, msg, ...)              \
  do {                                          \
    if (!(cond)) {                              \
      printf((msg), ##__VA_ARGS__);             \
      BUG();                                    \
    }                                           \
  } while (0)                                   \

/**
 * Assert that this statement is never executed. If it is, print an error message
 * and panic.
 *
 * @param msg   The message to print on failure
 * @param ...   Format arguments to the failure message
 */
#define SVA_ASSERT_UNREACHABLE(msg, ...)        \
  SVA_ASSERT(0, (msg), ##__VA_ARGS__)

/* 
 * TODO: this will be removed. It is only used for temporarily obtaining
 * performance numbers.
 */
static inline void SVA_NOOP_ASSERT(int res, char* st) {
  (void)st;
  if (!res) res++;
}

#endif /* SVA_ASSERT_H */
