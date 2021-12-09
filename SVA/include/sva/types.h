/*===- types.h - SVA primitive type definitions -----------------------------===
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
 * This header file contains definitions for primitive types such as `bool`,
 * `size_t` and `uintptr_t`.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_TYPES_H
#define _SVA_TYPES_H

#ifdef __XEN__
// System headers are unavailable when building XEN
#include <xen/types.h>
#else
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef uintptr_t paddr_t;
#endif

/**
 * Error type returned by SVA intrinsics.
 *
 * Will be 0 for success or a negative `errno` value.
 */
typedef int sva_error_t;

/**
 * A result that can represent either a success with a value or an error.
 */
typedef struct {

  /**
   * 0 for success, or an error code < 0.
   */
  sva_error_t error;

  /**
   * The successful result value.
   *
   * Only defined if `self.error` is 0.
   */
  unsigned long value;
} sva_result_t;

#endif /* _SVA_TYPES_H */
