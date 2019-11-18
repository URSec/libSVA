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
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#endif

#endif /* _SVA_TYPES_H */
