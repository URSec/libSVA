/*===- percpu.h - SVA Execution Engine  =------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2021.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * Constants and declarations for SVA's per-CPU region.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_PERCPU_H
#define _SVA_PERCPU_H

#include <sva/asm_const.h>
#include <sva/page.h>

#define PERCPU_REGION_SHIFT (PG_L1_SHIFT + 4)
#define PERCPU_REGION_SIZE (_ASM_CONST(1, UL) << PERCPU_REGION_SHIFT)
#define PARANOID_STACK_SHIFT PG_L1_SHIFT
#define PARANOID_STACK_SIZE (_ASM_CONST(1, UL) << PARANOID_STACK_SHIFT)

#endif /* _SVA_PERCPU_H */
