/*===- fpu.h - SVA x87, SSE, AVX, and XSAVE definitions ---------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2020.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header file contains definitions and utilities for the x87, SSE, AVX,
 * and XSAVE extentions.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_FPU_H
#define _SVA_FPU_H

#include <sva/fpu_types.h>
#include <sva/types.h>
#include <sva/cr.h>

extern uint32_t __svadata xsave_features;

/**
 * Disable use of the FPU.
 */
static inline void fpu_disable(void) {
  /*
   * Set the task-switched bit.
   */
  write_cr0(read_cr0() | CR0_TS);
}

/**
 * Enable use of the FPU.
 */
static inline void fpu_enable(void) {
  /*
   * Clear the task-switched bit.
   */
  asm volatile ("clts");
}

/**
 * Save FPU and extended states.
 */
static inline void xsave(struct xsave_area* xsave_area) {
  /*
   * If debug checks are enabled, we set the TS bit in `%cr0` on kernel entry
   * to ensure that the kernel does not attempt to use the FPU. We will need to
   * clear that here to avoid faulting.
   */
#ifdef SVA_DEBUG_CHECKS
  fpu_enable();
#endif
  asm volatile ("xsavesq %0"
                :: "m"(*xsave_area), "a"(xsave_features), "d"(0));
#ifdef SVA_DEBUG_CHECKS
  fpu_disable();
#endif
}

/**
 * Restore FPU and extended states.
 */
static inline void xrestore(struct xsave_area* xsave_area) {
  /*
   * See the comment in `xsave`.
   */
#ifdef SVA_DEBUG_CHECKS
  fpu_enable();
#endif
  asm volatile ("xrstorsq %0"
                :: "m"(*xsave_area), "a"(xsave_features), "d"(0));
#ifdef SVA_DEBUG_CHECKS
  fpu_disable();
#endif
}

/**
 * Initialize FPU and extended states.
 */
void xinit(struct xsave_area* xsave_area);

/**
 * Get the value of `%xcr0`, which determines which states are saved by `xsave`
 * and `xrestore`.
 *
 * @return  The value of `%xcr0`
 */
static inline uint32_t xgetbv(void) {
  uint32_t xcr0;
  asm volatile ("xgetbv" : "=a"(xcr0) : "c"(0) : "rdx");
  return xcr0;
}

/**
 * Set the value of `%xcr0`, which determines which states are saved by `xsave`
 * and `xrestore`.
 *
 * @param xcr0  The new value to set in `%xcr0`
 */
static inline void xsetbv(uint64_t xcr0) {
  asm volatile ("xsetbv"
                :: "a"((uint32_t)xcr0), "c"(0), "d"((uint32_t)(xcr0 >> 32)));
}

#endif /* _SVA_FPU_H */
