/*===- cr.h - SVA Control register definitions ------------------------------===
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
 * This header file contains definitions for the fields of the x86 control
 * registers and functions to manipulate the control registers.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_CR_H
#define _SVA_CR_H

/* CR0 Flags */
#define     CR0_PE      0x00000001      /* Protected mode enable */
#define     CR0_MP      0x00000002      /* FPU Monitor */
#define     CR0_EM      0x00000004      /* FPU emulation */
#define     CR0_TS      0x00000008      /* Task switched */
#define     CR0_ET      0x00000010      /* Extention type (always 1 since P1) */
#define     CR0_NE      0x00000020      /* Native floating-point error */
#define     CR0_WP      0x00010000      /* Write protect enable */
#define     CR0_AM      0x00040000      /* Alignment check enable */
#define     CR0_NW      0x20000000      /* Cache write-through */
#define     CR0_CD      0x40000000      /* Cache disable */
#define     CR0_PG      0x80000000      /* Paging enable */

/* CR4 Flags */
#define     CR4_DE          0x00000008      /* enable debug extentions */
#define     CR4_PSE         0x00000010      /* enable huge pages */
#define     CR4_PAE         0x00000020      /* enable physical address extention*/
#define     CR4_PGE         0x00000080      /* enable global pages */
#define     CR4_OSFXSR      0x00000200      /* enable FXSave and SSE */
#define     CR4_OSXMMEXCPT  0x00000400      /* enable unmasked SSE exceptions */
#define     CR4_FSGSBASE    0x00010000      /* enable fs/gs base instructions */
#define     CR4_PCIDE       0x00020000      /* enable PCID */
#define     CR4_OSXSAVE     0x00040000      /* enable XSave */

#ifndef __ASSEMBLER__

#include <sva/types.h>

/*
 *****************************************************************************
 * Low level register read/write functions
 *****************************************************************************
 */

/**
 * Get the current value of CR0.
 *
 * @return  The current value of CR0
 */
static inline uint64_t read_cr0(void) {
  uint64_t data;
  __asm __volatile("movq %%cr0, %0" : "=r"(data));
  return data;
}

/**
 * Get the current value of CR3.
 *
 * @return  The current value of CR3
 */
static inline uint64_t read_cr3(void) {
  uint64_t data;
  __asm __volatile("movq %%cr3, %0" : "=r"(data));
  return data;
}

/**
 * Get the current value of CR4.
 *
 * @return  The current value of CR4
 */
static inline uint64_t read_cr4(void) {
  uint64_t data;
  __asm __volatile("movq %%cr4, %0" : "=r"(data));
  return data;
}

/**
 * Set the value of CR0.
 *
 * @param val The value to set in CR0
 */
static inline void write_cr0(uint64_t val) {
  __asm __volatile("movq %0, %%cr0" : : "r"(val));
}

/**
 * Set the value of CR3.
 *
 * @param val The value to set in CR3
 */
static inline void write_cr3(uint64_t val) {
  __asm __volatile("movq %0, %%cr3" : : "r"(val) : "memory");
}

/**
 * Set the value of CR4.
 *
 * @param val The value to set in CR4
 */
static inline void write_cr4(uint64_t val) {
  __asm __volatile("movq %0, %%cr4" : : "r"(val));
}

#endif /* __ASSEMBLER__ */
#endif /* _SVA_CR_H */
