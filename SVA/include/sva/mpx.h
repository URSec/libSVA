/*===- mpx.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the SVA research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file defines constants and functions used by the SVA Execution
 * Engine to support SVA's use of Intel Memory Protection Extensions (MPX) to
 * implement software fault isolation.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_MPX_H
#define _SVA_MPX_H

#include <sva/mmu.h> /* Defines SECMESTART and SECMEMEND */

/* Bits to configure the BNDCFGS register */
static unsigned char BNDCFG_BNDENABLE = (1u << 0);
static unsigned char BNDCFG_BNDPRESERVE = (1u << 1);

/* ID number of the configuration register for MPX kernel mode code */
static const unsigned MSR_IA32_BNDCFGS = 0x0d90;

/**
 * Initialize the bounds registers for SFI.
 */
static inline void mpx_bnd_init(void) {
  asm volatile (
    "bndmk (%0, %1), %%bnd0"
    :
    : "r"(SECMEMEND - SECMEMSTART), "r"(-1UL));
  asm volatile (
    "bndmk (%0, %1), %%bnd1"
    :
    : "r"(0UL), "r"(-1UL));
}

/*
 * Intrinsic for use during development only. Prints MPX registers.
 * (Defined in debug.c.)
 */
void sva_print_mpx_regs(void);

#endif /* #ifndef _SVA_MPX_H */
