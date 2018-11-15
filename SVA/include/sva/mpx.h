/*===- mpx.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the SVA research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file defines functions and macros used by the SVA Execution
 * Engine to support SVA's use of Intel Memory Protection Extensions (MPX) to
 * implement software fault isolation.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_MPX_H
#define _SVA_MPX_H

/* First address of kernel memory */
static uintptr_t const KERNELBASE = SECMEMEND - SECMEMSTART;
static uintptr_t const KERNELSIZE = (0xffffffffffffffffu - KERNELBASE);

/* Bits within control register 4 (CR4) */
static const uintptr_t CR4_OSXSAVE = (1u << 18);

/* Bits to configure in the extended control register XCR0 */
static unsigned char XCR0_BNDREG = (1u << 3);
static unsigned char XCR0_BNDCSR = (1u << 4);
static unsigned char XCR0_X87 = (1u << 0);

/* Bits to configure the BNDCFGS register */
static unsigned char BNDCFG_BNDENABLE = (1u << 0);
static unsigned char BNDCFG_BNDPRESERVE = (1u << 1);

/* ID number of the configuration register for MPX kernel mode code */
static const unsigned MSR_IA32_BNDCFGS = 0x0d90;

#endif /* #ifndef _SVA_MPX_H */
