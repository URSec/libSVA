/*===- callbacks.h - SVA Execution Engine  =--------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines functions that the system software (operating system or
 * hypervisor) must implement to support the SVA VM.
 *
 */

#ifndef SVA_CALLBACKS_H
#define SVA_CALLBACKS_H

#include <sys/types.h>

/* Kernel callback function for allocating memory */
extern uintptr_t provideSVAMemory (uintptr_t size);
extern void releaseSVAMemory (uintptr_t, uintptr_t size);

/* These callbacks are used for debugging and assertions */
extern int printf(const char *, ...);
extern int panic(const char *, ...);

/*
 * These callbacks are an insecure alternative to the secmem frame allocation
 * functions. They are intended to be used only to support benchmarking
 * comparisons where the baseline should not include secmem overhead.
 *
 * (The motivating example of this is some SVA-VMX code which skips numerous
 * security checks when a compile-time option is set accordingly.)
 */
uintptr_t kernel_alloc_frame_unchecked(void);
void kernel_free_frame_unchecked(uintptr_t paddr);

#endif
