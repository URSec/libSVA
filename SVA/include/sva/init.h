/*===- init.h - SVA Execution Engine  =---------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===------------------------------------------------------------------------===
 *
 * This file contains prototypes for SVA initialization functions.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_INIT_H
#define SVA_INIT_H

#include <sva/types.h>

/**
 * Initialize the SVA Execution Engine on the primary processor (BSP).
 */
extern void sva_init_primary(void);

/**
 * Initialize the SVA Execution Engine on a secondary processor (AP).
 */
extern void __attribute__((__noreturn__)) sva_init_secondary(void);

#if defined(XEN) || defined(__XEN__)

/**
 * Initialize the SVA Execution Engine on the primary processor (BSP).
 *
 * @param tss The TSS which Xen created.
 */
extern void sva_init_primary_xen(void* tss);

/**
 * Initialize the SVA Execution Engine on a secondary processor (AP).
 *
 * @param tss The TSS which Xen created.
 */
extern void sva_init_secondary_xen(void* tss);

#endif

typedef void __attribute__((__noreturn__)) (*init_fn)(void);

extern bool sva_launch_ap(uint32_t apic_id, uintptr_t start_page,
                          init_fn init, void* stack);
#endif /* SVA_INIT_H */

