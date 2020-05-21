/*===- init.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_INIT_H
#define SVA_INIT_H

/* Initialization functions */
extern void sva_init_primary ();
extern void sva_init_primary_xen (void* tss);
extern void sva_init_secondary ();
#endif

typedef void __attribute__((__noreturn__)) (*init_fn)(void);

extern bool sva_launch_ap(uint32_t apic_id, uintptr_t start_page,
                          init_fn init, void* stack);
#endif /* SVA_INIT_H */

