/*===- mmu_types.h - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *
 *===----------------------------------------------------------------------===
 *
 *       Filename:  mmu_types.h
 *
 *    Description:  This file defines shared data types that are in both mmu.h
 *                  and mmu_intrinsics.h. 
 *
 *        Version:  1.0
 *        Created:  04/24/13 05:58:42
 *       Revision:  none
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_MMU_TYPES_H
#define SVA_MMU_TYPES_H

#if !(defined(XEN) || defined(__XEN__))
/* FreeBSD headers not available when building with Xen */
#include <stdint.h>
#include <sys/types.h>
#elif defined(XEN) && !defined(__XEN__)
/*
 * When building SVA for Xen (#ifdef XEN), we need to define uintptr_t
 * without the FreeBSD headers.
 *
 * However, when this header file is included into code in Xen proper
 * (#ifdef __XEN__) via downstream headers exporting SVA public interfaces
 * (e.g. mmu_intrinsics.h), we must *not* redefine uintptr_t, because Xen
 * already defines it (as unsigned long, just like we do) in its own types.h.
 */
typedef unsigned long uintptr_t;
#endif

typedef uintptr_t cr3_t;
typedef uintptr_t pml4e_t;
typedef uintptr_t pdpte_t;
typedef uintptr_t pde_t;
typedef uintptr_t pte_t;
typedef uintptr_t page_entry_t;
typedef uintptr_t eptp_t;

#endif /* SVA_MMU_TYPES_H */
