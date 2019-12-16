/*===- mmu_intrinsics.h - SVA Execution Engine  =----------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *
 *===------------------------------------------------------------------------===
 *
 *       Filename:  mmu_intrinsics.h
 *
 *    Description:  This file exports the sva instrinsics available for
 *                  manipulating page tables. The key reason to have this in
 *                  addition to the mmu.h is that the mmu.h code is primarily
 *                  internal SVA functionality for the mmu management and
 *                  should not be exported.
 *
 *        Version:  1.0
 *        Created:  04/24/13 04:31:31
 *       Revision:  none
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_MMU_INTRINSICS_H
#define SVA_MMU_INTRINSICS_H

#include <sva/mmu_types.h>

/**
 * Set the value of `%cr0`.
 *
 * Make sure that the new value doesn't compromise SVA.
 *
 * @param new_cr0 The new value to load into `%cr0`
 */
extern void sva_load_cr0(unsigned long new_cr0);

/*
 *****************************************************************************
 * Intrinsics to declare page table pages
 *****************************************************************************
 */

/**
 * Mark the specified frame as an L1 page table.
 *
 * Validates than any existing entries are safe, and will also remove write
 * access to the page from the kernel's direct map.
 *
 * @param frame The physical address of the frame that will become an L1 page
 *              table
 */
extern void sva_declare_l1_page(uintptr_t frame);

/**
 * Mark the specified frame as an L2 page table.
 *
 * Validates than any existing entries are safe, and will also remove write
 * access to the page from the kernel's direct map.
 *
 * @param frame The physical address of the frame that will become an L2 page
 *              table
 */
extern void sva_declare_l2_page(uintptr_t frame);

/**
 * Mark the specified frame as an L3 page table.
 *
 * Validates than any existing entries are safe, and will also remove write
 * access to the page from the kernel's direct map.
 *
 * @param frame The physical address of the frame that will become an L3 page
 *              table
 */
extern void sva_declare_l3_page(uintptr_t frame);

/**
 * Mark the specified frame as an L4 page table.
 *
 * Validates than any existing entries are safe, and will also remove write
 * access to the page from the kernel's direct map.
 *
 * @param frame The physical address of the frame that will become an L4 page
 *              table
 */
extern void sva_declare_l4_page(uintptr_t frame);

#ifdef FreeBSD
extern void sva_declare_dmap_page(uintptr_t frame);
#endif

/**
 * Unmark the specified frame as a page table.
 *
 * Works for both normal page tables and extended page tables.
 *
 * @param frame The frame that will no longer be a page table.
 */
extern void sva_remove_page(uintptr_t frame);

/*
 *****************************************************************************
 * Intrinsics to update page table entries
 *****************************************************************************
 */

/**
 * Update an L1 page table entry.
 *
 * Performs all necessary security checks to ensure the update is safe.
 *
 * @param l1e     The L1 entry to update
 * @param new_l1e The new value to set in `*l1e`
 */
extern void sva_update_l1_mapping(pte_t* l1e, pte_t new_l1e);

/**
 * Update an L2 page table entry.
 *
 * Performs all necessary security checks to ensure the update is safe.
 *
 * @param l2e     The L2 entry to update
 * @param new_l2e The new value to set in `*l2e`
 */
extern void sva_update_l2_mapping(pde_t* l2e, pde_t new_l2e);

/**
 * Update an L3 page table entry.
 *
 * Performs all necessary security checks to ensure the update is safe.
 *
 * @param l3e     The L3 entry to update
 * @param new_l3e The new value to set in `*l3e`
 */
extern void sva_update_l3_mapping(pdpte_t* l3e, pdpte_t new_l3e);

/**
 * Update an L4 page table entry.
 *
 * Performs all necessary security checks to ensure the update is safe.
 *
 * @param l4e     The L4 entry to update
 * @param new_l4e The new value to set in `*l4e`
 */
extern void sva_update_l4_mapping(pml4e_t* l4e, pml4e_t new_l4e);

#ifdef FreeBSD
/**
 * Update the L4 entries of the kernel's direct map.
 *
 * @param pml4pg  The virtual address of the L4 page table page to be updated
 * @param index   The index of the direct map L4 entry
 * @param val     The page table entry to be populated in
 */
extern void sva_update_l4_dmap(void* pml4pg, int index, page_entry_t val);
#endif

/**
 * Clear an entry in a page table page.
 *
 * This function is agnostic to the level of page table (and whether we are
 * dealing with an extended or regular page table).
 *
 * @param pte The page table entry which should be removed
 */
extern void sva_remove_mapping(page_entry_t* pte);

/**
 * Set the current root page table pointer.
 *
 * @param root_pgt  The physical address of the root page table
 */
extern void sva_mm_load_pgtable(cr3_t root_pgt);

/**
 * Get the current root page table pointer.
 *
 * @return The current page table pointer
 */
cr3_t sva_mm_save_pgtable(void);

/**
 * Remove write-protection from a code page.
 *
 * This is a hack which is intended to support limited uses of
 * runtime-generated code which have not been fully ported.
 *
 * @param vaddr The virtual address for which to change protections
 */
extern void sva_unprotect_code_page(void* vaddr);

/**
 * Re-add write-protection to a code page.
 *
 * This is a hack which is intended to support limited uses of
 * runtime-generated code which have not been fully ported.
 *
 * @param vaddr The virtual address for which to change protections
 */
extern void sva_protect_code_page(void* vaddr);

/**
 * Flush all TLB's holding translations for the specified virtual address
 *
 * @param address A virtual address for which all TLB entries will be flushed
 */
void sva_mm_flush_tlb(void* address);

#ifdef FreeBSD
extern void sva_mmu_init(pml4e_t * kpml4Mapping,
                         unsigned long nkpml4e,
                         uintptr_t *,
                         uintptr_t btext,
                         uintptr_t etext);
#endif

#if defined(XEN) || defined(__XEN__)
extern void sva_mmu_init(void);
#endif

/* Key initialization and secure storage allocation */
extern void* sva_translate(void* entryPoint);

#endif /* SVA_MMU_INTRINSICS_H */
