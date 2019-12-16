/*===- mmu.h - SVA Execution Engine  =-------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: release/9.0.0/sys/amd64/include/cpufunc.h 223796 2011-07-05 18:42:10Z jkim $
 *
 *===----------------------------------------------------------------------===
 *
 * SVA MMU control definitions and utilities.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_MMU_H
#define SVA_MMU_H

#include <sva/mmu_types.h>

#include <sva/assert.h>
#include <sva/callbacks.h>
#include <sva/dmap.h>
#include <sva/frame_meta.h>
#include <sva/page.h>
#include <sva/page_walk.h>
#include <sva/page_util.h>
#include <sva/secmem.h>
#include <sva/state.h>
#include <sva/tlb.h>
#include <sva/util.h>
#include <sva/vmx.h>

/**
 * True if the MMU has been initialized (and MMU checks should be performed),
 * otherwise false.
 */
extern bool mmuIsInitialized;

/* Fork code flags */
#define RFPROC      (1<<4)  /* change child (else changes curproc) */
#define RFMEM       (1<<5)  /* share `address space' */

extern pml4e_t mapSecurePage (uintptr_t v, uintptr_t paddr);
extern uintptr_t unmapSecurePage (struct SVAThread *, unsigned char * v);
extern uintptr_t alloc_frame(void);
extern void free_frame(uintptr_t paddr);

/**
 * Perform early initialization of the MMU metadata.
 */
void init_mmu(void);

/**
 * Determine if a virtual address is canonical.
 *
 * @param vaddr A virtual address
 * @return      True if `vaddr` is canonical, otherwise false
 */
static inline bool isCanonical(uintptr_t vaddr) {
  const uintptr_t canonical_mask = 0xffff800000000000UL;
  return (vaddr & canonical_mask) == 0 ||
         (vaddr & canonical_mask) == canonical_mask;
}

/*
 *****************************************************************************
 * SVA utility functions needed by multiple compilation units
 *****************************************************************************
 */

static inline void
print_regs(void) {
  printf("Printing Active Reg Values:\n");
  printf("\tEFER: 0x%lx\n", read_efer());
  printf("\t CR0: 0x%lx\n", read_cr0());
  printf("\t CR3: 0x%lx\n", read_cr3());
  printf("\t CR4: 0x%lx\n", read_cr4());
}

/*
 *****************************************************************************
 * MMU declare, update, and verification helper routines
 *****************************************************************************
 */

/**
 * Initialize a frame for use as a page table.
 *
 * @param frame The frame that was declared as a page table
 */
void initDeclaredPage(uintptr_t frame);

/**
 * Write a page table entry into a page table.
 *
 * Logically, this simply does `*page_entry = newVal`, but with additional logic
 * to ensure that it can safely write to the page table.
 *
 * Note: If this function needs to disable write protection in order to perform
 * the page table update (because SVA doesn't have its own direct map), then it
 * will unconditionally re-enable it.
 *
 * @param page_entry  The page table entry to update
 * @param newVal      The new page table entry to store to `page_entry`
 */
void page_entry_store(page_entry_t* page_entry, page_entry_t newVal);

/**
 * Perform a page table entry update with validity checks.
 *
 * Also works for extended page table (EPT) updates. Whether a regular or
 * extended page table is being updated and what level of page table is being
 * updated is inferred from the SVA frame type of the page table being
 * modified.
 *
 * @param pte     The page table entry to update
 * @param new_pte The new page table entry to validate and store to `pte`
 */
void update_mapping(page_entry_t* pte, page_entry_t new_pte);

/**
 * Mark the specified frame as a page table.
 *
 * Validates than any existing entries are safe, and that the frame is safe to
 * turn into a page table (it's not mapped writable anywhere).
 *
 * @param frame The physical address of the frame that will become a page table
 * @param level The level of page table that `frame` will become
 */
void sva_declare_page(uintptr_t frame, frame_type_t level);

/*
 * Function: readOnlyPage
 *
 * Description:
 *  This function determines whether or not the given page descriptor
 *  references a page that should be marked as read only. We set this for pages
 *  of type: l4,l3,l2,l1, code, and TODO: is this all of them?
 *
 * Inputs:
 *  pg  - page descriptor to check
 *
 * Return:
 *  - 0 denotes not a read only page
 *  - 1 denotes a read only page
 */
static inline int
readOnlyPageType(frame_desc_t *pg) {
  return  (pg->type == PGT_L4)
           || (pg->type == PGT_L3)
           || (pg->type == PGT_L2)
#if 0
           || (pg->type == PGT_L1)
#endif
           || (pg->type == PGT_CODE)
           || (pg->type == PGT_SVA)
           ;
}

/*
 * Function: mapPageReadOnly
 *
 * Description:
 *  This function determines if the particular page-translation-page entry in
 *  combination with the new mapping necessitates setting the new mapping as
 *  read only. The first thing to check is whether or not the new page needs to
 *  be marked as read only. The second issue is to distinguish between the case
 *  when the new read only page is being inserted as a page-translation-page
 *  reference or as the lookup value for a given VA by the MMU. The latter case
 *  is the only we mark as read only, which will protect the page from writes
 *  if the WP bit in CR0 is set.
 *
 * Inputs:
 *  ptePG    - The page descriptor of the page that we are inserting into the
 *             page table.  We will use this to determine if we are adding
 *             a page table page.
 *
 *  mapping - The mapping that will be used to insert the page.  This is used
 *            for cases in which what would ordinarily be a page table page is
 *            a large data page.
 *
 * Return value:
 *  0 - The mapping can safely be made writeable.
 *  1 - The mapping should be read-only.
 */
static inline unsigned char
mapPageReadOnly(frame_desc_t * ptePG, page_entry_t mapping) {
  frame_desc_t* mapping_pgDesc = get_frame_desc(mapping);
  SVA_ASSERT(mapping_pgDesc != NULL,
    "SVA: FATAL: Attempt to map non-existant frame\n");
  if (readOnlyPageType(mapping_pgDesc)){
    /*
     * L1 pages should always be mapped read-only.
     */
    if (isL1Pg(ptePG))
      return 1;

    /*
     * L2 and L3 pages should be mapped read-only unless they are data pages.
     */
    if ((isL2Pg(ptePG) || isL3Pg(ptePG)) && !isHugePage(mapping, ptePG->type))
      return 1;
  }

  return 0;
}

/**
 * Turn on write protection to prevent writes to page tables.
 */
static inline void protect_paging(void) {
  write_cr0(read_cr0() | CR0_WP);

  if(tsc_read_enable_sva)
    wp_num++;
}

/**
 * Turn off write protection to allow updates to page tables.
 *
 * If SVA is not configured to use its own direct map, it will perform updates
 * to page tables through the kernel's direct map. However, in order to prevent
 * the kernel from directly writing to the page tables, SVA makes the pages
 * which map page tables in the kernel's direct map read-only. However, this
 * also prevents SVA from writing to them when write protection is enabled. This
 * function disables write protection by writing to `%cr0` in order to allow SVA
 * to write to the page tables.
 *
 * Note that this function must be called in an atomic context (interrupts
 * disabled).
 */
static inline void unprotect_paging(void) {
  write_cr0(read_cr0() & ~CR0_WP);

  if(tsc_read_enable_sva)
    wp_num++;
}

void usersva_to_kernel_pcid(void);
void kernel_to_usersva_pcid(void);

/**
 * Flush the CPU cache.
 */
static inline void wbinvd(void) {
  asm volatile("wbinvd");
}

#endif
