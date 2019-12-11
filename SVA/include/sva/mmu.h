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
#include <sva/util.h>
#include <sva/vmx.h>

/* The number of references allowed per page table page */
static const int maxPTPVARefs = 1;

/* The count must be at least this value to remove a mapping to a page */
static const int minRefCountToRemoveMapping = 1;

/*
 * Offset into the PML4E at which the mapping for the secure memory region can
 * be found.
 */
static const uintptr_t secmemOffset = ((SECMEMSTART >> 39) << 3) & vmask;

/*
 *****************************************************************************
 * Define structures used in the SVA MMU interface.
 *****************************************************************************
 */

/* Mask to get the address bits out of a PTE, PDE, etc. */
static const uintptr_t addrmask = 0x000ffffffffff000u;

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

/*
 *****************************************************************************
 * SVA Implementation Function Prototypes
 *****************************************************************************
 */
void init_mmu(void);
void init_leaf_page_from_mapping(page_entry_t mapping);

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
 * Global TLB flush (except for this for pages marked PG_G)
 */ 
static inline void
invltlb(void) {
  write_cr3(read_cr3());
}


/*
 * Flush userspace TLB entries with kernel PCID (PCID 1)
 *
 * NOTE: this function has the side effect of changing the active PCID to 1!
 */
static inline void
invltlb_kernel(void) {
  write_cr3(read_cr3() | 0x1);
}

/*
 * Invalidate all TLB entries (including global entries)
 * Interrupts should have already been disabled when this function is invoked.
 * clear PGE of CR4 first and then write old PGE again to CR4 to flush TLBs
 */
static inline void
invltlb_all(void) {
  unsigned long cr4;
  cr4 = read_cr4();
  write_cr4(cr4 & ~CR4_PGE);
  write_cr4(cr4);
}

/**
 * Invalidate all the TLB entries with a specific virtual address (including
 * global entries).
 *
 * @param addr  The virtual address for which to invalidate TLB entries
 */
static inline void invlpg(uintptr_t addr) {
  /*
   * NB: I had to look at the FreeBSD implementation of invlpg() to figure out
   * that you need to "dereference" the address to get the operand to the
   * inline asm constraint to work properly.  While perhaps not necessary
   * (because I don't think such a trivial thing can by copyrighted), the fact
   * that I referenced the FreeBSD code is why we have the BSD copyright and
   * attribute comment at the top of this file.
   */
  asm volatile("invlpg %0" : : "m" (*(char *)addr) : "memory");
}

/*
 * Invalidate guest-physical mappings in the TLB, globally (for all sets of
 * extended page tables). These mappings are created when a guest system
 * performs accesses directly based on a (guest-)physical address *without*
 * going through its own guest-side page tables.
 *
 * Note: This function does *not* invalidate "combined"
 * guest-virtual/guest-physical mappings, which are created when a
 * guest-system performs accesses using linear addresses (i.e., using
 * guest-side page tables layered on top of extended paging). To clear those,
 * call invvpid_allcontexts().
 *
 * PRECONDITION:
 *  - SVA-VMX must have been successfully initialized, i.e., the SVA global
 *    variable "sva_vmx_initialized" should be true. Otherwise, the INVEPT
 *    instruction will not be valid to execute.
 */
static inline void
invept_allcontexts(void) {
  SVA_ASSERT(sva_vmx_initialized,
      "SVA: Tried to call invept_allcontexts() without SVA-VMX being "
      "initialized. The INVEPT instruction is not valid unless the system "
      "is running in VMX operation.\n");

  /*
   * Set up a 128-bit "INVEPT descriptor" in memory which serves as one of
   * the arguments to INVEPT.
   *
   * The lower 64 bits would be expected to contain an EPTP (pointer to
   * top-level extended page table, i.e. the EPT equivalent of CR3) value if
   * we were doing a single-context invalidation (i.e. for just one VM).
   * However, for an all-context invalidation its value doesn't matter (but
   * we still need to pass it anyway).
   *
   * The upper 64 bits are reserved and must be set to 0 for safe forward
   * compatibility.
   *
   * Long story short: we're going to set the whole thing to zero here.
   */
  uint64_t invept_descriptor[2];
  invept_descriptor[0] = invept_descriptor[1] = 0;

  uint64_t rflags_invept;
  asm __volatile__ (
      "invept (%[desc]), %[type]\n"
      "pushfq\n"
      "popq %[rflags]\n"
      : [rflags] "=r" (rflags_invept)
      : [desc] "r" (invept_descriptor),
        [type] "r" (2ul) /* INVEPT type: all-contexts (global) invalidation */
      : "memory", "cc"
      );
  /*
   * If the operation didn't succeed, the processor didn't support INVEPT in
   * the all-context mode. We check for this when initializing SVA-VMX, so if
   * this happens, something has gone wrong.
   *
   * FIXME: we're not actually checking this yet in sva_initvmx(), so this
   * "impossible" assertion could actually be triggered on a processor that
   * doesn't support this.
   */
  SVA_ASSERT(query_vmx_result(rflags_invept) == VM_SUCCEED,
      "SVA: INVEPT returned an error code other than VM_SUCCEED. "
      "This shouldn't be possible since we checked that this operation "
      "is supported when initializing SVA-VMX. Something has gone terribly "
      "wrong.\n");
}

/*
 * Invalidate "combined" guest-virtual/guest-physical mappings in the TLB,
 * globally (for all VPIDs except VPID=0, which represents the host system;
 * to flush host mappings, use invltlb_all()). These mappings are created
 * when a guest system performs accesses using linear addresses (i.e., using
 * guest-side page tables layered on top of extended paging).
 *
 * Note: This function does *not* invalidate standalone guest-physical
 * mappings, which are created when a guest system performs accesses directly
 * based on a (guest-)physical address without going through its own page
 * tables. To clear those, call invept_allcontexts().
 *
 * PRECONDITION:
 *  - SVA-VMX must have been successfully initialized, i.e., the SVA global
 *    variable "sva_vmx_initialized" should be true. Otherwise, the INVVPID
 *    instruction will not be valid to execute.
 */
static inline void
invvpid_allcontexts(void) {
  SVA_ASSERT(sva_vmx_initialized,
      "SVA: Tried to call invvpid_allcontexts() without SVA-VMX being "
      "initialized. The INVVPID instruction is not valid unless the system "
      "is running in VMX operation.\n");

  /*
   * Set up a 128-bit "INVVPID descriptor" in memory which serves as one of
   * the arguments to INVVPID.
   *
   * - Bits 0-15 specify the VPID whose mappings should be cleared from the
   *   TLB. Its setting does not matter for "all-contexts" flushes as we are
   *   going to do here, which flush mappings for all VPIDs.
   *
   * - Bits 16-63 are reserved and must be set to 0 for safe forward
   *   compatibility.
   *
   * - Bits 64-127 specify a linear address whose mappings should be cleared
   *   from the TLB. Its setting does not matter for global flushes such as
   *   we are going to do here, which flush mappings for all linear
   *   addresses.
   *
   * Long story short: we're going to set the whole thing to zero here.
   */
  uint64_t invvpid_descriptor[2];
  invvpid_descriptor[0] = invvpid_descriptor[1] = 0;

  uint64_t rflags_invvpid;
  asm __volatile__ (
      "invvpid (%[desc]), %[type]\n"
      "pushfq\n"
      "popq %[rflags]\n"
      : [rflags] "=r" (rflags_invvpid)
      : [desc] "r" (invvpid_descriptor),
        [type] "r" (2ul) /* INVVPID type: all-contexts (global) invalidation */
      : "memory", "cc"
      );
  /*
   * If the operation didn't succeed, the processor didn't support INVVPID in
   * the all-context mode. We check for this when initializing SVA-VMX, so if
   * this happens, something has gone wrong.
   *
   * FIXME: we're not actually checking this yet in sva_initvmx(), so this
   * "impossible" assertion could actually be triggered on a processor that
   * doesn't support this.
   */
  SVA_ASSERT(query_vmx_result(rflags_invvpid) == VM_SUCCEED,
      "SVA: INVVPID returned an error code other than VM_SUCCEED. "
      "This shouldn't be possible since we checked that this operation "
      "is supported when initializing SVA-VMX. Something has gone terribly "
      "wrong.\n");
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

/* See implementation in c file for details */
static inline page_entry_t * va_to_pte (uintptr_t va, enum page_type_t level);
static inline int isValidMappingOrder (page_desc_t *pgDesc, uintptr_t newVA);
void initDeclaredPage (unsigned long frameAddr);

void page_entry_store(unsigned long *page_entry, page_entry_t newVal);

#if 0
static inline uintptr_t
pageVA(page_desc_t pg){
    return getVirtual(pg.physAddress);    
}
#endif

/*
 * Mapping update function prototypes.
 */
void __update_mapping (pte_t * pageEntryPtr, page_entry_t val);

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
readOnlyPageType(page_desc_t *pg) {
  return  (pg->type == PG_L4)
           || (pg->type == PG_L3)
           || (pg->type == PG_L2)
#if 0
           || (pg->type == PG_L1)
#endif
           || (pg->type == PG_CODE)
           || (pg->type == PG_SVA)
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
mapPageReadOnly(page_desc_t * ptePG, page_entry_t mapping) {
  page_desc_t* mapping_pgDesc = getPageDescPtr(mapping);
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

/*
 * Function: protect_paging()
 *
 * Description:
 *  Actually enforce read only protection. 
 *
 *  Protects the page table entry. This disables the flag in CR0 which bypasses
 *  the RW flag in pagetables. After this call, it is safe to re-enable
 *  interrupts.
 */
static inline void
protect_paging(void) {
  write_cr0(read_cr0() | CR0_WP);

  if(tsc_read_enable_sva)
	  wp_num ++;
  return;
}

/*
 * Function: unprotect_paging
 *
 * Description:
 *  This function disables page protection on x86_64 systems.  It is used by
 *  the SVA VM to allow itself to disable protection to update the in-memory
 *  page tables.
 */
static inline void
unprotect_paging(void) {
  write_cr0(read_cr0() & ~CR0_WP);

  if(tsc_read_enable_sva)
	  wp_num ++;
}

/* functions to change PCID and page table during user/sva and kernel switch*/
void usersva_to_kernel_pcid(void);
void kernel_to_usersva_pcid(void);

static __inline void
wbinvd(void)
{   
  __asm __volatile("wbinvd");
} 

#endif
