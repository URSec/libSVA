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
#include <sva/page.h>
#include <sva/secmem.h>
#include <sva/state.h>
#include <sva/util.h>
#include <sva/vmx.h>

/* Size of the physical memory and page size in bytes */
static const unsigned long memSize = 0x0000002000000000u; /* 128GB */
static const unsigned long pageSize = 4096;
static const unsigned long numPageDescEntries = memSize / pageSize;

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

/*
 * Frame usage constants
 */

/**
 * The type of a frame.
 *
 * These types are mutually exclusive: a frame may only be one type at a time,
 * and all uses as its current type must be dropped before it can change type.
 *
 * Note that all types except `PG_DATA` are "sticky": a frame's type will not
 * automatically change to `PG_FREE` when it's type reference count drops to 0.
 * The type of the frame must be reset using the appropriate undeclare call for
 * its current type.
 */
typedef enum page_type_t {
  PG_FREE,     ///< Frame is not currently used as any type
  PG_UNUSABLE, ///< Frame is not present or is reserved by firmware
  PG_DATA,     ///< Frame is used as writable data
  PG_SVA,      ///< Frame is used internally by SVA
  PG_GHOST,    ///< Frame is used for ghost memory
  PG_CODE,     ///< Frame is used for code
  PG_L1,       ///< Frame is used as an L1 page table
  PG_L2,       ///< Frame is used as an L2 page table
  PG_L3,       ///< Frame is used as an L3 page table
  PG_L4,       ///< Frame is used as an L4 page table
  PG_EPTL1,    ///< Frame is used as an L1 extended page table
  PG_EPTL2,    ///< Frame is used as an L2 extended page table
  PG_EPTL3,    ///< Frame is used as an L3 extended page table
  PG_EPTL4,    ///< Frame is used as an L4 extended page table
  PG_SML1,     ///< Frame is used as an L1 page table for secure memory
  PG_SML2,     ///< Frame is used as an L2 page table for secure memory
  PG_SML3      ///< Frame is used as an L3 page table for secure memory
} page_type_t;

/* Mask to get the address bits out of a PTE, PDE, etc. */
static const uintptr_t addrmask = 0x000ffffffffff000u;

/**
 * Frame descriptor metadata.
 *
 * There is one element of this structure for each physical frame of memory in
 * the system.  It records information about the physical memory (and the data
 * stored within it) that SVA needs to perform its MMU safety checks.
 */
typedef struct page_desc_t {
#if 0 // The value stored in this field is never actually used
  /**
   * If the page is a page table page, mark the virtual address to which it is
   * mapped.
   */
  uintptr_t pgVaddr;
#endif

#ifdef SVA_ASID_PG
  /**
   * The physical adddress of the other (kernel or user/SVA) version pml4 page
   * table page.
   */
  uintptr_t other_pgPaddr;
#endif

  /**
   * The type of this frame.
   */
  page_type_t type : 8;

#define PG_REF_COUNT_BITS 12
#define PG_REF_COUNT_MAX ((1U << PG_REF_COUNT_BITS) - 1)

  /**
   * Number of times this frame is mapped.
   */
  unsigned count : PG_REF_COUNT_BITS;

  /**
   * Number of times this frame is mapped writable.
   */
  unsigned wr_count : PG_REF_COUNT_BITS;
} page_desc_t;

/* Array describing the physical pages. Used by SVA's MMU and EPT intrinsics.
 * The index is the physical page number.
 *
 * Defined in mmu.c.
 */
extern page_desc_t page_desc[numPageDescEntries];

/**
 * True if the MMU has been initialized (and MMU checks should be performed),
 * otherwise false.
 */
extern bool mmuIsInitialized;

/* Fork code flags */
#define RFPROC      (1<<4)  /* change child (else changes curproc) */
#define RFMEM       (1<<5)  /* share `address space' */

/**
 * Perform a page table walk and return pointers to the page table entries in
 * addition to the mapped physical address.
 *
 * This function is designed to perform a page table walk and return any
 * relavant information that is generated by that walk, while gracefully
 * handling any errors. This unfortunately results in a relatively complicated
 * interface which deserves a more in-depth explanation.
 *
 * If `vaddr` is actually mapped to some physical address, then the return value
 * will be positive and will indicate the level of page table at which the leaf
 * entry is found. For example, this will be 1 for a normal page or 2 or 3 for a
 * super page. Additionally, `*paddr` will be written with the virtual address
 * to which `vaddr` mapps.
 *
 * If `vaddr` is not mapped, then the return value will be negative and will
 * indicate the last level page table for which an entry covering `vaddr`
 * exists. In other words, if the L4 and L3 entries mapping `vaddr` are present
 * but the L2 entry is marked not present, then the return value will be -2.
 * Note that the return value may be -5 if it is determined that the root page
 * table pointer doesn't actually point to a valid root page table.
 *
 * In either of these cases, pointers to the page table entries mapping `vaddr`
 * will be written to `*pml4e`, `*pdpte`, `*pde`, and `*pte`, so long as the
 * entry exists. In other words, if the L2 entry is marked not present, then no
 * L1 entry exists, so nothing will be written to `*pte`. Note that `*pde` will
 * still be written with the address of the (not-present) L2 entry.
 *
 * In the edge case where `vaddr` is not a canonical address, the return value
 * will be 0.
 *
 * This function will also perform a page table walk starting at a lower level
 * in the paging hierarchy. If the caller passes an existing page table entry,
 * the walk will start at the lowest level entry which was given. For example,
 * if `pde` and `*pde` are both non-null, then the walk will start with the L2
 * entry `**pde`. In this case, none of the higher-level pages will be examined,
 * and the corresponding pointers to their entries will not be written.
 *
 * Note that there are several wrappers provided for this function to handle
 * common use cases. Due to their simpler interfaces, tt is recommended that you
 * use those whenever possible.
 *
 * @param[in]     cr3   The root page table pointer
 * @param[in]     vaddr The virtual address for which to perform the walk
 * @param[in,out] pml4e The L4 entry mapping `vaddr`
 * @param[in,out] pdpte The L3 entry mapping `vaddr`
 * @param[in,out] pde   The L2 entry mapping `vaddr`
 * @param[in,out] pte   The L1 entry mapping `vaddr`
 * @param[out]    paddr The physical address to which `vaddr` maps
 * @return              If `vaddr` is mapped, the paging level of the leaf
 *                      entry;
 *                      if `vaddr` is not mapped, the negative of the paging
 *                      level of the terminal entry;
 *                      or 0 of `vaddr` is not canonical.
 */
extern int walk_page_table(cr3_t cr3, uintptr_t vaddr, pml4e_t** pml4e,
                           pdpte_t** pdpte, pde_t** pde, pte_t** pte,
                           uintptr_t* paddr);

/**
 * Get the physical address of the specified virtual address using the virtual
 * address space currently in use on this processor.
 *
 * @param vaddr The virtual address for which to query the physical address
 * @return      The physical address to which `vaddr` maps, or PADDR_INVALID if
 *              `vaddr` is unmapped
 */
extern uintptr_t getPhysicalAddr(void* vaddr);

/**
 * Get the physical address of the specified virtual address using the specified
 * L4 pagetable entry.
 *
 * Because we save the L4 entry mapping ghost memory into our thread data, it is
 * common for us to already have the L4 entry when we want to do a walk for a
 * ghost memory address.
 *
 * @param[in]  vaddr  The virtual address to look up
 * @param[in]  pml4e  A pointer to the PML4E entry from which to start the lookup
 * @param[out] paddr  The physical address to which `vaddr` maps
 * @return            True if the walk succeeded, false if it failed (e.g.
 *                    because `vaddr` isn't mapped)
 */
extern bool
getPhysicalAddrFromPML4E(void* vaddr, pml4e_t* pml4e, uintptr_t* paddr);

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

/**
 * Get the currently active root page table pointer.
 *
 * @return  The physical address of the current root page table
 */
static inline uintptr_t get_root_pagetable(void) {
  /* Get the page table value out of CR3 */
  uintptr_t cr3 = read_cr3();

  /*
   * Mask off the flag bits in CR3, leaving just the 4 kB-aligned physical
   * address of the top-level page table.
   */
  return cr3 & PG_FRAME;
}

/*
 * Functions for returing the physical address of page table pages.
 */

/**
 * Get the physical address of the L4 page table entry that maps a virtual
 * address.
 *
 * @param cr3   The root page table pointer
 * @param vaddr A virtual address
 * @return      The physical address of the L4 page table entry that maps
 *              `vaddr`
 */
static inline uintptr_t get_pml4ePaddr(cr3_t cr3, uintptr_t vaddr) {
  return (uintptr_t)&((pml4e_t*)(cr3 & PG_FRAME))[PG_L4_ENTRY(vaddr)];
}

/**
 * Get the physical address of the L3 page table entry that maps a virtual
 * address.
 *
 * @param pml4e The L4 page table entry that mapps `vaddr`
 * @param vaddr A virtual address
 * @return      The physical address of the L3 page table entry that maps
 *              `vaddr`
 */
static inline uintptr_t get_pdptePaddr(pml4e_t pml4e, uintptr_t vaddr) {
  return (uintptr_t)&((pdpte_t*)(pml4e & PG_FRAME))[PG_L3_ENTRY(vaddr)];
}

/**
 * Get the physical address of the L2 page table entry that maps a virtual
 * address.
 *
 * @param pdpte The L3 page table entry that mapps `vaddr`
 * @param vaddr A virtual address
 * @return      The physical address of the L2 page table entry that maps
 *              `vaddr`
 */
static inline uintptr_t get_pdePaddr(pdpte_t pdpte, uintptr_t vaddr) {
  return (uintptr_t)&((pde_t*)(pdpte & PG_FRAME))[PG_L2_ENTRY(vaddr)];
}

/**
 * Get the physical address of the L1 page table entry that maps a virtual
 * address.
 *
 * @param pde   The L2 page table entry that mapps `vaddr`
 * @param vaddr A virtual address
 * @return      The physical address of the L1 page table entry that maps
 *              `vaddr`
 */
static inline uintptr_t get_ptePaddr(pde_t pde, uintptr_t vaddr) {
  return (uintptr_t)&((pte_t*)(pde & PG_FRAME))[PG_L1_ENTRY(vaddr)];
}

/*
 * Function prototypes for finding the virtual address of page table components
 */

/**
 * Get a pointer to the L4 page table entry that maps a virtual address.
 *
 * @param cr3   The root page table pointer
 * @param vaddr A virtual address
 * @return      A pointer to the L4 page table entry that maps `vaddr`
 */
static inline pml4e_t* get_pml4eVaddr(cr3_t cr3, uintptr_t vaddr) {
  return (pml4e_t*)getVirtual(get_pml4ePaddr(cr3, vaddr));
}

/**
 * Get a pointer to the L3 page table entry that maps a virtual address.
 *
 * @param pml4e The L4 page table entry that mapps `vaddr`
 * @param vaddr A virtual address
 * @return      A pointer to the L3 page table entry that maps `vaddr`
 */
static inline pdpte_t* get_pdpteVaddr(pml4e_t pml4e, uintptr_t vaddr) {
  return (pdpte_t*)getVirtual(get_pdptePaddr(pml4e, vaddr));
}

/**
 * Get a pointer to the L2 page table entry that maps a virtual address.
 *
 * @param pml4e The L3 page table entry that mapps `vaddr`
 * @param vaddr A virtual address
 * @return      A pointer to the L2 page table entry that maps `vaddr`
 */
static inline pde_t* get_pdeVaddr(pdpte_t pdpte, uintptr_t vaddr) {
  return (pde_t*)getVirtual(get_pdePaddr(pdpte, vaddr));
}

/**
 * Get a pointer to the L1 page table entry that maps a virtual address.
 *
 * @param pml4e The L2 page table entry that mapps `vaddr`
 * @param vaddr A virtual address
 * @return      A pointer to the L1 page table entry that maps `vaddr`
 */
static inline pte_t* get_pteVaddr(pde_t pde, uintptr_t vaddr) {
  return (pte_t*)getVirtual(get_ptePaddr(pde, vaddr));
}

/* Functions for querying information about a page table entry */

/**
 * Determine if a page table entry is present.
 *
 * @param pte The entry to test
 * @return    True if the entry is present, otherwise false
 */
static inline bool isPresent(page_entry_t pte) {
  return pte & PG_V;
}

/**
 * Determine if a extended page table entry is present.
 *
 * Note that, unlike regular page tables, extended page tables don't have a
 * present bit. Instead, an entry is considered present if any of the read,
 * write, or execute permissions are enabled for it.
 *
 * @param pte The entry to test
 * @return    True if the entry is present, otherwise false
 */
static inline bool isPresentEPT(page_entry_t epte) {
  /*
   * EPT page table entries don't have a "valid" flag. Instead, a mapping is
   * considered present if and only if any of the read, write, or execute
   * flags are set to 1.
   */
  return epte & PG_EPT_R || epte & PG_EPT_W || epte & PG_EPT_X;

  /*
   * NOTE: if the "mode-based execute control for EPT" VM-execution control
   * is enabled, the X bit only controls supervisor-mode accesses, and a
   * separate XU bit controls user-mode execute permissions. Thus, when this
   * feature is enabled, we need to check all four of the R, W, X, and XU
   * bits to determine whether the mapping is present.
   *
   * However, when this feature is disabled (or unsupported by the hardware),
   * the XU bit is *ignored* by the processor, we we need to check *only* the
   * R, W, and X bits.
   *
   * This is a brand-new feature recently added by Intel and our sort-of-new
   * development hardware (Broadwell) doesn't support it, so we do not
   * currently support it in SVA, i.e., it is assumed to be disabled. Thus we
   * can unconditionally check just the R, W, and X bits here.
   *
   * If/when we support or make use of this feature in SVA in the future, we
   * will need to change this function to behave as follows *ONLY* when
   * mode-based execute control is enabled:
   *
   *  return epte & PG_EPT_R || epte & PG_EPT_W || epte & PG_EPT_X ||
   *         epte & PG_EPT_XU;
   */
}

/**
 * Determine if a (possibly extended) page table entry is present.
 *
 * This is a convienient wrapper for `isPresent()` and `isPresentEPT()`.
 *
 * @param pte   The entry to test
 * @param isEPT Whether or not this is an EPT entry
 * @return      True if the entry is present, otherwise false
 */
static inline bool isPresent_maybeEPT(page_entry_t pte, unsigned char isEPT) {
  /*
   * Calls the right isPresent() function depending on whether this is an EPT
   * mapping.
   */
  if (isEPT)
    return isPresentEPT(pte);
  else
    return isPresent(pte);
}

/**
 * Determine if a page table entry maps a writable page.
 *
 * Note that this only tests the entry itself. Pages mapped by it may still not
 * be writable due to write permission being disabled somewhere else in the
 * paging hierarchy.
 *
 * @param pte The entry to test
 * @return    True if `entry` maps a writable page, otherwise false
 */
static inline bool isWritable(page_entry_t pte) {
  return pte & PG_RW;
}

/**
 * Determine if a page table entry maps an executable page.
 *
 * Note that this only tests the entry itself. Pages mapped by it may still not
 * be executable due to execute permission being disabled somewhere else in the
 * paging hierarchy.
 *
 * @param pte The entry to test
 * @return    True if `entry` maps an executable page, otherwise false
 */
static inline bool isExecutable(page_entry_t pte) {
  return !(pte & PG_NX);
}

/**
 * Determine if a page table entry maps a user-accessible page.
 *
 * Note that this only tests the entry itself. Pages mapped by it may still not
 * be accessible to user space due to write permission being disabled somewhere
 * else in the paging hierarchy.
 *
 * @param pte The entry to test
 * @return    True if `entry` maps a user-accessible page, otherwise false
 */
static inline bool isUserMapping(page_entry_t pte) {
  return pte & PG_U;
}

/**
 * Determine if a page table entry maps a "huge" page.
 *
 * @param entry The page table entry that may map a huge page
 * @param level The level of the page table which contains `entry`
 * @return      True if `entry` maps a huge page, otherwise false
 */
static inline bool isHugePage(page_entry_t pte, enum page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_L4:
  case PG_EPTL1:
  case PG_EPTL4:
    return false;
  case PG_L2:
  case PG_L3:
    return pte & PG_PS;
  case PG_EPTL2:
  case PG_EPTL3:
    return pte & PG_EPT_PS;
  default:
    // TODO: Other page table types
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Not a page table type %d\n", level);
  }
}

/**
 * Determine if a page table entry is a leaf entry (one that maps data, not a
 * lower level page table).
 *
 * @param entry The page table entry that may be a leaf entry
 * @param level The level of the page table which contains `entry`
 * @return      True if `entry` is a leaf entry, otherwise false
 */
static inline bool isLeafEntry(page_entry_t pte, enum page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_EPTL1:
    // L1 entries are always leaf entries.
    return true;
  default:
    return isHugePage(pte, level);
  }
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
/*
 * Description:
 *  Given a page table entry value, return the page description associate with
 *  the frame being addressed in the mapping.
 *
 * Inputs:
 *  mapping: the mapping with the physical address of the referenced frame
 *
 * Return:
 *  Pointer to the page_desc for this frame
 */
page_desc_t * getPageDescPtr(unsigned long mapping);

/* See implementation in c file for details */
static inline page_entry_t * va_to_pte (uintptr_t va, enum page_type_t level);
static inline int isValidMappingOrder (page_desc_t *pgDesc, uintptr_t newVA);
void initDeclaredPage (unsigned long frameAddr);

/**
 * Get the terminal page table entry mapping the specified virtual address.
 *
 * This could be the leaf entry that actually maps the virtual address to a
 * physical address, or it could be the first entry that doesn't have is not
 * present (valid bit unset).
 *
 * @param vaddr The virtual address for which to find the terminal entry
 * @return      A pointer to the terminal page table entry mapping `vaddr`, or
 *              `NULL` if an error was encountered during the page table walk
 */
page_entry_t* get_pgeVaddr(uintptr_t vaddr);

void page_entry_store(unsigned long *page_entry, page_entry_t newVal);

#if 0
static inline uintptr_t
pageVA(page_desc_t pg){
    return getVirtual(pg.physAddress);    
}
#endif

/*
 * Description:
 *  This function takes a page table mapping and set's the flag to read only. 
 *
 *  Also works for extended page table (EPT) updates, because the R bit in
 *  EPT PTEs is at the same place (#1) as the R/W bit in regular PTEs.
 * 
 * Inputs:
 *  - mapping: the mapping to add read only flag to
 *
 * Return:
 *  - A new mapping set to read only
 *
 *  Note that setting the read only flag does not necessarily mean that the
 *  read only protection is enabled in the system. It just indicates that if
 *  the system has the write protection enabled then the value of this bit is
 *  considered.
 */
static inline page_entry_t
setMappingReadOnly (page_entry_t mapping) { 
  return (mapping & ~((uintptr_t)(PG_RW))); 
}

/*
 * Description:
 *  This function takes a page table mapping and set's the flag to read/write. 
 * 
 * Inputs:
 *  - mapping: the mapping to which to add read/write permission
 *
 * Return:
 *  - A new mapping set with read/write permission
 */
static inline page_entry_t
setMappingReadWrite (page_entry_t mapping) { 
  return (mapping | PG_RW); 
}

/*
 * Mapping update function prototypes.
 */
void __update_mapping (pte_t * pageEntryPtr, page_entry_t val);

/**
 * Get the number of active references to a page.
 *
 * @param page  The page for which to get the reference count
 * @return      The reference count for the page
 */
static inline unsigned int pgRefCount(page_desc_t* page) {
  return page->count;
}

/**
 * Get the number of writable references to a page.
 *
 * @param page  The page for which to get the writable reference count
 * @return      The writable reference count for the page
 */
static inline unsigned int pgRefCountWr(page_desc_t* page) {
  return page->wr_count;
}

/**
 * Increment a page's writable reference count, and get the old value.
 *
 * This is useful for e.g. copy-on-write to change just a frame's writable
 * reference count.
 *
 * @param page  The page whose writable reference count is to be incremented
 * @return      The old writable reference count for the page
 */
static inline unsigned int pgRefCountIncWr(page_desc_t* page) {
  unsigned int wr_count = page->wr_count;

  SVA_ASSERT(wr_count + 1 <= page->count,
    "SVA: FATAL: Frame metadata inconsistency: "
    "writable count is greater than total count: frame 0x%lx\n",
    (page - page_desc));

  SVA_ASSERT(wr_count < PG_REF_COUNT_MAX,
    "SVA: FATAL: Overflow in frame writable reference count: frame %lx\n",
    (page - page_desc));
  page->wr_count = wr_count + 1;

  return wr_count;
}

/**
 * Decrement a page's writable reference count, and get the old value.
 *
 * This is useful for e.g. copy-on-write to change just a frame's writable
 * reference count.
 *
 * @param page  The page whose writable reference count is to be decremented
 * @return      The old writable reference count for the page
 */
static inline unsigned int pgRefCountDecWr(page_desc_t* page) {
  unsigned int wr_count = page->wr_count;

  SVA_ASSERT(wr_count <= page->count,
    "SVA: FATAL: Frame metadata inconsistency: "
    "writable count is greater than total count: frame 0x%lx\n",
    (page - page_desc));

  SVA_ASSERT(wr_count > 0,
    "SVA: FATAL: Frame metadata inconsistency: "
    "attempt to decrement writable reference count below 0: "
    "frame %lx\n", (page - page_desc));
  page->wr_count = wr_count - 1;

  return wr_count;
}

/**
 * Increment a page's reference count, and get the old value.
 *
 * @param page      The page whose reference count is to be incremented
 * @param writable  Whether to also increment the writable reference count
 * @return          The old reference count for the page
 */
static inline unsigned int pgRefCountInc(page_desc_t* page, bool writable) {
  unsigned int count = page->count;

  SVA_ASSERT(count < PG_REF_COUNT_MAX,
    "SVA: FATAL: Overflow in frame reference count: frame %lx\n",
    (page - page_desc));
  page->count = count + 1;
  if (writable) {
    pgRefCountIncWr(page);
  }

  return count;
}

/**
 * Decrement a page's reference count, and get the old value.
 *
 * @param page      The page whose reference count is to be decremented
 * @param writable  Whether to also increment the writable reference count
 * @return          The old reference count for the page
 */
static inline unsigned int pgRefCountDec(page_desc_t* page, bool writable) {
  unsigned int count = page->count;

  if (writable) {
    pgRefCountDecWr(page);
  }
  SVA_ASSERT(count > 0,
    "SVA: FATAL: Frame metadata inconsistency: "
    "attempt to decrement reference count below 0: "
    "frame %lx\n", (page - page_desc));
  page->count = count - 1;

  return count;
}

/*
 *******************************************************************************
 * Page type queries
 *******************************************************************************
 */

static inline int isL1Pg (page_desc_t *page) { return page->type == PG_L1; }

static inline int isL2Pg (page_desc_t *page) { return page->type == PG_L2; }

static inline int isL3Pg (page_desc_t *page) { return page->type == PG_L3; }

static inline int isL4Pg (page_desc_t *page) { return page->type == PG_L4; }

static inline int isEPTL1Pg (page_desc_t *page) { return page->type == PG_EPTL1; }

static inline int isEPTL2Pg (page_desc_t *page) { return page->type == PG_EPTL2; }

static inline int isEPTL3Pg (page_desc_t *page) { return page->type == PG_EPTL3; }

static inline int isEPTL4Pg (page_desc_t * page) { return page->type = PG_EPTL4; }

static inline int isSVAPg (page_desc_t *page) { return page->type == PG_SVA; }

static inline int isCodePg (page_desc_t *page) { return page->type == PG_CODE; }

static inline int isGhostPTP (page_desc_t *page) {
  switch (page->type) {
  case PG_SML1:
  case PG_SML2:
  case PG_SML3:
    return true;
  default:
    return false;
  }
}

static inline int isGhostPG(page_desc_t *page) {
    return page->type == PG_GHOST;
}

static inline int isPTP (page_desc_t *pg) {
    return  pg->type == PG_L4    ||
            pg->type == PG_L3    ||
            pg->type == PG_L2    ||
            pg->type == PG_L1
            ;
}

static inline int isCodePG (page_desc_t *page){ return page->type == PG_CODE; }

/**
 * Get the integer value of the page level of a page type.
 *
 * For example, `PG_L4` is level 4. Types that aren't page tables are defined
 * to have level 0.
 *
 * @param type The page type to get the integer level for
 * @return     The integer page level of the page type `type`
 */
static inline int getIntLevel(page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_EPTL1:
  case PG_SML1:
    return 1;
  case PG_L2:
  case PG_EPTL2:
  case PG_SML2:
    return 2;
  case PG_L3:
  case PG_EPTL3:
  case PG_SML3:
    return 3;
  case PG_L4:
  case PG_EPTL4:
    return 4;
  default:
    return 0;
  }
}

/**
 * Get the type of page mapped by the entries in a page table.
 *
 * @param level The level of page table
 * @return      The type of page mapped by entries in a page table at `level`
 */
static inline enum page_type_t getSublevelType(enum page_type_t level) {
  switch (level) {
  case PG_L4:
    return PG_L3;
  case PG_L3:
    return PG_L2;
  case PG_L2:
    return PG_L1;
  case PG_L1:
    return PG_DATA;
  default:
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Not a page table frame type\n");
  }
}

/**
 * Get the number of bytes mapped by a page table entry.
 *
 * @param level The level of the page table entry
 * @return      The number of bytes mapped by a page table entry at a given
 *              level page table
 */
static inline size_t getMappedSize(enum page_type_t level) {
  switch (level) {
  case PG_L4:
    return PG_L4_SIZE;
  case PG_L3:
    return PG_L3_SIZE;
  case PG_L2:
    return PG_L2_SIZE;
  case PG_L1:
    return PG_L1_SIZE;
  default:
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Not a page table frame type\n");
  }
}

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
