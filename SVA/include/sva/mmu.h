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
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
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
 * Derived from hp300 version by Mike Hibler, this version by William
 * Jolitz uses a recursive map [a pde points to the page directory] to
 * map the page tables using the pagetables themselves. This is done to
 * reduce the impact on kernel virtual memory for lots of sparse address
 * space, and to reduce the cost of memory to each process.
 *
 *  from: hp300: @(#)pmap.h 7.2 (Berkeley) 12/16/90
 *  from: @(#)pmap.h    7.4 (Berkeley) 5/12/91
 * $FreeBSD: release/9.0.0/sys/amd64/include/pmap.h 222813 2011-06-07 08:46:13Z attilio $
 *
 *===----------------------------------------------------------------------===
 */


#ifndef SVA_MMU_H
#define SVA_MMU_H

#include "mmu_types.h"

#include "sva/assert.h"
#include "sva/callbacks.h"
#include "sva/secmem.h"
#include "sva/state.h"
#include "sva/util.h"
#include "sva/vmx.h"

/* Size of the smallest page frame in bytes */
static const uintptr_t X86_PAGE_SIZE = 4096u;

/* Number of bits to shift to get the page number out of a PTE entry */
static const unsigned PAGESHIFT = 12;

/* Size of the physical memory and page size in bytes */
static const unsigned long memSize = 0x0000002000000000u; /* 128GB */
static const unsigned long pageSize = 4096;
static const unsigned long numPageDescEntries = memSize / pageSize;

/* Mask to get the proper number of bits from the virtual address */
static const uintptr_t vmask = 0x0000000000000ff8u;

/* The number of references allowed per page table page */
static const int maxPTPVARefs = 1;

/* The count must be at least this value to remove a mapping to a page */
static const int minRefCountToRemoveMapping = 1;

/*
 * Offset into the PML4E at which the mapping for the secure memory region can
 * be found.
 */
static const uintptr_t secmemOffset = ((SECMEMSTART >> 39) << 3) & vmask;

/* Zero mapping is the mapping that eliminates the previous entry */
static const uintptr_t ZERO_MAPPING = 0;

/*
 *****************************************************************************
 * Define structures used in the SVA MMU interface.
 *****************************************************************************
 */

/*
 * Frame usage constants
 */
/* Enum representing the four page types */
enum page_type_t {
    PG_UNUSED = 0,
    PG_L1,          /*  1: Defines a page being used as an L1 PTP */
    PG_L2,          /*  2: Defines a page being used as an L2 PTP */
    PG_L3,          /*  3: Defines a page being used as an L3 PTP */
    PG_L4,          /*  4: Defines a page being used as an L4 PTP */
    PG_LEAF,        /*  5: Generic type representing a valid LEAF page */
    PG_TKDATA,      /*  6: Defines a kernel data page */
    PG_TUDATA,      /*  7: Defines a user data page */
    PG_CODE,        /*  8: Defines a code page */
    PG_SVA,         /*  9: Defines an SVA system page */
    PG_GHOST,       /* 10: Defines a secure page */
    PG_DML1,        /* 11: Defines a L1 PTP  for the direct map */
    PG_DML2,        /* 12: Defines a L2 PTP  for the direct map */
    PG_DML3,        /* 13: Defines a L3 PTP  for the direct map */
    PG_DML4,        /* 14: Defines a L4 PTP  for the direct map */
    PG_EPTL1,       /* 15: Defines a L1 PTP for Extended Page Tables (VMX) */
    PG_EPTL2,       /* 16: Defines a L2 PTP for Extended Page Tables (VMX) */
    PG_EPTL3,       /* 17: Defines a L3 PTP for Extended Page Tables (VMX) */
    PG_EPTL4,       /* 18: Defines a L4 PTP for Extended Page Tables (VMX) */
};

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
    enum page_type_t type : 5;

    /**
     * Whether this frame is a Ghost page table page.
     */
    unsigned ghostPTP : 1;

    /**
     * Whether this frame is a page table for the SVA direct map.
     */
    unsigned dmap : 1;

    /**
     * Whether this frame is mapped in user space.
     */
    unsigned user : 1;

#define PG_REF_COUNT_BITS 12
#define PG_REF_COUNT_MAX ((1U << PG_REF_COUNT_BITS) - 1)

    /**
     * Number of times this frame is mapped.
     */
    unsigned count : PG_REF_COUNT_BITS;
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

/*
 * ===========================================================================
 * BEGIN FreeBSD CODE BLOCK
 *
 * $FreeBSD: release/9.0.0/sys/amd64/include/pmap.h 222813 2011-06-07 08:46:13Z attilio $
 * ===========================================================================
 */

/* MMU Flags ---- Intel Nomenclature ---- */
#define PG_V        0x001   /* P    Valid               */
#define PG_RW       0x002   /* R/W  Read/Write          */
#define PG_U        0x004   /* U/S  User/Supervisor     */
#define PG_NC_PWT   0x008   /* PWT  Write through       */
#define PG_NC_PCD   0x010   /* PCD  Cache disable       */
#define PG_A        0x020   /* A    Accessed            */
#define PG_M        0x040   /* D    Dirty               */
#define PG_PS       0x080   /* PS   Page size (0=4k,1=2M)   */
#define PG_PTE_PAT  0x080   /* PAT  PAT index           */
#define PG_G        0x100   /* G    Global              */
#define PG_AVAIL1   0x200   /*    / Available for system    */
#define PG_AVAIL2   0x400   /*   <  programmers use     */
#define PG_AVAIL3   0x800   /*    \                     */
#define PG_PDE_PAT  0x1000  /* PAT  PAT index           */
#define PG_NX       (1ul<<63) /* No-execute             */

/* Various interpretations of the above */
#define PG_W        PG_AVAIL1   /* "Wired" pseudoflag */
#define PG_MANAGED  PG_AVAIL2
#define PG_FRAME    (0x000ffffffffff000ul)
#define PG_PS_FRAME (0x000fffffffe00000ul)
#define PG_PROT     (PG_RW|PG_U)    /* all protection bits . */
#define PG_N        (PG_NC_PWT|PG_NC_PCD)   /* Non-cacheable */

/* Size of the level 1 page table units */
#define PAGE_SHIFT  12      /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE   (1<<PAGE_SHIFT) /* bytes/page */
#define NPTEPG      (PAGE_SIZE/(sizeof (pte_t)))
#define NPTEPGSHIFT 9       /* LOG2(NPTEPG) */
#define PAGE_MASK   (PAGE_SIZE-1)
/* Size of the level 2 page directory units */
#define NPDEPG      (PAGE_SIZE/(sizeof (pde_t)))
#define NPDEPGSHIFT 9       /* LOG2(NPDEPG) */
#define PDRSHIFT    21              /* LOG2(NBPDR) */
#define NBPDR       (1<<PDRSHIFT)   /* bytes/page dir */
#define PDRMASK     (NBPDR-1)
/* Size of the level 3 page directory pointer table units */
#define NPDPEPG     (PAGE_SIZE/(sizeof (pdpte_t)))
#define NPDPEPGSHIFT    9       /* LOG2(NPDPEPG) */
#define PDPSHIFT    30      /* LOG2(NBPDP) */
#define NBPDP       (1<<PDPSHIFT)   /* bytes/page dir ptr table */
#define PDPMASK     (NBPDP-1)
/* Size of the level 4 page-map level-4 table units */
#define NPML4EPG    (PAGE_SIZE/(sizeof (pml4e_t)))
#define NPML4EPGSHIFT   9       /* LOG2(NPML4EPG) */
#define PML4SHIFT   39      /* LOG2(NBPML4) */
#define NBPML4      (1UL<<PML4SHIFT)/* bytes/page map lev4 table */
#define PML4MASK    (NBPML4-1)

/*
 * Note (Ethan Johnson, 8/23/18): I'm not sure if the following lines should
 * be included in the "FreeBSD code block". They were added in a 10/9/17
 * commit by Xiaowan Dong (hash 8339693, note "COW on ghost memory"), so they
 * may be original content written by the SVA research group and not part of
 * the FreeBSD-copyrighted section.
 */
/* Page fault code flags*/
#define PGEX_P      0x01    /* Protection violation vs. not present */
#define PGEX_W      0x02    /* during a Write cycle */

/* Fork code flags */
#define RFPROC      (1<<4)  /* change child (else changes curproc) */
#define RFMEM       (1<<5)  /* share `address space' */
/*
 * ===========================================================================
 * END FreeBSD CODE BLOCK
 * ===========================================================================
 */

/// The number of entries in a page table
#define PG_ENTRIES 512

/*
 * Shift amounts for the virtual address bits corresponding to each paging
 * level.
 */
#define PG_L1_SHIFT 12
#define PG_L2_SHIFT 21
#define PG_L3_SHIFT 30
#define PG_L4_SHIFT 39

/*
 * The number of bytes mapped by a page table entry at each level.
 */
#define PG_L1_SIZE (1UL << PG_L1_SHIFT)
#define PG_L2_SIZE (1UL << PG_L2_SHIFT)
#define PG_L3_SIZE (1UL << PG_L3_SHIFT)
#define PG_L4_SIZE (1UL << PG_L4_SHIFT)

/*
 * Macros to get the entry index in a page table at each level for a given
 * virtual address.
 */
#define PG_L1_ENTRY(v) ((uintptr_t)(v) >> PG_L1_SHIFT & (PG_ENTRIES - 1))
#define PG_L2_ENTRY(v) ((uintptr_t)(v) >> PG_L2_SHIFT & (PG_ENTRIES - 1))
#define PG_L3_ENTRY(v) ((uintptr_t)(v) >> PG_L3_SHIFT & (PG_ENTRIES - 1))
#define PG_L4_ENTRY(v) ((uintptr_t)(v) >> PG_L4_SHIFT & (PG_ENTRIES - 1))

#ifdef SVA_DMAP
/*
 * Flags for SVA direct map page table entries.
 */
#define PG_DMAP_L3 (PG_V | PG_RW | PG_A | PG_PS | PG_G | PG_NX)
#define PG_DMAP_L4 (PG_V | PG_RW | PG_A | PG_G | PG_NX)
#endif

/*
 * NDMPML4E is the number of PML4 entries that are used to implement the
 * SVA direct map.  It must be a power of two.
 */
#define NDMPML4E    1 
#define KPML4I      (NPML4EPG - 1)    /* Top 512GB for KVM */
#define DMPML4I     (KPML4I - 4) //(KPML4I - NDMPML4E)/NDMPML4E * NDMPML4E /* the index of SVA direct mapping on pml4*/


/* ASID/page table switch*/
#define PML4PML4I   (NPML4EPG/2)    /* Index of recursive pml4 mapping */
#define PML4_SWITCH_DISABLE 0x10    /*Disable pmle4 page table page switch in Trap() handler*/

/* EPT page table entry flags */
#define PG_EPT_R    0x1     /* R    Read                */
#define PG_EPT_W    PG_RW   /* W    Write               */
                            /* (0x2, same as R/W bit in regular page tables) */
#define PG_EPT_X    0x4     /* X    Execute             */
                            /* (only for supervisor accesses if mode-based
                             * control enabled) */
#define PG_EPT_IPAT 0x40    /* IPAT Ignore PAT memory type */
#define PG_EPT_PS   PG_PS   /* PS   Page size           */
                            /* (0x80, same as regular page tables) */
#define PG_EPT_A    0x100   /* A    Accessed            */
#define PG_EPT_D    0x200   /* D    Dirty               */
#define PG_EPT_XU   0x400   /* XU   Execute (user-mode) */
                            /* (only if mode-based execute control enabled) */
#define PG_EPT_SVE  (1ul<<63) /* SVE Suppress EPT-violation #VE (if enabled) */

extern uintptr_t getPhysicalAddr (void * v);
extern unsigned char
getPhysicalAddrFromPML4E (void * v, pml4e_t * pml4e, uintptr_t * paddr);
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

/*
 *****************************************************************************
 * SVA utility functions needed by multiple compilation units
 *****************************************************************************
 */

/*
 * Function: getVirtualSVADMAP()
 *
 * Description:
 *  This function takes a physical address and converts it into a virtual
 *  address that the SVA VM can access based on SVA direct mapping.
 *
 */
static inline unsigned char *
getVirtualSVADMAP (uintptr_t physical) {
  return (unsigned char *)(physical | SVADMAPSTART);
}

/**
 * Get the kernel direct map virtual address for a physical address.
 *
 * @param paddr A physical address
 * @return      A virtual address in the kernel's direct map which maps to
 *              `paddr`
 */
static inline unsigned char*
getVirtualKernelDMAP(uintptr_t physical) {
  return (unsigned char *)(physical | KERNDMAPSTART);
}


/*
 * Function: getVirtual()
 *
 * Description:
 *  This function takes a physical address and converts it into a virtual
 *  address that the SVA VM can access based on kernel direct mapping.
 *
 *  In a real system, this is done by having the SVA VM create its own
 *  virtual-to-physical mapping of all of physical memory within its own
 *  reserved portion of the virtual address space.  However, for now, we'll
 *  take advantage of FreeBSD's direct map of physical memory so that we don't
 *  have to set one up.
 */
static inline unsigned char *
getVirtual (uintptr_t physical) {
#ifdef SVA_DMAP
  return getVirtualSVADMAP(physical);
#else
  return getVirtualKernelDMAP(physical);
#endif
}

/* 
 * Function prototypes for finding the virtual address of page table components
 */

static inline pml4e_t *
get_pml4eVaddr (unsigned char * cr3, uintptr_t vaddr) {
  /* Offset into the page table */
  uintptr_t offset = (vaddr >> (39 - 3)) & vmask;
#ifdef SVA_DMAP
  return (pml4e_t *) getVirtualSVADMAP (((uintptr_t)cr3) | offset);
#else
  return (pml4e_t *) getVirtual (((uintptr_t)cr3) | offset);
#endif
}
 
static inline pdpte_t *
get_pdpteVaddr (pml4e_t * pml4e, uintptr_t vaddr) {
  uintptr_t base   = (*pml4e) & 0x000ffffffffff000u;
  uintptr_t offset = (vaddr >> (30 - 3)) & vmask;
#ifdef SVA_DMAP
  return (pdpte_t *) getVirtualSVADMAP (base | offset);
#else
  return (pdpte_t *) getVirtual (base | offset);
#endif
}

static inline pde_t *
get_pdeVaddr (pdpte_t * pdpte, uintptr_t vaddr) {
  uintptr_t base   = (*pdpte) & 0x000ffffffffff000u;
  uintptr_t offset = (vaddr >> (21 - 3)) & vmask;
#ifdef SVA_DMAP
  return (pde_t *) getVirtualSVADMAP (base | offset);
#else
  return (pde_t *) getVirtual (base | offset);
#endif
}

static inline pte_t *
get_pteVaddr (pde_t * pde, uintptr_t vaddr) {
  uintptr_t base   = (*pde) & 0x000ffffffffff000u;
  uintptr_t offset = (vaddr >> (12 - 3)) & vmask;
#ifdef SVA_DMAP  
  return (pte_t *) getVirtualSVADMAP (base | offset);
#else
  return (pte_t *) getVirtual (base | offset);
#endif
}


 /*
  * Functions for returing the physical address of page table pages.
  */
static inline uintptr_t
get_pml4ePaddr (unsigned char * cr3, uintptr_t vaddr) {
  /* Offset into the page table */
  uintptr_t offset = ((vaddr >> 39) << 3) & vmask;
  return (((uintptr_t)cr3) | offset);
}
 
static inline uintptr_t
get_pdptePaddr (pml4e_t * pml4e, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr  >> 30) << 3) & vmask;
  return ((*pml4e & 0x000ffffffffff000u) | offset);
}

static inline uintptr_t
get_pdePaddr (pdpte_t * pdpte, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr  >> 21) << 3) & vmask;
  return ((*pdpte & 0x000ffffffffff000u) | offset);
}

static inline uintptr_t
get_ptePaddr (pde_t * pde, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr >> 12) << 3) & vmask;
  return ((*pde & 0x000ffffffffff000u) | offset);
}

/* Functions for querying information about a page table entry */
static inline unsigned char
isPresent (page_entry_t * pte) {
  return (*pte & PG_V) ? 1u : 0u;
}
static inline unsigned char
isPresentEPT (page_entry_t * epte) {
  /*
   * EPT page table entries don't have a "valid" flag. Instead, a mapping is
   * considered present if and only if any of the read, write, or execute
   * flags are set to 1.
   */
  if ((*epte & PG_EPT_R) || (*epte & PG_EPT_W) || (*epte & PG_EPT_X))
    return 1;
  else
    return 0;
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
   *  if ((*epte & PG_EPT_R) || (*epte & PG_EPT_W) || (*epte & PG_EPT_X)
   *      || (*epte & PG_EPT_XU))
   *    return 1;
   *  else
   *    return 0;
   */
}
static inline unsigned char
isPresent_maybeEPT (page_entry_t * pte, unsigned char isEPT) {
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
 * Determine if a page table entry maps a "huge" page.
 *
 * Note: Behavior is undefined if this is called on a page table entry that is
 * not from an l2 or l3 table.
 *
 * @param entry The page table entry that may map a huge page
 * @return      True if `entry` maps a huge page, otherwise false.
 */
static inline bool isHugePage(page_entry_t* pte) {
  return *pte & PG_PS;
}

/*
 * Function: get_pagetable()
 *
 * Description:
 *  Return a physical address that can be used to access the current
 *  top-level page table.
 */
static inline unsigned char *
get_pagetable (void) {
  /* Get the page table value out of CR3 */
  uintptr_t cr3 = read_cr3();

  /*
   * Mask off the flag bits in CR3, leaving just the 4 kB-aligned physical
   * address of the top-level page table.
   */
  return (unsigned char *)(cr3 & PG_FRAME);
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

/*
 * Invalidate all the TLB entries with a specific virtual address
 * (including global entries)
 */
static __inline void
invlpg(u_long addr) {
  __asm __volatile("invlpg %0" : : "m" (*(char *)addr) : "memory");
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
page_entry_t *get_pgeVaddr(uintptr_t vaddr);
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


/*
 *****************************************************************************
 * Page descriptor query functions
 *****************************************************************************
 */

/* Page setter methods */

/* State whether this kernel virtual address is in the secure memory range */
static inline int isGhostVA(uintptr_t va)
    { return (va >= SECMEMSTART) && (va < SECMEMEND); }

/* 
 * The following functions query the given page descriptor for type attributes.
 */
static inline int isFramePg (page_desc_t *page) { 
  return (page->type == PG_UNUSED)   ||      /* Defines an unused page */
         (page->type == PG_TKDATA)   ||      /* Defines a kernel data page */
         (page->type == PG_TUDATA)   ||      /* Defines a user data page */
         (page->type == PG_CODE);           /* Defines a code page */
}

/* Description: Return whether the page is active or not */
static inline int pgIsActive (page_desc_t *page) 
    { return page->type != PG_UNUSED ; } 

/**
 * Determine if a virtual address is part of the kernel's direct map.
 *
 * @param address The virtual address to check
 * @return        Whether or not `address` is part of the kernel's direct map
 */
static inline bool isKernelDirectMap(uintptr_t address) {
  return ((KERNDMAPSTART <= address) && (address < KERNDMAPEND));
}

#ifdef SVA_DMAP
/**
 * Determine if a virtual address is part of SVA's direct map.
 *
 * @param address The virtual address to check
 * @return        Whether or not `address` is part of SVA's direct map
 */
static inline bool isSVADirectMap(uintptr_t address) {
  return ((SVADMAPSTART <= address) && (address < SVADMAPEND));
}
#endif

/**
 * Determine if a virtual address is part of the direct map.
 *
 * This checks SVA's direct map if it is enabled, otherwise it checks the
 * kernel's.
 *
 * @param address The virtual address to check
 * @return        Whether or not `address` is part of the direct map
 */
static inline bool isDirectMap(uintptr_t address) {
#ifdef SVA_DMAP
  return isSVADirectMap(address);
#else
  return isKernelDirectMap(address);
#endif
}

/**
 * Get the number of active references to the page.
 *
 * @param page  The page for which to get the reference count
 * @return      The reference count for the page
 */
static inline unsigned int pgRefCount(page_desc_t* page) {
  return page->count;
}

/**
 * Increment a page's reference count, and get the old value.
 *
 * @param page  The page whose reference count is to be incremented
 * @return      The old reference count for the page
 */
static inline unsigned int pgRefCountInc(page_desc_t* page) {
  unsigned int count = page->count;
  SVA_ASSERT(count < PG_REF_COUNT_MAX,
    "Overflow in page reference count: frame %lx\n", (page - page_desc));
  page->count = count + 1;
  return count;
}

/**
 * Decrement a page's reference count, and get the old value.
 *
 * @param page  The page whose reference count is to be decremented
 * @return      The old reference count for the page
 */
static inline unsigned int pgRefCountDec(page_desc_t* page) {
  unsigned int count = page->count;
  SVA_ASSERT(count > 0,
    "Frame metadata inconsistency: "
    "attempt to decrement reference count below 0: "
    "frame %lx\n", (page - page_desc));
  page->count = count - 1;
  return count;
}

/* Page type queries */
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
static inline int isGhostPTP (page_desc_t *page) { return page->ghostPTP; }

static inline int isGhostPG (page_desc_t *page) { 
    return page->type == PG_GHOST; 
}

static inline int isPTP (page_desc_t *pg) { 
    return  pg->type == PG_L4    ||  
            pg->type == PG_L3    ||  
            pg->type == PG_L2    ||  
            pg->type == PG_L1
            ;
}

static inline int isUserMapping (page_entry_t mapping) { return (mapping & PG_U);}
static inline int isUserPTP (page_desc_t *page) { return isPTP(page) && page->user;}
static inline int isUserPG (page_desc_t *page){ return page->user; }
static inline int isCodePG (page_desc_t *page){ return page->type == PG_CODE; }

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
    if ((isL2Pg(ptePG) || isL3Pg(ptePG) ) && (!(mapping & PG_PS)))
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
