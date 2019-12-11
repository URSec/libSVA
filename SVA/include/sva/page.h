/*===- page.h - SVA Execution Engine  =--------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2019.
 * Copyright (c) Peter Wemm, 2003.
 * Copyright (c) Regents of the University of California, 1991.
 * All rights reserved.
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
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
 *===------------------------------------------------------------------------===
 *
 * X86 page table definitions.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_PAGE_H
#define SVA_PAGE_H

#include <sva/types.h>

/**
 * Invalid physical address.
 *
 * Note that current hardware only supports up to 46 bit physical addresses.
 */
static const uintptr_t PADDR_INVALID = ~0UL;

/**
 * Size of the smallest page frame in bytes.
 */
static const uintptr_t X86_PAGE_SIZE = 4096u;

/**
 * Number of bits to shift to get the page number out of a PTE entry.
 */
static const unsigned PAGESHIFT = 12;

/**
 * Mask to get the proper number of bits from the virtual address.
 */
static const uintptr_t vmask = 0x0000000000000ff8u;

/**
 * Zero mapping is the mapping that eliminates the previous entry.
 */
static const uintptr_t ZERO_MAPPING = 0;

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
 * NDMPML4E is the number of PML4 entries that are used to implement the
 * SVA direct map.  It must be a power of two.
 */
#define NDMPML4E    1
#define KPML4I      (NPML4EPG - 1)    /* Top 512GB for KVM */
#define DMPML4I     (KPML4I - 4) //(KPML4I - NDMPML4E)/NDMPML4E * NDMPML4E /* the index of SVA direct mapping on pml4*/
#define PML4PML4I   (NPML4EPG/2)    /* Index of recursive pml4 mapping */

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

/*
 * ===========================================================================
 * END FreeBSD CODE BLOCK
 * ===========================================================================
 */

/**
 * The number of entries in a page table.
 */
#define PG_ENTRIES 512

/**
 * The virtual address shift for an L1 page table.
 */
#define PG_L1_SHIFT 12

/**
 * The virtual address shift for an L2 page table.
 */
#define PG_L2_SHIFT 21

/**
 * The virtual address shift for an L3 page table.
 */
#define PG_L3_SHIFT 30

/**
 * The virtual address shift for an L4 page table.
 */
#define PG_L4_SHIFT 39

/**
 * The number of bytes mapped by an entry in an L1 page table.
 */
#define PG_L1_SIZE (1UL << PG_L1_SHIFT)

/**
 * The number of bytes mapped by an entry in an L2 page table.
 */
#define PG_L2_SIZE (1UL << PG_L2_SHIFT)

/**
 * The number of bytes mapped by an entry in an L3 page table.
 */
#define PG_L3_SIZE (1UL << PG_L3_SHIFT)

/**
 * The number of bytes mapped by an entry in an L4 page table.
 */
#define PG_L4_SIZE (1UL << PG_L4_SHIFT)

/**
 * Get the index of the L1 pagetable entry mapping a virtual address.
 *
 * @param v A virtual address
 * @return  The index of the L1 page table entry which maps `v`
 */
#define PG_L1_ENTRY(v) ((uintptr_t)(v) >> PG_L1_SHIFT & (PG_ENTRIES - 1))

/**
 * Get the index of the L2 pagetable entry mapping a virtual address.
 *
 * @param v A virtual address
 * @return  The index of the L2 page table entry which maps `v`
 */
#define PG_L2_ENTRY(v) ((uintptr_t)(v) >> PG_L2_SHIFT & (PG_ENTRIES - 1))

/**
 * Get the index of the L3 pagetable entry mapping a virtual address.
 *
 * @param v A virtual address
 * @return  The index of the L3 page table entry which maps `v`
 */
#define PG_L3_ENTRY(v) ((uintptr_t)(v) >> PG_L3_SHIFT & (PG_ENTRIES - 1))

/**
 * Get the index of the L4 pagetable entry mapping a virtual address.
 *
 * @param v A virtual address
 * @return  The index of the L4 page table entry which maps `v`
 */
#define PG_L4_ENTRY(v) ((uintptr_t)(v) >> PG_L4_SHIFT & (PG_ENTRIES - 1))

/**
 * Get the physical address of the frames mapped by an L3 page table entry.
 *
 * This assumes the L3 entry maps a huge page.
 *
 * @param l3e A L3 page table entry
 * @return    The physical address of the frames mapped by `l3e`
 */
#define PG_L3_FRAME(l3e) ((l3e) & PG_FRAME & ~(PG_L3_SIZE - 1))

/**
 * Get the physical address of the frames mapped by an L2 page table entry.
 *
 * This assumes the L2 entry maps a huge page.
 *
 * @param l2e A L2 page table entry
 * @return    The physical address of the frames mapped by `l2e`
 */
#define PG_L2_FRAME(l2e) ((l2e) & PG_FRAME & ~(PG_L2_SIZE - 1))

/**
 * Get the physical address of the frames mapped by an L1 page table entry.
 *
 * @param l1e A L1 page table entry
 * @return    The physical address of the frames mapped by `l1e`
 */
#define PG_L1_FRAME(l1e) ((l1e) & PG_FRAME & ~(PG_L1_SIZE - 1))

/**
 * Get the offset of the L4 page table entry for a virtual address.
 *
 * @param v A virtual address
 * @return  The offset of the entry mapping `v` in an L4 page table
 */
#define PG_L4_OFFSET(v) ((uintptr_t)(v) & (PG_L4_SIZE - 1))

/**
 * Get the offset of the L3 page table entry for a virtual address.
 *
 * @param v A virtual address
 * @return  The offset of the entry mapping `v` in an L3 page table
 */
#define PG_L3_OFFSET(v) ((uintptr_t)(v) & (PG_L3_SIZE - 1))

/**
 * Get the offset of the L2 page table entry for a virtual address.
 *
 * @param v A virtual address
 * @return  The offset of the entry mapping `v` in an L2 page table
 */
#define PG_L2_OFFSET(v) ((uintptr_t)(v) & (PG_L2_SIZE - 1))

/**
 * Get the offset of the L1 page table entry for a virtual address.
 *
 * @param v A virtual address
 * @return  The offset of the entry mapping `v` in an L1 page table
 */
#define PG_L1_OFFSET(v) ((uintptr_t)(v) & (PG_L1_SIZE - 1))

#ifdef SVA_DMAP
/**
 * Flags for an SVA direct map L3 page table entrie.
 */
#define PG_DMAP_L3 (PG_V | PG_RW | PG_A | PG_PS | PG_G | PG_NX)

/**
 * Flags for an SVA direct map L4 page table entry.
 */
#define PG_DMAP_L4 (PG_V | PG_RW | PG_A | PG_G | PG_NX)
#endif

#ifdef SVA_ASID_PG
/* ASID/page table switch*/

/**
 * Disable pmle4 page table page switch in Trap() handler.
 */
#define PML4_SWITCH_DISABLE 0x10
#endif

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

#endif /* SVA_PAGE_H */
