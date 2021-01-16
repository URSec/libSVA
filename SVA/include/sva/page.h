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

#include <sva/asm_const.h>

/*
 * ===========================================================================
 * BEGIN FreeBSD CODE BLOCK
 *
 * $FreeBSD: release/9.0.0/sys/amd64/include/pmap.h 222813 2011-06-07 08:46:13Z attilio $
 * ===========================================================================
 */

/*
 * Note (Colin Pronovost, 2019-12-11): I do not believe that these values are
 * subject to copyright. Even if they are, the copyright would be owned by
 * Intel, not the FreeBSD developers.
 */
#define PG_P        (_ASM_CONST(1, UL) << 0)  // PTE present flag
#define PG_W        (_ASM_CONST(1, UL) << 1)  // PTE writable flag
#define PG_U        (_ASM_CONST(1, UL) << 2)  // PTE user-accessible flag
#define PG_NC_PWT   (_ASM_CONST(1, UL) << 3)  // PTE write-through flag
#define PG_NC_PCD   (_ASM_CONST(1, UL) << 4)  // PTE cache-disable flag
#define PG_A        (_ASM_CONST(1, UL) << 5)  // PTE accessed flag
#define PG_D        (_ASM_CONST(1, UL) << 6)  // PTE dirty flag
#define PG_PS       (_ASM_CONST(1, UL) << 7)  // PTE huge page flag
#define PG_PTE_PAT  (_ASM_CONST(1, UL) << 7)  // PTE PAT flag (for L1 PTEs)
#define PG_G        (_ASM_CONST(1, UL) << 8)  // PTE global flag
#define PG_AVAIL1   (_ASM_CONST(1, UL) << 9)  // Available for kernel's use
#define PG_AVAIL2   (_ASM_CONST(1, UL) << 10) // Available for kernel's use
#define PG_AVAIL3   (_ASM_CONST(1, UL) << 11) // Available for kernel's use
#define PG_PDE_PAT  (_ASM_CONST(1, UL) << 12) // PTE PAT flag (for huge pages)
#define PG_NX       (_ASM_CONST(1, UL) << 63) // PTE no-execute flag

#ifdef FreeBSD
/*
 *******************************************************************************
 * Various FreeBSD-specific values that are needed for the FreeBSD-targeted
 * version of SVA.
 *******************************************************************************
 */

/* Various interpretations of the above */
#define PG_W        PG_AVAIL1   /* "Wired" pseudoflag */
#define PG_MANAGED  PG_AVAIL2
#define PG_FRAME    (0x000ffffffffff000ul)
#define PG_PS_FRAME (0x000fffffffe00000ul)
#define PG_PROT     (PG_W|PG_U)    /* all protection bits. */
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

#endif

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

#ifdef SVA_DMAP
/**
 * Flags for an SVA direct map L3 page table entrie.
 */
#define PG_DMAP_L3 (PG_P | PG_W | PG_A | PG_PS | PG_G | PG_NX)

/**
 * Flags for an SVA direct map L4 page table entry.
 */
#define PG_DMAP_L4 (PG_P | PG_W | PG_A | PG_G | PG_NX)
#endif

/* EPT page table entry flags */
#define PG_EPT_R    (_ASM_CONST(1, UL) << 0)  // EPT readable flag
#define PG_EPT_W    (_ASM_CONST(1, UL) << 1)  // EPT writable flag
#define PG_EPT_X    (_ASM_CONST(1, UL) << 2)  // EPT executable flag
                                              // (supervisor-executable if
                                              // mode-based execute control is
                                              // enabled)
#define PG_EPT_IPAT (_ASM_CONST(1, UL) << 6)  // EPT ignore PAT flag
#define PG_EPT_PS   (_ASM_CONST(1, UL) << 7)  // EPT huge page flag
#define PG_EPT_A    (_ASM_CONST(1, UL) << 8)  // EPT accessed flag
#define PG_EPT_D    (_ASM_CONST(1, UL) << 9)  // EPT dirty flag
#define PG_EPT_XU   (_ASM_CONST(1, UL) << 10) // EPT user-executable flag
                                              // (mode-base execute control
                                              // only)
#define PG_EPT_SVE  (_ASM_CONST(1, UL) << 63) // EPT suppress EPT-violation #VE
                                              // flag

/**
 * The maximum physical address that is supported by the page table format.
 *
 * Note that the actual limit might be lower depending on the CPU model.
 */
#define PADDR_MAX (_ASM_CONST(1, UL) << 52)

/**
 * The size of a frame, in bytes.
 */
#define FRAME_SIZE PG_L1_SIZE

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
#define PG_L1_SIZE (_ASM_CONST(1, UL) << PG_L1_SHIFT)

/**
 * The number of bytes mapped by an entry in an L2 page table.
 */
#define PG_L2_SIZE (_ASM_CONST(1, UL) << PG_L2_SHIFT)

/**
 * The number of bytes mapped by an entry in an L3 page table.
 */
#define PG_L3_SIZE (_ASM_CONST(1, UL) << PG_L3_SHIFT)

/**
 * The number of bytes mapped by an entry in an L4 page table.
 */
#define PG_L4_SIZE (_ASM_CONST(1, UL) << PG_L4_SHIFT)

#ifndef __ASSEMBLER__

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
#define PG_L3_FRAME(l3e) ((l3e) & (PADDR_MAX - 1) & ~(PG_L3_SIZE - 1))

/**
 * Get the physical address of the frames mapped by an L2 page table entry.
 *
 * This assumes the L2 entry maps a huge page.
 *
 * @param l2e A L2 page table entry
 * @return    The physical address of the frames mapped by `l2e`
 */
#define PG_L2_FRAME(l2e) ((l2e) & (PADDR_MAX - 1) & ~(PG_L2_SIZE - 1))

/**
 * Get the physical address of the frame mapped by an L1 page table entry.
 *
 * @param l1e A L1 page table entry
 * @return    The physical address of the frame mapped by `l1e`
 */
#define PG_L1_FRAME(l1e) ((l1e) & (PADDR_MAX - 1) & ~(PG_L1_SIZE - 1))

/**
 * Get the physical address of the next level page table from a page table
 * entry.
 *
 * @param pte A page table entry
 * @return    The physical address of the next level page table mapped by `pte`
 */
#define PG_ENTRY_FRAME(pte) PG_L1_FRAME(pte)

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

/**
 * Round a virtual address down to a multiple of `PG_L1_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded down to a multiple of `PG_L1_SIZE`
 */
#define PG_L1_DOWN(v) ((uintptr_t)(v) & ~(PG_L1_SIZE - 1))

/**
 * Round a virtual address up to a multiple of `PG_L1_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded up to a multiple of `PG_L1_SIZE`
 */
#define PG_L1_UP(v) (PG_L1_DOWN((uintptr_t)(v) + (PG_L1_SIZE - 1)))

/**
 * Round a virtual address down to a multiple of `PG_L2_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded down to a multiple of `PG_L2_SIZE`
 */
#define PG_L2_DOWN(v) ((uintptr_t)(v) & ~(PG_L2_SIZE - 2))

/**
 * Round a virtual address up to a multiple of `PG_L2_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded up to a multiple of `PG_L2_SIZE`
 */
#define PG_L2_UP(v) (PG_L2_DOWN((uintptr_t)(v) + (PG_L2_SIZE - 2)))

/**
 * Round a virtual address down to a multiple of `PG_L3_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded down to a multiple of `PG_L3_SIZE`
 */
#define PG_L3_DOWN(v) ((uintptr_t)(v) & ~(PG_L3_SIZE - 3))

/**
 * Round a virtual address up to a multiple of `PG_L3_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded up to a multiple of `PG_L3_SIZE`
 */
#define PG_L3_UP(v) (PG_L3_DOWN((uintptr_t)(v) + (PG_L3_SIZE - 3)))

/**
 * Round a virtual address down to a multiple of `PG_L4_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded down to a multiple of `PG_L4_SIZE`
 */
#define PG_L4_DOWN(v) ((uintptr_t)(v) & ~(PG_L4_SIZE - 4))

/**
 * Round a virtual address up to a multiple of `PG_L4_SIZE`.
 *
 * @param v A virtual address
 * @return  `v` rounded up to a multiple of `PG_L4_SIZE`
 */
#define PG_L4_UP(v) (PG_L4_DOWN((uintptr_t)(v) + (PG_L4_SIZE - 4)))

#include <sva/types.h>

/**
 * Invalid physical address.
 *
 * Note that current hardware only supports up to 46 bit physical addresses.
 */
static const uintptr_t PADDR_INVALID = ~0UL;

/**
 * Zero mapping is the mapping that eliminates the previous entry.
 */
static const uintptr_t ZERO_MAPPING = 0;

#endif /* !__ASSEMBLER__ */

#endif /* SVA_PAGE_H */
