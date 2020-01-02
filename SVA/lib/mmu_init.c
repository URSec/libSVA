/*===- mmu_init.c - SVA Execution Engine  =----------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * MMU initialization code.
 *
 * Note: We try to use the term "frame" to refer to a page of physical memory
 *       and a "page" to refer to the virtual addresses mapped to the page of
 *       physical memory.
 *
 *===------------------------------------------------------------------------===
 */

#include <string.h>

#include <sva/types.h>
#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/mmu.h>
#include <sva/mmu_intrinsics.h>
#include <sva/x86.h>
#include <sva/self_profile.h>
#include <sva/state.h>
#include <sva/util.h>

/*
 * Defines for #if #endif blocks for commenting out lines of code
 */
/* Used to denote unimplemented code */
#define NOT_YET_IMPLEMENTED 0

/* Used to denote obsolete code that hasn't been deleted yet */
#define OBSOLETE            0

/* Define whether to enable DEBUG blocks #if statements */
#define DEBUG               0

/* Define whether or not the mmu_init code assumes virtual addresses */
#define USE_VIRT            0

#if DEBUG
#define sva_dbg(...) printf(__VA_ARGS__)
#else
/*
 * Silence unused variable warnings for variables that are only used as
 * arguments to this macro.
 */
#define sva_dbg(...) ({ if (false) { printf(__VA_ARGS__); } })
#endif

/*
 *****************************************************************************
 * Define paging structures and related constants local to this source file
 *****************************************************************************
 */

/* Flags whether the MMU has been initialized */
bool __svadata mmuIsInitialized = 0;

/* Cache of page table pages */
extern unsigned char __svadata SVAPTPages[1024][FRAME_SIZE];

/*
 * Function: init_mmu
 *
 * Description:
 *  Initialize MMU data structures.
 */
void
init_mmu () {
  /* Initialize the frame descriptor array */
  memset(frame_desc, 0, sizeof(frame_desc));
  return;
}

#ifdef FreeBSD
/*
 * Function: removeOSDirectMap
 *
 * Description:
 *  This function removes the OS's direct mapping page table entry
 *  translating the virtual address of the newly allocated SVA page
 *  table page for ghost memory.
 *
 * Inputs:
 *  v    -   Virtual address of the page table page of ghost memory*
 *  val  -   The translation to insert into the direct mapping
 */
void removeOSDirectMap(void* v) {
  /* Virtual address to convert */
  uintptr_t vaddr = (uintptr_t)v;

  /*
   * Get the terminal entry which maps the virtual address.
   */
  page_entry_t* pte = get_pgeVaddr(vaddr);

  SVA_ASSERT(pte != NULL && isPresent(*pte),
    "The direct mapping PTE of the SVA PTP does not exist\n");

  *pte = ZERO_MAPPING;

  return;
}

/*
 * Function: declare_kernel_code_pages()
 *
 * Description:
 *  Mark all kernel code pages as code pages.
 *
 * Inputs:
 *  btext - The first virtual address of the text segment.
 *  etext - The last virtual address of the text segment.
 */
void
declare_kernel_code_pages (uintptr_t btext, uintptr_t etext) {
  /* Get pointers for the pages */
  uintptr_t page;
  uintptr_t btextPage = PG_L1_DOWN(getPhysicalAddr((void*)btext));
  uintptr_t etextPage = PG_L1_UP(getPhysicalAddr((void*)etext));

  /*
   * Scan through each page in the text segment.  Note that it is a code page,
   * and make the page read-only within the page table.
   */
  for (page = btextPage; page < etextPage; page += pageSize) {
    /* Mark the page as both a code page and kernel level */
    frame_desc[page / pageSize].type = PGT_CODE;

    /* Configure the MMU so that the page is read-only */
    page_entry_t * page_entry = get_pgeVaddr (btext + (page - btextPage));
    page_entry_store(page_entry, setMappingReadOnly (*page_entry));
  }
}

/*
 * Function: makePTReadOnly()
 *
 * Description:
 *  Scan through all of the page descriptors and find all the page descriptors
 *  for page table pages.  For each such page, make the virtual page that maps
 *  it into the direct map read-only.
 */
static inline void
makePTReadOnly (void) {
  /* Disable page protection */
  //unprotect_paging();

  /*
   * For each physical page, determine if it is used as a page table page.
   * If so, make its entry in the direct map read-only.
   */
  uintptr_t paddr;
  for (paddr = 0; paddr < memSize; paddr += pageSize) {
    frame_type_t pgType = get_frame_desc(paddr)->type;

    if ((PGT_L1 <= pgType) && (pgType <= PGT_L4)) {
      page_entry_t *pageEntry = get_pgeVaddr((uintptr_t) getVirtual(paddr));
      page_entry_store(pageEntry, setMappingReadOnly(*pageEntry));
    }
  }

  /* Re-enable page protection */
  //protect_paging();
}

/*
 * Function: sva_create_dmap()
 *
 * Description:
 *  This function sets up the SVA direct mapping region.
 *
 * Input:
 * KPML4phys - phys addr of kernel level 4 page table page
 * DMPDPphys - phys addr of SVA direct mapping level 3 page table page
 * DMPDphys -  phys addr of SVA direct mapping level 2 page table page
 * DMPTphys -  phys addr of SVA direct mapping level 1 page table page
 * ndmpdp   -  number of SVA direct mapping level 3 page table pages
 * ndm1g    -  number of 1GB pages used for SVA direct mapping
 */
void
sva_create_dmap(void * KPML4phys, void * DMPDPphys,
void * DMPDphys, void * DMPTphys, unsigned long ndmpdp, unsigned long ndm1g)
{
  unsigned long i, j;

  for (i = 0; i < NPTEPG * NPDEPG * ndmpdp; i++) {
    ((pte_t *)DMPTphys)[i] = (uintptr_t) i << PAGE_SHIFT;
    ((pte_t *)DMPTphys)[i] |= PG_W | PG_P | PG_G;
  }

  for (i = NPDEPG * ndm1g, j = 0; i < NPDEPG * ndmpdp; i++, j++) {
    ((pde_t *)DMPDphys)[j] = (uintptr_t)DMPTphys + ((uintptr_t)j << PAGE_SHIFT);
    /* Preset PG_M and PG_A because demotion expects it. */
    ((pde_t *)DMPDphys)[j] |= PG_W | PG_P | PG_PS | PG_G | PG_M | PG_A;
  }

  for (i = 0/*384*/; i < 0 /*384*/ + ndm1g; i++) {
    ((pdpte_t *)DMPDPphys)[i] = (uintptr_t)(i /*- 384*/) << PDPSHIFT;
    /* Preset PG_M and PG_A because demotion expects it. */
    ((pdpte_t *)DMPDPphys)[i] |= PG_W | PG_P | PG_PS | PG_G | PG_M | PG_A;
  }
  for (j = 0; i < /*384 +*/ ndmpdp; i++, j++) {
    ((pdpte_t *)DMPDPphys)[i] = (uintptr_t)DMPDphys + (uintptr_t)(j << PAGE_SHIFT);
    ((pdpte_t *)DMPDPphys)[i] |= PG_W | PG_P | PG_U;
  }


  /* Connect the Direct Map slot(s) up to the PML4. */
  for (i = 0; i < NDMPML4E; i++) {
    ((pdpte_t *)KPML4phys)[DMPML4I + i] = (uintptr_t)DMPDPphys + (uintptr_t)
      (i << PAGE_SHIFT);
    ((pdpte_t *)KPML4phys)[DMPML4I + i] |= PG_W | PG_P | PG_U;
  }


  for(i = 0; i < NDMPML4E; i++) {
    sva_declare_dmap_page((unsigned long)DMPDPphys + (i << PAGE_SHIFT));
  }

  for(i = 0; i < ndmpdp - ndm1g; i ++) {
    sva_declare_dmap_page((unsigned long)DMPDphys + (i << PAGE_SHIFT));
  }

  return;
}

/*
 * Function: declare_ptp_and_walk_pt_entries
 *
 * Descriptions:
 *  This function recursively walks a page table and it's entries to initalize
 *  the SVA data structures for the given page. This function is meant to
 *  initialize SVA data structures so they mirror the static page table setup
 *  by a kernel. However, it uses the paging structure itself to walk the
 *  pages, which means it should be agnostic to the operating system being
 *  employed upon. The function only walks into page table pages that are valid
 *  or enabled. It also makes sure that if a given page table is already active
 *  in SVA then it skips over initializing its entries as that could cause an
 *  infinite loop of recursion. This is an issue in FreeBSD as they have a
 *  recursive mapping in the pml4 top level page table page.
 *
 *  If a given page entry is marked as having a larger page size, such as may
 *  be the case with a 2MB page size for PD entries, then it doesn't traverse
 *  the page. Therefore, if the kernel page tables are configured correctly
 *  this won't initialize any SVA page descriptors that aren't in use.
 *
 *  The primary objective of this code is to for each valid page table page:
 *      [1] Initialize the frame_desc for the given page
 *      [2] Set the page permissions as read only
 *
 * Assumptions:
 *  - The number of entries per page assumes a amd64 paging hardware mechanism.
 *    As such the number of entires per a 4KB page table page is 2^9 or 512
 *    entries.
 *  - This page referenced in pageMapping has already been determined to be
 *    valid and requires SVA metadata to be created.
 *
 * Inputs:
 *   pageMapping: Page mapping associated with the given page being traversed.
 *                This mapping identifies the physical address/frame of the
 *                page table page so that SVA can initialize it's data
 *                structures then recurse on each entry in the page table page.
 *  numPgEntries: The number of entries for a given level page table.
 *     pageLevel: The page level of the given mapping {1,2,3,4}.
 *
 *
 * TODO:
 *  - Modify the page entry number to be dynamic in some way to accomodate
 *    differing numbers of entries. This only impacts how we traverse the
 *    address structures. The key issue is that we don't want to traverse an
 *    entry that randomly has the valid bit set, but not have it point to a
 *    real page. For example, if the kernel did not zero out the entire page
 *    table page and only inserted a subset of entries in the page table, the
 *    non set entries could be identified as holding valid mappings, which
 *    would then cause this function to traverse down truly invalid page table
 *    pages. In FreeBSD this isn't an issue given the way they initialize the
 *    static mapping, but could be a problem given different intialization
 *    methods.
 *
 *  - Add code to mark direct map page table pages to prevent the OS from
 *    modifying them.
 *
 */
#define DEBUG_INIT 0
void
declare_ptp_and_walk_pt_entries(page_entry_t *pageEntry, unsigned long
        numPgEntries, frame_type_t pageLevel )
{
  int traversedPTEAlready;
  frame_type_t subLevelPgType;
  unsigned long numSubLevelPgEntries;
  frame_desc_t *thisPg;
  page_entry_t pageMapping;
  page_entry_t *pagePtr;

  /* Store the pte value for the page being traversed */
  pageMapping = *pageEntry;

  /* Set the page pointer for the given page */
#if USE_VIRT
  uintptr_t pagePhysAddr = PG_ENTRY_FRAME(pageMapping);
  pagePtr = (page_entry_t *) getVirtual(pagePhysAddr);
#else
  pagePtr = (page_entry_t *)PG_ENTRY_FRAME(pageMapping);
#endif

  /* Get the frame_desc for this page */
  thisPg = get_frame_desc(pageMapping);

  /* Mark if we have seen this traversal already */
  traversedPTEAlready = (thisPg->type != PGT_FREE);

#if DEBUG_INIT >= 1
  /* Character inputs to make the printing pretty for debugging */
  char * indent = "";
  char * l4s = "L4:";
  char * l3s = "\tL3:";
  char * l2s = "\t\tL2:";
  char * l1s = "\t\t\tL1:";

  switch (pageLevel){
    case PGT_L4:
        indent = l4s;
        printf("%sSetting L4 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PGT_L3:
        indent = l3s;
        printf("%sSetting L3 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PGT_L2:
        indent = l2s;
        printf("%sSetting L2 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PGT_L1:
        indent = l1s;
        printf("%sSetting L1 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    default:
        break;
  }
#endif

  /*
   * For each level of page we do the following:
   *  - Set the page descriptor type for this page table page
   *  - Set the sub level page type and the number of entries for the
   *    recursive call to the function.
   */
  switch(pageLevel){

    case PGT_L4:

      frame_take_force(thisPg, PGT_L4); /* Set the page type to L4 */
      subLevelPgType = PGT_L3;
      numSubLevelPgEntries = NPML4EPG; // numPgEntries;
      break;

    case PGT_L3:

      /* TODO: Determine why we want to reassign an L4 to an L3 */
      if (thisPg->type != PGT_L4)
        frame_take_force(thisPg, PGT_L3); /* Set the page type to L3 */
      subLevelPgType = PGT_L2;
      numSubLevelPgEntries = NPDPEPG; // numPgEntries;
      break;

    case PGT_L2:

      /*
       * If my L2 page mapping signifies that this mapping references a 1GB
       * page frame, then get the frame address using the correct page mask
       * for a L3 page entry and initialize the frame_desc for this entry.
       * Then return as we don't need to traverse frame pages.
       */
      if (isHugePage(pageMapping, PGT_L3)) {
#if DEBUG_INIT >= 1
        printf("\tIdentified 1GB page...\n");
#endif
        unsigned long index = (pageMapping & ~PDPMASK) / pageSize;
        frame_type_t ty = frame_desc[index].type;
        if (isWritable(pageMapping)) {
          ty = PGT_DATA;
        }
        frame_take_force(&frame_desc[index], ty);
        return;
      } else {
        frame_take_force(thisPg, PGT_L2); /* Set the page type to L2 */
        subLevelPgType = PGT_L1;
        numSubLevelPgEntries = NPDEPG; // numPgEntries;
      }
      break;

    case PGT_L1:
      /*
       * If my L1 page mapping signifies that this mapping references a 2MB
       * page frame, then get the frame address using the correct page mask
       * for a L2 page entry and initialize the frame_desc for this entry.
       * Then return as we don't need to traverse frame pages.
       */
      if (isHugePage(pageMapping, PGT_L2)) {
#if DEBUG_INIT >= 1
        printf("\tIdentified 2MB page...\n");
#endif
        /* The frame address referencing the page obtained */
        unsigned long index = (pageMapping & ~PDRMASK) / pageSize;
        frame_type_t ty = frame_desc[index].type;
        if (isWritable(pageMapping)) {
          ty = PGT_DATA;
        }
        frame_take_force(&frame_desc[index], ty);
        return;
      } else {
        frame_take_force(thisPg, PGT_L1); /* Set the page type to L1 */
        subLevelPgType = PGT_DATA;
        numSubLevelPgEntries = NPTEPG;//      numPgEntries;
      }
      break;

    default:
      SVA_ASSERT_UNREACHABLE(
        "SVA: FATAL: Walked an entry with invalid page type %d "
        "(frame address %p).\n",
        thisPg->type, pagePtr);
  }

  /*
   * There is one recursive mapping, which is the last entry in the PML4 page
   * table page. Thus we return before traversing the descriptor again.
   * Notice though that we keep the last assignment to the page as the page
   * type information.
   */
  if(traversedPTEAlready) {
#if DEBUG_INIT >= 1
    printf("%s Recursed on already initialized frame_desc\n", indent);
#endif
    return;
  }

#if DEBUG_INIT >= 1
  u_long nNonValPgs=0;
  u_long nValPgs=0;
#endif
  /*
   * Iterate through all the entries of this page, recursively calling the
   * walk on all sub entries.
   */
  for (unsigned long i = 0; i < numSubLevelPgEntries; i++){
    if ((pageLevel == PGT_L4) && (i == 256))
      continue;
#if 0
    /*
     * Do not process any entries that implement the direct map.  This prevents
     * us from marking physical pages in the direct map as kernel data pages.
     */
    if ((pageLevel == PGT_L4) && (i == (KERNDMAPSTART / 0x1000))) {
      continue;
    }
#endif

    page_entry_t *nextEntry = &pagePtr[i];

#if DEBUG_INIT >= 5
    printf("%sPagePtr in loop: %p, val: 0x%lx\n", indent, nextEntry, *nextEntry);
#endif

    /*
     * If this entry is valid then recurse the page pointed to by this page
     * table entry.
     */
    if (isPresent(*nextEntry)) {
#if DEBUG_INIT >= 1
      nValPgs++;
#endif

      /*
       * If we hit the level 1 pages we have hit our boundary condition for
       * the recursive page table traversals. Now we just mark the leaf page
       * descriptors.
       */
      if (pageLevel == PGT_L1) {
#if DEBUG_INIT >= 2
        printf("%sInitializing leaf entry: pteaddr: %p, mapping: 0x%lx\n",
            indent, nextEntry, *nextEntry);
#endif
      } else {
#if DEBUG_INIT >= 2
        printf("%sProcessing:pte addr: %p, newPgAddr: %p, mapping: 0x%lx\n",
            indent, nextEntry, PG_ENTRY_FRAME(*nextEntry), *nextEntry);
#endif
        declare_ptp_and_walk_pt_entries(nextEntry,
            numSubLevelPgEntries, subLevelPgType);
      }
    }
#if DEBUG_INIT >= 1
    else {
      nNonValPgs++;
    }
#endif
  }

#if DEBUG_INIT >= 1
  SVA_ASSERT((nNonValPgs + nValPgs) == PG_ENTRIES,
             "Wrong number of entries traversed");

  printf("%sThe number of || non valid pages: %lu || valid pages: %lu\n",
          indent, nNonValPgs, nValPgs);
#endif

}

/*
 * Function: remap_internal_memory()
 *
 * Description:
 *  Map sufficient physical memory into the SVA VM internal address space.
 *
 * Inputs:
 *  firstpaddr - A pointer to the first free physical address.
 *
 * Outputs:
 *  firstpaddr - The first free physical address is updated to account for the
 *               pages used in the remapping.
 */
void
remap_internal_memory (uintptr_t * firstpaddr) {
  /* Pointers to the internal SVA VM memory */
  extern char _svastart[];
  extern char _svaend[];

  /*
   * Disable protections.
   */
#ifndef SVA_DMAP
  unprotect_paging();
#endif
  /*
   * Get the PML4E of the current page table.  If there isn't one in the
   * table, add one.
   */
  uintptr_t vaddr = 0xffffff8000000000u;
  pml4e_t * pml4e = get_pml4eVaddr (get_pagetable(), vaddr);
  if (!isPresent(*pml4e)) {
    /* Allocate a new frame */
    uintptr_t paddr = *firstpaddr;
    *firstpaddr += FRAME_SIZE;

    /* Set the type of the frame */
    frame_take_force(get_frame_desc(paddr), PGT_L3);

    /* Zero the contents of the frame */
    memset(getVirtual(paddr), 0, FRAME_SIZE);

    /* Install a new PDPTE entry using the page  */
    *pml4e = PG_ENTRY_FRAME(paddr) | PG_P | PG_W;
  }

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);
  if (!isPresent(*pdpte)) {
    /* Allocate a new frame */
    uintptr_t pdpte_paddr = *firstpaddr;
    *firstpaddr += FRAME_SIZE;

    /* Set the type of the frame */
    frame_take_force(get_frame_desc(pdpte_paddr), PGT_L2);

    /* Zero the contents of the frame */
    memset(getVirtual(pdpte_paddr), 0, FRAME_SIZE);

    /* Install a new PDE entry using the page. */
    *pdpte = PG_ENTRY_FRAME(pdpte_paddr) | PG_P | PG_W;
  }

  /*
   * Advance the physical address to the next 2 MB boundary.
   */
  if (*firstpaddr & 0x0fffff) {
    uintptr_t oldpaddr = *firstpaddr;
    *firstpaddr = (*firstpaddr + 0x200000) & 0xffffffffffc00000u;
    printf("SVA: remap: %lx %lx\n", oldpaddr, *firstpaddr);
  }

  /*
   * Allocate 8 MB worth of SVA address space.
   */
  for (unsigned index = 0; index < 4; ++index) {
    /*
     * Get the PDE entry.
     */
    pde_t * pde = get_pdeVaddr (pdpte, vaddr);
    /* Allocate a new frame */
    uintptr_t pde_paddr = *firstpaddr;
    *firstpaddr += (2 * 1024 * 1024);

    /*
     * Set the types of the frames
     */
    for (uintptr_t p = pde_paddr; p < *firstpaddr; p += FRAME_SIZE) {
      frame_take_force(get_frame_desc(p), PGT_L1);
    }

    /*
     * Install a new PDE entry.
     */
    *pde = PG_ENTRY_FRAME(pde_paddr) | PG_P | PG_W | PG_PS;
    *pde |= PG_G;

    /*
     * Verify that the mapping works.
     */
    unsigned char * p = (unsigned char *) vaddr;
#ifdef SVA_DMAP
    unsigned char * q = (unsigned char *) getVirtualSVADMAP (pde_paddr);
#else
    unsigned char * q = (unsigned char *) getVirtual (pde_paddr);
#endif
    for (unsigned index = 0; index < 100; ++index) {
      (*(p + index)) = ('a' + index);
    }

    for (unsigned index = 0; index < 100; ++index) {
      SVA_ASSERT((*(q + index)) == ('a' + index),
        "SVA: No match: %x: %p != %p\n", index, p + index, q + index);
    }

    /* Move to the next virtual address */
    vaddr += (2 * 1024 * 1024);
  }

  /*
   * Re-enable page protections.
   */
#ifndef SVA_DMAP
  protect_paging();
#endif
  return;
}

/*
 * Function: sva_mmu_init
 *
 * Description:
 *  This function initializes the sva mmu unit by zeroing out the page
 *  descriptors, capturing the statically allocated initial kernel mmu state,
 *  and identifying all kernel code pages, and setting them in the page
 *  descriptor array.
 *
 *  To initialize the sva page descriptors, this function takes the pml4 base
 *  mapping and walks down each level of the page table tree.
 *
 *  NOTE: In this function we assume that the page mapping for the kpml4 has
 *  physical addresses in it. We then dereference by obtaining the virtual
 *  address mapping of this page. This works whether or not the processor is in
 *  a virtually addressed or physically addressed mode.
 *
 * Inputs:
 *  - kpml4Mapping  : Mapping referencing the base kernel pml4 page table page
 *  - nkpml4e       : The number of entries in the pml4
 *  - firstpaddr    : A pointer to the physical address of the first free frame.
 *  - btext         : The first virtual address of the text segment.
 *  - etext         : The last virtual address of the text segment.
 */
void
sva_mmu_init (pml4e_t * kpml4Mapping,
              unsigned long nkpml4e,
              uintptr_t * firstpaddr,
              uintptr_t btext,
              uintptr_t etext) {
  SVA_PROF_ENTER();

  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /*
   * This intrinsic should only be called *once*, during system boot.
   * Attempting to call it again later (e.g. maliciously) would be sheer
   * insanity and could compromise system security in any number of ways.
   */
  SVA_ASSERT(!mmuIsInitialized,
      "SVA: MMU: The system software attempted to call sva_mmu_init(), but "
      "the MMU has already been initialized. This must only be done *once* "
      "during system boot.");

  /* Get the virtual address of the pml4e mapping */
#if USE_VIRT
  pml4e_t * kpml4eVA = (pml4e_t *) getVirtual((uintptr_t) kpml4Mapping);
#else
  pml4e_t * kpml4eVA = kpml4Mapping;
#endif

  /* Zero out the page descriptor array */
  memset(frame_desc, 0, sizeof(frame_desc));

#if 0
  /*
   * Remap the SVA internal data structure memory into the part of the address
   * space protected by the sandboxing (SF) instrumentation.
   */
  remap_internal_memory(firstpaddr);
#endif

  /* Walk the kernel page tables and initialize the sva frame_desc */
  declare_ptp_and_walk_pt_entries(kpml4eVA, nkpml4e, PGT_L4);

#if 0
  /* I (Colin Pronovost, 2019-12-16) commented this out because:
   *   1. It needs to be updated for the new frame reference count system.
   *   2. It's not clear how to determine the appropriate frame type.
   *   3. It shouldn't be necessary in the first place: the import code should
   *      take care of it.
   * This should be fixed before this version of the import code is used again.
   */
  /*
   * Increment each physical page's refcount in the frame_desc by 2 to reflect
   * the fact that it's referenced by both the kernel's and SVA's direct
   * maps.
   *
   * SVA's direct map is not part of the kernel's page tables so it is not
   * seen by declare_ptp_and_walk_pt_entries().
   *
   * FIXME: I'm not really sure why the page-table walk isn't picking up the
   * references from the kernel's direct map. There's some code that that,
   * per the comments, is supposed to skip over kernel DMAP references (to
   * avoid setting all the memory referenced by the DMAP as PGT_DATA), but
   * it's commented out.
   */
  for (unsigned long i = 0; i < ARRAY_SIZE(frame_desc); i++) {
    // frame_desc[i].count += 2;
    pgRefCountInc(&frame_desc[i], true);
    pgRefCountInc(&frame_desc[i], true);
  }
#endif

  /* Identify kernel code pages and intialize the descriptors */
  declare_kernel_code_pages(btext, etext);

  unsigned long initial_cr3 = PG_ENTRY_FRAME(*kpml4Mapping);

  /*
   * Increment the refcount of the initial top-level page table page to
   * reflect the fact that CR3 will be pointing to it.
   *
   * Note that we don't need to increment the refcount for the companion
   * kernel version of the PML4 (as we do in sva_mm_load_pgtable()) because
   * it doesn't exist yet for the initial set of page tables loaded here.
   * (This is guaranteed to be true because we zeroed out the page descriptor
   * array earlier in this function. If the kernel made any attempt to
   * improperly set up an alternate PML4 prior to calling sva_mmu_init(), it
   * would've been wiped away.)
   */
  frame_desc_t *pml4Desc = get_frame_desc(initial_cr3);
  frame_take(pml4Desc, PGT_L4);

  /* Now load the initial value of CR3 to complete kernel init. */
  write_cr3(initial_cr3);

  /*
   * Make existing page table pages read-only.
   *
   * TODO:
   *  Using this function on the SVA test machine with 16 GB of RAM worked when
   *  writing the Virtual Ghost and KCoFI papers.  However, either there has
   *  been a regression, or this code does not work on VirtualBox on Mac OS X
   *  with a 4 GB VM running SVA FreeBSD.  Either way, there is a bug that
   *  needs to be fixed.
   *
   *  (EJJ 8/24/18): As another data point, it seems to work fine without the
   *  hack on my virtual machine, with 2 GB of RAM, running under KVM on
   *  Linux.
   */
  if (!keepPTWriteableHack) {
    makePTReadOnly();
  }

  /*
   * Note that the MMU is now initialized.
   */
  mmuIsInitialized = 1;

#ifdef SVA_DMAP
  for (int ptindex = 0; ptindex < 1024; ++ptindex) {
    SVA_ASSERT(SVAPTPages[ptindex] != NULL,
      "SVAPTPages[%d] is not allocated\n", ptindex);

    PTPages[ptindex].paddr   = getPhysicalAddr(SVAPTPages[ptindex]);
    PTPages[ptindex].vosaddr = getVirtualSVADMAP(PTPages[ptindex].paddr);

    if (pgdef)
      removeOSDirectMap(getVirtual(PTPages[ptindex].paddr));
  }
#endif

  /* Restore interrupts. */
  sva_exit_critical(rflags);

  SVA_PROF_EXIT(mmu_init);
}
#endif /* FreeBSD */

#ifdef XEN
/**
 * Canonicalize a virtual address
 *
 * @param vaddr A (possibly non-canonical) virtual address
 * @return      The canonicalization of `vaddr` (sign-extention of its low 48
 *              bits)
 */
static inline uintptr_t canonicalize(uintptr_t vaddr) {
  uintptr_t sign = vaddr & 0x0000800000000000UL;
  return sign ? vaddr | 0xffff800000000000UL : vaddr;
}

/**
 * Compute the intersection of a permissions mask and the permissions specified
 * in a page table entry.
 *
 * NB: The meaning of the "no-execute" bit in the permissions mask is reversed
 * from its meaning in the hardware page tables: the bit being *set* indicates
 * that the page is executable. This makes computing the permission
 * intersections much easier.
 *
 * @param perms The initial permissions mask
 * @param pte   A page table entry
 * @return      A permissions mask with the intersection of the permissions in
 *              `perms` and those specified by `pte`.
 */
static page_entry_t intersect_perms(page_entry_t perms, page_entry_t pte) {
  // The execute permission is *disabled* by setting this bit. Reverse that
  // to make computing permission intersections more convienient.
  pte ^= PG_NX;

  // The flags we care about are read, write, execute, and user-accesible.
  if (perms & pte & PG_P) {
    return perms & pte & (PG_P | PG_W | PG_NX | PG_U);
  } else {
    return 0; // An unmapped page has no permissions
  }
}

/**
 * Print a page table entry and the virtual address it maps for debugging.
 *
 * Doesn't do anything in a release build.
 *
 * @param entry The page table entry
 * @param level The level of page table containing `entry`
 * @param vaddr The base virtual address mapped by `entry`
 */
static void print_entry(page_entry_t entry, int level, uintptr_t vaddr) {
  const char *level_name;
  switch (level) {
  case 5:
    level_name = "CR3";
    break;
  case 4:
    level_name = "  L4";
    break;
  case 3:
    level_name = "    L3";
    break;
  case 2:
    level_name = "      L2";
    break;
  case 1:
    level_name = "        L1";
    break;
  default:
    level_name = "(unknown)";
    break;
  }
  sva_dbg("%s entry 0x%016lx mapping 0x%016lx\n",
          level_name, entry, vaddr);
}

/**
 * Lower permissions of page mappings to conform to SVA's security model.
 *
 * This function walks the page tables and lowers the permissions of page table
 * entries to ensure that they are appropriate for the type of the pages being
 * mapped. This function assumes that the `frame_desc` array has already been
 * initialized.
 *
 * @param entry The page table entry currently under examination
 * @param level The level of page table that contains `entry`
 * @param vaddr The virtual address that `entry' maps
 * @return      `entry` with the necessary permissions removed.
 */
static page_entry_t lower_permissions(page_entry_t entry,
                                      int level,
                                      uintptr_t vaddr) {
  frame_desc_t* desc = get_frame_desc(entry);

  print_entry(entry, level, vaddr);

  if (level != 5 && isLeafEntry(entry, PGT_L1 + (level - 1))) {
    // This is a leaf (super)page.
    if (!isDirectMap(vaddr)) {
      /// The type of the page table that contains this entry.
      frame_type_t ty = PGT_L1 + (level - 1);

      /// The number of 4KB frames mapped by this entry.
      size_t count = getMappedSize(ty) / FRAME_SIZE;
      /// The maximal set of permissions this mapping is allowed to have.
      page_entry_t perms = PG_P | PG_W | PG_NX;

      for (size_t i = 0; i < count; ++i) {
        switch (desc[i].type) {
        case PGT_L4:
        case PGT_L3:
        case PGT_L2:
        case PGT_L1:
        case PGT_CODE:
          if (!isDirectMap(vaddr)) {
            perms &= ~PG_W;
          }
          break;
        case PGT_DATA:
          // NB: we use the "no-execute" bit here to mean "page is executable."
          perms &= ~PG_NX;
          break;
        case PGT_SVA:
        case PGT_SML3:
        case PGT_SML2:
        case PGT_SML1:
          if (!isInSecureMemory(vaddr)) {
            perms = 0;
          }
          break;
        case PGT_FREE:
          if (!isDirectMap(vaddr)) {
            perms &= ~PG_W;
          }
          break;
        default:
          SVA_ASSERT_UNREACHABLE("SVA: FATAL: Bad frame type\n");
        }
      }

      if (perms & PG_P) {
        entry = (entry & ~(PG_P | PG_W)) | (entry & (perms & ~PG_NX));
        // Turn the "no-execute" bit *on* if the permission is disabled.
        entry |= (PG_NX ^ (perms & PG_NX));
      } else {
        /*
         * We removed the mapping to these frames, decrement their reference
         * count.
         */
        for (size_t i = 0; i < count; ++i) {
          frame_drop_force(&desc[i]);
        }

        entry = 0;
      }
      sva_dbg("Entry changed to 0x%016lx\n", entry);
    }
  } else {
    // This is a page table page.

    /// The type of this page table.
    frame_type_t ty = PGT_L1 + (level - 2);

    /// The number of bytes mapped by entries in this page table.
    size_t span = getMappedSize(ty);

    page_entry_t* entries = (page_entry_t*)getVirtual(PG_ENTRY_FRAME(entry));
    for (size_t i = 0; i < PG_ENTRIES; ++i) {
      if (isPresent(entries[i])) {
        entries[i] = lower_permissions(entries[i], level - 1,
                                       canonicalize(vaddr + span * i));
      }
    }
  }

  return entry;
}

/**
 * Import existing page tables from the kernel.
 *
 * This function walks the page tables, starting at the root table in `%cr3`,
 * and registers them with SVA. It also performs consistency checks on the page
 * tables as they are being imported, specifically checking to make sure that a
 * given frame is only used as one particular type (code, data, or page table
 * page at exactly one level).
 *
 * This function is recursive and should initially be called with
 * `entry = %cr3` and `level = 5`.
 *
 * @param entry     The page table entry mapping the current page being examined
 * @param level     The level of page table that contains `entry`
 * @param max_perms The maximal permissions that a paged mapped my this entry
 *                  may have
 * @param vaddr     The beginning of the virtual address range mapped by this
 *                  entry
 */
static void
import_existing_mappings(page_entry_t entry,
                         int level,
                         page_entry_t max_perms,
                         uintptr_t vaddr) {
  frame_desc_t* desc = get_frame_desc(entry);

  print_entry(entry, level, vaddr);

  // Disabled permissions higher in the page table hierarchy override enabled
  // ones that appear lower.
  page_entry_t perms =
    level == 5 ?
      // CR3 does not specify any permissions, so ignore its "permission" bits.
      max_perms :
      intersect_perms(max_perms, entry);

  if (level != 5 && isLeafEntry(entry, PGT_L1 + (level - 1))) {
    // This is a leaf (super)page.
    if (!isDirectMap(vaddr)) {
      /// The type of the page table that contains this entry.
      frame_type_t ty = PGT_L1 + (level - 1);

      /// The number of 4KB frames mapped by this entry.
      size_t count = getMappedSize(ty) / FRAME_SIZE;

      if ((perms & PG_NX) && (perms & PG_W)) {
        sva_dbg("SVA: WARNING: Page is writable and executable\n");
      }

      frame_type_t type;
      if (isGhostVA(vaddr)) {
        type = PGT_SVA;
      } else {
        type = perms & PG_NX ? PGT_CODE : PGT_DATA;
      }

      for (size_t i = 0; i < count; ++i) {
        frame_type_t newType = type;

        if (desc[i].type != PGT_FREE && desc[i].type != type) {
          switch (desc[i].type) {
          case PGT_L4:
          case PGT_L3:
          case PGT_L2:
          case PGT_L1:
          case PGT_SML3:
          case PGT_SML2:
          case PGT_SML1:
            if (type == PGT_SVA) {
              SVA_ASSERT_UNREACHABLE(
                "SVA: FATAL: Page table frame also mapped as SVA data\n");
            } else if (type == PGT_CODE) {
              // Page table mapped as code?!
              SVA_ASSERT_UNREACHABLE(
                "SVA: FATAL: Page table frame also mapped as code\n");
            } else {
              // Page table mapped as data; make the mapping read-only.
              sva_dbg("SVA: WARNING: Page table mapped as data\n");
              newType = desc[i].type;
            }
            break;
          case PGT_CODE:
          case PGT_DATA:
            if (type == PGT_SVA) {
              SVA_ASSERT_UNREACHABLE(
                "SVA: FATAL: Kernel mapped frame 0x%lx used for SVA memory\n",
                &desc[i] - frame_desc);
            } else {
              sva_dbg("SVA: WARNING: Frame mapped as both code and data\n");
              newType = PGT_CODE;
            }
            break;
          case PGT_SVA:
            SVA_ASSERT_UNREACHABLE(
              "SVA: FATAL: Kernel mapped SVA memory frame 0x%lx at 0x%016lx\n",
              &desc[i] - frame_desc, vaddr);
            break;
          default:
            SVA_ASSERT_UNREACHABLE(
              "SVA: FATAL: Frame shouldn't have this type yet\n");
          }
        }

        frame_take_force(&desc[i], newType);
      }
    }
  } else {
    // This is a page table page.

    /// The type of this page table.
    frame_type_t ty = PGT_L1 + (level - 2);

    /// The number of bytes mapped by entries in this page table.
    size_t span = getMappedSize(ty);

    if (desc->type != PGT_FREE && desc->type != ty) {
      switch (desc->type) {
      case PGT_L4:
      case PGT_L3:
      case PGT_L2:
      case PGT_L1:
        SVA_ASSERT_UNREACHABLE(
          "SVA: FATAL: Frame used at multiple page table levels\n");
      case PGT_CODE:
        SVA_ASSERT_UNREACHABLE("SVA: FATAL: Code frame used as page table\n");
      case PGT_DATA:
        sva_dbg("SVA: WARNING: Data frame used as page table\n");
        break;
      case PGT_SVA:
        SVA_ASSERT_UNREACHABLE("SVA: FATAL: SVA memory used as page table\n");
      default:
        SVA_ASSERT_UNREACHABLE(
          "SVA: FATAL: Frame shouldn't have this type yet\n");
      }
    }

    bool isSecMemPageTable = isGhostVA(vaddr);
#ifdef SVA_DMAP
    isSecMemPageTable |= isSVADirectMap(vaddr);
#endif

    if (isSecMemPageTable) {
      switch (ty) {
      case PGT_L3:
        ty = PGT_SML3;
        break;
      case PGT_L2:
        ty = PGT_SML2;
        break;
      case PGT_L1:
        ty = PGT_SML1;
        break;
      default:
        // No change
        break;
      }
    }

    frame_take_force(desc, ty);

    page_entry_t* entries = (page_entry_t*)getVirtual(PG_ENTRY_FRAME(entry));
    for (size_t i = 0; i < PG_ENTRIES; ++i) {
      if (isPresent(entries[i])) {
        import_existing_mappings(entries[i], level - 1, perms,
                                 canonicalize(vaddr + span * i));
      }
    }
  }
}

#ifdef SVA_DMAP
/**
 * Create SVA's direct map.
 *
 * This function will create a direct map in a specified virtual address range
 * using 1GB super pages. It will request pages from the kernel to use as L3
 * page tables.
 *
 * @param first_dmap_entry  A pointer to the first L4 entry of the direct map
 * @param num_dmap_entries  The number of L4 entries to use for the direct map
 */
void create_sva_direct_map(pml4e_t *first_dmap_entry, size_t num_dmap_entries) {
  for (size_t i = 0; i < num_dmap_entries; ++i) {
    SVA_ASSERT(first_dmap_entry[i] == 0,
               "SVA: FATAL: DMAP entry not initially empty");

    if (i * PG_L4_SIZE < memSize) {
      uintptr_t l3_table_frame = provideSVAMemory(FRAME_SIZE);
      SVA_ASSERT(l3_table_frame != 0, "SVA: FATAL: Out of memory\n");
      pdpte_t* l3_table = (pdpte_t*)(KERNDMAPSTART + l3_table_frame);

      memset(l3_table, 0, FRAME_SIZE);
      for (size_t j = 0; j < PG_ENTRIES; ++j) {
        uintptr_t frame = i * PG_L4_SIZE + j * PG_L3_SIZE;
        if (frame >= memSize) {
          break;
        }
        l3_table[j] = frame | PG_DMAP_L3;
      }

      first_dmap_entry[i] = l3_table_frame | PG_DMAP_L4;
    } else {
      first_dmap_entry[i] = 0;
    }
  }
}
#endif

/**
 * Initialize SVA's MMU handling.
 *
 * This function will walk over the currently active page tables and initialize
 * the page descriptors for all currently used frames.
 */
void sva_mmu_init(void) {
  SVA_PROF_ENTER();

  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /*
   * This intrinsic should only be called *once*, during system boot.
   * Attempting to call it again later (e.g. maliciously) would be sheer
   * insanity and could compromise system security in any number of ways.
   */
  SVA_ASSERT(!mmuIsInitialized,
      "SVA: MMU: The system software attempted to call sva_mmu_init(), but "
      "the MMU has already been initialized. This must only be done *once* "
      "during system boot.");

  /* Zero out the page descriptor array */
  memset(frame_desc, 0, sizeof(frame_desc));

  cr3_t root_tbl = read_cr3();

#ifdef SVA_DMAP
  /*
   * Since SVA's direct map doesn't exist yet, we have to get the virtual
   * address for the L4 page table from the kernel's direct map.
   */
  pml4e_t* l4_table = (pml4e_t*)(KERNDMAPSTART + (PG_ENTRY_FRAME(root_tbl)));
  create_sva_direct_map(l4_table + PG_L4_ENTRY(SVADMAPSTART),
                        PG_L4_ENTRY(SVADMAPEND) - PG_L4_ENTRY(SVADMAPSTART));
  sva_dbg("SVA: INFO: Built SVA direct map\n");
#endif

  /* Walk the kernel page tables and initialize the sva frame_desc. */
  import_existing_mappings(root_tbl, 5, (PG_P | PG_W | PG_NX | PG_U), 0);
  lower_permissions(root_tbl, 5, 0);
  invltlb_all();

  unsigned long initial_cr3 = PG_ENTRY_FRAME(root_tbl);

  /* Now load the initial value of CR3 to complete kernel init. */
  write_cr3(initial_cr3);

  /*
   * Note that the MMU is now initialized.
   */
  mmuIsInitialized = 1;

  /* Restore interrupts. */
  sva_exit_critical(rflags);

  SVA_PROF_EXIT(mmu_init);
}
#endif /* XEN */
