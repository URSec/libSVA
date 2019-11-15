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

#include <stdbool.h>
#include <string.h>

#include <sys/types.h>

#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/mmu.h>
#include <sva/mmu_intrinsics.h>
#include <sva/x86.h>
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

/*
 *****************************************************************************
 * Define paging structures and related constants local to this source file
 *****************************************************************************
 */

/* Flags whether the MMU has been initialized */
bool mmuIsInitialized = 0;

/* Cache of page table pages */
extern unsigned char __svadata SVAPTPages[1024][X86_PAGE_SIZE];

/*
 * Function: init_mmu
 *
 * Description:
 *  Initialize MMU data structures.
 */
void
init_mmu () {
  /* Initialize the page descriptor array */
  memset (page_desc, 0, sizeof (struct page_desc_t) * numPageDescEntries);
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
  uintptr_t btextPage = getPhysicalAddr((void *)btext) & PG_FRAME;
  uintptr_t etextPage = getPhysicalAddr((void *)etext) & PG_FRAME;

  /*
   * Scan through each page in the text segment.  Note that it is a code page,
   * and make the page read-only within the page table.
   */
  for (page = btextPage; page < etextPage; page += pageSize) {
    /* Mark the page as both a code page and kernel level */
    page_desc[page / pageSize].type = PG_CODE;
    page_desc[page / pageSize].user = 0;

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
    enum page_type_t pgType = getPageDescPtr(paddr)->type;

    if ((PG_L1 <= pgType) && (pgType <= PG_L4)) {
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
    ((pte_t *)DMPTphys)[i] |= PG_RW | PG_V
#ifdef SVA_ASID_PG
      ;
#else
      | PG_G;
#endif
  }

  for (i = NPDEPG * ndm1g, j = 0; i < NPDEPG * ndmpdp; i++, j++) {
    ((pde_t *)DMPDphys)[j] = (uintptr_t)DMPTphys + ((uintptr_t)j << PAGE_SHIFT);
    /* Preset PG_M and PG_A because demotion expects it. */
    ((pde_t *)DMPDphys)[j] |= PG_RW | PG_V; /*| PG_PS |
#ifdef SVA_ASID_PG
      PG_M | PG_A;
#else	
      PG_G | PG_M | PG_A;
#endif*/
  }

  for (i = 0/*384*/; i < 0 /*384*/ + ndm1g; i++) {
    ((pdpte_t *)DMPDPphys)[i] = (uintptr_t)(i /*- 384*/) << PDPSHIFT;
    /* Preset PG_M and PG_A because demotion expects it. */
    ((pdpte_t *)DMPDPphys)[i] |= PG_RW | PG_V | PG_PS |
#ifdef SVA_ASID_PG
      PG_M | PG_A;
#else	
      PG_G | PG_M | PG_A;
#endif
  }
  for (j = 0; i < /*384 +*/ ndmpdp; i++, j++) {
    ((pdpte_t *)DMPDPphys)[i] = (uintptr_t)DMPDphys + (uintptr_t)(j << PAGE_SHIFT);
    ((pdpte_t *)DMPDPphys)[i] |= PG_RW | PG_V | PG_U;
  }


  /* Connect the Direct Map slot(s) up to the PML4. */
  for (i = 0; i < NDMPML4E; i++) {
    ((pdpte_t *)KPML4phys)[DMPML4I + i] = (uintptr_t)DMPDPphys + (uintptr_t)
      (i << PAGE_SHIFT);
    ((pdpte_t *)KPML4phys)[DMPML4I + i] |= PG_RW | PG_V | PG_U;
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
 *      [1] Initialize the page_desc for the given page
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
        numPgEntries, enum page_type_t pageLevel )
{
  int traversedPTEAlready;
  enum page_type_t subLevelPgType;
  unsigned long numSubLevelPgEntries;
  page_desc_t *thisPg;
  page_entry_t pageMapping;
  page_entry_t *pagePtr;

  /* Store the pte value for the page being traversed */
  pageMapping = *pageEntry;

  /* Set the page pointer for the given page */
#if USE_VIRT
  uintptr_t pagePhysAddr = pageMapping & PG_FRAME;
  pagePtr = (page_entry_t *) getVirtual(pagePhysAddr);
#else
  pagePtr = (page_entry_t *)(pageMapping & PG_FRAME);
#endif

  /* Get the page_desc for this page */
  thisPg = getPageDescPtr(pageMapping);

  /* Mark if we have seen this traversal already */
  traversedPTEAlready = (thisPg->type != PG_UNUSED);

#if DEBUG_INIT >= 1
  /* Character inputs to make the printing pretty for debugging */
  char * indent = "";
  char * l4s = "L4:";
  char * l3s = "\tL3:";
  char * l2s = "\t\tL2:";
  char * l1s = "\t\t\tL1:";

  switch (pageLevel){
    case PG_L4:
        indent = l4s;
        printf("%sSetting L4 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L3:
        indent = l3s;
        printf("%sSetting L3 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L2:
        indent = l2s;
        printf("%sSetting L2 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L1:
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

    case PG_L4:

      thisPg->type = PG_L4;       /* Set the page type to L4 */
      thisPg->user = 0;           /* Set the priv flag to kernel */
      ++(thisPg->count);
      subLevelPgType = PG_L3;
      numSubLevelPgEntries = NPML4EPG;//    numPgEntries;
      break;

    case PG_L3:

      /* TODO: Determine why we want to reassign an L4 to an L3 */
      if (thisPg->type != PG_L4)
        thisPg->type = PG_L3;       /* Set the page type to L3 */
      thisPg->user = 0;           /* Set the priv flag to kernel */
      ++(thisPg->count);
      subLevelPgType = PG_L2;
      numSubLevelPgEntries = NPDPEPG; //numPgEntries;
      break;

    case PG_L2:

      /*
       * If my L2 page mapping signifies that this mapping references a 1GB
       * page frame, then get the frame address using the correct page mask
       * for a L3 page entry and initialize the page_desc for this entry.
       * Then return as we don't need to traverse frame pages.
       */
      if ((pageMapping & PG_PS) != 0) {
#if DEBUG_INIT >= 1
        printf("\tIdentified 1GB page...\n");
#endif
        unsigned long index = (pageMapping & ~PDPMASK) / pageSize;
        if (page_desc[index].type == PG_UNUSED)
          page_desc[index].type = PG_TKDATA;
        page_desc[index].user = 0;           /* Set the priv flag to kernel */
        ++(page_desc[index].count);
        return;
      } else {
        thisPg->type = PG_L2;       /* Set the page type to L2 */
        thisPg->user = 0;           /* Set the priv flag to kernel */
        ++(thisPg->count);
        subLevelPgType = PG_L1;
        numSubLevelPgEntries = NPDEPG; // numPgEntries;
      }
      break;

    case PG_L1:
      /*
       * If my L1 page mapping signifies that this mapping references a 2MB
       * page frame, then get the frame address using the correct page mask
       * for a L2 page entry and initialize the page_desc for this entry.
       * Then return as we don't need to traverse frame pages.
       */
      if ((pageMapping & PG_PS) != 0){
#if DEBUG_INIT >= 1
        printf("\tIdentified 2MB page...\n");
#endif
        /* The frame address referencing the page obtained */
        unsigned long index = (pageMapping & ~PDRMASK) / pageSize;
        if (page_desc[index].type == PG_UNUSED)
          page_desc[index].type = PG_TKDATA;
        page_desc[index].user = 0;           /* Set the priv flag to kernel */
        ++(page_desc[index].count);
        return;
      } else {
        thisPg->type = PG_L1;       /* Set the page type to L1 */
        thisPg->user = 0;           /* Set the priv flag to kernel */
        ++(thisPg->count);
        subLevelPgType = PG_TKDATA;
        numSubLevelPgEntries = NPTEPG;//      numPgEntries;
      }
      break;

    default:
      printf("SVA: page type %d. Frame addr: %p\n",thisPg->type, pagePtr);
      panic("SVA: walked an entry with invalid page type.");
  }

  /*
   * There is one recursive mapping, which is the last entry in the PML4 page
   * table page. Thus we return before traversing the descriptor again.
   * Notice though that we keep the last assignment to the page as the page
   * type information.
   */
  if(traversedPTEAlready) {
#if DEBUG_INIT >= 1
    printf("%s Recursed on already initialized page_desc\n", indent);
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
    if ((pageLevel == PG_L4) && (i == 256))
      continue;
#if 0
    /*
     * Do not process any entries that implement the direct map.  This prevents
     * us from marking physical pages in the direct map as kernel data pages.
     */
    if ((pageLevel == PG_L4) && (i == (KERNDMAPSTART / 0x1000))) {
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
    if (*nextEntry & PG_V) {
#if DEBUG_INIT >= 1
      nValPgs++;
#endif

      /*
       * If we hit the level 1 pages we have hit our boundary condition for
       * the recursive page table traversals. Now we just mark the leaf page
       * descriptors.
       */
      if (pageLevel == PG_L1) {
#if DEBUG_INIT >= 2
        printf("%sInitializing leaf entry: pteaddr: %p, mapping: 0x%lx\n",
            indent, nextEntry, *nextEntry);
#endif
      } else {
#if DEBUG_INIT >= 2
        printf("%sProcessing:pte addr: %p, newPgAddr: %p, mapping: 0x%lx\n",
            indent, nextEntry, (*nextEntry & PG_FRAME), *nextEntry );
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
  SVA_ASSERT((nNonValPgs + nValPgs) == 512, "Wrong number of entries traversed");

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
  if (!isPresent (pml4e)) {
    /* Allocate a new frame */
    uintptr_t paddr = *(firstpaddr);
    (*firstpaddr) += X86_PAGE_SIZE;

    /* Set the type of the frame */
    getPageDescPtr(paddr)->type = PG_L3;
    ++(getPageDescPtr(paddr)->count);

    /* Zero the contents of the frame */
#ifdef SVA_DMAP
    memset (getVirtualSVADMAP (paddr), 0, X86_PAGE_SIZE);
#else
    memset (getVirtual (paddr), 0, X86_PAGE_SIZE);
#endif
    /* Install a new PDPTE entry using the page  */
    *pml4e = (paddr & addrmask) | PTE_CANWRITE | PTE_PRESENT;
  }

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);
  if (!isPresent (pdpte)) {
    /* Allocate a new frame */
    uintptr_t pdpte_paddr = *(firstpaddr);
    (*firstpaddr) += X86_PAGE_SIZE;

    /* Set the type of the frame */
    getPageDescPtr(pdpte_paddr)->type = PG_L2;
    ++(getPageDescPtr(pdpte_paddr)->count);

    /* Zero the contents of the frame */
#ifdef SVA_DMAP
    memset (getVirtualSVADMAP (pdpte_paddr), 0, X86_PAGE_SIZE);
#else
    memset (getVirtual (pdpte_paddr), 0, X86_PAGE_SIZE);
#endif
    /* Install a new PDE entry using the page. */
    *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_PRESENT;
  }

  /*
   * Advance the physical address to the next 2 MB boundary.
   */
  if ((*firstpaddr & 0x0fffff)) {
    uintptr_t oldpaddr = *firstpaddr;
    *firstpaddr = ((*firstpaddr) + 0x200000) & 0xffffffffffc00000u;
    printf ("SVA: remap: %lx %lx\n", oldpaddr, *firstpaddr);
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
    uintptr_t pde_paddr = *(firstpaddr);
    (*firstpaddr) += (2 * 1024 * 1024);

    /*
     * Set the types of the frames
     */
    for (uintptr_t p = pde_paddr; p < *firstpaddr; p += X86_PAGE_SIZE) {
      getPageDescPtr(p)->type = PG_L1;
      ++(getPageDescPtr(p)->count);
    }

    /*
     * Install a new PDE entry.
     */
    *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_PRESENT | PTE_PS;
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
      if ((*(q + index)) != ('a' + index))
        panic ("SVA: No match: %x: %p != %p\n", index, p + index, q + index);
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
  uint64_t tsc_tmp = 0;
  if (tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

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
  memset(page_desc, 0, numPageDescEntries * sizeof(page_desc_t));

#if 0
  /*
   * Remap the SVA internal data structure memory into the part of the address
   * space protected by the sandboxing (SF) instrumentation.
   */
  remap_internal_memory(firstpaddr);
#endif

  /* Walk the kernel page tables and initialize the sva page_desc */
  declare_ptp_and_walk_pt_entries(kpml4eVA, nkpml4e, PG_L4);

  /*
   * Increment each physical page's refcount in the page_desc by 2 to reflect
   * the fact that it's referenced by both the kernel's and SVA's direct
   * maps.
   *
   * SVA's direct map is not part of the kernel's page tables so it is not
   * seen by declare_ptp_and_walk_pt_entries().
   *
   * FIXME: I'm not really sure why the page-table walk isn't picking up the
   * references from the kernel's direct map. There's some code that that,
   * per the comments, is supposed to skip over kernel DMAP references (to
   * avoid setting all the memory referenced by the DMAP as PG_TKDATA), but
   * it's commented out.
   */
  for (unsigned long i = 0; i < numPageDescEntries; i++)
    page_desc[i].count += 2;

  /* Identify kernel code pages and intialize the descriptors */
  declare_kernel_code_pages(btext, etext);

  unsigned long initial_cr3 = *kpml4Mapping & PG_FRAME;
#ifdef SVA_ASID_PG
  /* Enable processor support for PCIDs. */
  write_cr4(read_cr4() | CR4_PCIDE);

  /*
   * Set the PCID field (bits 0-11) in the initial CR3 value to 1 so that we
   * will start in the kernel's version of the address space (which does not
   * include certain protected regions like ghost memory and SVA internal
   * memory).
   */
  initial_cr3 = (initial_cr3 & ~0xfff) | 0x1;
#endif

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
  page_desc_t *pml4Desc = getPageDescPtr(initial_cr3);
  SVA_ASSERT(pgRefCount(pml4Desc) < ((1u << 13) - 1),
      "SVA: MMU: integer overflow in page refcount");
  pml4Desc->count++;

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
    if (SVAPTPages[ptindex] == NULL)
      panic("SVAPTPages[%d] is not allocated\n", ptindex);

    PTPages[ptindex].paddr   = getPhysicalAddr(SVAPTPages[ptindex]);
    PTPages[ptindex].vosaddr = getVirtualSVADMAP(PTPages[ptindex].paddr);

    if (pgdef)
      removeOSDirectMap(getVirtual(PTPages[ptindex].paddr));
  }
#endif

  /* Restore interrupts. */
  sva_exit_critical(rflags);

  record_tsc(sva_mmu_init_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}
