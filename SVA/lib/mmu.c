/*===- mmu.c - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Note: We try to use the term "frame" to refer to a page of physical memory
 *       and a "page" to refer to the virtual addresses mapped to the page of
 *       physical memory.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include "icat.h"

#include "sva/types.h"
#include "sva/callbacks.h"
#include "sva/config.h"
#include "sva/mmu.h"
#include "sva/mmu_intrinsics.h"
#include "sva/x86.h"
#include "sva/state.h"
#include "sva/util.h"

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
 * Function prototype declarations.
 *****************************************************************************
 */

/*
 * SVA direct mapping related functions
 */
static inline uintptr_t getPhysicalAddrKDMAP (void * v);
static inline uintptr_t getPhysicalAddrSVADMAP (void * v);

/*
 *****************************************************************************
 * Define paging structures and related constants local to this source file
 *****************************************************************************
 */

/*
 * Struct: PTInfo
 *
 * Description:
 *  This structure contains information on pages fetched from the OS that are
 *  used for page table pages that the SVA VM creates for its own purposes
 *  (e.g., secure memory).
 */
struct PTInfo {
  /* Virtual address of page provided by the OS */
  unsigned char * vosaddr;

  /* Physical address to which the virtual address is mapped. */
  uintptr_t paddr;

  /* Number of uses in this page table page */
  unsigned short uses;

  /* Flags whether this entry is used */
  unsigned char valid;
};

/*
 * Structure: PTPages
 *
 * Description:
 *  This table records information on pages fetched from the operating system
 *  that the SVA VM will use for its own purposes.
 */
struct PTInfo __svadata PTPages[1024];

/* Cache of page table pages */
extern unsigned char __svadata SVAPTPages[1024][FRAME_SIZE];

void printPageType(unsigned char* p) {
  frame_desc_t* pageDesc = get_frame_desc(getPhysicalAddr(p));
  if (pageDesc == NULL) {
    printf("SVA: page type: %p: nonexistant\n", p);
  } else {
    printf ("SVA: page type: %p: %s\n", p, frame_type_name(pageDesc->type));
  }
}

/*
 *****************************************************************************
 * Define helper functions for MMU operations
 *****************************************************************************
 */

/**
 * Get the type of frame that can be mapped by a page table entry.
 *
 * Note: this is designed to be used only for page table entries created by the
 * kernel. It will not work for page table entries created by SVA.
 *
 * @param pte     A page table entry
 * @param pt_type The type of the page table containing `pte`
 * @return        The appropriate type for a frame mapped by `pte`
 */
frame_type_t frame_type_from_pte(page_entry_t pte, frame_type_t pt_type) {
  bool isEPT = pt_type >= PGT_EPTL1 && pt_type <= PGT_EPTL4;

  if (!isPresent_maybeEPT(pte, isEPT)) {
    /*
     * If the entry isn't present, then it doesn't map anything. Return
     * `PGT_FREE` as a safe default.
     */
    return PGT_FREE;
  }

  if (isLeafEntry(pte, pt_type)) {
    /*
     * The kernel can only create executable mappings for user space, never for
     * itself. EPT mappings are always safe in this regard because the kernel
     * (which executes in VMX root mode) cannot use them.
     */
    SVA_ASSERT(isEPT || !isExecutable(pte) || isUserMapping(pte),
      "SVA: FATAL: Attempt to create supervisor-mode code page "
      "with mapping 0x%016lx\n", pte);

    /*
     * If the mapping is writable, force the frame type to `PGT_DATA`.
     * Otherwise, the frame type is PGT_FREE, which can be used to map
     * (read-only) any frame which is not used for secure memory.
     */
    return isWritable(pte) ? PGT_DATA : PGT_FREE;
  } else {
    /*
     * If the entry is not a leaf entry, then the only thing it can map is a
     * page table one level down.
     */
    return getSublevelType(pt_type);
  }
}

/* Functions for aiding in declare and updating of page tables */

void page_entry_store(page_entry_t* page_entry, page_entry_t newVal) {
  uint64_t tsc_tmp = 0;
  if (tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

#ifdef SVA_DMAP
  uintptr_t ptePA = getPhysicalAddr(page_entry);
  page_entry_t* page_entry_svadm = (page_entry_t*)getVirtual(ptePA);

#if 0
  frame_desc_t *ptePG = get_frame_desc(ptePA);

  /*
   * If we are setting a mapping within SVA's direct map, ensure it is a
   * writable mapping.
   *
   * (EJJ 8/28/18: Why is this code needed? I don't see anywhere in the SVA
   * source code where page_entry_store() would be called such that
   * ptePG->dmap would be true. It appears that SVA doesn't utilize
   * page_entry_store() when it sets up its direct map.)
   */
  if (ptePG->dmap) 
    newVal |= PG_W;
#endif

  /* Write the new value to the page_entry */
  *page_entry_svadm = newVal;

#else
  /* Disable page protection so we can write to the referencing table entry */
  unprotect_paging();

  /* Write the new value to the page_entry */
  *page_entry = newVal;

  /* Reenable page protection */
  protect_paging();    
#endif

  record_tsc(page_entry_store_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

/**
 * Determine if a page table entry is allowed to be changed.
 *
 * Certain page table entries must not be modified. Specifically, all of the L4
 * entries which map secure memory must not be modified in order to ensure the
 * integrity of that data. Additionally, any entry which maps a kernel code
 * page must not be modified in order to prevent the kernel from bypassing SFI
 * checks.
 *
 * It also works for extended page table (EPT) updates.
 *
 * @param page_entry  The page table entry that is about to be changed.
 * @return            Whether or not the page table entry may be changed.
 */
static inline bool pte_can_change(page_entry_t* page_entry) {
  /* Collect associated information for the existing mapping */
  unsigned long origPA = PG_ENTRY_FRAME(*page_entry);
  frame_desc_t *origPG = get_frame_desc(origPA);

#if 0
  /* Get the page table page descriptor. */
  uintptr_t ptePAddr = getPhysicalAddr(page_entry);
  frame_desc_t *ptePG = get_frame_desc(ptePAddr);
#endif
 
  /*
   * If MMU checks are disabled, allow the page table entry to be modified.
   */
  if (disableMMUChecks) {
    return true;
  }

#if 0
  /*
   * Verify that we're not trying to modify the PML4 entry that controls the
   * secure memory virtual address space.
   */
  size_t entryIdx =
    ((uintptr_t)page_entry & (FRAME_SIZE - 1)) / sizeof(*page_entry);
  bool isSecMemL4Entry = isL4Pg(ptePG) &&
                         entryIdx >= PG_L4_ENTRY(SECMEMSTART) &&
                         entryIdx < PG_L4_ENTRY(SECMEMEND);
  if (isSecMemL4Entry) {
    return false;
  }
#endif

  /*
   * We know that we are not attempting to modify a mapping in a secure memory
   * page table, because we would have already failed if we were (secure memory
   * page tables have their own type, and we would have errored out earlier
   * when we checked that the page table type was correct for the type of
   * update being performed.
   */

  /*
   * No need to check anything about the new mapping: the reference count
   * system checks that for us.
   */

  /*
   * Don't allow existing kernel code mappings to be changed/removed.
   * TODO: Also check this at higher levels.
   */
  if (origPG != NULL && isCodePg(origPG) && !isUserMapping(*page_entry)) {
    return false;
  }

  return true;
}

/**
 * Update the metadata for a page that is having a new mapping created to it.
 *
 * The goal is to manage any SVA page data that needs to be set for tracking
 * the new mapping with the existing page data. This is essential to enable the
 * MMU verification checks.
 *
 * @param mapping An x86_64 page table entry describing the new mapping of the
 *                page
 * @param type    The type of the frames mapped by the new entry
 * @param count   The number of frames mapped by `mapping`
 */
static inline void
updateNewPageData(page_entry_t mapping, frame_type_t type, size_t count) {
  bool isEPT = type >= PGT_EPTL1 && type <= PGT_EPTL4;

  /*
   * If the new mapping is valid, update the counts for it.
   */
  if (isPresent_maybeEPT(mapping, isEPT)) {
    for (size_t i = 0; i < count; ++i) {
      uintptr_t newPA = PG_ENTRY_FRAME(mapping) + i * FRAME_SIZE;
      frame_desc_t *newPG = get_frame_desc(newPA);
      SVA_ASSERT(newPG != NULL,
        "SVA: FATAL: Attempted to create mapping to non-existant frame\n");

#if 0
      /*
       * If the new page is to a page table page and this is the first reference
       * to the page, we need to set the VA mapping this page so that the
       * verification routine can enforce that this page is only mapped
       * to a single VA. Note that if we have gotten here, we know that
       * we currently do not have a mapping to this page already, which
       * means this is the first mapping to the page.
       */
      if (isPTP(newPG)) {
        newPG->pgVaddr = newVA;
      }
#endif

      if (type == PGT_DATA && newPG->type == PGT_FREE) {
        /*
         * The frame is currently free, but we need to use it as data. Make the
         * frame a data frame.
         */
        frame_morph(newPG, PGT_DATA);
      }

      /*
       * Update the reference count for the new page frame. Check that we aren't
       * overflowing the counter.
       */
      frame_take(newPG, type);
    }
  }
}

/*
 * Update the metadata for a page that is having its mapping removed.
 *
 * @param mapping An x86_64 page table entry describing the old mapping of the
 *                page
 * @param type    The type of the frames that were mapped by the old entry
 * @param count   The number of frames mapped by `mapping`
 */
static inline void
updateOrigPageData(page_entry_t mapping, frame_type_t type, size_t count) {
  bool isEPT = type >= PGT_EPTL1 && type <= PGT_EPTL4;

  /*
   * Only decrement the reference count if the page has an existing valid
   * mapping.
   */
  if (isPresent_maybeEPT(mapping, isEPT)) {
    for (size_t i = 0; i < count; ++i) {
      uintptr_t origPA = PG_ENTRY_FRAME(mapping) + i * FRAME_SIZE;
      frame_desc_t *origPG = get_frame_desc(origPA);
      SVA_ASSERT(origPG != NULL,
        "SVA: FATAL: Attempted to create mapping to non-existant frame\n");

      frame_drop(origPG, type);
      if (origPG->type == PGT_DATA && origPG->type_count == 0) {
        /*
         * This was a data frame, and its type count is now 0. Make it a free
         * frame.
         */
        frame_morph(origPG, PGT_FREE);
      }
    }
  }
}

/**
 * Perform a page table update and update reference counts.
 *
 * Also works for extended page table (EPT) updates. Whether a regular or
 * extended page table is being updated is inferred from the SVA frame type of
 * the PTP being modified.
 *
 * This function should only be called after it is known that it is safe to
 * change the entry.
 *
 * @param pte     Pointer to the page entry being modified
 * @param new_pte The new mapping to insert into `*pte`
 */
static inline void do_mmu_update(page_entry_t* pte, page_entry_t new_pte) {
  frame_desc_t* ptePG = get_frame_desc(getPhysicalAddr(pte));

  bool oldIsLeaf = isLeafEntry(*pte, ptePG->type);
  bool newIsLeaf = isLeafEntry(new_pte, ptePG->type);
  size_t oldCount = oldIsLeaf ? getMappedSize(ptePG->type) / FRAME_SIZE : 1;
  size_t newCount = newIsLeaf ? getMappedSize(ptePG->type) / FRAME_SIZE : 1;
  frame_type_t oldType = frame_type_from_pte(*pte, ptePG->type);
  frame_type_t newType = frame_type_from_pte(new_pte, ptePG->type);

  /*
   * If we have a new mapping as opposed to just changing the flags of an
   * existing mapping, then update the SVA meta data for the pages. We know
   * that we have passed the validation checks so these updates have been
   * vetted.
   */
  updateOrigPageData(*pte, oldType, oldCount);
  updateNewPageData(new_pte, newType, newCount);

  /* Perform the actual write to into the page table entry. */
  page_entry_store(pte, new_pte);
}

void update_mapping(page_entry_t* pte, page_entry_t new_pte) {
  SVA_ASSERT(pte_can_change(pte),
    "SVA: FATAL: Bad update attempt for PTE at %p: 0x%016lx -> 0x%016lx\n",
    pte, *pte, new_pte);
  do_mmu_update(pte, new_pte);
}

void sva_mm_flush_tlb(void* address) {
  invlpg((uintptr_t)address);
}

void initDeclaredPage(uintptr_t frame) {
#if 0
  /*
   * Get the direct map virtual address of the physical address.
   */
  unsigned char* vaddr = getVirtualKernelDMAP(frame);

  /*
   * Get a pointer to the page table entry that maps the physical page into the
   * direct map.
   */
  page_entry_t* page_entry = get_pgeVaddr((uintptr_t)vaddr);
  if (page_entry != NULL && isPresent(*page_entry)) {
    /*
     * Make the direct map entry for the page read-only to ensure that the OS
     * goes through SVA to make page table changes.
     *
     * This change will take effect when we do a global TLB flush below.
     */
    __do_mmu_update(page_entry, setMappingReadOnly(*page_entry));
  }
#endif

  /*
   * Do a global TLB flush (including for EPT if SVA-VMX is active) to
   * ensure that there are no stale mappings to this page that the OS
   * neglected to flush.
   *
   * Ideally we'd prefer to selectively flush mappings from the TLB at the
   * time they are removed (e.g., in updateOrigPageData()), which would make
   * this unnecessary because we'd know the TLB is consistent at all times.
   * But SVA doesn't have a good way of knowing what virtual address(es)
   * correspond to a mapping that it's asked to remove, making this
   * impractical. Instead we leave it to the OS to flush the TLBs itself in
   * general, and only force a TLB flush when a failure by the OS to uphold
   * that responsibility could compromise SVA's security guarantees.
   *
   * There are two places in SVA's codebase this is the case:
   *  - Here, in initDeclaredPage(), when we need to ensure that the OS
   *    *only* has access to a declared PTP through its entry in the kernel's
   *    DMAP (which SVA has made read-only).
   *
   *  - In get_frame_from_os() (secmem.c), when we need to ensure that a
   *    frame the OS gave us for use as secure/ghost memory isn't accessible
   *    at all to the OS.
   */
  invltlb_all();
  if (sva_vmx_initialized) {
    invept_allcontexts();
    invvpid_allcontexts();
  }
}

/* Functions for finding the virtual address of page table components */

page_entry_t* get_pgeVaddr(uintptr_t vaddr) {
  /* Pointers to the page table entries for the virtual address */
  pml4e_t* l4e = NULL;
  pdpte_t* l3e = NULL;
  pde_t* l2e = NULL;
  pte_t* l1e = NULL;

  /* Get the base of the pml4 to traverse */
  cr3_t cr3 = get_root_pagetable();

  switch(walk_page_table(cr3, vaddr, &l4e, &l3e, &l2e, &l1e, NULL)) {
  case 0:
    /* Walk failed: address isn't canonical */
  case -5:
    /* Walk failed: bad root page table */
    return NULL;
  case 1:
  case -1:
    /* Found L1 entry */
    return l1e;
  case 2:
  case -2:
    /* Found L2 entry */
    return l2e;
  case 3:
  case -3:
    /* Found L3 entry */
    return l3e;
  case 4:
  case -4:
    /* Found L4 entry */
    return l4e;
  }

  // Unreachable
  BUG();
}

int walk_page_table(cr3_t cr3, uintptr_t vaddr, pml4e_t** pml4e,
                    pdpte_t** pdpte, pde_t** pde, pte_t** pte, uintptr_t* paddr)
{
  pml4e_t* l4e;
  pdpte_t* l3e;
  pde_t* l2e;
  pte_t* l1e;

  /*
   * Bail out early if we are given a non-canonical address
   */
  if (!isCanonical(vaddr)) {
    return 0;
  }

  if (pte == NULL || *pte == NULL) {
    if (pde == NULL || *pde == NULL) {
      if (pdpte == NULL || *pdpte == NULL) {
        if (pml4e == NULL || *pml4e == NULL) {
          /*
           * Make sure we've been given a reasonable root page table pointer.
           *
           * FIXME: Theoretically, there's no reason we couldn't use frame 0 as a page
           * table.
           */
          if (PG_ENTRY_FRAME(cr3) == 0) {
            return -5;
          }

          /*
           * Get the L4 entry mapping this virtual address.
           */
          l4e = get_pml4eVaddr(cr3, vaddr);
          if (pml4e != NULL) {
            *pml4e = l4e;
          }
        } else {
          /*
           * Caller gave us L4 entry.
           */
          l4e = *pml4e;
        }

        if (!isPresent(*l4e)) {
          return -4;
        }

        /*
         * Get the L3 entry mapping this virtual address.
         */
        l3e = get_pdpteVaddr(*l4e, vaddr);
        if (pdpte != NULL) {
          *pdpte = l3e;
        }
      } else {
        /*
         * Caller gave us L3 entry.
         */
        l3e = *pdpte;
      }

      if (!isPresent(*l3e)) {
        return -3;
      }
      /*
       * The L3 entry can be configured in large page mode. If it is then we have
       * the entry corresponding to the given virtual address. If not then we go
       * deeper in the page walk.
       */
      if (isHugePage(*l3e, PGT_L3)) {
        if (paddr != NULL) {
          *paddr = PG_L3_FRAME(*l3e) + PG_L3_OFFSET(vaddr);
        }
        return 3;
      }

      /*
       * Get the L2 entry mapping this virtual address.
       */
      l2e = get_pdeVaddr(*l3e, vaddr);
      if (pde != NULL) {
        *pde = l2e;
      }
    } else {
      /*
       * Caller gave us L3 entry.
       */
      l2e = *pde;
    }

    if (!isPresent(*l2e)) {
      return -2;
    }
    /*
     * As is the case with the L3 entry, if the L2 entry is configured for large
     * page size then we have the corresponding entry. Otherwise we need to
     * traverse one more level, which is the last.
     */
    if (isHugePage(*l2e, PGT_L2)) {
      if (paddr != NULL) {
        *paddr = PG_L2_FRAME(*l2e) + PG_L2_OFFSET(vaddr);
      }
      return 2;
    }

    /*
     * Get the L1 entry mapping this virtual address.
     */
    l1e = get_pteVaddr(*l2e, vaddr);
    if (pte != NULL) {
      *pte = l1e;
    }
  } else {
    /*
     * Caller gave us L1 entry.
     */
    l1e = *pte;
  }

  if (!isPresent(*l1e)) {
    return -1;
  }
  if (paddr != NULL) {
    *paddr = PG_L1_FRAME(*l1e) + PG_L1_OFFSET(vaddr);
  }
  return 1;
}

/*
 * Function: getPhysicalAddrDMAP()
 *
 * Description:
 *  Find the physical page number of the specified virtual address based on kernel direct mapping.
 */
static inline uintptr_t
getPhysicalAddrKDMAP (void * v) {
 return  ((uintptr_t) v & ~KERNDMAPSTART);
}

/*
 * Function: getPhysicalAddrSVADMAP()
 *
 * Description:
 *  Find the physical page number of the specified virtual address based on SVA direct mapping.
 */
static inline uintptr_t
getPhysicalAddrSVADMAP (void * v) {
 return  ((uintptr_t) v & ~SVADMAPSTART);
}

bool getPhysicalAddrFromPML4E(void* v, pml4e_t* pml4e, uintptr_t* paddr) {
  /* Virtual address to convert */
  uintptr_t vaddr = (uintptr_t)v;

  return walk_page_table((cr3_t)0, vaddr, &pml4e, NULL, NULL, NULL, paddr) > 0;
}

uintptr_t getPhysicalAddr(void* v) {
  /* Virtual address to convert */
  uintptr_t vaddr = (uintptr_t)v;

  /* Physical address */
  uintptr_t paddr;

  /*
   * If the pointer is within the kernel's direct map, use a simple
   * bit-masking operation to convert the virtual address to a physical
   * address.
   */
  if (vaddr >= KERNDMAPSTART && vaddr < KERNDMAPEND) {
       return getPhysicalAddrKDMAP(v);
  }

  /*
   * If the virtual address falls within the SVA VM's direct map, use a simple
   * bit-masking operation to find the physical address.
   */
#ifdef SVA_DMAP
  if (vaddr >= SVADMAPSTART && vaddr <= SVADMAPEND) {
       return getPhysicalAddrSVADMAP(v);
  }
#endif

  /*
   * Get the currently active page table.
   */
  cr3_t cr3 = get_root_pagetable();
  if (walk_page_table(cr3, vaddr, NULL, NULL, NULL, NULL, &paddr) > 0) {
    return paddr;
  } else {
    return PADDR_INVALID;
  }
}

/*
 * Function: allocPTPage()
 *
 * Description:
 *  This function allocates a page table page, initializes it, and returns it
 *  to the caller.
 */
static unsigned int allocPTPage(frame_type_t level) {
  /* Index into the page table information array */
  unsigned int ptindex;

  /* Pointer to newly allocated memory */
  unsigned char * p;

  /*
   * Find an empty page table array entry to record information about this page
   * table page.  Note that we're a multi-processor system, so use an atomic to
   * keep things valid.
   *
   * Note that we leave the first entry reserved.  This permits us to use a
   * zero index to denote an invalid index.
   */
  for (ptindex = 1; ptindex < 1024; ++ptindex) {
    if (__sync_bool_compare_and_swap (&(PTPages[ptindex].valid), 0, 1)) {
      break;
    }
  }
  SVA_ASSERT(ptindex < 1024,
    "SVA: allocPTPage: No more table space!\n");

  /*
   * Ask the system software for a page of memory.
   */
#ifdef SVA_DMAP
  if ((p = PTPages[ptindex].vosaddr) != NULL) {
#else
  if ((p = SVAPTPages[ptindex]) != NULL) {
#endif
    /*
     * Initialize the memory.
     */
    memset(p, 0, FRAME_SIZE);

    /*
     * Record the information about the page in the page table page array.
     * We'll need the virtual address by which the system software knows the
     * page as well as the physical address so that the SVA VM can unmap it
     * later.
     */
#ifndef SVA_DMAP
    PTPages[ptindex].vosaddr = p;
    PTPages[ptindex].paddr   = getPhysicalAddr (p);
#endif
    /*
     * Set the type of the page to be a ghost page table page.
     */
    frame_morph(get_frame_desc(getPhysicalAddr(p)), level);

    /*
     * Return the index in the table.
     */
    return ptindex;
  }

  return 0;
}

/*
 * Function: freePTPage()
 *
 * Description:
 *  Return an SVA VM page table page back to the operating system for use.
 */
void
freePTPage (unsigned int ptindex) {
  /*
   * Mark the entry in the page table page array as available.
   */
  PTPages[ptindex].valid = 0;

  /*
   * Change the type of the page table page.
   */
  frame_morph(get_frame_desc(PTPages[ptindex].paddr), PGT_FREE);

  return;
}

/*
 * Function: updateUses()
 *
 * Description:
 *  This function will update the number of present entries within a page table
 *  page that was allocated by the SVA VM.
 *
 * Inputs:
 *  ptp - A pointer to the page table page.  This does not need to be a page
 *        table page owned by the SVA VM.
 */
static void
updateUses (uintptr_t * ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = getPhysicalAddr (ptp) & 0xfffffffffffff000u;

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, increment the number of uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      ++PTPages[ptindex].uses;
    }
  }

  return;
}

/*
 * Function: releaseUse()
 *
 * Description:
 *  This function will decrement the number of present entries within a page
 *  table page allocated by the SVA VM.
 *
 * Inputs:
 *  pde - A pointer to the page table page.  This does not need to be an SVA VM
 *        page table page.
 *
 * Return value:
 *  0 - The page is not a SVA VM page table page, or the page still has live
 *      references in it.
 *  Otherwise, the index into the page table array will be returned.
 */
static unsigned int
releaseUse (uintptr_t * ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = getPhysicalAddr (ptp) & 0xfffffffffffff000u;

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, decrement the uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      if ((--(PTPages[ptindex].uses)) == 0) {
        return ptindex;
      }
    }
  }

  return 0;
}

/*
 * Function: mapSecurePage()
 *
 * Description:
 *  Map a single frame of secure memory into the specified virtual address.
 *
 * Inputs:
 *  vaddr - The virtual address into which to map the physical page frame.
 *  paddr - The physical address of the page frame to map.
 *
 * Return value:
 *  The value of the PML4E entry mapping the secure memory region is returned.
 */
uintptr_t
mapSecurePage (uintptr_t vaddr, uintptr_t paddr) {
  /* PML4e value for the secure memory region */
  pml4e_t pml4eVal;
  /*
   * Ensure that this page is not being used for something else. The refcount
   * should be 1, i.e., the page should only be present in SVA's direct map.
   */
  frame_desc_t *pgDesc = get_frame_desc(paddr);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Attempted to create mapping to non-existant frame\n");

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
  pml4e_t *pml4e = get_pml4eVaddr(get_root_pagetable(), vaddr);
  if (!isPresent(*pml4e)) {
    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage(PGT_SML3);

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t paddr = PTPages[ptindex].paddr;
    *pml4e = PG_ENTRY_FRAME(paddr) | PG_P | PG_W | PG_U;
  }

  /*
   * Enable writing to the virtual address space used for secure memory.
   */
  *pml4e |= PG_U;

  /*
   * Record the value of the PML4E so that we can return it to the caller.
   */
  pml4eVal = *pml4e;

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t *pdpte = get_pdpteVaddr(*pml4e, vaddr);
  if (!isPresent(*pdpte)) {
    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage(PGT_SML2);

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
    *pdpte = PG_ENTRY_FRAME(pdpte_paddr) | PG_P | PG_W | PG_U;

    /*
     * Note that we've added another translation to the pml4e.
     */
    updateUses(pdpte);
  }
  *pdpte |= PG_U;

  if (isHugePage(*pdpte, PGT_L3)) {
    printf("mapSecurePage: PDPTE has PS BIT\n");
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t *pde = get_pdeVaddr(*pdpte, vaddr);
  if (!isPresent(*pde)) {
    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage(PGT_SML1);

    /*
     * Install a new PDE entry.
     */
    uintptr_t pde_paddr = PTPages[ptindex].paddr;
    *pde = PG_ENTRY_FRAME(pde_paddr) | PG_P | PG_W | PG_U;

    /*
     * Note that we've added another translation to the pdpte.
     */
    updateUses(pde);
  }
  *pde |= PG_U;

  if (isHugePage(*pde, PGT_L2)) {
    printf("mapSecurePage: PDE has PS BIT\n");
  }

  /*
   * Get the PTE entry (or add it if it is not present).
   */
  pte_t *pte = get_pteVaddr(*pde, vaddr);
#if 0
  SVA_ASSERT(!isPresent(*pte),
    "SVA: mapSecurePage: PTE is present: %p!\n", pte);
#endif

  /*
   * Mark the physical page frame as a ghost memory page frame. Also checks
   * that this frame is safe to use for ghost memory.
   */
  frame_morph(pgDesc, PGT_GHOST);

  /*
   * Increment the refcount for the frame to reflect that it is in use by the
   * ghost mapping we are creating.
   */
  frame_take(pgDesc, PGT_GHOST);

  /*
   * Modify the PTE to install the physical to virtual page mapping.
   */
  *pte = PG_ENTRY_FRAME(paddr) | PG_P | PG_W | PG_U;

  /*
   * Note that we've added another translation to the pde.
   */
  updateUses(pte);

  /*
   * Re-enable page protections.
   */
#ifndef SVA_DMAP
  protect_paging();
#endif

  return pml4eVal;
}

/*
 * Function: unmapSecurePage()
 *
 * Description:
 *  Unmap a single frame of secure memory from the specified virtual address.
 *
 * Inputs:
 *  threadp - A pointer to the SVA Thread for which we should release the frame
 *            of secure memory.
 *  v       - The virtual address to unmap.
 *
 * Return value:
 *  The physical address of the unmapped page on success, 0 otherwise
 *
 * TODO:
 *  Implement code that will tell other processors to invalidate their TLB
 *  entries for this page.
 */
uintptr_t
unmapSecurePage (struct SVAThread * threadp, unsigned char * v) {
  /*
   * Get the PML4E of the page table associated with the specified thread.
   */
  uintptr_t vaddr = (uintptr_t) v;
  uintptr_t paddr = 0;
  pdpte_t* pdpte = get_pdpteVaddr(threadp->secmemPML4e, vaddr);
  if (!isPresent(*pdpte)) {
    return 0;
  }

  if (isHugePage(*pdpte, PGT_L3)) {
    return 0;
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t* pde = get_pdeVaddr(*pdpte, vaddr);
  if (!isPresent(*pde)) {
    return 0;
  }

  if (isHugePage(*pde, PGT_L2)) {
    return 0;
  }

  /*
   * Get the PTE entry (or add it if it is not present).
   */
  pte_t* pte = get_pteVaddr(*pde, vaddr);
  if (!isPresent(*pte)) {
    return 0;
  }

  /*
   * Decrement the refcount for the frame to reflect that it is no longer in
   * use by the ghost mapping we are removing.
   */
  frame_desc_t *pageDesc = get_frame_desc(PG_L1_FRAME(*pte));

  /*
   * Modify the PTE so that the page is not present.
   */
#ifndef SVA_DMAP
  unprotect_paging();
#endif
  paddr = PG_L1_FRAME(*pte);
  *pte = 0;

  /*
   * Invalidate any TLBs in the processor.
   */
  sva_mm_flush_tlb(v);

  frame_drop(pageDesc, PGT_GHOST);

  /*
   * If we have removed the last ghost mapping to this frame, mark the frame as
   * free.
   */
  if (pageDesc->type_count == 0) {
    frame_morph(pageDesc, PGT_FREE);
  }

  /*
   * Go through and determine if any of the SVA VM pages tables are now unused.
   * If so, decrement their uses.
   *
   * The goal here is to make unused page tables have all unused entries so
   * that the operating system doesn't get confused.
   */
  unsigned int ptindex;
  if ((ptindex = releaseUse(pte))) {
    freePTPage(ptindex);
    *pde = 0;
    if ((ptindex = releaseUse(pde))) {
      freePTPage(ptindex);
      *pdpte = 0;
      if ((ptindex = releaseUse(pdpte))) {
        freePTPage(ptindex);
        threadp->secmemPML4e = 0;
#if 0
        if ((ptindex = releaseUse(getVirtual(*thread->secmemPML4e)))) {
          freePTPage(ptindex);
        }
#endif
      }
    }
  }

#ifndef SVA_DMAP
  /* Re-enable protection of page table pages */
  protect_paging();
#endif
  return paddr;
}

/*   Function: ghostmemCOW()
 *   
 *   Description: 
 *   Copy the parent's page table of ghost memory to the child. 
 *   Write protect these page table entries for both the parent and the child.
 *
 *   Inputs:
 *   oldThread - the SVAThread variable of the parent process
 *   newThread - the SVAThread variable of the child process   
 */
void
ghostmemCOW(struct SVAThread* oldThread, struct SVAThread* newThread) {
  uintptr_t vaddr_start, vaddr_end, size;

  vaddr_start = (uintptr_t) SECMEMSTART;
  size = oldThread->secmemSize;
  vaddr_end = vaddr_start + size;

  /*
   * Create the PML4E of the new process's page table.
   */
  pml4e_t pml4e_val;

  /* Page table page index */
  unsigned int ptindex;

  /* Fetch a new page table page */
  ptindex = allocPTPage(PGT_SML3);
  /*
   * Install a new PDPTE entry using the page.
   */
  uintptr_t paddr = PTPages[ptindex].paddr;
  pml4e_val = PG_ENTRY_FRAME(paddr) | PG_P | PG_W | PG_U;

  /*
   * Enable writing to the virtual address space used for secure memory.
   */
  pml4e_val |= PG_U;

  newThread->secmemPML4e = pml4e_val;

  pdpte_t* src_pdpte = (pdpte_t *)get_pdpteVaddr(oldThread->secmemPML4e, vaddr_start);
  pdpte_t* pdpte = get_pdpteVaddr(pml4e_val, vaddr_start);

  for (uintptr_t vaddr_pdp = vaddr_start;
      vaddr_pdp < vaddr_end;
      vaddr_pdp += PG_L3_SIZE, src_pdpte++, pdpte++) {

    if (!isPresent(*src_pdpte))
      continue;
    if (!isPresent(*pdpte)) {
      /* Page table page index */
      unsigned int ptindex;

      /* Fetch a new page table page */
      ptindex = allocPTPage(PGT_SML2);

      /*
       * Install a new PDPTE entry using the page.
       */
      uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
      *pdpte = PG_ENTRY_FRAME(pdpte_paddr) | PG_P | PG_W | PG_U;
    }
    *pdpte |= PG_U;

    /*
     * Note that we've added another translation to the pml4e.
     */
    updateUses(pdpte);

    if (isHugePage(*pdpte, PGT_L3)) {
      printf("ghostmemCOW: PDPTE has PS BIT\n");
    }

    pde_t* src_pde = get_pdeVaddr(*src_pdpte, vaddr_pdp);
    pde_t* pde = get_pdeVaddr(*pdpte, vaddr_pdp);
    for (uintptr_t vaddr_pde = vaddr_pdp;
        vaddr_pde < vaddr_pdp + PG_L3_SIZE;
        vaddr_pde += PG_L2_SIZE, src_pde++, pde++) {

      /*
       * Get the PDE entry (or add it if it is not present).
       */
      if (!isPresent(*src_pde))
        continue;

      if (!isPresent(*pde)) {
        /* Page table page index */
        unsigned int ptindex;

        /* Fetch a new page table page */
        ptindex = allocPTPage(PGT_SML1);

        /*
         * Install a new PDE entry.
         */
        uintptr_t pde_paddr = PTPages[ptindex].paddr;
        *pde = PG_ENTRY_FRAME(pde_paddr) | PG_P | PG_W | PG_U;
      }
      *pde |= PG_U;

      /*
       * Note that we've added another translation to the pdpte.
       */
      updateUses(pde);

      if (isHugePage(*pde, PGT_L2)) {
        printf("ghostmemCOW: PDE has PS BIT\n");
      }

      pte_t* src_pte = get_pteVaddr(*src_pde, vaddr_pde);
      pte_t* pte = get_pteVaddr(*pde, vaddr_pde);
      for (uintptr_t vaddr_pte = vaddr_pde;
          vaddr_pte < vaddr_pde + PG_L2_SIZE;
          vaddr_pte += PG_L1_SIZE, src_pte++, pte++) {

        if (!isPresent(*src_pte))
          continue;

        frame_desc_t *pgDesc = get_frame_desc(*src_pte);

        frame_take(pgDesc, PGT_GHOST);

        *src_pte &= ~PG_W;
        *pte = *src_pte;
        updateUses(pte);
      }
    }
  }
}

/*
 * Intrinsic: sva_mm_load_pgtable()
 *
 * Description:
 *  Set the current page table.  This implementation will also enable paging.
 *
 * Inputs:
 *  pg - The physical address of the top-level page table page.
 */
void
sva_mm_load_pgtable (cr3_t pg_ptr) {
  if (!mmuIsInitialized) {
    write_cr3(pg_ptr);
    return;
  }

  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure there are no extraneous bits set in the page table pointer (which
   * would be interpreted as flags in CR3). Masking with `PG_ENTRY_FRAME` will
   * leave us with just the 4 kB-aligned physical address.
   *
   * (These bits aren't *supposed* to be set by the caller, but we can't
   * trust the system software to be honest.)
   */
  uintptr_t new_pml4 = PG_ENTRY_FRAME(pg_ptr);

  /*
   * Check that the new page table is an L4 page table page.
   */
  if ((mmuIsInitialized) && (!disableMMUChecks)) {
    frame_desc_t* pml4Desc = get_frame_desc(new_pml4);
    SVA_ASSERT(pml4Desc != NULL,
      "SVA: FATAL: Using non-existant frame as root page table\n");
    SVA_ASSERT(pml4Desc->type == PGT_L4,
      "SVA: Loading non-L4 page into CR3: %lx %x\n",
      new_pml4, get_frame_desc(new_pml4)->type);
  }

  /*
   * Ensure that the secure memory region is still mapped within the new set
   * of page tables.
   */
  struct SVAThread *threadp = getCPUState()->currentThread;
  if (vg && threadp->secmemSize) {
    /*
     * Get a pointer to the section of the new top-level page table that maps
     * the secure memory region.
     */
    pml4e_t* root_pgtable = (pml4e_t*)getVirtual(new_pml4);
    pml4e_t* secmemp = &root_pgtable[PG_L4_ENTRY(SECMEMSTART)];

    /*
     * Write the PML4 entry for the secure memory region into the new
     * top-level page table.
     */
    *secmemp = threadp->secmemPML4e;
  }

  /*
   * Increment the reference count for the new PML4 page that we're about to
   * point CR3 to, and decrement it for the old PML4 being switched out.
   */
  frame_desc_t *newpml4Desc = get_frame_desc(new_pml4);
  frame_desc_t *oldpml4Desc = get_frame_desc(read_cr3());

  SVA_ASSERT(newpml4Desc != NULL,
    "SVA: FATAL: Using non-existant frame 0x%lx as root page table\n",
    new_pml4 / FRAME_SIZE);
  frame_take(newpml4Desc, PGT_L4);

#ifdef SVA_ASID_PG
  /*
   * Also do this for the respective kernel versions of the PML4s (if they
   * exist).
   */
  if (newpml4Desc->other_pgPaddr) {
    frame_desc_t *kernel_newpml4Desc =
      get_frame_desc(newpml4Desc->other_pgPaddr);

    frame_take(kernel_newpml4Desc, PGT_L4);
  }

  if (oldpml4Desc->other_pgPaddr) {
    frame_desc_t *kernel_oldpml4Desc =
      get_frame_desc(oldpml4Desc->other_pgPaddr);

    frame_drop(kernel_oldpml4Desc, PGT_L4);
  }

  /*
   * Invalidate the TLB's entries for this process in the kernel's address
   * space (PCID = 1).
   *
   * The invltlb_kernel() function has the side effect of changing the active
   * PCID to 1. We will immediately change it back to 0 (user/SVA) below when
   * we load the new page table.
   */
  invltlb_kernel();
#endif

  /*
   * Load the new page table.
   *
   * This also invalidates all TLB entries for this process in the user/SVA
   * address space (which, among other necessary effects, ensures that the
   * secure memory mapping in the PML4 that we updated above is in effect).
   */
  write_cr3(new_pml4);

  frame_drop(oldpml4Desc, PGT_L4);

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();

  record_tsc(sva_mm_load_pgtable_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

cr3_t sva_mm_save_pgtable(void) {
  return read_cr3();
}

/*
 * Function: sva_load_cr0
 *
 * Description:
 *  SVA Intrinsic to load the cr0 value. We need to make sure write protection
 *  is enabled. 
 */
void 
sva_load_cr0 (unsigned long val) {
    uint64_t tsc_tmp = 0;
    if(tsc_read_enable_sva)
       tsc_tmp = sva_read_tsc();


    val |= CR0_WP;
    write_cr0(val);


    record_tsc(sva_load_cr0_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

/*
 * PCID-related functions: 
 * kernel pcid is 1, and user/SVA pcid is 0
 */

/*
 * Function: usersva_to_kernel_pcid()
 *
 * Description:
 *  Switch to the kernel's version of the current process's address space
 *  (which does not include certain protected regions like ghost memory and
 *  SVA internal memory).
 */
void usersva_to_kernel_pcid(void) {
#ifdef SVA_ASID_PG
  unsigned long old_cr3 = read_cr3();

  /*
   * If the PCID is not already 1 (kernel), set PCID to 1 and switch to the
   * kernel version of the top-level page table.
   */
  if (!(old_cr3 & 0x1)) {
    /* Get the alternate PML4 address from SVA's page metadata. */
    frame_desc_t *pml4Desc = get_frame_desc(old_cr3);
    unsigned long altpml4 = pml4Desc->other_pgPaddr;

    /*
     * If we haven't yet set up the separate PML4 tables for the kernel and
     * user/SVA, stay with the current value loaded in CR3 (but still reload
     * CR3 to set the new PCID).
     */
    if (altpml4 == 0)
      altpml4 = old_cr3;

    /* Load CR3 with the new PML4 address and PCID = 1. */
    unsigned long new_cr3 =
      (altpml4 & ~0xfff) /* clear PCID field (bits 0-11) */
      | 0x1 /* set PCID field to 1 */
      | ((unsigned long)1 << 63) /* ensure XD (bit 63) is set */;

    write_cr3(new_cr3);

    if (tsc_read_enable_sva)
      as_num++;
  }
#endif

#ifdef SVA_LLC_PART
  /* Switch to the OS cache partition. */
  wrmsr(COS_MSR, OS_COS);
#endif
}

/*
 * Function: kernel_to_usersva_pcid()
 *
 * Description:
 *  Switch to the user/SVA version of the current process's address space
 *  (which includes certain protected regions, like ghost memory and SVA
 *  internal memory, that are not present in the kernel's version).
 */
void kernel_to_usersva_pcid(void) {
#ifdef SVA_ASID_PG
  unsigned long old_cr3 = read_cr3();

  /*
   * If the PCID is not already 0 (user/SVA), set PCID to 0 and switch to the
   * user/SVA version of the top-level page table.
   */
  if (old_cr3 & 0x1 /* if PCID != 1, it will be 0 */) {
    /* Get the alternate PML4 address from SVA's page metadata. */
    frame_desc_t *pml4Desc = get_frame_desc(old_cr3);
    unsigned long altpml4 = pml4Desc->other_pgPaddr;

    /*
     * If we haven't yet set up the separate PML4 tables for the kernel and
     * user/SVA, stay with the current value loaded in CR3 (but still reload
     * CR3 to set the new PCID).
     */
    if (altpml4 == 0)
      altpml4 = old_cr3;

    unsigned long new_cr3 =
      (altpml4 & ~0xfff) /* clear PCID field (bits 0-11) */
      | ((unsigned long)1 << 63) /* ensure XD (bit 63) is set */;

    write_cr3(new_cr3);

    if (tsc_read_enable_sva)
      as_num++;
  }
#endif

#ifdef SVA_LLC_PART
  /* Switch to the SVA cache partition. */
  wrmsr(COS_MSR, SVA_COS);
#endif
}

#ifdef FreeBSD
/*
 * Instrinsic: sva_update_l4_dmap
 *
 * Description:
 *  This function updates the pml4 entries of a process with the SVA direct mapping.
 *
 * Input:
 *  pml4pg - the virtual address of the pml4 page table page to be updated
 *  index  - the index of the SVA direct mapping pml4 entry
 *  val    - the page table entry to be populated in
 */

void sva_update_l4_dmap(void * pml4pg, int index, page_entry_t val)
{
  if(index < NDMPML4E)
  sva_update_l4_mapping(&(((pdpte_t *)pml4pg)[DMPML4I + index]), val);
}
#endif /* FreeBSD */

/**
 * Validate that a leaf mapping is safe.
 *
 * @param entry The leaf entry
 * @param level The level of page table which contains `entry`
 */
static void validate_existing_leaf(page_entry_t entry, frame_type_t level) {
  size_t frames = getMappedSize(level) / FRAME_SIZE;

  for (size_t i = 0; i < frames; ++i) {
    uintptr_t frame = PG_ENTRY_FRAME(entry) + i * FRAME_SIZE;
    frame_desc_t* pgDesc = get_frame_desc(frame);
    SVA_ASSERT(pgDesc != NULL,
      "SVA: FATAL: New page table contains mapping to non-existant "
      "frame 0x%lx\n", frame / FRAME_SIZE);

    frame_take(pgDesc, frame_type_from_pte(entry, level));
  }
}

/**
 * Validate that any existing entries in a new page table conform to SVA's
 * security policy.
 *
 * This function will also update reference counts for the frames referenced in
 * the entries.
 *
 * @param frame The new page table frame
 * @param level The level of the new page table
 */
static void validate_existing_entries(uintptr_t frame, frame_type_t level) {
  page_entry_t* entries = (page_entry_t*)getVirtual(frame);

  for (size_t i = 0; i < PG_ENTRIES; ++i) {
    if (isPresent(entries[i])) {
      if (isLeafEntry(entries[i], level)) {
        validate_existing_leaf(entries[i], level);
      } else {
        uintptr_t entryFrame = PG_ENTRY_FRAME(entries[i]);
        frame_desc_t* pgDesc = get_frame_desc(entryFrame);
        SVA_ASSERT(pgDesc != NULL,
          "SVA: FATAL: New L%d table at 0x%lx contains mapping to non-existant "
          "frame 0x%lx\n",
          getIntLevel(level), frame / FRAME_SIZE, entryFrame / FRAME_SIZE);

        frame_take(pgDesc, getSublevelType(level));
      }
    }
  }
}

void sva_declare_page(uintptr_t frame, frame_type_t level) {
  if (!mmuIsInitialized) {
    return;
  }

  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the frame_desc for the newly declared page table */
  frame_desc_t *pgDesc = get_frame_desc(frame);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame %lx as %s page table\n",
    frame / FRAME_SIZE, frame_type_name(level));

  /*
   * Mark this page frame as a page table.
   */
  frame_morph(pgDesc, level);

#if 0
  /*
   * Reset the virtual address which can point to this page table page.
   */
  pgDesc->pgVaddr = 0;
#endif

  /*
   * Initialize the new page table.
   */
  initDeclaredPage(frame);

  /*
   * Validate any existing entries in the new page table.
   */
  validate_existing_entries(frame, level);

  /* Restore interrupts */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}

void sva_declare_l1_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PGT_L1);

  record_tsc(sva_declare_l1_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_declare_l2_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PGT_L2);

  record_tsc(sva_declare_l2_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_declare_l3_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PGT_L3);

  record_tsc(sva_declare_l3_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_declare_l4_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PGT_L4);

  record_tsc(sva_declare_l4_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

static inline page_entry_t * 
printPTES (uintptr_t vaddr) {
  /* Pointer to the page table entry for the virtual address */
  page_entry_t *pge = 0;

  /* Get the base of the pml4 to traverse */
  cr3_t cr3 = get_root_pagetable();
  if (PG_ENTRY_FRAME(cr3) == 0)
    return NULL;

  /* Get the VA of the pml4e for this vaddr */
  pml4e_t* pml4e = get_pml4eVaddr(cr3, vaddr);

  if (isPresent(*pml4e)) {
    /* Get the VA of the pdpte for this vaddr */
    pdpte_t* pdpte = get_pdpteVaddr(*pml4e, vaddr);
    if (isPresent(*pdpte)) {
      /* 
       * The PDPE can be configurd in large page mode. If it is then we have the
       * entry corresponding to the given vaddr If not then we go deeper in the
       * page walk.
       */
      if (isHugePage(*pdpte, PGT_L3)) {
        pge = pdpte;
      } else {
        /* Get the pde associated with this vaddr */
        pde_t* pde = get_pdeVaddr(*pdpte, vaddr);
        if (isPresent(*pde)) {
          /* 
           * As is the case with the pdpte, if the pde is configured for large
           * page size then we have the corresponding entry. Otherwise we need
           * to traverse one more level, which is the last. 
           */
          if (isHugePage(*pde, PGT_L2)) {
            pge = pde;
          } else {
            pge = get_pteVaddr(*pde, vaddr);
            printf("SVA: PTE: %lx %lx %lx %lx\n", *pml4e, *pdpte, *pde, *pge);
          }
        }
      }
    }
  }

  /* Return the entry corresponding to this vaddr */
  return pge;
}

/*
 * Function: sva_remove_page()
 *
 * Description:
 *  This function informs the SVA VM that the system software no longer wants
 *  to use the specified page as a page table page.
 *
 *  This intrinsic should be used to undeclare EPT PTPs as well as regular
 *  PTPs.
 *
 * Inputs:
 *  paddr - The physical address of the page table page.
 */
void
sva_remove_page (uintptr_t paddr) {
  if (!mmuIsInitialized) {
    return;
  }

  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();
  
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  unsigned char isEPT; /* whether we are undeclaring an extended page table */

  /* Get the descriptor for the physical frame where this PTP resides. */
  frame_desc_t *pgDesc = get_frame_desc(paddr);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Frame being removed doesn't exist\n");

  /*
   * Make sure that this is a page table page. We don't want the system
   * software to trick us.
   *
   * Also take the opportunity to determine whether the PTP being undeclared
   * is an extended page table.
   */
  switch (pgDesc->type) {
    case PGT_L1:
    case PGT_L2:
    case PGT_L3:
    case PGT_L4:
      isEPT = 0;
      break;

    case PGT_EPTL1:
    case PGT_EPTL2:
    case PGT_EPTL3:
    case PGT_EPTL4:
      isEPT = 1;
      break;

    default:
      SVA_ASSERT_UNREACHABLE(
        "SVA: FATAL: undeclare bad page type: %lx %s\n",
        paddr, frame_type_name(pgDesc->type));
  }

  /*
   * If any valid mappings remain within the PTP, explicitly remove them to
   * ensure consistency of SVA's page metadata.
   *
   * (Note: PG_ENTRIES = # of entries in a PTP. We assume this is the same at
   * all levels of the paging hierarchy.)
   */
  page_entry_t* ptp_vaddr = (page_entry_t*)getVirtual(paddr);
  for (unsigned long i = 0; i < PG_ENTRIES; i++) {
    if (isPresent_maybeEPT(ptp_vaddr[i], isEPT)) {
      /* Remove the mapping */
      frame_desc_t *mappedPg = get_frame_desc(ptp_vaddr[i]);
      if (isGhostPTP(mappedPg)) {
        /*
         * The method of removal for ghost PTP mappings is slightly
         * different than for ordinary mappings created by the OS (SVA has
         * a separate refcount system to keep track of them).
         */
        unsigned int ptindex = releaseUse(&ptp_vaddr[i]);
        freePTPage(ptindex);
        ptp_vaddr[i] = ZERO_MAPPING;
      } else {
        bool isLeaf = isLeafEntry(ptp_vaddr[i], pgDesc->type);
        size_t count = isLeaf ? getMappedSize(pgDesc->type) / FRAME_SIZE : 1;
        /*
         * NB: We don't want to actually change the data in the page table, as
         * the kernel may be relying on being able to access it for its own
         * bookkeeping.  Instead, just update our metadata to reflect that the
         * reference has been dropped.  Since this page is about to become a
         * data page, there is no safety concern with leaving the entry intact.
         */
        updateOrigPageData(ptp_vaddr[i],
                           frame_type_from_pte(ptp_vaddr[i], pgDesc->type),
                           count);
      }
    }
  }

  /*
   * Mark the page frame as an unused page.  Note that this will also check
   * that there are no references to this page (i.e., there is no page table
   * entry that refers to this physical page frame).
   */
  frame_morph(pgDesc, PGT_FREE);

#if 0
  /*
   * Make the page writeable again in the kernel's direct map. Be sure to
   * flush entries pointing to it in the TLBs so that the change takes
   * effect right away.
   */
  do_mmu_update(pte_kdmap, setMappingReadWrite(*pte_kdmap));
  sva_mm_flush_tlb(getVirtualKernelDMAP(paddr));
#endif

#ifdef SVA_ASID_PG
  /*
   * If the PTP being undeclared is a level-4 PTP (non-EPT), undeclare the
   * kernel's copy of it in addition to the SVA/userspace copy.
   *
   * (It doesn't matter which one of the two copies we were given as the
   * parameter to this intrinsic - whichever one we were given, we'll
   * undeclare the other one here.)
   */
  if (pgDesc->type == PGT_L4) {
    uintptr_t other_cr3 = pgDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;

    /*
     * Only proceed if there actually *is* an alternate PML4 associated
     * with this one. In general the kernel will set these up together but
     * SVA doesn't *force* it to do so. (In particular, the alternate PML4
     * may not exist for the initial set of page tables loaded during
     * boot.)
     */
    if (other_cr3) {
      frame_desc_t *other_pgDesc = get_frame_desc(other_cr3);

      /*
       * If any valid mappings remain within the PTP, explicitly remove
       * them to ensure consistency of SVA's page metadata.
       */
      page_entry_t *other_pml4_vaddr =
        (page_entry_t *) getVirtualSVADMAP(other_cr3);
      for (int i = 0; i < PG_ENTRIES; i++) {
        if (isPresent_maybeEPT(other_pml4_vaddr[i], isEPT)) {
          /* Remove the mapping */
          update_mapping(&other_pml4_vaddr[i], ZERO_MAPPING);
        }
      }

      /* Mark the page frame as an unused page. */
      other_pgDesc->type = PGT_FREE;

#if 0
      /*
       * Make the page writable again in the kernel's direct map. Be sure
       * to flush entries pointing to it in the TLBs so that the change
       * takes effect right away.
       */
      page_entry_t* other_pte =
        get_pgeVaddr((uintptr_t)getVirtualKernelDMAP(other_cr3));
      do_mmu_update(other_pte, setMappingReadWrite(*other_pte));
      sva_mm_flush_tlb(getVirtual(other_cr3));
#endif

      other_pgDesc->other_pgPaddr = 0;
      pgDesc->other_pgPaddr = 0;
    }
  }
#endif

  /* Restore interrupts and return to kernel page tables */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_remove_page_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

#if SVA_ASID_PG
/*
 * Function: sva_get_kernel_pml4pg
 * 
 * Description:
 *   Return the physical address of the kernel pml4 page table page
 *
 * Input:
 *   paddr - the physical address of the original (user/sva verison) pml4 page table page
 */
uintptr_t sva_get_kernel_pml4pg(uintptr_t paddr)
{
	frame_desc_t *pgDesc = get_frame_desc(paddr);
        SVA_ASSERT(pgDesc != NULL,
          "SVA: FATAL: Frame doesn't exist\n");
	uintptr_t other_paddr = pgDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
	return other_paddr;		
}
#endif /* SVA_ASID_PG */

/* 
 * Function: sva_remove_mapping()
 *
 * Description:
 *  This function clears an entry in a page table page. It is agnostic to the
 *  level of page table (and whether we are dealing with an extended or
 *  regular page table). The particular needs for each page table level/type
 *  are handled in the update_mapping function.
 *
 * Inputs:
 *  pteptr - The location within the page table page for which the translation
 *           should be removed.
 */
void
sva_remove_mapping(page_entry_t * pteptr) {
  if (!mmuIsInitialized) {
    *pteptr = ZERO_MAPPING;
    return;
  }

  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
    tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Update the page table mapping to zero */
  update_mapping(pteptr, ZERO_MAPPING);

#ifdef SVA_ASID_PG
  /*
   * If we are removing a mapping in a level-4 page table (non-EPT), remove
   * it in the kernel's copy of the PML4 in addition to the SVA/userspace
   * copy.
   */
  uintptr_t ptePA = getPhysicalAddr(pteptr);
  frame_desc_t *ptePG = get_frame_desc(ptePA);
  SVA_ASSERT(ptePG != NULL,
    "SVA: FATAL: Page table frame doesn't exist\n");

  if(ptePG->type == PGT_L4) {
    uintptr_t other_cr3 = ptePG->other_pgPaddr & ~PML4_SWITCH_DISABLE;

    if(other_cr3) {
      page_entry_t * other_pteptr = (page_entry_t *)
        ((unsigned long) getVirtual(other_cr3)
         | ((unsigned long) pteptr & vmask));

      update_mapping(other_pteptr, ZERO_MAPPING);
    }
  }
#endif

  /* Restore interrupts and return to kernel page tables */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_remove_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

#ifdef SVA_ASID_PG
/* 
 * Function: sva_update_l1_mapping_checkglobal()
 *
 * Description:
 *  This function updates a Level-1 Mapping.  In other words, it adds a
 *  a direct translation from a virtual page to a physical page.
 *  Compared to sva_update_l1_mapping, this function checks whether the virtual 
 *  address falls within the sva internal memory. If yes, make sure the PTEs are
 *  not marked as global.
 *
 *  This function makes different checks to ensure the mapping
 *  does not bypass the type safety proven by the compiler.
 *
 * Inputs:
 *  pteptr - The location within the L1 page in which the new translation
 *           should be placed.
 *  val    - The new translation to insert into the page table.
 */
void
sva_update_l1_mapping_checkglobal(pte_t * pteptr, page_entry_t val, unsigned long va) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  if((va >= 0xffffffff819ef000u) && (va <= 0xffffffff89b96060u) )
  {
    val &= ~PG_G;
  }

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  frame_desc_t * ptDesc = get_frame_desc (getPhysicalAddr(pteptr));
  SVA_ASSERT(ptDesc != NULL,
    "SVA: FATAL: Page table frame doesn't exist\n");
  SVA_ASSERT(disableMMUChecks || ptDesc->type == PGT_L1,
    "SVA: MMU: update_l1 not an L1: %p %lx: %x\n", pteptr, val, ptDesc->type);

  /*
   * Update the page table with the new mapping.
   */
  update_mapping(pteptr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}
#endif /* SVA_ASID_PG */

/**
 * Update a page table entry.
 *
 * Performs all necessary security checks to ensure the update is safe.
 *
 * @param pte     The page table entry to update
 * @param new_pte The new value to set in `*pte`
 * @param level   The level of page table which contains `pte`
 */
void sva_update_mapping(page_entry_t* pte, page_entry_t new_pte,
                        frame_type_t level)
{
  if (!mmuIsInitialized) {
    /*
     * MMU initialization has not been performed, so don't perform any safety
     * checks.
     */
    *pte = new_pte;
    return;
  }

  kernel_to_usersva_pcid();

  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to the specified level of page table.
   * If it does not, then report an error.
   */
  frame_desc_t* ptDesc = get_frame_desc(getPhysicalAddr(pte));
  SVA_ASSERT(ptDesc != NULL,
    "SVA: FATAL: %s page table frame at %p doesn't exist\n",
    frame_type_name(level), pte);
  SVA_ASSERT(disableMMUChecks || ptDesc->type == level,
    "SVA: FATAL: Attempt update %s entry at %p, but frame type is %s\n",
    frame_type_name(level), pte, frame_type_name(ptDesc->type));

  update_mapping(pte, new_pte);

  /* Restore interrupts */
  sva_exit_critical(rflags);

  usersva_to_kernel_pcid();
}

void sva_update_l1_mapping(pte_t* l1e, pte_t new_l1e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_update_mapping(l1e, new_l1e, PGT_L1);

  record_tsc(sva_update_l1_mapping_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_update_l2_mapping(pde_t* l2e, pde_t new_l2e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_update_mapping(l2e, new_l2e, PGT_L2);

  record_tsc(sva_update_l2_mapping_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_update_l3_mapping(pdpte_t* l3e, pdpte_t new_l3e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_update_mapping(l3e, new_l3e, PGT_L3);

  record_tsc(sva_update_l3_mapping_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_update_l4_mapping(pml4e_t* l4e, pml4e_t new_l4e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  sva_update_mapping(l4e, new_l4e, PGT_L4);

#ifdef SVA_ASID_PG 
  uintptr_t other_cr3 = ptDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
  if (other_cr3) {
    uintptr_t index = (uintptr_t)l4e & vmask;
    pml4e_t* kernel_pml4ePtr =
      (pml4e_t*)((uintptr_t)getVirtual(other_cr3) | index);
    frame_desc_t* kernel_ptDesc = get_frame_desc(other_cr3);
    SVA_ASSERT(disableMMUChecks || kernel_ptDesc->type == PGT_L4,
      "SVA: MMU: update_l4 kernel or sva version pte not an L4: %lx %lx: %x\n",
      kernel_pml4ePtr, new_l4e, kernel_ptDesc->type);

    if (((index >> 3) == PML4PML4I) &&
        (PG_ENTRY_FRAME(new_l4e) == PG_ENTRY_FRAME(getPhysicalAddr(l4e))))
    {
        new_l4e = other_cr3 | (new_l4e & 0xfff);
    }
    update_mapping(kernel_pml4ePtr, new_l4e);
  }
#endif

  /* Restore interrupts */
  sva_exit_critical(rflags);

  record_tsc(sva_update_l4_mapping_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

/**
 * Change the permissions on a code page.
 *
 * Note: This function allows the creation of writable+executable mappings as
 * well as setting unvetted data as executable. Use with caution.
 *
 * @param vaddr The virtual address for which to change permissions
 * @param perms The new permissions to set
 */
static void protect_code_page(uintptr_t vaddr, page_entry_t perms) {
  // Get a pointer to the page table entry
  page_entry_t* leaf_entry = get_pgeVaddr(vaddr);
  SVA_ASSERT(leaf_entry != NULL && isPresent(*leaf_entry),
    "SVA: FATAL: Attempt to change permissions on unmapped page 0x%016lx\n",
    vaddr);

  frame_desc_t* pgDesc = get_frame_desc(*leaf_entry);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Page table entry maps invalid frame\n");
  SVA_ASSERT(pgDesc->type = PGT_CODE,
    "SVA: FATAL: Changing permissons on non-code page 0x%016lx\n", vaddr);

  *leaf_entry &= ~(PG_P | PG_W | PG_NX) | perms;
  *leaf_entry |= perms;

  invlpg(vaddr);
}

/*
 * Remove write-protection from a code page.
 *
 * This is a hack which is intended to support limited uses of runtime-generated
 * code which have not been fully ported.
 *
 * @param vaddr The virtual address for which to change protections
 */
void sva_unprotect_code_page(void* vaddr) {
  SVA_ASSERT(mmuIsInitialized,
    "SVA: FATAL: sva_unprotect_code_page called before MMU init\n");

  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  unsigned long flags = sva_enter_critical();
  kernel_to_usersva_pcid();

  protect_code_page((uintptr_t)vaddr, PG_P | PG_W | PG_NX);

  usersva_to_kernel_pcid();
  sva_exit_critical(flags);

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

/*
 * Re-add write-protection to a code page.
 *
 * This is a hack which is intended to support limited uses of runtime-generated
 * code which have not been fully ported.
 *
 * @param vaddr The virtual address for which to change protections
 */
void sva_protect_code_page(void* vaddr) {
  SVA_ASSERT(mmuIsInitialized,
    "SVA: FATAL: sva_unprotect_code_page called before MMU init\n");

  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  unsigned long flags = sva_enter_critical();
  kernel_to_usersva_pcid();

  protect_code_page((uintptr_t)vaddr, PG_P);

  usersva_to_kernel_pcid();
  sva_exit_critical(flags);

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

#ifdef SVA_ASID_PG
/*
 * Intrisic: sva_create_kernel_pml4pg()
 *
 * Description:
 *  Record the kernel version of a level-4 page table page (PML4) in the page
 *  descriptor of the orignal (user/SVA version) level-4 page table page. The
 *  kernel version does not have the mappings of ghost memory and SVA
 *  internal memory.
 *
 *  Currently, for the pure purpose of measuring the overhead of ASID and
 *  page table manipulation, the kernel's version of the PML4 page table page
 *  is entirely the same as the user/SVA version. This avoids challenges due
 *  to x86's behavior of automatically saving interrupt contexts on one stack
 *  upon traps/interrupts. However, for a complete/secure SVA implementation,
 *  mappings to the secure memory regions (plus other sensitive mappings such
 *  as SVA's direct map) should actually be removed from the kernel's PML4.
 *
 * Inputs:
 *  orig_phys   - the physical address of the original PML4 page table page
 *                (which will become the user/SVA version)
 *  kernel_phys - the physical address of the page to be used for the new
 *                kernel version PML4
 */
void sva_create_kernel_pml4pg(uintptr_t orig_phys, uintptr_t kernel_phys) {
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   *
   * Note that this is for the *currently active* page table, which is
   * generally not the same as the one for which this intrinsic was called to
   * bifurcate the PML4 - though it could be. If that is the case,
   * kernel_to_usersva_pcid() will change the PCID but not the PML4 that CR3
   * points to (since we are already using the user/SVA PML4, it being the
   * only one currently in existence).
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure no extraneous bits are set in the PML4 pointers which would be
   * interpreted as flags in CR3.
   */
  orig_phys = PG_ENTRY_FRAME(orig_phys);
  kernel_phys = PG_ENTRY_FRAME(kernel_phys);

  frame_desc_t *kernel_ptDesc = get_frame_desc(kernel_phys);
  SVA_ASSERT(kernel_ptDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame as a root page table\n");
  frame_desc_t *usersva_ptDesc = get_frame_desc(orig_phys);
  SVA_ASSERT(usersva_ptDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame as a root page table\n");

  /*
   * Ensure that the new kernel PML4 page has been declared to SVA as an L4
   * PTP frame.
   */
  SVA_ASSERT(kernel_ptDesc->type == PGT_L4,
    "SVA: MMU: attempted to use a page as a kernel PML4 that wasn't "
    "declared to SVA as an L4 PTP frame!\n"
    "paddr = 0x%lx\n; type = %d\n", kernel_phys, kernel_ptDesc->type);

  /*
   * Ensure that the original PML4 page (i.e. the user/SVA version PML4) that
   * the new kernel PML4 is being attached to really is itself a PML4.
   */
  SVA_ASSERT(usersva_ptDesc->type == PGT_L4,
    "SVA: MMU: attempted to set up a kernel version of a PML4 that "
    "isn't actually a PML4!\n"
    "Fake original page paddr = 0x%lx, "
    "type = %d; Kernel PML4 paddr = 0x%lx\n",
    orig_phys, usersva_ptDesc->type, kernel_phys);

  /*
   * If the kernel already set up a kernel PML4 for this user/SVA PML4, don't
   * let it do so again.
   *
   * (I'm not sure this would *necessarily* create a security loophole, but
   * it's certainly not a sane way to configure things and would be a mess to
   * support, especially w.r.t. refcounts.)
   */
  SVA_ASSERT(usersva_ptDesc->other_pgPaddr == 0,
    "SVA: MMU: attempted to set up a kernel version of a user/SVA PML4 "
    "that already has a counterpart kernel PML4. paddr = 0x%lx\n", kernel_phys);

  /*
   * Point the two PML4s' page descriptors' cross-references (the
   * other_pgPaddr field) to each other.
   *
   * Set the PML4_SWITCH_DISABLE flag in the user/SVA PML4's cross-reference
   * to inhibit the Trap() handler from attempting to switch to the kernel
   * PML4 before the kernel has declared it ready by calling
   * sva_set_kernel_pml4pg_ready().
   */
  kernel_ptDesc->other_pgPaddr = orig_phys;
  usersva_ptDesc->other_pgPaddr = kernel_phys | PML4_SWITCH_DISABLE;

  /*
   * If (and only if) the PML4 being bifurcated is the one currently loaded
   * in CR3, increment the refcount of the new kernel PML4 to keep it
   * consistent with the user/SVA one (whose refcount was incremented when it
   * was loaded).
   */
  if (orig_phys == PG_ENTRY_FRAME(read_cr3())) {
    frame_take(kernel_ptDesc, PGT_L4);
  }

  /* 
   * Restore interrupts and return to the kernel page tables.
   *
   * If this intrinsic just set up a newly-minted kernel PML4 for the
   * *currently active* page table, then this call to
   * usersva_to_kernel_pcid() will make that new PML4 active.
   */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}
#endif /* SVA_ASID_PG */

uintptr_t sva_get_physical_address(uintptr_t vaddr) {
  return getPhysicalAddr((void*)vaddr);
}

pte_t* sva_get_l1_entry(uintptr_t vaddr) {
  pde_t* pde = sva_get_l2_entry(vaddr);
  if (pde != NULL && isPresent(*pde) && !isHugePage(*pde, PGT_L2)) {
    return get_pteVaddr(*pde, vaddr);
  } else {
    return NULL;
  }
}

pde_t* sva_get_l2_entry(uintptr_t vaddr) {
  pdpte_t* pdpte = sva_get_l3_entry(vaddr);
  if (pdpte != NULL && isPresent(*pdpte) && !isHugePage(*pdpte, PGT_L3)) {
    return get_pdeVaddr(*pdpte, vaddr);
  } else {
    return NULL;
  }
}

pdpte_t* sva_get_l3_entry(uintptr_t vaddr) {
  pml4e_t* pml4e = sva_get_l4_entry(vaddr);
  if (isPresent(*pml4e)) {
    return get_pdpteVaddr(*pml4e, vaddr);
  } else {
    return NULL;
  }
}

pml4e_t* sva_get_l4_entry(uintptr_t vaddr) {
  return get_pml4eVaddr(get_root_pagetable(), vaddr);
}

#ifdef SVA_ASID_PG
/*
 * Intrinsic: sva_set_kernel_pml4pg_ready()
 *
 * Description:
 *  Declare that the kernel version of a level-4 page table page (PML4)
 *  previously set up with sva_create_kernel_pml4pg() is ready for use.
 *
 *  Until this is called, the Trap() handler will refrain from switching
 *  PML4s when it performs an ASID switch.
 *
 * Inputs:
 *  orig_phys - the physical address of the original (user/SVA version)
 *              level-4 page table page whose kernel counterpart we want to
 *              mark ready for use
 */
void sva_set_kernel_pml4pg_ready(uintptr_t orig_phys) {
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /*
   * Unset the PML4_SWITCH_DISABLE bit in the user/SVA PML4's pointer to its
   * kernel counterpart.
   */
  frame_desc_t *usersva_ptDesc = get_frame_desc(orig_phys);
  SVA_ASSERT(usersva_ptDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame as a root page table\n");
  usersva_ptDesc->other_pgPaddr =
    usersva_ptDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}
#endif /* SVA_ASID_PG */
