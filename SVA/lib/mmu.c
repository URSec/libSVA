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
extern unsigned char __svadata SVAPTPages[1024][X86_PAGE_SIZE];

/* Array describing the physical pages. Used by SVA's MMU and EPT intrinsics.
 * The index is the physical page number.
 *
 * There is an "extern" declaration for this object in mmu.h so that the EPT
 * intrinsics can see it.
 */
page_desc_t __svadata page_desc[numPageDescEntries];

/*
 * Description:
 *  Given a page table entry value, return the page description associate with
 *  the frame being addressed in the mapping.
 *
 *  Also accepts a physical address pointer to any location in the frame in
 *  lieu of a PTE value, since (either way) we will mask off the higher and
 *  lower bits to yield the 4 kB-aligned frame pointer.
 *
 * Inputs:
 *  mapping: the mapping with the physical address of the referenced frame
 *           (or a physical address pointing anywhere within the frame)
 *
 * Return value:
 *  Pointer to the page_desc for this frame, or `NULL` if the frame is beyond
 *  the maximum supported physical memory.
 */
page_desc_t * getPageDescPtr(unsigned long mapping) {
  unsigned long frameIndex = (mapping & PG_FRAME) / PG_L1_SIZE;
  if (frameIndex >= numPageDescEntries)
    return NULL;
  return page_desc + frameIndex;
}

void
printPageType (unsigned char * p) {
  page_desc_t *pageDesc = getPageDescPtr(getPhysicalAddr(p));
  if (pageDesc == NULL) {
    printf("SVA: page type: %p: nonexistant\n", p);
  } else {
    printf ("SVA: page type: %p: %x\n", p, pageDesc->type);
  }
  return;
}

/*
 *****************************************************************************
 * Define helper functions for MMU operations
 *****************************************************************************
 */

/* Functions for aiding in declare and updating of page tables */

/*
 * Function: page_entry_store
 *
 * Description:
 *  This function takes a pointer to a page table entry and updates its value
 *  to the new value provided.
 *
 * Assumptions: 
 *  - This function assumes that write protection is enabled in CR0 (WP bit set
 *    to 1). 
 *
 * Inputs:
 *  *page_entry -: A pointer to the page entry to store the new value to, a
 *                 valid VA for accessing the page_entry.
 *  newVal      -: The new value to store, including the address of the
 *                 referenced page.
 *
 * Side Effect:
 *  - This function enables system wide write protection in CR0. 
 */
void
page_entry_store (unsigned long *page_entry, page_entry_t newVal) {
  uint64_t tsc_tmp = 0;
  if (tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

#ifdef SVA_DMAP
  uintptr_t ptePA = getPhysicalAddr(page_entry);
  unsigned long *page_entry_svadm = (unsigned long *) getVirtualSVADMAP(ptePA);

#if 0
  page_desc_t *ptePG = getPageDescPtr(ptePA);

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
    newVal |= PG_RW;
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

/*
 *****************************************************************************
 * Page table page index and entry lookups 
 *****************************************************************************
 */

/**
 * Check if the permissions on a page table entry are safe for a frame.
 *
 * NB: This assumes that the entry maps a normal virtual address (i.e. not one
 * in secure memory).
 *
 * @param entry The page table entry to check
 * @param type  The type of the frame being mapped
 * @return      True if the permissions on `entry` are safe for a `type` frame,
 *              otherwise false.
 */
static bool mappingIsSafe(page_entry_t entry, enum page_type_t type) {
  switch (type) {
  case PG_FREE:
    /* Safe as long as the mapping is read-only. */
    return !isWritable(entry) && !isExecutable(entry);
  case PG_L1 ... PG_L4:
  case PG_EPTL1 ... PG_EPTL4:
  case PG_SML1 ... PG_SML3:
    /* Safe if neither writable nor executable. */
    return !isWritable(entry) &&
           (!isExecutable(entry) || isUserMapping(entry)); // Assume SMEP
  case PG_DATA:
    /* Safe if only executable by user. */
    return !isExecutable(entry) || isUserMapping(entry); // Assume SMEP
  case PG_CODE:
    /* Safe if not writable. */
    return !isWritable(entry);
  case PG_SVA:
  case PG_GHOST:
  case PG_UNUSABLE:
    /* Never safe. */
    return false;
  default:
    SVA_ASSERT_UNREACHABLE("SVA: Invalid page type %d\n", type);
  }
}

/*
 * Function: pt_update_is_valid()
 *
 * Description:
 *  This function assesses a potential page table update for a valid mapping.
 *
 *  It also works for extended page table (EPT) updates.
 *
 *  NOTE: This function assumes that the page being mapped in has already been
 *  declared and has its intial page metadata captured as defined in the
 *  initial mapping of the page.
 *
 * Inputs:
 *  *page_entry  - VA pointer to the page entry being modified
 *  newVal       - Representes the new value to write including the reference
 *                 to the underlying mapping.
 *
 * Return:
 *  0  - The update is not valid and should not be performed.
 *  1  - The update is valid but should disable write access.
 *  2  - The update is valid and can be performed.
 */
static inline unsigned char
pt_update_is_valid (page_entry_t *page_entry, page_entry_t newVal) {
  /* Collect associated information for the existing mapping */
  unsigned long origPA = *page_entry & PG_FRAME;
  page_desc_t *origPG = getPageDescPtr(origPA);

  /* Get associated information for the new page being mapped */
  unsigned long newPA = newVal & PG_FRAME;
  page_desc_t *newPG = getPageDescPtr(newPA);

  /* Get the page table page descriptor. */
  uintptr_t ptePAddr = getPhysicalAddr(page_entry);
  page_desc_t *ptePG = getPageDescPtr(ptePAddr);

  /* Is this an extended page table update? */
  unsigned char isEPT = ptePG->type >= PG_EPTL1 && ptePG->type <= PG_EPTL4;
 
  /* Return value */
  unsigned char retValue = 2;

  /*
   * If MMU checks are disabled, allow the page table entry to be modified.
   */
  if (disableMMUChecks)
    return retValue;

  /*
   * Determine if the page table pointer is within the kernel's direct map.
   * If not, then it's an error.
   *
   * TODO: This check can cause a panic because the SVA VM does not set up
   *       the kernel's direct map before starting the kernel. As a result,
   *       we get page table addresses that don't fall into the direct map.
   */
  SVA_NOOP_ASSERT(isKernelDirectMap((uintptr_t)page_entry),
                  "SVA: MMU: Not direct map\n");

  /*
   * Verify that we're not trying to modify the PML4 entry that controls the
   * secure memory virtual address space.
   */
  SVA_ASSERT(!(ptePG->type == PG_L4 &&
               (ptePAddr & PG_FRAME) == secmemOffset),
    "SVA: MMU: Kernel attempted to modify ghost memory pml4e!\n");

  /*
   * Verify that we're not modifying any of the page tables that control the
   * securem memory virtual address space. Ensuring that the page that we're
   * writing into isn't a secure memory page table (along with the previous
   * check) should suffice.
   */
  SVA_ASSERT(!isGhostPTP(ptePG),
    "SVA: MMU: Kernel attempted to modify ghost memory mappings!\n");

  /* 
   * If we aren't mapping a new page then we can skip several checks, and in
   * some cases we must, otherwise the checks will fail.
   */
  if (isPresent_maybeEPT(newVal, isEPT)) {
    SVA_ASSERT(newPG != NULL,
      "SVA: FATAL: Attempted to create mapping to non-existant frame 0x%lx"
      "(PTE 0x%016lx)\n",
      newPA / PAGE_SIZE, newVal);

    /*
     * Verify that we're not attempting to establish a mapping to a ghost PTP.
     */
    SVA_ASSERT(!isGhostPTP(newPG),
      "SVA: MMU: Kernel attempted to map a ghost PTP!\n");

    /*
     * If this is a last-level mapping (L1 or large page with PS bit set),
     * verify that the mapping points to physical memory the OS is allowed to
     * access.
     *
     * For non-last-level mappings, verify that the mappoing points to the
     * appropriate next-level page table.
     */
    if (isLeafEntry(newVal, ptePG->type)) {
      /*
       * The OS is only allowed to create mappings to certain types of frames
       * (e.g., unused, kernel data, or user data frames). Some frame types
       * are allowed but are forced to be mapped non-writably (e.g. PTPs and
       * code pages).
       *
       * All requests to add mappings to frame types not explicitly handled
       * here are rejected by SVA. This is a "fail-closed" design that will
       * reduce the risk of loopholes as we add frame types in ongoing SVA
       * development.
       */
      switch (newPG->type) {
        /* These mappings are allowed without restriction. */
        case PG_DATA:
          break;
        case PG_FREE:
          if (isWritable(newVal)) {
            /* Make the page writable */
            newPG->type = PG_DATA;
          }
          break;

          /* These are allowed, but forced to be non-writable. */
        case PG_CODE:
          /*
           * NOTE (EJJ 8/25/18): This code was included in this function
           * before I refactored it. Based on the original comment, it
           * *appeared* to be intended to *allow* writable mappings to code
           * pages if they were in userspace. However, it was superseded by
           * another check which explicitly made all code-page mappings
           * non-writable (which is reflected in this switch table here in
           * the refactored code).
           *
           * If not for the superseding check, I believe this would have been
           * a security hole, since giving the kernel the power to make
           * writable mappings in userspace to any code page is as good as
           * allowing the kernel to make its own writable code page mappings.
           *
           * Perhaps what was intended (but incorrectly implemented) was to
           * allow writable mappings to code pages which have been declare to
           * SVA as being for use in userspace? (In any case, SVA doesn't
           * presently have a frame type to represent that.)
           *
           * I've included the code here, commented-out, for posterity in
           * case it existed for a reason which remains relevant. Please note
           * that it will not simply "work" if you uncomment it, because this
           * case falls through to "retValue = 1" (force non-writable) below,
           * which matches the *actual* behavior of the pre-refactoring code
           * (due to a superseding check which blanketly disallowed writable
           * code-page mappings).
           *
           *    Original comment:
           * New mappings to code pages are permitted as long as they are
           * either for user-space pages or do not permit write access.
           */
#if 0
          if (isCodePg(newPG)) {
            SVA_ASSERT(!((newVal & (PG_RW | PG_U)) == PG_RW)
              "SVA: Making kernel code writeable: %lx %lx\n", newVA, newVal);
          }
#endif
        case PG_L1:
        case PG_L2:
        case PG_L3:
        case PG_L4:
          /* NOTE (EJJ 8/25/18): This code was commented-out in the original
           * version of this function before I refactored it. I've left it
           * that way and have not changed the comment below because I'm not
           * entirely sure whether this code is still needed or worked
           * correctly (given it was commented out).
           */
          /* 
           * If the new page is a page table page, then we verify some page
           * table page specific checks. 
           *
           * If we have a page table page being mapped in and it currently
           * has a mapping to it, then we verify that the new VA from the new
           * mapping matches the existing currently mapped VA.   
           *
           * This guarantees that we each page table page (and the
           * translations within it) maps a singular region of the address
           * space.
           *
           * Otherwise, this is the first mapping of the page, and we should
           * record in what virtual address it is being placed.
           */
#if 0
          if (pgRefCount(newPG) > 1) {
            SVA_ASSERT(newPG->pgVaddr == page_entry,
              "SVA: PG: %lx %lx: type=%x\n",
              newPG->pgVaddr, page_entry, newPG->type);
            SVA_ASSERT (newPG->pgVaddr == page_entry,
                "MMU: Map PTP to second VA");
          } else {
            newPG->pgVaddr = page_entry;
          }
#endif
        case PG_EPTL1:
        case PG_EPTL2:
        case PG_EPTL3:
        case PG_EPTL4:
          retValue = 1;
          break;

          /* These are explicitly disallowed. */
        case PG_GHOST:
          /*
           * Silently ignore the mapping request. This reduces porting effort
           * because it's less likely to break something if the kernel
           * accidentally attempts to map a ghost page (as long as the kernel
           * doesn't actually try to access it).
           */
          printf("SVA: MMU: Kernel attempted to map a ghost page. "
              "Ignoring and continuing...\n");
          retValue = 0;
          break;
        case PG_SVA:
          SVA_ASSERT_UNREACHABLE(
            "SVA: MMU: Kernel attempted to map an SVA page!\n");

          /* All other mapping types are disallowed. */
        default:
          SVA_ASSERT_UNREACHABLE(
            "SVA: MMU: Kernel attempted to map a page of unrecognized type! "
            "paddr: 0x%lx; type: 0x%x\n", newPA, newPG->type);
      }
    } else { /* not an L1 or large page PTE */
      /*
       * This is a non-last-level mapping. Verify that it points to the
       * appropriate type of next-level PTP.
       */
      switch (ptePG->type) {
        case PG_L4:
#ifdef FreeBSD
          /* 
           * FreeBSD inserts a self mapping into the pml4, therefore it is
           * valid to map in an L4 page into the L4.
           *
           * TODO: Consider the security implications of allowing an L4 to
           *       map an L4.
           */
          SVA_ASSERT(isL3Pg(newPG) || isL4Pg(newPG), 
              "SVA: MMU: Mapping non-L3/L4 page into L4.");
#else
          SVA_ASSERT(isL3Pg(newPG),
              "SVA: MMU: Mapping non-L3 page into L4.");
#endif
          break;
        case PG_L3:
          SVA_ASSERT(isL2Pg(newPG),
              "SVA: MMU: Mapping non-L2 page into L3.");
          break;
        case PG_L2:
          SVA_ASSERT(isL1Pg(newPG),
              "SVA: MMU: Mapping non-L1 page into L2.");
          break;
        /* L1 mappings are always last-level, no case needed.
         * (We couldn't be in this "else" branch if it were true.)
         */

        case PG_EPTL4:
          SVA_ASSERT(isEPTL3Pg(newPG),
              "SVA: MMU: Mapping non-L3 EPT page into EPT L4.");
          break;
        case PG_EPTL3:
          SVA_ASSERT(isEPTL2Pg(newPG),
              "SVA: MMU: Mapping non-L2 EPT page into EPT L3.");
          break;
        case PG_EPTL2:
          SVA_ASSERT(isEPTL1Pg(newPG),
              "SVA: MMU: Mapping non-L1 EPT page into EPT L1.");
          break;
        /* L1 mappings are always last-level, no case needed. */

        default:
          SVA_ASSERT_UNREACHABLE(
              "SVA: MMU: attempted to use a page table update intrinsic on "
              "a page that isn't a PTP!");
          break;
      }
    } /* end else (not editing L1 or large-page PTP) */

    /* Don't allow existing kernel code mappings to be changed/removed. */
    if (origPA != newPA) {
      if (origPG != NULL && isCodePg(origPG)) {
        SVA_ASSERT(isUserMapping(*page_entry),
          "SVA: MMU: Kernel attempted to modify "
          "a kernel-space code page mapping!");
      }
    }

    /*
     * TODO: actually implement the checks described here. This comment has
     * been around for a while but doesn't actually correspond to any code.
     *
     * If the new mapping is set for user access, but the VA being used is to
     * kernel space, fail. Also capture in this check is if the new mapping is
     * set for super user access, but the VA being used is to user space, fail.
     *
     * 3 things to assess for matches: 
     *  - U/S Flag of new mapping
     *  - Type of the new mapping frame
     *  - Type of the PTE frame
     * 
     * Ensures the new mapping U/S flag matches the PT page frame type and the
     * mapped in frame's page type, as well as no mapping kernel code pages
     * into userspace.
     */
  } /* end if (new mapping is present) */

  return retValue;
}

/*
 * Update the metadata for a page that is having a new mapping created to it.
 *
 * The goal is to manage any SVA page data that needs to be set for tracking
 * the new mapping with the existing page data. This is essential to enable the
 * MMU verification checks.
 *
 * @param mapping An x86_64 page table entry describing the new mapping of the
 *                page
 * @param isLeaf  True if the entry is a leaf mapping (L1 entry or PS bit set),
 *                otherwise false
 * @param count   The number of frames mapped by `mapping`
 * @param isEPT   Whether we are updating a mapping in an extended page table
 */
static inline void
updateNewPageData(page_entry_t mapping, bool isLeaf,
                  size_t count, unsigned char isEPT) {
  /*
   * If the new mapping is valid, update the counts for it.
   */
  if (isPresent_maybeEPT(mapping, isEPT)) {
    for (size_t i = 0; i < count; ++i) {
      uintptr_t newPA = (mapping & PG_FRAME) + i * PAGE_SIZE;
      page_desc_t *newPG = getPageDescPtr(newPA);
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

      /*
       * Update the reference count for the new page frame. Check that we aren't
       * overflowing the counter.
       */
      pgRefCountInc(newPG, isLeaf ? isWritable(mapping) : false);
    }
  }

  return;
}

/*
 * Update the metadata for a page that is having its mapping removed.
 *
 * @param mapping An x86_64 page table entry describing the old mapping of the
 *                page
 * @param isLeaf  True if the entry is a leaf mapping (L1 entry or PS bit set),
 *                otherwise false
 * @param count   The number of frames mapped by `mapping`
 * @param isEPT   Whether we are updating a mapping in an extended page table
 */
static inline void
updateOrigPageData(page_entry_t mapping, bool isLeaf,
                   size_t count, unsigned char isEPT) {
  /*
   * Only decrement the reference count if the page has an existing valid
   * mapping.
   */
  if (isPresent_maybeEPT(mapping, isEPT)) {
    for (size_t i = 0; i < count; ++i) {
      uintptr_t origPA = (mapping & PG_FRAME) + i * PAGE_SIZE;
      page_desc_t *origPG = getPageDescPtr(origPA);
      SVA_ASSERT(origPG != NULL,
        "SVA: FATAL: Attempted to create mapping to non-existant frame\n");

      /*
       * Check that the refcount isn't already below 2, which would mean it
       * isn't mapped anywhere besides SVA's direct map. That shouldn't be the
       * case for any present mapping that the OS is allowed to remove with an
       * intrinsic that calls this code. If it is, SVA's frame metadata has
       * somehow become inconsistent.
       */
      SVA_ASSERT(pgRefCount(origPG) >= 2,
        "SVA: MMU: frame metadata inconsistency detected "
        "(attempted to decrement refcount below 1)\n"
        "[updateOrigPageData()] "
        "refcount = %d\n",
        pgRefCount(origPG));

      pgRefCountDec(origPG, isLeaf ? isWritable(mapping) : false);
    }
  }
}

/*
 * Function: __do_mmu_update
 *
 * Description:
 *  This function manages metadata by updating the internal SVA reference
 *  counts for pages and then performs the actual update.
 *
 *  Also works for extended page table (EPT) updates. Whether a regular or
 *  extended page table is being updated is inferred from the SVA frame type
 *  of the PTP being modified.
 *
 * Assumption:
 *  This function should only be called after the update has been validated
 *  to ensure it is safe (e.g. by pt_update_is_valid()). This is the case in
 *  the function's only current caller, __update_mapping().
 *
 * Inputs:
 *  *page_entry  - VA pointer to the page entry being modified
 *  mapping      - The new mapping to insert into page_entry
 */
static inline void
__do_mmu_update (pte_t * pteptr, page_entry_t mapping) {
  /* Is this an extended page table update? */
  uintptr_t ptePaddr = getPhysicalAddr(pteptr);
  page_desc_t *ptePG = getPageDescPtr(ptePaddr);
  bool oldIsLeaf = isLeafEntry(*pteptr, ptePG->type);
  bool newIsLeaf = isLeafEntry(mapping, ptePG->type);
  size_t oldCount = oldIsLeaf ? getMappedSize(ptePG->type) / PAGE_SIZE : 1;
  size_t newCount = newIsLeaf ? getMappedSize(ptePG->type) / PAGE_SIZE : 1;
  unsigned char isEPT = ptePG->type >= PG_EPTL1 && ptePG->type <= PG_EPTL4;

  /*
   * If we have a new mapping as opposed to just changing the flags of an
   * existing mapping, then update the SVA meta data for the pages. We know
   * that we have passed the validation checks so these updates have been
   * vetted.
   */
  updateOrigPageData(*pteptr, oldIsLeaf, oldCount, isEPT);
  updateNewPageData(mapping, newIsLeaf, newCount, isEPT);

  /* Perform the actual write to into the page table entry */
  page_entry_store((page_entry_t *) pteptr, mapping);
  return;
}

void sva_mm_flush_tlb(void* address) {
  invlpg((uintptr_t)address);
}

/*
 * Function: initDeclaredPage
 *
 * Description:
 *  This function zeros out the physical page pointed to by frameAddr and
 *  changes the permissions of the page in the direct map to read-only.
 *  This function is agnostic as to which level page table entry we are
 *  modifying because the format of the entry is the same in all cases. 
 *
 * Assumption: This function should only be called by a declare intrinsic.
 *      Otherwise it has side effects that may break the system.
 *
 * Inputs:
 *  frameAddr: represents the physical address of this frame
 */
void 
initDeclaredPage (unsigned long frameAddr) {
  /*
   * Get the direct map virtual address of the physical address.
   */
  unsigned char * vaddr = getVirtual (frameAddr);

  /*
   * Get a pointer to the page table entry that maps the physical page into the
   * direct map.
   */
  vaddr = getVirtualKernelDMAP(frameAddr);
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

  return;
}

/*
 * Function: __update_mapping
 *
 * Description:
 *  Mapping update function that is agnostic to the level of page table. Most
 *  of the verification code is consistent regardless of which level page
 *  update we are doing. 
 *
 *  Also works for extended page table (EPT) updates. Whether a regular or
 *  extended page table is being updated is inferred from the SVA frame type
 *  of the PTP being modified.
 *
 * Inputs:
 *  - pageEntryPtr : reference to the page table entry to insert the mapping
 *      into
 *  - val : new entry value
 */
void
__update_mapping (pte_t * pageEntryPtr, page_entry_t val) {
  /* 
   * If the given page update is valid then store the new value to the page
   * table entry, else raise an error.
   */
  switch (pt_update_is_valid((page_entry_t *) pageEntryPtr, val)) {
    case 1:
      val = setMappingReadOnly(val);
      __do_mmu_update((page_entry_t *) pageEntryPtr, val);
      break;

    case 2:
      __do_mmu_update((page_entry_t *) pageEntryPtr, val);
      break;

    case 0:
      /* Silently ignore the request */
      return;

    default:
      SVA_ASSERT_UNREACHABLE("##### SVA invalid page update!!!\n");
  }

  return;
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
          if ((cr3 & PG_FRAME) == 0) {
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
      if (isHugePage(*l3e, PG_L3)) {
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
    if (isHugePage(*l2e, PG_L2)) {
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
static unsigned int allocPTPage(page_type_t level) {
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
    memset (p, 0, X86_PAGE_SIZE);

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
    getPageDescPtr(getPhysicalAddr(p))->type = level;

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
  getPageDescPtr(PTPages[ptindex].paddr)->type = PG_FREE;

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
  page_desc_t *pgDesc = getPageDescPtr(paddr);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Attempted to create mapping to non-existant frame\n");
  SVA_ASSERT(pgRefCount(pgDesc) <= 1,
    "SVA: Ghost page still in use somewhere else! "
    "refcount = %d\n", pgRefCount(pgDesc));
  SVA_ASSERT(!isPTP(pgDesc) && !isCodePG(pgDesc),
    "SVA: Ghost page has wrong type! "
    "type = %d\n", pgDesc->type);

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
    ptindex = allocPTPage(PG_SML3);

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t paddr = PTPages[ptindex].paddr;
    *pml4e = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
  }

  /*
   * Enable writing to the virtual address space used for secure memory.
   */
  *pml4e |= PTE_CANUSER;

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
    ptindex = allocPTPage(PG_SML2);

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
    *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

    /*
     * Note that we've added another translation to the pml4e.
     */
    updateUses(pdpte);
  }
  *pdpte |= PTE_CANUSER;

  if (isHugePage(*pdpte, PG_L3)) {
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
    ptindex = allocPTPage(PG_SML1);

    /*
     * Install a new PDE entry.
     */
    uintptr_t pde_paddr = PTPages[ptindex].paddr;
    *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

    /*
     * Note that we've added another translation to the pdpte.
     */
    updateUses(pde);
  }
  *pde |= PTE_CANUSER;

  if (isHugePage(*pde, PG_L2)) {
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
   * Modify the PTE to install the physical to virtual page mapping.
   */
  *pte = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

  /*
   * Note that we've added another translation to the pde.
   */
  updateUses(pte);

  /*
   * Mark the physical page frame as a ghost memory page frame.
   */
  pgDesc->type = PG_GHOST;
 
  /*
   * Increment the refcount for the frame to reflect that it is in use by the
   * ghost mapping we are creating.
   *
   * Check that we don't overflow the counter.
   */
  pgRefCountInc(pgDesc, true);

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

  if (isHugePage(*pdpte, PG_L3)) {
    return 0;
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t* pde = get_pdeVaddr(*pdpte, vaddr);
  if (!isPresent(*pde)) {
    return 0;
  }

  if (isHugePage(*pde, PG_L2)) {
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
   *
   * Check that the refcount is at least two (i.e., the frame is mapped
   * somewhere other than SVA's DMAP). If not, something has gone wrong
   * (either SVA's frame metadata has become inconsistent, or the caller has
   * improperly used this function to remove an entry in SVA's DMAP).
   */
  page_desc_t *pageDesc = getPageDescPtr(*pte & PG_FRAME);
  SVA_ASSERT(pgRefCount(pageDesc) >= 2,
    "SVA: MMU: frame metadata inconsistency detected "
    "(attempted to remove ghost mapping with refcount < 2). "
    "refcount = %d\n", pgRefCount(pageDesc));
  pgRefCountDec(pageDesc, isWritable(*pte));

  /*
   * If we have removed the last ghost mapping to this frame, mark its type
   * as regular internal SVA memory so it can be safely returned to the frame
   * cache.
   *
   * This is what the frame's type was when we first obtained it from the
   * frame cache (assuming that the preconditions on free_frame() have always
   * been upheld). Now that we are done using it as ghost memory, we return
   * it to this type.
   */
  if (pgRefCount(pageDesc) == 1) {
    /* count == 1 means mapped only in SVA's DMAP */
    pageDesc->type = PG_SVA;
  }

  /*
   * Modify the PTE so that the page is not present.
   */
#ifndef SVA_DMAP
  unprotect_paging();
#endif
  paddr = *pte & PG_FRAME;
  *pte = 0;

  /*
   * Invalidate any TLBs in the processor.
   */
  sva_mm_flush_tlb(v);

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
  ptindex = allocPTPage(PG_SML3);
  /*
   * Install a new PDPTE entry using the page.
   */
  uintptr_t paddr = PTPages[ptindex].paddr;
  pml4e_val = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

  /*
   * Enable writing to the virtual address space used for secure memory.
   */
  pml4e_val |= PTE_CANUSER;

  newThread->secmemPML4e = pml4e_val;

  pdpte_t* src_pdpte = (pdpte_t *)get_pdpteVaddr(oldThread->secmemPML4e, vaddr_start);
  pdpte_t* pdpte = get_pdpteVaddr(pml4e_val, vaddr_start);

  for (uintptr_t vaddr_pdp = vaddr_start;
      vaddr_pdp < vaddr_end;
      vaddr_pdp += NBPDP, src_pdpte++, pdpte++) {

    if (!isPresent(*src_pdpte))
      continue;
    if (!isPresent(*pdpte)) {
      /* Page table page index */
      unsigned int ptindex;

      /* Fetch a new page table page */
      ptindex = allocPTPage(PG_SML2);

      /*
       * Install a new PDPTE entry using the page.
       */
      uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
      *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
    }
    *pdpte |= PTE_CANUSER;

    /*
     * Note that we've added another translation to the pml4e.
     */
    updateUses(pdpte);

    if (isHugePage(*pdpte, PG_L3)) {
      printf("ghostmemCOW: PDPTE has PS BIT\n");
    }

    pde_t* src_pde = get_pdeVaddr(*src_pdpte, vaddr_pdp);
    pde_t* pde = get_pdeVaddr(*pdpte, vaddr_pdp);
    for (uintptr_t vaddr_pde = vaddr_pdp;
        vaddr_pde < vaddr_pdp + NBPDP;
        vaddr_pde += NBPDR, src_pde++, pde++) {

      /*
       * Get the PDE entry (or add it if it is not present).
       */
      if (!isPresent(*src_pde))
        continue;

      if (!isPresent(*pde)) {
        /* Page table page index */
        unsigned int ptindex;

        /* Fetch a new page table page */
        ptindex = allocPTPage(PG_SML1);

        /*
         * Install a new PDE entry.
         */
        uintptr_t pde_paddr = PTPages[ptindex].paddr;
        *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
      }
      *pde |= PTE_CANUSER;

      /*
       * Note that we've added another translation to the pdpte.
       */
      updateUses(pde);

      if (isHugePage(*pde, PG_L2)) {
        printf("ghostmemCOW: PDE has PS BIT\n");
      }

      pte_t* src_pte = get_pteVaddr(*src_pde, vaddr_pde);
      pte_t* pte = get_pteVaddr(*pde, vaddr_pde);
      for (uintptr_t vaddr_pte = vaddr_pde;
          vaddr_pte < vaddr_pde + NBPDR;
          vaddr_pte += PAGE_SIZE, src_pte++, pte++) {

        if (!isPresent(*src_pte))
          continue;

        page_desc_t *pgDesc = getPageDescPtr(*src_pte & PG_FRAME);

        SVA_ASSERT(pgDesc->type == PG_GHOST,
          "SVA: ghostmemCOW: page is not a ghost memory page!\n"
          "vaddr = 0x%lx, src_pte = %p, *src_pte = 0x%lx, "
          "src_pde = %p, *src_pde = 0x%lx\n",
          vaddr_pte, src_pte, *src_pte, src_pde, *src_pde);

        *src_pte &= ~PTE_CANWRITE;
        *pte = *src_pte;
        updateUses(pte);
        /*
         * We are taking a writable page, and making a new mapping to it while
         * making both mappings unwritable, so we need to decrement the writable
         * reference count and increment the total reference count.
         */
        pgRefCountDecWr(pgDesc);
        pgRefCountInc(pgDesc, false);
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
   * Ensure there are no extraneous bits set in the page table pointer
   * (which would be interpreted as flags in CR3). Masking with PG_FRAME will
   * leave us with just the 4 kB-aligned physical address.
   *
   * (These bits aren't *supposed* to be set by the caller, but we can't
   * trust the system software to be honest.)
   */
  uintptr_t new_pml4 = pg_ptr & PG_FRAME;

  /*
   * Check that the new page table is an L4 page table page.
   */
  if ((mmuIsInitialized) && (!disableMMUChecks)) {
    page_desc_t* pml4Desc = getPageDescPtr(new_pml4);
    SVA_ASSERT(pml4Desc != NULL,
      "SVA: FATAL: Using non-existant frame as root page table\n");
    SVA_ASSERT(pml4Desc->type == PG_L4,
      "SVA: Loading non-L4 page into CR3: %lx %x\n",
      new_pml4, getPageDescPtr(new_pml4)->type);
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
    pml4e_t *secmemp =
      (pml4e_t *) getVirtualSVADMAP(new_pml4 + secmemOffset);

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
  page_desc_t *newpml4Desc = getPageDescPtr(new_pml4);
  page_desc_t *oldpml4Desc = getPageDescPtr(read_cr3());

  SVA_ASSERT(newpml4Desc != NULL,
    "SVA: FATAL: Using non-existant frame as root page table\n");
  pgRefCountInc(newpml4Desc, false);

  /*
   * Check that the refcount isn't already below 2, which would mean that it
   * isn't mapped anywhere besides SVA's direct map. That shouldn't be the
   * case for a PML4 that was (until now) in use by CR3. If it is, SVA's
   * frame metadata has somehow become inconsistent.
   */
  SVA_ASSERT(pgRefCount(oldpml4Desc) >= 2,
    "SVA: MMU: frame metadata inconsistency detected "
    "(attempted to decrement refcount below 1)\n"
    "[old CR3 being replaced] "
    "refcount = %d\n", pgRefCount(oldpml4Desc));
  pgRefCountDec(oldpml4Desc, false);

#ifdef SVA_ASID_PG
  /*
   * Also do this for the respective kernel versions of the PML4s (if they
   * exist).
   */
  if (newpml4Desc->other_pgPaddr) {
    page_desc_t *kernel_newpml4Desc =
      getPageDescPtr(newpml4Desc->other_pgPaddr);

    pgRefCountInc(kernel_newpml4Desc, false);
  }

  if (oldpml4Desc->other_pgPaddr) {
    page_desc_t *kernel_oldpml4Desc =
      getPageDescPtr(oldpml4Desc->other_pgPaddr);

    SVA_ASSERT(pgRefCount(oldpml4Desc) >= 2,
      "SVA: MMU: frame metadata inconsistency detected "
      "(attempted to decrement refcount below 1)\n"
      "[old kernel PML4 being replaced] "
      "refcount = %d\n", pgRefCount(oldpml4Desc));
    pgRefCountDec(kernel_oldpml4Desc, false);
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
    page_desc_t *pml4Desc = getPageDescPtr(old_cr3);
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
    page_desc_t *pml4Desc = getPageDescPtr(old_cr3);
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

/**
 * Validate that a leaf mapping is safe.
 *
 * @param entry   The leaf entry
 * @param frames  The number of frames mapped by `entry`
 */
static void validate_existing_leaf(page_entry_t entry, size_t frames) {
  for (size_t i = 0; i < frames; ++i) {
    uintptr_t frame = (entry & PG_FRAME) + i * PAGE_SIZE;
    page_desc_t* pgDesc = getPageDescPtr(frame);
    SVA_ASSERT(pgDesc != NULL,
      "SVA: FATAL: New page table contains mapping to non-existant "
      "frame 0x%lx\n", frame / PAGE_SIZE);

    if (pgDesc->type == PG_FREE && isWritable(entry)) {
      pgDesc->type = PG_DATA;
    }
    SVA_ASSERT(mappingIsSafe(entry, pgDesc->type),
      "SVA: FATAL: New page table contains unsafe mapping to frame 0x%lx "
      "with type %d (entry is 0x%016lx)\n",
      frame, pgDesc->type, entry);
    pgRefCountInc(pgDesc, isWritable(entry));
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
static void validate_existing_entries(uintptr_t frame, enum page_type_t level) {
  page_entry_t* entries = (page_entry_t*)getVirtual(frame);

  for (size_t i = 0; i < PG_ENTRIES; ++i) {
    if (isPresent(entries[i])) {
      if (isLeafEntry(entries[i], level)) {
        validate_existing_leaf(entries[i], getMappedSize(level) / PAGE_SIZE);
      } else {
        uintptr_t entryFrame = entries[i] & PG_FRAME;
        page_desc_t* pgDesc = getPageDescPtr(entryFrame);
        SVA_ASSERT(pgDesc != NULL,
          "SVA: FATAL: New L%d table at 0x%lx contains mapping to non-existant "
          "frame 0x%lx\n",
          getIntLevel(level), frame / PAGE_SIZE, entryFrame / PAGE_SIZE);

        if (pgDesc->type != getSublevelType(level)) {
          SVA_ASSERT_UNREACHABLE(
            "SVA: FATAL: Recursive page validation not yet supported\n");
        }
        pgRefCountInc(pgDesc, false);
      }
    }
  }
}

/**
 * Mark the specified frame as a page table.
 *
 * Validates than any existing entries are safe, and will also remove write
 * access to the page from the kernel's direct map.
 *
 * @param frame The physical address of the frame that will become a page table
 * @param level The level of page table that `frame` will become
 */
void sva_declare_page(uintptr_t frame, enum page_type_t level) {
  if (!mmuIsInitialized) {
    return;
  }

  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared page table */
  page_desc_t *pgDesc = getPageDescPtr(frame);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame %lx as L%d page table\n",
    frame / PAGE_SIZE, getIntLevel(level));

  /*
   * Make sure that this frame is free.
   */
  SVA_ASSERT(pgDesc->type == PG_FREE,
    "SVA: FATAL: Declaring L%d page table for frame %lx with invalid type %d\n",
    getIntLevel(level), frame / PAGE_SIZE, pgDesc->type);

#ifdef SVA_DMAP
  /*
   * A page can only be declared as a page table page if its writable reference
   * count is 2 or less.
   */
  SVA_ASSERT(pgRefCountWr(pgDesc) <= 2,
    "SVA: FATAL: Cannot declare L%d page: "
    "There are still %u writable mappings to frame 0x%ld!\n",
    getIntLevel(level), pgRefCountWr(pgDesc), frame / PAGE_SIZE);
#else
#if 0
  /* A page can only be declared as a page table page if its reference count is 0 or 1.*/
  SVA_ASSERT((pgRefCount(pgDesc) <= 1),
    "sva_declare_page: more than one virtual addresses "
    "are still using this page!");
#endif
#endif

  /*
   * Mark this page frame as a page table.
   */
  pgDesc->type = level;

#if 0
  /*
   * Reset the virtual address which can point to this page table page.
   */
  pgDesc->pgVaddr = 0;
#endif

  /*
   * Initialize the page data and page entry. Note that we pass a general
   * page_entry_t to the function as it enables reuse of code for each of the
   * entry declaration functions.
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

  sva_declare_page(frame, PG_L1);

  record_tsc(sva_declare_l1_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_declare_l2_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PG_L2);

  record_tsc(sva_declare_l2_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_declare_l3_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PG_L3);

  record_tsc(sva_declare_l3_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_declare_l4_page(uintptr_t frame) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_declare_page(frame, PG_L4);

  record_tsc(sva_declare_l4_page_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

static inline page_entry_t * 
printPTES (uintptr_t vaddr) {
  /* Pointer to the page table entry for the virtual address */
  page_entry_t *pge = 0;

  /* Get the base of the pml4 to traverse */
  cr3_t cr3 = get_root_pagetable();
  if ((cr3 & PG_FRAME) == 0)
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
      if (isHugePage(*pdpte, PG_L3)) {
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
          if (isHugePage(*pde, PG_L2)) {
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

  /*
   * Get the last-level page table entry in the kernel's direct map that
   * references this PTP.
   */
  page_entry_t *pte_kdmap =
    get_pgeVaddr((uintptr_t)getVirtualKernelDMAP(paddr));

  /* Get the descriptor for the physical frame where this PTP resides. */
  page_desc_t *pgDesc = getPageDescPtr(paddr);
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
    case PG_L1:
    case PG_L2:
    case PG_L3:
    case PG_L4:
      isEPT = 0;
      break;

    case PG_EPTL1:
    case PG_EPTL2:
    case PG_EPTL3:
    case PG_EPTL4:
      isEPT = 1;
      break;

    default:
      SVA_ASSERT_UNREACHABLE(
        "SVA: undeclare bad page type: %lx %x\n", paddr, pgDesc->type);
#if 0
      /* Restore interrupts and return to kernel page tables */
      sva_exit_critical(rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_remove_page_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return;
#endif
  }

  /*
   * Check that there are no references to this page (i.e., there is no page
   * table entry that refers to this physical page frame).  If there is a
   * mapping, then someone is still using it as a page table page.  In that
   * case, raise an error.
   *
   * Note that we check for a reference count of 2 because all pages are
   * always mapped into SVA's direct map, and PTPs in particular remain
   * mapped in the kernel's direct map (albeit read-only, which we'll be
   * un-setting below).
   */
  if (pgRefCount(pgDesc) >= 2) {
#ifdef XEN
    /*
     * Xen PV guests have read-only mappings of page tables, which raises their
     * reference count above 2. Ignore the error until we set up proper per-type
     * reference counts.
     */
#if 0
    printf("SVA: WARNING: undeclare page with outstanding references: "
        "type=%d count=%d\n", pgDesc->type, pgRefCount(pgDesc));
    printf("SVA: This should be fatal, but is allowed as a hack to support "
           "PV guests.\n");
#endif
#else
    SVA_ASSERT_UNREACHABLE(
      "SVA: FATAL: undeclare page with outstanding references: "
      "type=%d count=%d\n", pgDesc->type, pgRefCount(pgDesc));
#endif
  }

  /*
   * If any valid mappings remain within the PTP, explicitly remove them to
   * ensure consistency of SVA's page metadata.
   *
   * (Note: NPTEPG = # of entries in a PTP. We assume this is the same at
   * all levels of the paging hierarchy.)
   */
  page_entry_t *ptp_vaddr = (page_entry_t *) getVirtualSVADMAP(paddr);
  for (unsigned long i = 0; i < NPTEPG; i++) {
    if (isPresent_maybeEPT(ptp_vaddr[i], isEPT)) {
      /* Remove the mapping */
      page_desc_t *mappedPg = getPageDescPtr(ptp_vaddr[i]);
      if (isGhostPTP(mappedPg)) {
        /*
         * The method of removal for ghost PTP mappings is slightly
         * different than for ordinary mappings created by the OS (SVA has
         * a separate refcount system to keep track of them).
         */
        unsigned int ptindex = releaseUse(&ptp_vaddr[i]);
        freePTPage(ptindex);
        ptp_vaddr[i] = 0;
      } else {
        bool isLeaf = isLeafEntry(ptp_vaddr[i], pgDesc->type);
        size_t count = isLeaf ? getMappedSize(pgDesc->type) / PAGE_SIZE : 1;
        /*
         * NB: We don't want to actually change the data in the page table, as
         * the kernel may be relying on being able to access it for its own
         * bookkeeping.  Instead, just update our metadata to reflect that the
         * reference has been dropped.  Since this page is about to become a
         * data page, there is no safety concern with leaving the entry intact.
         */
        updateOrigPageData(ptp_vaddr[i], isLeaf, count, isEPT);
      }
    }
  }

  /* Mark the page frame as an unused page. */
  pgDesc->type = PG_FREE;

  /*
   * Make the page writeable again in the kernel's direct map. Be sure to
   * flush entries pointing to it in the TLBs so that the change takes
   * effect right away.
   */
  __do_mmu_update(pte_kdmap, setMappingReadWrite(*pte_kdmap));
  sva_mm_flush_tlb(getVirtualKernelDMAP(paddr));

#ifdef SVA_ASID_PG
  /*
   * If the PTP being undeclared is a level-4 PTP (non-EPT), undeclare the
   * kernel's copy of it in addition to the SVA/userspace copy.
   *
   * (It doesn't matter which one of the two copies we were given as the
   * parameter to this intrinsic - whichever one we were given, we'll
   * undeclare the other one here.)
   */
  if (pgDesc->type == PG_L4) {
    uintptr_t other_cr3 = pgDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;

    /*
     * Only proceed if there actually *is* an alternate PML4 associated
     * with this one. In general the kernel will set these up together but
     * SVA doesn't *force* it to do so. (In particular, the alternate PML4
     * may not exist for the initial set of page tables loaded during
     * boot.)
     */
    if (other_cr3) {
      page_desc_t *other_pgDesc = getPageDescPtr(other_cr3);
      SVA_ASSERT(pgRefCount(other_pgDesc) <= 2,
          "the kernel version pml4 page table page "
          "still has reference.\n" );

      /*
       * If any valid mappings remain within the PTP, explicitly remove
       * them to ensure consistency of SVA's page metadata.
       */
      page_entry_t *other_pml4_vaddr =
        (page_entry_t *) getVirtualSVADMAP(other_cr3);
      for (int i = 0; i < NPTEPG; i++) {
        if (isPresent_maybeEPT(other_pml4_vaddr[i], isEPT)) {
          /* Remove the mapping */
          __update_mapping(&other_pml4_vaddr[i], ZERO_MAPPING);
        }
      }

      /* Mark the page frame as an unused page. */
      other_pgDesc->type = PG_FREE;

      /*
       * Make the page writable again in the kernel's direct map. Be sure
       * to flush entries pointing to it in the TLBs so that the change
       * takes effect right away.
       */
      page_entry_t* other_pte =
        get_pgeVaddr((uintptr_t)getVirtualKernelDMAP(other_cr3));
      __do_mmu_update(other_pte, setMappingReadWrite(*other_pte));
      sva_mm_flush_tlb(getVirtual(other_cr3));

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
	page_desc_t *pgDesc = getPageDescPtr(paddr);
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
 *  are handled in the __update_mapping function.
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
  __update_mapping(pteptr, ZERO_MAPPING);

#ifdef SVA_ASID_PG
  /*
   * If we are removing a mapping in a level-4 page table (non-EPT), remove
   * it in the kernel's copy of the PML4 in addition to the SVA/userspace
   * copy.
   */
  uintptr_t ptePA = getPhysicalAddr(pteptr);
  page_desc_t *ptePG = getPageDescPtr(ptePA);
  SVA_ASSERT(ptePG != NULL,
    "SVA: FATAL: Page table frame doesn't exist\n");

  if(ptePG->type == PG_L4) {
    uintptr_t other_cr3 = ptePG->other_pgPaddr & ~PML4_SWITCH_DISABLE;

    if(other_cr3) {
      page_entry_t * other_pteptr = (page_entry_t *)
        ((unsigned long) getVirtual(other_cr3)
         | ((unsigned long) pteptr & vmask));

      __update_mapping(other_pteptr, ZERO_MAPPING);
    }
  }
#endif

  /* Restore interrupts and return to kernel page tables */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_remove_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}


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
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr(pteptr));
  SVA_ASSERT(ptDesc != NULL,
    "SVA: FATAL: Page table frame doesn't exist\n");
  SVA_ASSERT(disableMMUChecks || ptDesc->type == PG_L1,
    "SVA: MMU: update_l1 not an L1: %p %lx: %x\n", pteptr, val, ptDesc->type);

  /*
   * Update the page table with the new mapping.
   */
  __update_mapping(pteptr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

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
                        enum page_type_t level)
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
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr(getPhysicalAddr(pte));
  SVA_ASSERT(ptDesc != NULL,
    "SVA: FATAL: L%d page table frame doesn't exist\n", getIntLevel(level));
  SVA_ASSERT(disableMMUChecks || ptDesc->type == level,
    "SVA: MMU: update_l%d bad type: %p %lx: %x\n",
    level, pte, new_pte, ptDesc->type);

  /*
   * Update the page table with the new mapping.
   */
  __update_mapping(pte, new_pte);

  /* Restore interrupts */
  sva_exit_critical(rflags);

  usersva_to_kernel_pcid();
}

void sva_update_l1_mapping(pte_t* l1e, pte_t new_l1e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_update_mapping(l1e, new_l1e, PG_L1);

  record_tsc(sva_update_l1_mapping_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_update_l2_mapping(pde_t* l2e, pde_t new_l2e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_update_mapping(l2e, new_l2e, PG_L2);

  record_tsc(sva_update_l2_mapping_api, (uint64_t)sva_read_tsc() - tsc_tmp);
}

void sva_update_l3_mapping(pdpte_t* l3e, pdpte_t new_l3e) {
  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  sva_update_mapping(l3e, new_l3e, PG_L3);

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

  sva_update_mapping(l4e, new_l4e, PG_L4);

#ifdef SVA_ASID_PG 
  uintptr_t other_cr3 = ptDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
  if (other_cr3) {
    uintptr_t index = (uintptr_t)l4e & vmask;
    pml4e_t* kernel_pml4ePtr =
      (pml4e_t*)((uintptr_t)getVirtual(other_cr3) | index);
    page_desc_t* kernel_ptDesc = getPageDescPtr(other_cr3);
    SVA_ASSERT(disableMMUChecks || kernel_ptDesc->type == PG_L4,
      "SVA: MMU: update_l4 kernel or sva version pte not an L4: %lx %lx: %x\n",
      kernel_pml4ePtr, new_l4e, kernel_ptDesc->type);

    if (((index >> 3) == PML4PML4I) &&
        ((new_l4e & PG_FRAME) == (getPhysicalAddr(l4e) & PG_FRAME)))
    {
        new_l4e = other_cr3 | (new_l4e & 0xfff);
    }
    __update_mapping(kernel_pml4ePtr, new_l4e);
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

  page_desc_t* pgDesc = getPageDescPtr(*leaf_entry & PG_FRAME);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Page table entry maps invalid frame\n");
  SVA_ASSERT(pgDesc->type = PG_CODE,
    "SVA: FATAL: Changing permissons on non-code page 0x%016lx\n", vaddr);

  *leaf_entry &= ~(PG_V | PG_RW | PG_NX) | perms;
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

  protect_code_page((uintptr_t)vaddr, PG_V | PG_RW | PG_NX);

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

  protect_code_page((uintptr_t)vaddr, PG_V);

  usersva_to_kernel_pcid();
  sva_exit_critical(flags);

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

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
  orig_phys &= PG_FRAME;
  kernel_phys &= PG_FRAME;

  page_desc_t *kernel_ptDesc = getPageDescPtr(kernel_phys);
  SVA_ASSERT(kernel_ptDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame as a root page table\n");
  page_desc_t *usersva_ptDesc = getPageDescPtr(orig_phys);
  SVA_ASSERT(usersva_ptDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame as a root page table\n");

  /*
   * Ensure that the new kernel PML4 page has been declared to SVA as an L4
   * PTP frame.
   */
  SVA_ASSERT(kernel_ptDesc->type == PG_L4,
    "SVA: MMU: attempted to use a page as a kernel PML4 that wasn't "
    "declared to SVA as an L4 PTP frame!\n"
    "paddr = 0x%lx\n; type = %d\n", kernel_phys, kernel_ptDesc->type);

  /*
   * Ensure that the original PML4 page (i.e. the user/SVA version PML4) that
   * the new kernel PML4 is being attached to really is itself a PML4.
   */
  SVA_ASSERT(usersva_ptDesc->type == PG_L4,
    "SVA: MMU: attempted to set up a kernel version of a PML4 that "
    "isn't actually a PML4!\n"
    "Fake original page paddr = 0x%lx, "
    "type = %d; Kernel PML4 paddr = 0x%lx\n",
    orig_phys, usersva_ptDesc->type, kernel_phys);

#ifdef SVA_ASID_PG
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
#endif /* SVA_ASID_PG */

  /*
   * If (and only if) the PML4 being bifurcated is the one currently loaded
   * in CR3, increment the refcount of the new kernel PML4 to keep it
   * consistent with the user/SVA one (whose refcount was incremented when it
   * was loaded).
   */
  if (orig_phys == (read_cr3() & PG_FRAME)) {
    pgRefCountInc(kernel_ptDesc, false);
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

uintptr_t sva_get_physical_address(uintptr_t vaddr) {
  return getPhysicalAddr((void*)vaddr);
}

pte_t* sva_get_l1_entry(uintptr_t vaddr) {
  pde_t* pde = sva_get_l2_entry(vaddr);
  if (pde != NULL && isPresent(*pde) && !isHugePage(*pde, PG_L2)) {
    return get_pteVaddr(*pde, vaddr);
  } else {
    return NULL;
  }
}

pde_t* sva_get_l2_entry(uintptr_t vaddr) {
  pdpte_t* pdpte = sva_get_l3_entry(vaddr);
  if (pdpte != NULL && isPresent(*pdpte) && !isHugePage(*pdpte, PG_L3)) {
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
  page_desc_t *usersva_ptDesc = getPageDescPtr(orig_phys);
  SVA_ASSERT(usersva_ptDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame as a root page table\n");
  usersva_ptDesc->other_pgPaddr =
    usersva_ptDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}
#endif /* SVA_ASID_PG */
