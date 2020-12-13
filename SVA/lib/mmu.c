/*===- mmu.c - SVA Execution Engine  =---------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * Note: We try to use the term "frame" to refer to a page of physical memory
 *       and a "page" to refer to the virtual addresses mapped to the page of
 *       physical memory.
 *
 *===------------------------------------------------------------------------===
 */

#include <string.h>

#include "icat.h"

#include <sva/apic.h>
#include <sva/types.h>
#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/init.h>
#include <sva/mmu.h>
#include <sva/mmu_intrinsics.h>
#include <sva/x86.h>
#include <sva/self_profile.h>
#include <sva/state.h>
#include <sva/util.h>

unsigned int __svadata invtlb_cpus_acked = 0;

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

page_entry_t page_entry_store(page_entry_t* page_entry, page_entry_t newVal) {
  SVA_PROF_ENTER();

#ifdef SVA_DMAP
  page_entry = (page_entry_t*)__va(__pa(page_entry));
#endif

  /* Disable page protection so we can write to the referencing table entry */
  unprotect_paging();

  /* Write the new value to the page_entry */
  page_entry_t oldVal =
    __atomic_exchange_n(page_entry, newVal, __ATOMIC_ACQ_REL);

  /* Reenable page protection */
  protect_paging();

  SVA_PROF_EXIT(page_entry_store);
  return oldVal;
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

  /* Get the page table page descriptor. */
  frame_desc_t *ptePG = get_frame_desc(__pa(page_entry));

  /*
   * If MMU checks are disabled, allow the page table entry to be modified.
   */
  if (disableMMUChecks) {
    return true;
  }

  /*
   * Verify that we're not trying to modify the PML4 entry that controls the
   * secure memory virtual address space.
   */
  size_t entryIdx =
    ((uintptr_t)page_entry & (FRAME_SIZE - 1)) / sizeof(*page_entry);
  if (frame_get_type(ptePG) == PGT_L4 && isSecMemL4Entry(entryIdx)) {
    return false;
  }

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
  if (origPG != NULL && frame_get_type(origPG) == PGT_CODE &&
      !isUserMapping(*page_entry))
  {
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

      if (type == PGT_DATA && frame_get_type(newPG) == PGT_FREE) {
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

/**
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

      struct refcount_pair counts = frame_drop(origPG, type);
      if (type == PGT_DATA && counts.type_count == 1) {
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
  frame_desc_t* ptePG = get_frame_desc(__pa(pte));

  frame_type_t pt_type = frame_get_type(ptePG);
  bool newIsLeaf = isLeafEntry(new_pte, pt_type);
  size_t newCount = newIsLeaf ? getMappedSize(pt_type) / FRAME_SIZE : 1;
  frame_type_t newType = frame_type_from_pte(new_pte, pt_type);

  /*
   * If we have a new mapping as opposed to just changing the flags of an
   * existing mapping, then update the SVA meta data for the pages. We know
   * that we have passed the validation checks so these updates have been
   * vetted.
   */
  updateNewPageData(new_pte, newType, newCount);

  /* Perform the actual write to into the page table entry. */
  page_entry_t orig_pte = page_entry_store(pte, new_pte);

  bool oldIsLeaf = isLeafEntry(orig_pte, pt_type);
  size_t oldCount = oldIsLeaf ? getMappedSize(pt_type) / FRAME_SIZE : 1;
  frame_type_t oldType = frame_type_from_pte(orig_pte, pt_type);

  updateOrigPageData(orig_pte, oldType, oldCount);
}

void update_mapping(page_entry_t* pte, page_entry_t new_pte) {
  SVA_ASSERT(pte_can_change(pte),
    "SVA: FATAL: Bad update attempt for PTE at %p: 0x%016lx -> 0x%016lx\n",
    pte, *pte, new_pte);
  do_mmu_update(pte, new_pte);
}

void sva_mm_flush_tlb_at(const void* address) {
  invlpg((uintptr_t)address);
}

void sva_mm_flush_tlb(void) {
    /*
     * Reload `%cr3` with its current value. According to ISDM V3 S4.10.4.1,
     * this will invalidate all non-global TLB entries for the current PCID.
     */
    write_cr3(read_cr3());
}

void sva_mm_flush_tlb_global(void) {
    /*
     * Flip the "page global enable" flag in `%cr4`. According to ISDM V3
     * S4.10.4.1, this will invalidate all entries in the TLB.
     */
    uint64_t cr4 = read_cr4();
    write_cr4(cr4 ^ CR4_PGE);
    write_cr4(cr4);
}

void invtlb_global(void) {
  unsigned int expected_count = 0;

  invtlb_everything();

  /*
   * Because of some TSC calibration logic in Xen, we can hang if we wait for
   * rendezvous with interrupts disabled.
   *
   * TODO: Don't disable interrupts for most MMU intrinsics.
   */
  unsigned long rflags = sva_save_in_critical();
  sva_exit_critical(-1); /* Enable interrupts */

  while (!__atomic_compare_exchange_n(
            &invtlb_cpus_acked, &expected_count, 1, false,
            __ATOMIC_RELAXED, __ATOMIC_RELAXED))
  {
    /*
     * Another CPU is currently waiting on a rendezvous.
     */

    expected_count = 0;

    /*
     * Wait for other CPUs to rendezvous.
     */
    while (__atomic_load_n(&invtlb_cpus_acked, __ATOMIC_RELAXED) > 0) {
      pause();
    }
  }

#if 0
  printk("SVA: CPU %u initiating TLB flush rendezvous\n",
         (unsigned int)rdmsr(MSR_X2APIC_ID));
#endif

  apic_send_ipi(MAKE_IPI_BROADCAST(TLB_FLUSH_VECTOR));

  /*
   * Wait for other CPUs to rendezvous.
   */
  while (__atomic_load_n(&invtlb_cpus_acked, __ATOMIC_RELAXED)
          < cpu_online_count)
  {
    pause();
  }

  __atomic_store_n(&invtlb_cpus_acked, 0, __ATOMIC_RELAXED);

  /*
   * Synchronizes with the store-release in the IPI handler.
   *
   * See `lib/interrupt.c:tlb_flush`.
   */
  __atomic_thread_fence(__ATOMIC_ACQUIRE);

  if (!(rflags & 0x200)) {
    sva_enter_critical();
  }
}

void initDeclaredPage(uintptr_t frame) {
  /*
   * Currently, we don't actually do anything with the frame itself. The
   * parameter is vestigial.
   */
  (void)frame;

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
   *    DMAP (which SVA has verified is read-only).
   *
   *  - In get_frame_from_os() (secmem.c), when we need to ensure that a
   *    frame the OS gave us for use as secure/ghost memory isn't accessible
   *    at all to the OS.
   */
  invtlb_global();
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

/**
 * Find the corresponding physical address for a virtual address which must be
 * in the kernel's direct map.
 *
 * @param v A virtual address in the kernel's direct map
 * @return  The physical address to which `v` maps
 */
static inline paddr_t getPhysicalAddrKDMAP(uintptr_t v) {
  return v & ~KERNDMAPSTART;
}

/**
 * Find the corresponding physical address for a virtual address which must be
 * in SVA's direct map.
 *
 * @param v A virtual address in SVA's direct map
 * @return  The physical address to which `v` maps
 */
static inline paddr_t getPhysicalAddrSVADMAP(uintptr_t v) {
  return v & ~SVADMAPSTART;
}

bool getPhysicalAddrFromPML4E(void* v, pml4e_t* pml4e, uintptr_t* paddr) {
  /* Virtual address to convert */
  uintptr_t vaddr = (uintptr_t)v;

  return walk_page_table((cr3_t)0, vaddr, &pml4e, NULL, NULL, NULL, paddr) > 0;
}

paddr_t getPhysicalAddr(uintptr_t vaddr) {
  /* Physical address */
  uintptr_t paddr;

  /*
   * We don't verify that the kernel isn't changing mappings in its direct map
   * if SVA is using its own direct map, so we can't trust that kernel direct
   * map virtual addresses are actually what we expect them to be.
   */
  if (!sva_dmap && vaddr >= KERNDMAPSTART && vaddr < KERNDMAPEND) {
      /*
       * If the pointer is within the kernel's direct map, use a simple
       * bit-masking operation to convert the virtual address to a physical
       * address.
       */
       return getPhysicalAddrKDMAP(vaddr);
  }

  /*
   * If the virtual address falls within the SVA VM's direct map, use a simple
   * bit-masking operation to find the physical address.
   */
  if (sva_dmap && vaddr >= SVADMAPSTART && vaddr <= SVADMAPEND) {
       return getPhysicalAddrSVADMAP(vaddr);
  }

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

/**
 * Allocate and initialize a frame for use as a secure memory page table.
 *
 * @param level The level of page table to allocate
 * @return      The index in `PTPages` of the allocated page table
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
    frame_morph(get_frame_desc(__pa(p)), level);

    /*
     * Return the index in the table.
     */
    return ptindex;
  }

  return 0;
}

/**
 * Free a page table frame allocated with `allocPTPage`.
 *
 * @param ptindex The index in `PTPages` of the frame to be freed
 */
void freePTPage(unsigned int ptindex) {
  /*
   * Mark the entry in the page table page array as available.
   */
  PTPages[ptindex].valid = 0;

  /*
   * Change the type of the page table page.
   */
  frame_morph(get_frame_desc(PTPages[ptindex].paddr), PGT_FREE);
}

/**
 * Increment the number of uses of a secure memory page table.
 *
 * @param ptp A page table which is used to map secure memory
 */
static void updateUses(uintptr_t* ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = PG_ENTRY_FRAME(__pa(ptp));

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, increment the number of uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      ++PTPages[ptindex].uses;
    }
  }
}

/**
 * Decrement the number of uses of a secure memory page table.
 *
 * The return value indicates whether or not the page table should be freed
 * (via `freePTPage`).
 *
 * @param ptp A page table which is used to map secure memory
 * @return    If the frame should not be freed: 0.
 *            If the frame should be freed: The index of the frame in `PTPages`
 */
static unsigned int releaseUse(uintptr_t* ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = PG_ENTRY_FRAME(__pa(ptp));

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

uintptr_t mapSecurePage(uintptr_t vaddr, uintptr_t paddr) {
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
  unprotect_paging();

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
  protect_paging();

  return pml4eVal;
}

uintptr_t unmapSecurePage(struct SVAThread* threadp, uintptr_t vaddr) {
  /*
   * TODO:
   *  Implement code that will tell other processors to invalidate their TLB
   *  entries for this page.
   */

  /*
   * Get the PML4E of the page table associated with the specified thread.
   */
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
  unprotect_paging();
  paddr = PG_L1_FRAME(*pte);
  *pte = ZERO_MAPPING;

  /*
   * Invalidate any TLBs in the processor.
   */
  sva_mm_flush_tlb_at((const void*)vaddr);

  struct refcount_pair counts = frame_drop(pageDesc, PGT_GHOST);

  /*
   * If we have removed the last ghost mapping to this frame, mark the frame as
   * free.
   */
  if (counts.type_count == 1) {
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
    *pde = ZERO_MAPPING;
    if ((ptindex = releaseUse(pde))) {
      freePTPage(ptindex);
      *pdpte = ZERO_MAPPING;
      if ((ptindex = releaseUse(pdpte))) {
        freePTPage(ptindex);
        threadp->secmemPML4e = ZERO_MAPPING;
#if 0
        if ((ptindex = releaseUse(getVirtual(*thread->secmemPML4e)))) {
          freePTPage(ptindex);
        }
#endif
      }
    }
  }

  /* Re-enable protection of page table pages */
  protect_paging();

  return paddr;
}

void ghostmemCOW(struct SVAThread* oldThread, struct SVAThread* newThread) {
  uintptr_t vaddr_start, vaddr_end, size;

  vaddr_start = (uintptr_t)GHOSTMEMSTART;
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

void sva_mm_load_pgtable(cr3_t pg_ptr) {
  SVA_PROF_ENTER();

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
   * Increment the reference count for the new PML4 page that we're about to
   * point CR3 to, and decrement it for the old PML4 being switched out.
   */
  frame_desc_t *newpml4Desc = get_frame_desc(new_pml4);
  frame_desc_t *oldpml4Desc = get_frame_desc(read_cr3());

  SVA_ASSERT(newpml4Desc != NULL,
    "SVA: FATAL: Using non-existant frame 0x%lx as root page table\n",
    new_pml4 / FRAME_SIZE);
  frame_take(newpml4Desc, PGT_L4);

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
    pml4e_t* root_pgtable = __va(new_pml4);
    pml4e_t* secmemp = &root_pgtable[PG_L4_ENTRY(GHOSTMEMSTART)];

    /*
     * Write the PML4 entry for the secure memory region into the new
     * top-level page table.
     */
    *secmemp = threadp->secmemPML4e;
  }

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

  SVA_PROF_EXIT(mm_load_pgtable);
}

cr3_t sva_mm_save_pgtable(void) {
  return read_cr3();
}

void sva_load_cr0(unsigned long val) {
  SVA_PROF_ENTER();

  val |= CR0_WP;
  write_cr0(val);

  SVA_PROF_EXIT(load_cr0);
}

void usersva_to_kernel_pcid(void) {
#ifdef SVA_LLC_PART
  /* Switch to the OS cache partition. */
  wrmsr(COS_MSR, OS_COS);
#endif
}

void kernel_to_usersva_pcid(void) {
#ifdef SVA_LLC_PART
  /* Switch to the SVA cache partition. */
  wrmsr(COS_MSR, SVA_COS);
#endif
}

#ifdef FreeBSD
void sva_update_l4_dmap(void* pml4pg, int index, page_entry_t val) {
  if(index < NDMPML4E)
    sva_update_l4_mapping(&(((pml4e_t*)pml4pg)[DMPML4I + index]), val);
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
  page_entry_t* entries = __va(frame);

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
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the frame_desc for the newly declared page table */
  frame_desc_t *pgDesc = get_frame_desc(frame);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Attempt to use non-existant frame %lx as %s page table\n",
    frame / FRAME_SIZE, frame_type_name(level));

  /*
   * Lock this frame to prevent modifications to it while we are validating it.
   */
  frame_lock(pgDesc);

  /*
   * Initialize the new page table.
   */
  initDeclaredPage(frame);

  /*
   * Validate any existing entries in the new page table.
   */
  validate_existing_entries(frame, level);

  /*
   * Unlock the frame and mark it as a page table.
   */
  frame_unlock(pgDesc, level);

  /* Restore interrupts */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}

void sva_declare_l1_page(uintptr_t frame) {
  SVA_PROF_ENTER();

  sva_declare_page(frame, PGT_L1);

  SVA_PROF_EXIT(declare_l1_page);
}

void sva_declare_l2_page(uintptr_t frame) {
  SVA_PROF_ENTER();

  sva_declare_page(frame, PGT_L2);

  SVA_PROF_EXIT(declare_l2_page);
}

void sva_declare_l3_page(uintptr_t frame) {
  SVA_PROF_ENTER();

  sva_declare_page(frame, PGT_L3);

  SVA_PROF_EXIT(declare_l3_page);
}

void sva_declare_l4_page(uintptr_t frame) {
  SVA_PROF_ENTER();

  sva_declare_page(frame, PGT_L4);

  /*
   * Install SVA's L4 entries into the new page table.
   */
  pml4e_t* current_l4_table = __va(get_root_pagetable());
  pml4e_t* new_l4_table = __va(frame);

  unprotect_paging();
  for (size_t i = PG_L4_ENTRY(SECMEMSTART); i < PG_L4_ENTRY(SECMEMEND); ++i) {
    pml4e_t l4e = current_l4_table[i];
    if (isPresent(l4e)) {
      frame_take(get_frame_desc(PG_ENTRY_FRAME(l4e)), PGT_SML3);
    }
    new_l4_table[i] = l4e;
  }
  protect_paging();

  SVA_PROF_EXIT(declare_l4_page);
}

void sva_remove_page(uintptr_t paddr) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  unsigned char isEPT; /* whether we are undeclaring an extended page table */

  /* Get the descriptor for the physical frame where this PTP resides. */
  frame_desc_t *pgDesc = get_frame_desc(paddr);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Frame being removed doesn't exist\n");

  /*
   * Mark the page frame as an unused page.  Note that this will also check
   * that there are no references to this page (i.e., there is no page table
   * entry that refers to this physical page frame).
   */
  frame_type_t old_type = frame_lock(pgDesc);

  /*
   * Make sure that this is a page table page. We don't want the system
   * software to trick us.
   *
   * Also take the opportunity to determine whether the PTP being undeclared
   * is an extended page table.
   */
  switch (old_type) {
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
        paddr, frame_type_name(old_type));
  }

  /*
   * If any valid mappings remain within the PTP, explicitly remove them to
   * ensure consistency of SVA's page metadata.
   *
   * (Note: PG_ENTRIES = # of entries in a PTP. We assume this is the same at
   * all levels of the paging hierarchy.)
   */
  page_entry_t* ptp_vaddr = __va(paddr);
  for (unsigned long i = 0; i < PG_ENTRIES; i++) {
    if (isPresent_maybeEPT(ptp_vaddr[i], isEPT)) {
      /* Remove the mapping */
      frame_desc_t *mappedPg = get_frame_desc(ptp_vaddr[i]);
      frame_type_t mapped_ty = frame_get_type(mappedPg);
      if (mapped_ty >= PGT_SML1 && mapped_ty <= PGT_SML3) {
#ifdef XEN
        updateOrigPageData(ptp_vaddr[i], mapped_ty, 1);
#else
        /*
         * The method of removal for ghost PTP mappings is slightly
         * different than for ordinary mappings created by the OS (SVA has
         * a separate refcount system to keep track of them).
         */
        unsigned int ptindex = releaseUse(&ptp_vaddr[i]);
        freePTPage(ptindex);
#endif
        __atomic_store_n(&ptp_vaddr[i], ZERO_MAPPING, __ATOMIC_RELEASE);
      } else {
        bool isLeaf = isLeafEntry(ptp_vaddr[i], old_type);
        size_t count = isLeaf ? getMappedSize(old_type) / FRAME_SIZE : 1;
        frame_type_t ty = frame_type_from_pte(ptp_vaddr[i], old_type);
        /*
         * NB: We don't want to actually change the data in the page table, as
         * the kernel may be relying on being able to access it for its own
         * bookkeeping.  Instead, just update our metadata to reflect that the
         * reference has been dropped.  Since this page is about to become a
         * data page, there is no safety concern with leaving the entry intact.
         */
        updateOrigPageData(ptp_vaddr[i], ty, count);
      }
    }
  }

  frame_unlock(pgDesc, PGT_FREE);

  /* Restore interrupts and return to kernel page tables */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();

  SVA_PROF_EXIT_MULTI(remove_page, 2);
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
                        frame_type_t level)
{
  kernel_to_usersva_pcid();

  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to the specified level of page table.
   * If it does not, then report an error.
   */
  frame_desc_t* ptDesc = get_frame_desc(__pa(pte));
  SVA_ASSERT(ptDesc != NULL,
    "SVA: FATAL: %s page table frame at %p doesn't exist\n",
    frame_type_name(level), pte);

  /*
   * Take a temporary reference to the frame to prevent it from changing types
   * out from under us.
   */
  frame_take(ptDesc, level);

  update_mapping(pte, new_pte);

  /*
   * Drop the temporary reference.
   */
  frame_drop(ptDesc, level);

  /* Restore interrupts */
  sva_exit_critical(rflags);

  usersva_to_kernel_pcid();
}

void sva_remove_mapping(page_entry_t* pteptr) {
  SVA_PROF_ENTER();

  frame_desc_t* pt = get_frame_desc(__pa(pteptr));

  /* Update the page table mapping to zero */
  sva_update_mapping(pteptr, ZERO_MAPPING, frame_get_type(pt));

  SVA_PROF_EXIT(remove_mapping);
}

void sva_update_l1_mapping(pte_t* l1e, pte_t new_l1e) {
  SVA_PROF_ENTER();

  sva_update_mapping(l1e, new_l1e, PGT_L1);

  SVA_PROF_EXIT(update_l1_mapping);
}

void sva_update_l2_mapping(pde_t* l2e, pde_t new_l2e) {
  SVA_PROF_ENTER();

  sva_update_mapping(l2e, new_l2e, PGT_L2);

  SVA_PROF_EXIT(update_l2_mapping);
}

void sva_update_l3_mapping(pdpte_t* l3e, pdpte_t new_l3e) {
  SVA_PROF_ENTER();

  sva_update_mapping(l3e, new_l3e, PGT_L3);

  SVA_PROF_EXIT(update_l3_mapping);
}

void sva_update_l4_mapping(pml4e_t* l4e, pml4e_t new_l4e) {
  SVA_PROF_ENTER();

  sva_update_mapping(l4e, new_l4e, PGT_L4);

  SVA_PROF_EXIT(update_l4_mapping);
}

/**
 * Change the permissions on a code page.
 *
 * Note: This function allows the creation of writable+executable mappings as
 * well as setting unvetted data as executable. Use with caution.
 *
 * @param vaddr       The virtual address for which to change permissions
 * @param perms       The new permissions to set
 * @param allow_morph Allow changing a non-code page into a code page
 */
static void protect_code_page(uintptr_t vaddr, page_entry_t perms,
                              bool allow_morph)
{
  // Get a pointer to the page table entry
  page_entry_t* leaf_entry = get_pgeVaddr(vaddr);
  SVA_ASSERT(leaf_entry != NULL && isPresent(*leaf_entry),
    "SVA: FATAL: Attempt to change permissions on unmapped page 0x%016lx\n",
    vaddr);

  frame_desc_t* pgDesc = get_frame_desc(*leaf_entry);
  SVA_ASSERT(pgDesc != NULL,
    "SVA: FATAL: Page table entry maps invalid frame\n");
  if (frame_get_type(pgDesc) != PGT_CODE) {
    SVA_ASSERT(allow_morph,
      "SVA: FATAL: Changing permissons on non-code page 0x%016lx\n", vaddr);
    frame_morph(pgDesc, PGT_CODE);
    frame_take(pgDesc, PGT_CODE);
    frame_drop(pgDesc, PGT_FREE);
  }

  *leaf_entry &= ~(PG_P | PG_W | PG_NX) | perms;
  *leaf_entry |= perms;

  invlpg(vaddr);
}

void sva_unprotect_code_page(void* vaddr) {
  SVA_ASSERT(mmuIsInitialized,
    "SVA: FATAL: sva_unprotect_code_page called before MMU init\n");

  SVA_PROF_ENTER();

  unsigned long flags = sva_enter_critical();
  kernel_to_usersva_pcid();

  protect_code_page((uintptr_t)vaddr, PG_P | PG_W | PG_NX, false);

  usersva_to_kernel_pcid();
  sva_exit_critical(flags);

  SVA_PROF_EXIT(update_l1_mapping);
}

void sva_protect_code_page(void* vaddr) {
  SVA_ASSERT(mmuIsInitialized,
    "SVA: FATAL: sva_unprotect_code_page called before MMU init\n");

  SVA_PROF_ENTER();

  unsigned long flags = sva_enter_critical();
  kernel_to_usersva_pcid();

  protect_code_page((uintptr_t)vaddr, PG_P, false);

  usersva_to_kernel_pcid();
  sva_exit_critical(flags);

  SVA_PROF_EXIT(update_l1_mapping);
}

void sva_debug_make_code_page(void* vaddr) {
  SVA_ASSERT(mmuIsInitialized,
    "SVA: FATAL: sva_unprotect_code_page called before MMU init\n");

  SVA_PROF_ENTER();

  unsigned long flags = sva_enter_critical();
  kernel_to_usersva_pcid();

  protect_code_page((uintptr_t)vaddr, PG_P, true);

  usersva_to_kernel_pcid();
  sva_exit_critical(flags);

  SVA_PROF_EXIT(update_l1_mapping);
}
