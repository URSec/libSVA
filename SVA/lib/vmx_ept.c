/*===- vmx_ept.c - SVA Execution Engine  =---------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the SVA research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements SVA's intrinsics for managing extended page tables
 * (EPT) in conjunction with other support for hardware-accelerated
 * virtualization implemented in vmx.c
 *
 *===----------------------------------------------------------------------===
 *
 * Note: We try to use the term "frame" to refer to a page of physical memory
 *       and a "page" to refer to the virtual addresses mapped to the page of
 *       physical memory.
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/vmx.h>
#include <sva/vmx_intrinsics.h>
#include <sva/mmu.h>
#include <sva/config.h>
#include <sva/util.h>

extern vmx_host_state_t __svadata host_state;

/*
 * Intrinsic: sva_declare_l1_eptpage()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 1 extended
 *  page table frame. It will zero out the contents of the page frame so that
 *  stale mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The physical address of the page frame that will be used as a
 *              Level 1 extended page table frame.
 */
void
sva_declare_l1_eptpage(uintptr_t frameAddr) {
  sva_declare_page(frameAddr, PGT_EPTL1);
}

/*
 * Intrinsic: sva_declare_l2_eptpage()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 2 extended
 *  page table frame. It will zero out the contents of the page frame so that
 *  stale mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The physical address of the page frame that will be used as a
 *              Level 2 extended page table frame.
 */
void
sva_declare_l2_eptpage(uintptr_t frameAddr) {
  sva_declare_page(frameAddr, PGT_EPTL2);
}

/*
 * Intrinsic: sva_declare_l3_eptpage()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 3 extended
 *  page table frame. It will zero out the contents of the page frame so that
 *  stale mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The physical address of the page frame that will be used as a
 *              Level 3 extended page table frame.
 */
void
sva_declare_l3_eptpage(uintptr_t frameAddr) {
  sva_declare_page(frameAddr, PGT_EPTL3);
}

/*
 * Intrinsic: sva_declare_l4_eptpage()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 4 extended
 *  page table frame. It will zero out the contents of the page frame so that
 *  stale mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The physical address of the page frame that will be used as a
 *              Level 4 extended page table frame.
 */
void
sva_declare_l4_eptpage(uintptr_t frameAddr) {
  sva_declare_page(frameAddr, PGT_EPTL4);
}

/*
 * Intrinsic: sva_update_ept_mapping()
 *
 * Description:
 *  This intrinsic updates a page table entry (PTE) within an extended page
 *  table. That is, it adds/replaces a mapping from a guest-physical page to
 *  a host-physical page, or a reference to a lower-level page table (in the
 *  case of a PTE located in a non-last-level table).
 *
 *  This function makes different checks to ensure the mapping does not
 *  bypass the type safety proven by the compiler.
 *
 *  Note that this intrinsic supports changing mappings at any level in the
 *  EPT paging hierarchy. It infers the level of the page-table page being
 *  modified from SVA's internal data structures which remember the declared
 *  usage of each physical frame.
 *
 *  (The non-EPT intrinsics sva_update_l<1-4>_mapping() actually do the same
 *  thing internally, even though they are separate intrinsics on the
 *  surface. We could/should unify those into a single intrinsic.)
 *
 * Inputs:
 *  epteptr - A (host-virtual) pointer to the location within the page table
 *            page in which the new translation should be placed.
 *  val     - The new translation (page-table entry) to insert into the
 *            extended page table.
 */
void
sva_update_ept_mapping(page_entry_t __kern* eptePtr, page_entry_t val) {
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an EPT page table. If it does not,
   * report an error.
   */
  paddr_t epte_paddr = __pa(eptePtr);
  frame_desc_t *ptDesc = get_frame_desc(epte_paddr);
  SVA_ASSERT(ptDesc != NULL,
    "SVA: FATAL: EPT page table frame at %p doesn't exist\n", eptePtr);

  frame_type_t ty = frame_get_type(ptDesc);
  if (!disableMMUChecks) {
    switch(ty) {
      case PGT_EPTL1:
      case PGT_EPTL2:
      case PGT_EPTL3:
      case PGT_EPTL4:
        break;

      default:
        panic("SVA: MMU: attempted to update an EPTE in a page that isn't "
            "an EPTP! Location: %p; new value: 0x%lx; "
            "actual frame type: 0x%x\n", eptePtr, val, ty);
        break;
    }
  }

  /*
   * Take a phantom reference to the extended page table while updating it to
   * prevent it from changing types out from under us.
   */
  frame_take(ptDesc, ty);

  /*
   * Update the page table with the new mapping. The __update_mapping()
   * function is responsible for doing any further checks.
   */
  update_mapping(__va(epte_paddr), val);

  frame_drop(ptDesc, ty);

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}

/*
 * Intrinsic: sva_load_eptable()
 *
 * Description:
 *  Sets the current extended page table for a virtual machine.
 *
 * Inputs:
 *  - vmid: the numeric handle of the virtual machine whose extended page
 *    table should be set.
 *  - epml4t: a (host-virtual) pointer to the top-level extended page table
 *    (EPML4) that the VM should use.
 */
void
sva_load_eptable(int vmid, pml4e_t __kern* epml4t) {
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_load_eptable(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_getfp(): failed to acquire VM descriptor lock!\n");

  /*
   * If the VM descriptor indicated by this ID has a null VMCS pointer, it
   * is not a valid descriptor. (i.e., it is an empty slot not assigned to
   * any VM)
   */
  if (!vm_descs[vmid].vmcs_paddr) {
    panic("Fatal error: tried to reference an unallocated VM!\n");
  }

  /*
   * Call a helper function which vets the EPML4 pointer and sets the EPTP in
   * the VM descriptor.
   */
  load_eptable_internal(vmid, epml4t, 0 /* is not initial setting */);

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
}

/*
 * Helper function: load_eptable_internal()
 *
 * Description:
 *  Like sva_load_eptable(), but skips checks on vmid.
 *
 *  Verifies that epml4t points to a valid declared EPML4 frame and sets the
 *  EPTP in the VM descriptor to point to it.
 *
 *  Used to share code between sva_load_eptable() and sva_allocvm(), which
 *  also needs to set the EPTP from an untrusted value, but knows it has a
 *  valid vmid (because it generated that ID).
 *
 * Inputs:
 *  - vmid, epml4t: same as sva_load_eptable()
 *
 *  - is_initial_setting: boolean indicating whether this is the first time
 *    the EPTP is being loaded for this VM. (This indicates whether we need
 *    to decrement the refcount for an existing top-level PTP.)
 *
 * Preconditions:
 *  - Must be called by an SVA intrinsic, i.e., interrupts should be disabled
 *    and the SVA/userspace page tables should be active.
 *
 *  - vmid must be valid (i.e., in-bounds and pointing to an active VM).
 *
 *  - is_initial_setting must come from a trusted source (as it determines
 *    whether we skip a security check that is invalid the first time the
 *    extended page table is loaded for a new VM). In general, SVA code
 *    calling this function should be able to set it as a constant.
 *      (As the code is currently structured, this is only set to true
 *      when sva_allocvm() is the caller.)
 */
void
load_eptable_internal(
    int vmid, pml4e_t __kern* epml4t, unsigned char is_initial_setting) {
  /*
   * Verify that the given extended page table pointer points to a valid
   * top-level extended-page-table page (i.e., one properly declared with
   * sva_declare_l4_eptpage()).
   */
  paddr_t epml4t_paddr = __pa(epml4t);
  frame_desc_t *ptpDesc = get_frame_desc(epml4t_paddr);
  SVA_ASSERT(ptpDesc != NULL,
    "SVA: FATAL: EPT root page table frame at %p doesn't exist\n", epml4t);

  /*
   * Increment the reference count for the new top-level extended PTP to
   * reflect that it is now referenced by this VM. Also checks that this is in
   * fact an EPT root page table.
   */
  frame_take(ptpDesc, PGT_EPTL4);

  /*
   * Decrement the reference count for the old PTP.
   *
   * Skip this if this is the first time we are loading the EPTP for this VM
   * (i.e., there is no old PTP).
   */
  if (!is_initial_setting) {
    frame_desc_t *old_ptpDesc = get_frame_desc(vm_descs[vmid].eptp);

    frame_drop(old_ptpDesc, PGT_EPTL4);
  }

  /*
   * Construct the value to load into the VMCS's Extended Page Table Pointer
   * (EPTP) field.
   *
   * Similar to the CR3 register for normal paging, the EPTP contains the
   * 4 kB-aligned host-physical address (sans 12 least significant bits,
   * which are always zero due to the alignment) of the top-level extended
   * page table in bits 12:MAXPHYADDR. The other bits are used for various
   * settings controlling how the EPT paging hierarchy is interpreted.
   *
   * We set the following fields (which, as of this writing, are all of the
   * defined fields):
   *
   *  - Bits 0-2: EPT paging structures memory type = 6 (writeback, i.e., no
   *              unusual caching modes are used for the page tables)
   *
   *  - Bits 3-5: EPT page-walk length minus 1. Since we are using 4-level
   *              paging, we set this to 3. (Currently, 4-level paging is the
   *              *only* mode supported for EPT; this field exists to
   *              facilitate adding more levels in future processors.)
   *
   *  - Bit 6:    Enable accessed and dirty flags for EPT. We enable this.
   *
   * Per Intel's spec, all other bits are reserved and must be set to 0. This
   * yields a mask of:
   *              1 011 110   = 0x5e
   */
  eptp_t eptp_val = 0x5e | epml4t_paddr;

  /* Store the EPTP value in the VM descriptor. */
  vm_descs[vmid].eptp = eptp_val;
}

/*
 * Intrinsic: sva_save_eptable()
 *
 * Description:
 *  Get the host-physical address of top-level extended page table currently
 *  in use by a virtual machine.
 *
 * Inputs:
 *  - vmid: the numeric handle of the virtual machine whose extended page
 *    table is being queried.
 */
uintptr_t
sva_save_eptable(int vmid) {
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_save_eptable(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_getfp(): failed to acquire VM descriptor lock!\n");

  /*
   * If the VM descriptor indicated by this ID has a null VMCS pointer, it
   * is not a valid descriptor. (i.e., it is an empty slot not assigned to
   * any VM)
   */
  if (!vm_descs[vmid].vmcs_paddr) {
    panic("Fatal error: tried to reference an unallocated VM!\n");
  }

  /* Get the current EPTP value from the VM descriptor. */
  eptp_t eptp = vm_descs[vmid].eptp;
  /*
   * Mask off the flags in the EPTP to get the host-physical address of the
   * top-level table.
   */
  uintptr_t epml4t_paddr = PG_ENTRY_FRAME(eptp);

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();

  return epml4t_paddr;
}

/*
 * Helper function: do_invept()
 *
 * Encapsulates INVEPT inline assembly used by multiple higher-level
 * functions.
 *
 * @param invept_type   Type of the INVEPT operation to be performed
 *                      (see Intel manual for valid types).
 * @param ept_root_ptp  The host-physical address of the root extended page
 *                      table whose address translations are to be
 *                      invalidated.
 *
 * @return    True if INVEPT returned status code VMsucceed, false otherwise.
 */
static inline bool
do_invept(uint64_t invept_type, paddr_t ept_root_ptp) {
  /*
   * Set up a 128-bit "INVEPT descriptor" in memory which serves as one of
   * the arguments to INVEPT.
   *
   * The lower 64 bits contain the EPT root pointer whose associated TLB
   * entries are to be flushed.
   *
   * The upper 64 bits are reserved and must be set to 0 for safe forward
   * compatibility.
   *
   * Note: Intel treats the INVEPT descriptor as a single 128-bit
   * little-endian (unsigned) integer, so the lower 64 bits are at the
   * *beginning* (bytewise, i.e. the first byte is bits 7-0 in that order,
   * the second is 15-7 in that order, etc.). The net result is that we can
   * represent the descriptor as a packed struct comprised of individual
   * integer fields of the appropriate sizes, but we have to list those
   * fields in "reverse order" in the struct definition vs. how they're
   * listed in the Intel manual.
   */
  struct __packed {
    uint64_t eptp;
    uint64_t reserved;
  } invept_descriptor = {ept_root_ptp, 0};

  uint64_t rflags_invept;
  asm __volatile__ (
      "invept %[desc], %[type]\n"
      "pushfq\n"
      "popq %[rflags]\n"
      : [rflags] "=r" (rflags_invept)
      : [desc] "m" (invept_descriptor),
        [type] "r" (invept_type)
      : "memory", "cc"
      );

  return query_vmx_result(rflags_invept) == VM_SUCCEED;
}

/*
 * Helper function: do_invvpid()
 *
 * Encapsulates INVVPID inline assembly used by multiple higher-level
 * functions.
 *
 * @param invvpid_type        Type of the INVVPID operation to be performed
 *                            (see Intel manual for valid types).
 * @param vpid                The VPID to be flushed (for single-context and
 *                            individual-address flushes).
 * @param guest_linear_addr   The guest-linear address to be flushed (for
 *                            individual-address flushes).
 *
 * @return    True if INVVPID returned status code VMsucceed, false otherwise.
 */
static inline bool
do_invvpid(uint64_t invvpid_type, uint16_t vpid, uint64_t guest_linear_addr) {
  /*
   * Set up a 128-bit "INVVPID descriptor" in memory which serves as one of
   * the arguments to INVVPID.
   *
   * - Bits 0-15 specify the VPID whose translations should be cleared from
   *   the TLB.
   *
   * - Bits 16-63 are reserved and must be set to 0 for safe forward
   *   compatibility.
   *
   * - Bits 64-127 specify a linear address whose translations should be
   *   cleared from the TLB. Its setting does not matter for single-context
   *   flushes such as we are going to do here, which flush mappings
   *   irrespective of linear address so long as they match the specified
   *   VPID.
   *
   * Note: Intel treats the INVVPID descriptor as a single 128-bit
   * little-endian (unsigned) integer, so bits 0-15 are at the beginning
   * (bytewise, i.e. the first byte is bits 7-0 in that order, the second is
   * 15-7 in that order, etc.). The net result is that we can represent the
   * descriptor as a packed struct comprised of individual integer fields of
   * the appropriate sizes, but we have to list those fields in "reverse
   * order" in the struct definition vs. how they're listed in the Intel
   * manual.
   */
  struct __packed {
    uint16_t vpid;
    uint64_t reserved:48;
    uint64_t guest_linear_addr;
  } invvpid_descriptor = {vpid, 0, guest_linear_addr};

  uint64_t rflags_invvpid;
  asm __volatile__ (
      "invvpid %[desc], %[type]\n"
      "pushfq\n"
      "popq %[rflags]\n"
      : [rflags] "=r" (rflags_invvpid)
      : [desc] "m" (invvpid_descriptor),
        [type] "r" (invvpid_type)
      : "memory", "cc"
      );

  return query_vmx_result(rflags_invvpid) == VM_SUCCEED;
}

/*
 * Intrinsic: sva_flush_ept_all()
 *
 * Issues a global INVEPT, i.e. invalidates all EPT-associated translations
 * in the current processor's TLB.
 *
 * This can include both what the Intel manual refers to as "guest-physical"
 * and "combined" translations, which are respectively used for unpaged and
 * paged memory accesses by the guest while EPT is enabled. ("Combined"
 * translations are tagged with *both* the associated EPT root pointer and
 * the associated VPID, and can be flushed by *either* an INVEPT or INVVPID
 * that matches the appropriate tag.)
 */
void
sva_flush_ept_all(void) {
  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_flush_ept_all(): Shade has not yet been initialized on this "
      "processor. Cannot issue INVEPT as that instruction is not valid "
      "unless the system is running in VMX operation.\n");

  bool result = do_invept(
      2 /* INVEPT type: all-contexts (global) invalidation */,
      0 /* EPT root pointer is irrelevant for all-contexts flush */);

  SVA_ASSERT(result,
      "sva_flush_ept_all: INVEPT failed. Perhaps the processor isn't "
      "new enough to support INVEPT?");
}

/*
 * Intrinsic: sva_flush_ept_single()
 *
 * Issues a single-context INVEPT to invalidate all translations in the
 * current procesesor's TLB that are associated with the specified extended
 * page table root pointer.
 *
 * This can include both what the Intel manual refers to as "guest-physical"
 * and "combined" translations, which are respectively used for unpaged and
 * paged memory accesses by the guest while EPT is enabled. ("Combined"
 * translations are tagged with *both* the associated EPT root pointer and
 * the associated VPID, and can be flushed by *either* an INVEPT or INVVPID
 * that matches the appropriate tag.)
 *
 * @param ept_root_ptp  The host-physical address of the root extended page
 *                      table whose address translations are to be
 *                      invalidated.
 */
void
sva_flush_ept_single(paddr_t ept_root_ptp) {
 /*
  * NOTE: The specified EPT root pointer should, operationally, correspond to
  * a valid host-physical address that has been declared to SVA as a level-4
  * extended page table frame.
  *
  * However, we do *not* need to enforce this with a runtime check, as it is
  * not security sensitive. There is no harm in allowing the system software
  * to issue a TLB flush for an invalid EPT root address; at worst, it could
  * slow the system down by discarding pefectly good TLB entries. (Since we
  * allow the system software to perform wholesale TLB flushes with other
  * intrinsics, that's nothing it can't already do.)
  */

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_flush_ept_single(): Shade has not yet been initialized on this "
      "processor. Cannot issue INVEPT as that instruction is not valid "
      "unless the system is running in VMX operation.\n");

  bool result = do_invept(
      1 /* INVEPT type: single-context invalidation */,
      ept_root_ptp);

  SVA_ASSERT(result,
      "sva_flush_ept_single(): INVEPT failed. Perhaps the processor "
      "isn't new enough to support the single-context mode for INVEPT?");
}

/*
 * Intrinsic: sva_flush_vpid_all()
 *
 * Issues an all-contexts INVVPID, i.e. invalidates all VPID-associated
 * translations in the current processor's TLB, except for VPID 0. (VPID 0
 * represents the host system; to flush host mappings, use sva_mm_flush_tlb()
 * or sva_mm_flush_tlb_global() as appropriate.)
 *
 * This can include both what the Intel manual refers to as "guest-physical"
 * and "combined" translations, which are respectively used for unpaged and
 * paged memory accesses by the guest while EPT is enabled. ("Combined"
 * translations are tagged with *both* the associated EPT root pointer and
 * the associated VPID, and can be flushed by *either* an INVEPT or INVVPID
 * that matches the appropriate tag.)
 */
void
sva_flush_vpid_all(void) {
  /*
   * Xen sometimes calls this intrinsic before it has called sva_initvmx() to
   * initialize Shade (and thus perform VMXON) on a processor.
   *
   * In such a case, this intrinsic can safely be a no-op, as no
   * VPID-associated translations can have yet been created in the TLB.
   *
   * There is no functional reason for Xen to do this, but it seems to do so
   * for code-organizational reasons because non-SVA Xen implements this
   * flush such that it is a harmless no-op when done prior to VMXON.
   * Non-SVA Xen increments the VPID value through a generational scheme
   * rather than explicitly issuing INVVPID; it implements the all-context
   * flush by starting a new generation (i.e. incrementing a per-CPU
   * counter). That generational scheme doesn't play nice with how Shade
   * handles VPIDs, so in the SVA port we changed Xen to instead explicitly
   * call our INVVPID intrinsics (eliminating the need to change the actual
   * VPID value). This means, however, that we need to tolerate this
   * intrinsic being called prior to sva_initvmx() even though INVVPID will
   * #UD if issued prior to VMXON.
   */
  if (!getCPUState()->vmx_initialized)
    return;

  bool result = do_invvpid(
      2 /* INVVPID type: all-contexts (global) invalidation */,
      0 /* VPID is irrelevant for all-contexts flush */,
      0 /* guest-linear address is irrelevant for all-contexts flush */);

  SVA_ASSERT(result,
      "sva_flush_vpid_all(): INVVPID failed. Perhaps the processor "
      "isn't new enough to support INVVPID?");
}

/*
 * Intrinsic: sva_flush_vpid_single()
 *
 * Issues a single-context INVVPID to invalidate all translations in the
 * current processor's TLB that are associated with the specified VM's VPID.
 *
 * This can include both what the Intel manual refers to as "guest-physical"
 * and "combined" translations, which are respectively used for unpaged and
 * paged memory accesses by the guest while EPT is enabled. ("Combined"
 * translations are tagged with *both* the associated EPT root pointer and
 * the associated VPID, and can be flushed by *either* an INVEPT or INVVPID
 * that matches the appropriate tag.)
 *
 * @param vmid            The SVA VM ID of the VM whose associated
 *                        translations in the TLB should be flushed.
 *
 * @param retain_global   Whether global translations should be retained by
 *                        the flush even if they match the specified VPID.
 */
void
sva_flush_vpid_single(int vmid, bool retain_global) {
  /*
   * NOTE: It is not necessary to bounds-check the VMID, check whether it
   * actually corresponds to a valid (i.e. currently in-use) descriptor, or
   * to check/take the descriptor lock. There is no harm in allowing the
   * system software to issue a TLB flush for an invalid VM's VPID; at worst,
   * it could slow the system down by discarding pefectly good TLB entries.
   * (Since we allow the system software to perform wholesale TLB flushes
   * with other intrinsics, that's nothing it can't already do.)
   *
   * The one edge case of an invalid VMID that *won't* fail silently is if
   * the value 0 is passed. 0 represents the host, so the processor will
   * return VMfail if it is given as the argument to INVVPID. Our assert
   * below will notice that and cause a panic. This is OK as it's the
   * hypervisor's fault (it shouldn't be passing a garbage VMID in the first
   * place), but it's something to be aware of if you're wondering why you're
   * crashing here on a processor that you know supports single-context
   * INVVPID. :-)
   */

  /*
   * NOTE: Currently, we use the scheme VPID == VMID in all cases. If
   * this becomes inadequate in the future and we need to adopt a more
   * complicated scheme (say, if we want to support more than 2^16 concurrent
   * vCPUs, or if for some reason we want to adopt an incrementing scheme
   * like non-SVA Xen uses), this code will need to be changed to look up the
   * current VPID in the VM descriptor (or wherever we might store it). Note
   * that if we were to do so, we might (depending on the design) need to
   * check or take the VM descriptor lock (which we don't now, see above).
   *
   * We therefore can simply cast vmid to a 16-bit uint to conform with the
   * hardware's VPID format. If the caller gave us a value outside of
   * uint16_t's range, casting it by value as we do here will suffice to
   * prevent undefined behavior and simply pass a garbage value to INVVPID.
   * As noted above, a "stray" INVVPID is harmless from a security
   * perspective.
   */
  uint16_t vpid = (uint16_t) vmid;

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_flush_vpid_single(): Shade has not yet been initialized on this "
      "processor. Cannot issue INVVPID as that instruction is not valid "
      "unless the system is running in VMX operation.\n");

  bool result = do_invvpid(
      retain_global
        ? 3 /* INVVPID type: single-context invalidation,
               retaining global translations */
        : 1 /* INVVPID type: single-context invalidation */,
      vpid,
      0 /* guest-linear address is irrelevant for single-context flush */);

  SVA_ASSERT(result,
      "sva_flush_vpid_single(): INVVPID failed. Perhaps the processor "
      "isn't new enough to support the specified INVVPID mode? (Or the "
      "hypervisor passed an invalid VMID of 0.)");
}

/*
 * Intrinsic: sva_flush_vpid_addr()
 *
 * Issues an individual-address INVVPID to invalidate translations in the
 * current processor's TLB that are associated with the specified VM's VPID
 * *and* the given guest-linear address (i.e., which translate that linear
 * address within the context of the specified guest environment).
 *
 * @param vmid    The SVA VM ID of the VM whose associated translations
 *                translating the given guest-linear address should be
 *                flushed.
 *
 * @param guest_linear_addr   The guest-linear address whose associated
 *                            translations should be flushed within the
 *                            context of the specified VM.
 */
void
sva_flush_vpid_addr(int __attribute__((unused)) vmid, uintptr_t __attribute__((unused)) guest_linear_addr) {
  panic("sva_flush_vpid_addr(): Unimplemented");
}
