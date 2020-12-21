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
   * If the specified VM is currently active on this CPU, we already hold its
   * lock and it is safe to proceed. Otherwise, we need to take the lock.
   */
  if (host_state.active_vm != &vm_descs[vmid])
    vm_desc_lock(&vm_descs[vmid]);

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
  if (host_state.active_vm != &vm_descs[vmid])
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
   * If the specified VM is currently active on this CPU, we already hold its
   * lock and it is safe to proceed. Otherwise, we need to take the lock.
   */
  if (host_state.active_vm != &vm_descs[vmid])
    vm_desc_lock(&vm_descs[vmid]);

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
  if (host_state.active_vm != &vm_descs[vmid])
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();

  return epml4t_paddr;
}
