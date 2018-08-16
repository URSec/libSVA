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
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared page frame. */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L1 EPT page, an unused page, or a
   * kernel data page.
   */
  switch (pgDesc->type) {
    case PG_EPTL1:
    case PG_UNUSED:
    case PG_TKDATA:
      break;

    default:
      printf("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic("SVA: Declaring EPT L1 for wrong page: "
          "frameAddr = %lx, pgDesc=%lx, type=%x\n",
          frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /*
   * A page can only be declared as a page table page if its reference count
   * is less than 2.
   *
   * (i.e., the kernel shouldn't have it mapped anywhere except in its direct
   * map)
   */
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l1_eptpage: "
      "more than one virtual addresses are still using this page!");

  /* 
   * Declare the page as an EPT L1 page (unless it is already one).
   */
  if (pgDesc->type != PG_EPTL1) {
    /*
     * Mark this page frame as an EPT L1 page frame.
     */
    pgDesc->type = PG_EPTL1;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical(rflags);
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
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared page frame. */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L2 EPT page, an unused page, or a
   * kernel data page.
   */
  switch (pgDesc->type) {
    case PG_EPTL2:
    case PG_UNUSED:
    case PG_TKDATA:
      break;

    default:
      printf("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic("SVA: Declaring EPT L2 for wrong page: "
          "frameAddr = %lx, pgDesc=%lx, type=%x\n",
          frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /*
   * A page can only be declared as a page table page if its reference count
   * is less than 2.
   *
   * (i.e., the kernel shouldn't have it mapped anywhere except in its direct
   * map)
   */
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l2_eptpage: "
      "more than one virtual addresses are still using this page!");

  /* 
   * Declare the page as an EPT L2 page (unless it is already one).
   */
  if (pgDesc->type != PG_EPTL2) {
    /*
     * Mark this page frame as an EPT L2 page frame.
     */
    pgDesc->type = PG_EPTL2;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical(rflags);
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
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared page frame. */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L3 EPT page, an unused page, or a
   * kernel data page.
   */
  switch (pgDesc->type) {
    case PG_EPTL3:
    case PG_UNUSED:
    case PG_TKDATA:
      break;

    default:
      printf("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic("SVA: Declaring EPT L3 for wrong page: "
          "frameAddr = %lx, pgDesc=%lx, type=%x\n",
          frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /*
   * A page can only be declared as a page table page if its reference count
   * is less than 2.
   *
   * (i.e., the kernel shouldn't have it mapped anywhere except in its direct
   * map)
   */
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l3_eptpage: "
      "more than one virtual addresses are still using this page!");

  /* 
   * Declare the page as an EPT L3 page (unless it is already one).
   */
  if (pgDesc->type != PG_EPTL3) {
    /*
     * Mark this page frame as an EPT L2 page frame.
     */
    pgDesc->type = PG_EPTL3;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical(rflags);
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
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared page frame. */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L4 EPT page, an unused page, or a
   * kernel data page.
   */
  switch (pgDesc->type) {
    case PG_EPTL4:
    case PG_UNUSED:
    case PG_TKDATA:
      break;

    default:
      printf("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic("SVA: Declaring EPT L4 for wrong page: "
          "frameAddr = %lx, pgDesc=%lx, type=%x\n",
          frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /*
   * A page can only be declared as a page table page if its reference count
   * is less than 2.
   *
   * (i.e., the kernel shouldn't have it mapped anywhere except in its direct
   * map)
   */
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l4_eptpage: "
      "more than one virtual addresses are still using this page!");

  /* 
   * Declare the page as an EPT L4 page (unless it is already one).
   */
  if (pgDesc->type != PG_EPTL4) {
    /*
     * Mark this page frame as an EPT L2 page frame.
     */
    pgDesc->type = PG_EPTL4;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical(rflags);
}
