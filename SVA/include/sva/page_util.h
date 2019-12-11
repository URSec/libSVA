/*===- page_util.h - SVA Execution Engine  =---------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2019.
 * All rights reserved.
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * X86 page table entry predicates and other utilities.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_PAGE_UTIL_H
#define SVA_PAGE_UTIL_H

#include <sva/page.h>
#include <sva/mmu_types.h>
#include <sva/frame_meta.h>

/**
 * Determine if a page table entry is present.
 *
 * @param pte The entry to test
 * @return    True if the entry is present, otherwise false
 */
static inline bool isPresent(page_entry_t pte) {
  return pte & PG_V;
}

/**
 * Determine if a extended page table entry is present.
 *
 * Note that, unlike regular page tables, extended page tables don't have a
 * present bit. Instead, an entry is considered present if any of the read,
 * write, or execute permissions are enabled for it.
 *
 * @param pte The entry to test
 * @return    True if the entry is present, otherwise false
 */
static inline bool isPresentEPT(page_entry_t epte) {
  /*
   * EPT page table entries don't have a "valid" flag. Instead, a mapping is
   * considered present if and only if any of the read, write, or execute
   * flags are set to 1.
   */
  return epte & PG_EPT_R || epte & PG_EPT_W || epte & PG_EPT_X;

  /*
   * NOTE: if the "mode-based execute control for EPT" VM-execution control
   * is enabled, the X bit only controls supervisor-mode accesses, and a
   * separate XU bit controls user-mode execute permissions. Thus, when this
   * feature is enabled, we need to check all four of the R, W, X, and XU
   * bits to determine whether the mapping is present.
   *
   * However, when this feature is disabled (or unsupported by the hardware),
   * the XU bit is *ignored* by the processor, we we need to check *only* the
   * R, W, and X bits.
   *
   * This is a brand-new feature recently added by Intel and our sort-of-new
   * development hardware (Broadwell) doesn't support it, so we do not
   * currently support it in SVA, i.e., it is assumed to be disabled. Thus we
   * can unconditionally check just the R, W, and X bits here.
   *
   * If/when we support or make use of this feature in SVA in the future, we
   * will need to change this function to behave as follows *ONLY* when
   * mode-based execute control is enabled:
   *
   *  return epte & PG_EPT_R || epte & PG_EPT_W || epte & PG_EPT_X ||
   *         epte & PG_EPT_XU;
   */
}

/**
 * Determine if a (possibly extended) page table entry is present.
 *
 * This is a convienient wrapper for `isPresent()` and `isPresentEPT()`.
 *
 * @param pte   The entry to test
 * @param isEPT Whether or not this is an EPT entry
 * @return      True if the entry is present, otherwise false
 */
static inline bool isPresent_maybeEPT(page_entry_t pte, unsigned char isEPT) {
  /*
   * Calls the right isPresent() function depending on whether this is an EPT
   * mapping.
   */
  if (isEPT)
    return isPresentEPT(pte);
  else
    return isPresent(pte);
}

/**
 * Determine if a page table entry maps a writable page.
 *
 * Note that this only tests the entry itself. Pages mapped by it may still not
 * be writable due to write permission being disabled somewhere else in the
 * paging hierarchy.
 *
 * @param pte The entry to test
 * @return    True if `entry` maps a writable page, otherwise false
 */
static inline bool isWritable(page_entry_t pte) {
  return pte & PG_RW;
}

/**
 * Determine if a page table entry maps an executable page.
 *
 * Note that this only tests the entry itself. Pages mapped by it may still not
 * be executable due to execute permission being disabled somewhere else in the
 * paging hierarchy.
 *
 * @param pte The entry to test
 * @return    True if `entry` maps an executable page, otherwise false
 */
static inline bool isExecutable(page_entry_t pte) {
  return !(pte & PG_NX);
}

/**
 * Determine if a page table entry maps a user-accessible page.
 *
 * Note that this only tests the entry itself. Pages mapped by it may still not
 * be accessible to user space due to write permission being disabled somewhere
 * else in the paging hierarchy.
 *
 * @param pte The entry to test
 * @return    True if `entry` maps a user-accessible page, otherwise false
 */
static inline bool isUserMapping(page_entry_t pte) {
  return pte & PG_U;
}

/**
 * Determine if a page table entry maps a "huge" page.
 *
 * @param entry The page table entry that may map a huge page
 * @param level The level of the page table which contains `entry`
 * @return      True if `entry` maps a huge page, otherwise false
 */
static inline bool isHugePage(page_entry_t pte, enum page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_L4:
  case PG_EPTL1:
  case PG_EPTL4:
    return false;
  case PG_L2:
  case PG_L3:
    return pte & PG_PS;
  case PG_EPTL2:
  case PG_EPTL3:
    return pte & PG_EPT_PS;
  default:
    // TODO: Other page table types
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Not a page table type %d\n", level);
  }
}

/**
 * Determine if a page table entry is a leaf entry (one that maps data, not a
 * lower level page table).
 *
 * @param entry The page table entry that may be a leaf entry
 * @param level The level of the page table which contains `entry`
 * @return      True if `entry` is a leaf entry, otherwise false
 */
static inline bool isLeafEntry(page_entry_t pte, enum page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_EPTL1:
    // L1 entries are always leaf entries.
    return true;
  default:
    return isHugePage(pte, level);
  }
}

/**
 * Make a page table entry read-only.
 *
 * Also works for extended page table (EPT) updates, because the R bit in
 * EPT PTEs is at the same place (#1) as the R/W bit in regular PTEs.
 *
 * Note that setting the read only flag does not necessarily mean that the
 * read only protection is enabled in the system. It just indicates that if
 * the system has the write protection enabled then the value of this bit is
 * considered.
 *
 * @param mapping The mapping from which to remove write permission
 * @return        A page table entry without write permission but otherwise
 *                identical to `mapping`
 */
static inline page_entry_t setMappingReadOnly(page_entry_t mapping) {
  return mapping & ~PG_RW;
}

/**
 * Make a page table entry writable.
 *
 * @param mapping The mapping to which to add write permission
 * @return        A page table entry with write permission but otherwise
 *                identical to `mapping`
 */
static inline page_entry_t setMappingReadWrite(page_entry_t mapping) {
  return mapping | PG_RW;
}

/**
 * Determine if this frame is an L1 page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L1 page table
 */
static inline bool isL1Pg(page_desc_t* frame) {
  return frame->type == PG_L1;
}

/**
 * Determine if this frame is an L2 page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L2 page table
 */
static inline bool isL2Pg(page_desc_t* frame) {
  return frame->type == PG_L2;
}

/**
 * Determine if this frame is an L3 page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L3 page table
 */
static inline bool isL3Pg(page_desc_t* frame) {
  return frame->type == PG_L3;
}

/**
 * Determine if this frame is an L4 page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L4 page table
 */
static inline bool isL4Pg(page_desc_t* frame) {
  return frame->type == PG_L4;
}

/**
 * Determine if this frame is an L1 extended page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L1 extended page table
 */
static inline bool isEPTL1Pg(page_desc_t* frame) {
  return frame->type == PG_EPTL1;
}

/**
 * Determine if this frame is an L2 extended page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L2 extended page table
 */
static inline bool isEPTL2Pg(page_desc_t* frame) {
  return frame->type == PG_EPTL2;
}

/**
 * Determine if this frame is an L3 extended page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L3 extended page table
 */
static inline bool isEPTL3Pg(page_desc_t* frame) {
  return frame->type == PG_EPTL3;
}

/**
 * Determine if this frame is an L4 extended page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is an L4 extended page table
 */
static inline bool isEPTL4Pg(page_desc_t* frame) {
  return frame->type == PG_EPTL4;
}

/**
 * Determine if this frame is used for SVA-internal data.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used for SVA-internal data
 */
static inline bool isSVAPg(page_desc_t* frame) {
  return frame->type == PG_SVA;
}

/**
 * Determine if this frame holds ghost data.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used to hold ghost data
 */
static inline bool isGhostPg(page_desc_t* frame) {
    return frame->type == PG_GHOST;
}

/**
 * Determine if this frame is used for code.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used for code
 */
static inline bool isCodePg(page_desc_t* frame) {
  return frame->type == PG_CODE;
}

/**
 * Determine if this frame is a page table which maps ordinary (non-secure)
 * memory.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used as a page table to map ordinary
 *              memory
 */
static inline bool isRegularPTP(page_desc_t* frame) {
  switch (frame->type) {
  case PG_L1:
  case PG_L2:
  case PG_L3:
  case PG_L4:
    return true;
  default:
    return false;
  }
}

/**
 * Determine if this frame is an extended page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used as an extended page table
 */
static inline bool isEPTP(page_desc_t* frame) {
  switch (frame->type) {
  case PG_EPTL1:
  case PG_EPTL2:
  case PG_EPTL3:
  case PG_EPTL4:
    return true;
  default:
    return false;
  }
}

/**
 * Determine if this frame is a page table which maps secure memory.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used as a page table to map secure
 *              memory
 */
static inline bool isGhostPTP(page_desc_t* frame) {
  switch (frame->type) {
  case PG_SML1:
  case PG_SML2:
  case PG_SML3:
    return true;
  default:
    return false;
  }
}

/**
 * Determine if this frame is a page table.
 *
 * @param frame The metadata for a frame
 * @return      Whether or not `frame` is used as a page table
 */
static inline bool isPTP(page_desc_t* frame) {
  return isRegularPTP(frame) || isEPTP(frame) || isGhostPTP(frame);
}

/**
 * Get the integer value of the page level of a page type.
 *
 * For example, `PG_L4` is level 4. Types that aren't page tables are defined
 * to have level 0.
 *
 * @param type The page type to get the integer level for
 * @return     The integer page level of the page type `type`
 */
static inline int getIntLevel(page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_EPTL1:
  case PG_SML1:
    return 1;
  case PG_L2:
  case PG_EPTL2:
  case PG_SML2:
    return 2;
  case PG_L3:
  case PG_EPTL3:
  case PG_SML3:
    return 3;
  case PG_L4:
  case PG_EPTL4:
    return 4;
  default:
    return 0;
  }
}

/**
 * Get the type of page mapped by the entries in a page table.
 *
 * @param level The level of page table
 * @return      The type of page mapped by entries in a page table at `level`
 */
static inline enum page_type_t getSublevelType(enum page_type_t level) {
  switch (level) {
  case PG_L4:
    return PG_L3;
  case PG_L3:
    return PG_L2;
  case PG_L2:
    return PG_L1;
  case PG_L1:
    return PG_DATA;
  default:
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Not a page table frame type\n");
  }
}

/**
 * Get the number of bytes mapped by a page table entry.
 *
 * @param level The level of the page table entry
 * @return      The number of bytes mapped by a page table entry at a given
 *              level page table
 */
static inline size_t getMappedSize(enum page_type_t level) {
  switch (level) {
  case PG_L1:
  case PG_EPTL1:
  case PG_SML1:
    return PG_L1_SIZE;
  case PG_L2:
  case PG_EPTL2:
  case PG_SML2:
    return PG_L2_SIZE;
  case PG_L3:
  case PG_EPTL3:
  case PG_SML3:
    return PG_L3_SIZE;
  case PG_L4:
  case PG_EPTL4:
    return PG_L4_SIZE;
  default:
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Not a page table frame type\n");
  }
}

#endif /* SVA_PAGE_UTIL_H */
