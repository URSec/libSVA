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
  return pte & PG_P;
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
  return pte & PG_W;
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
static inline bool isHugePage(page_entry_t pte, frame_type_t level) {
  switch (level) {
  case PGT_L1:
  case PGT_L4:
  case PGT_EPTL1:
  case PGT_EPTL4:
    return false;
  case PGT_L2:
  case PGT_L3:
    return pte & PG_PS;
  case PGT_EPTL2:
  case PGT_EPTL3:
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
static inline bool isLeafEntry(page_entry_t pte, frame_type_t level) {
  switch (level) {
  case PGT_L1:
  case PGT_EPTL1:
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
  return mapping & ~PG_W;
}

/**
 * Make a page table entry writable.
 *
 * @param mapping The mapping to which to add write permission
 * @return        A page table entry with write permission but otherwise
 *                identical to `mapping`
 */
static inline page_entry_t setMappingReadWrite(page_entry_t mapping) {
  return mapping | PG_W;
}

/**
 * Determine if this frame type is a page table which maps ordinary
 * (non-secure) memory.
 *
 * @param type  A frame type
 * @return      Whether or not `type` is an ordinary page table type
 */
static inline bool isRegularPTP(frame_type_t type) {
  switch (type) {
  case PGT_L1:
  case PGT_L2:
  case PGT_L3:
  case PGT_L4:
    return true;
  default:
    return false;
  }
}


/**
 * Determine if this frame type is an extended page table.
 *
 * @param type  A frame type
 * @return      Whether or not `type` is an extended page table type
 */
static inline bool isEPTP(frame_type_t type) {
  switch (type) {
  case PGT_EPTL1:
  case PGT_EPTL2:
  case PGT_EPTL3:
  case PGT_EPTL4:
    return true;
  default:
    return false;
  }
}

/**
 * Determine if this frame type is a page table which maps secure memory.
 *
 * @param type  A frame type
 * @return      Whether or not `type` is a secure memory page table type
 */
static inline bool isGhostPTP(frame_type_t type) {
  switch (type) {
  case PGT_SML1:
  case PGT_SML2:
  case PGT_SML3:
    return true;
  default:
    return false;
  }
}

/**
 * Determine if this frame type is a page table.
 *
 * @param type  A frame type
 * @return      Whether or not `type` is a page table type
 */
static inline bool isPTP(frame_type_t type) {
  return isRegularPTP(type) || isEPTP(type) || isGhostPTP(type);
}

/**
 * Get the integer value of the page level of a page type.
 *
 * For example, `PGT_L4` is level 4. Types that aren't page tables are defined
 * to have level 0.
 *
 * @param type The page type to get the integer level for
 * @return     The integer page level of the page type `type`
 */
static inline int getIntLevel(frame_type_t level) {
  switch (level) {
  case PGT_L1:
  case PGT_EPTL1:
  case PGT_SML1:
    return 1;
  case PGT_L2:
  case PGT_EPTL2:
  case PGT_SML2:
    return 2;
  case PGT_L3:
  case PGT_EPTL3:
  case PGT_SML3:
    return 3;
  case PGT_L4:
  case PGT_EPTL4:
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
static inline frame_type_t getSublevelType(frame_type_t level) {
  switch (level) {
  case PGT_L4:
    return PGT_L3;
  case PGT_L3:
    return PGT_L2;
  case PGT_L2:
    return PGT_L1;
  case PGT_EPTL4:
    return PGT_EPTL3;
  case PGT_EPTL3:
    return PGT_EPTL2;
  case PGT_EPTL2:
    return PGT_EPTL1;
  default:
    SVA_ASSERT_UNREACHABLE(
      "SVA: FATAL: %s not a page table frame type\n",
      frame_type_name(level));
  }
}

/**
 * Get the number of bytes mapped by a page table entry.
 *
 * @param level The level of the page table entry
 * @return      The number of bytes mapped by a page table entry at a given
 *              level page table
 */
static inline size_t getMappedSize(frame_type_t level) {
  switch (level) {
  case PGT_L1:
  case PGT_EPTL1:
  case PGT_SML1:
    return PG_L1_SIZE;
  case PGT_L2:
  case PGT_EPTL2:
  case PGT_SML2:
    return PG_L2_SIZE;
  case PGT_L3:
  case PGT_EPTL3:
  case PGT_SML3:
    return PG_L3_SIZE;
  case PGT_L4:
  case PGT_EPTL4:
    return PG_L4_SIZE;
  default:
    SVA_ASSERT_UNREACHABLE(
      "SVA: FATAL: %s not a page table frame type\n",
      frame_type_name(level));
  }
}

/**
 * Determine if an index into an L4 page table is a secure memory entry.
 *
 * @param idx An index into an L4 page table
 * @return    Whether `idx` is an index for a secure memory L4 entry
 */
static inline bool isSecMemL4Entry(size_t idx) {
  return idx >= PG_L4_ENTRY(SECMEMSTART) && idx < PG_L4_ENTRY(SECMEMEND);
}

#endif /* SVA_PAGE_UTIL_H */
