/*===- frame_meta.h - SVA Execution Engine  =--------------------------------===
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
 * SVA frame metadata.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_FRAME_META_H
#define SVA_FRAME_META_H

#include <sva/page.h>

/**
 * The type of a frame.
 *
 * These types are mutually exclusive: a frame may only be one type at a time,
 * and all uses as its current type must be dropped before it can change type.
 *
 * Note that all types except `PGT_DATA` are "sticky": a frame's type will not
 * automatically change to `PGT_FREE` when it's type reference count drops to 0.
 * The type of the frame must be reset using the appropriate undeclare call for
 * its current type.
 */
typedef enum page_type_t {
  PGT_FREE,     ///< Frame is not currently used as any type
  PGT_UNUSABLE, ///< Frame is not present or is reserved by firmware
  PGT_DATA,     ///< Frame is used as writable data
  PGT_SVA,      ///< Frame is used internally by SVA
  PGT_GHOST,    ///< Frame is used for ghost memory
  PGT_CODE,     ///< Frame is used for code
  PGT_L1,       ///< Frame is used as an L1 page table
  PGT_L2,       ///< Frame is used as an L2 page table
  PGT_L3,       ///< Frame is used as an L3 page table
  PGT_L4,       ///< Frame is used as an L4 page table
  PGT_EPTL1,    ///< Frame is used as an L1 extended page table
  PGT_EPTL2,    ///< Frame is used as an L2 extended page table
  PGT_EPTL3,    ///< Frame is used as an L3 extended page table
  PGT_EPTL4,    ///< Frame is used as an L4 extended page table
  PGT_SML1,     ///< Frame is used as an L1 page table for secure memory
  PGT_SML2,     ///< Frame is used as an L2 page table for secure memory
  PGT_SML3      ///< Frame is used as an L3 page table for secure memory
} page_type_t;

/**
 * Frame descriptor metadata.
 *
 * There is one element of this structure for each physical frame of memory in
 * the system.  It records information about the physical memory (and the data
 * stored within it) that SVA needs to perform its MMU safety checks.
 */
typedef struct page_desc_t {
#if 0 // The value stored in this field is never actually used
  /**
   * If the page is a page table page, mark the virtual address to which it is
   * mapped.
   */
  uintptr_t pgVaddr;
#endif

#ifdef SVA_ASID_PG
  /**
   * The physical adddress of the other (kernel or user/SVA) version pml4 page
   * table page.
   */
  uintptr_t other_pgPaddr;
#endif

  /**
   * The type of this frame.
   */
  page_type_t type : 8;

#define PG_REF_COUNT_BITS 12
#define PG_REF_COUNT_MAX ((1U << PG_REF_COUNT_BITS) - 1)

  /**
   * Number of times this frame is mapped.
   */
  unsigned count : PG_REF_COUNT_BITS;

  /**
   * Number of times this frame is mapped writable.
   */
  unsigned wr_count : PG_REF_COUNT_BITS;
} page_desc_t;

/**
 * Size in bytes of the maximum supported amount of physical memory
 */
static const unsigned long memSize = 0x0000002000000000u; /* 128GB */

/**
 * Number of frame metadata entries
 */
static const unsigned long numPageDescEntries = memSize / PG_L1_SIZE;

/**
 * Array describing the physical frames.
 *
 * Used by SVA's MMU and EPT intrinsics.
 *
 * The index is the physical frame number.
 */
extern page_desc_t page_desc[numPageDescEntries];

/**
 * Get the frame metadata for the specified frame.
 *
 * @param mapping Either the physical address of the frame or a page table entry
 *                which maps the frame
 * @return        The frame metadata for the frame specified in `mapping`
 */
page_desc_t* getPageDescPtr(unsigned long mapping);

/**
 * Get the number of active references to a page.
 *
 * @param page  The page for which to get the reference count
 * @return      The reference count for the page
 */
static inline unsigned int pgRefCount(page_desc_t* page) {
  return page->count;
}

/**
 * Get the number of writable references to a page.
 *
 * @param page  The page for which to get the writable reference count
 * @return      The writable reference count for the page
 */
static inline unsigned int pgRefCountWr(page_desc_t* page) {
  return page->wr_count;
}

/**
 * Increment a page's writable reference count, and get the old value.
 *
 * This is useful for e.g. copy-on-write to change just a frame's writable
 * reference count.
 *
 * @param page  The page whose writable reference count is to be incremented
 * @return      The old writable reference count for the page
 */
static inline unsigned int pgRefCountIncWr(page_desc_t* page) {
  unsigned int wr_count = page->wr_count;

  SVA_ASSERT(wr_count + 1 <= page->count,
    "SVA: FATAL: Frame metadata inconsistency: "
    "writable count is greater than total count: frame 0x%lx\n",
    (page - page_desc));

  SVA_ASSERT(wr_count < PG_REF_COUNT_MAX,
    "SVA: FATAL: Overflow in frame writable reference count: frame %lx\n",
    (page - page_desc));
  page->wr_count = wr_count + 1;

  return wr_count;
}

/**
 * Decrement a page's writable reference count, and get the old value.
 *
 * This is useful for e.g. copy-on-write to change just a frame's writable
 * reference count.
 *
 * @param page  The page whose writable reference count is to be decremented
 * @return      The old writable reference count for the page
 */
static inline unsigned int pgRefCountDecWr(page_desc_t* page) {
  unsigned int wr_count = page->wr_count;

  SVA_ASSERT(wr_count <= page->count,
    "SVA: FATAL: Frame metadata inconsistency: "
    "writable count is greater than total count: frame 0x%lx\n",
    (page - page_desc));

  SVA_ASSERT(wr_count > 0,
    "SVA: FATAL: Frame metadata inconsistency: "
    "attempt to decrement writable reference count below 0: "
    "frame %lx\n", (page - page_desc));
  page->wr_count = wr_count - 1;

  return wr_count;
}

/**
 * Increment a page's reference count, and get the old value.
 *
 * @param page      The page whose reference count is to be incremented
 * @param writable  Whether to also increment the writable reference count
 * @return          The old reference count for the page
 */
static inline unsigned int pgRefCountInc(page_desc_t* page, bool writable) {
  unsigned int count = page->count;

  SVA_ASSERT(count < PG_REF_COUNT_MAX,
    "SVA: FATAL: Overflow in frame reference count: frame %lx\n",
    (page - page_desc));
  page->count = count + 1;
  if (writable) {
    pgRefCountIncWr(page);
  }

  return count;
}

/**
 * Decrement a page's reference count, and get the old value.
 *
 * @param page      The page whose reference count is to be decremented
 * @param writable  Whether to also increment the writable reference count
 * @return          The old reference count for the page
 */
static inline unsigned int pgRefCountDec(page_desc_t* page, bool writable) {
  unsigned int count = page->count;

  if (writable) {
    pgRefCountDecWr(page);
  }
  SVA_ASSERT(count > 0,
    "SVA: FATAL: Frame metadata inconsistency: "
    "attempt to decrement reference count below 0: "
    "frame %lx\n", (page - page_desc));
  page->count = count - 1;

  return count;
}

#endif /* SVA_FRAME_META_H */
