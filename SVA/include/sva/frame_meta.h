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

#include <sva/assert.h>
#include <sva/page.h>

/**
 * The type of a frame.
 *
 * These types are mutually exclusive: a frame may only be one type at a time,
 * and all uses as its current type must be dropped before it can change type.
 *
 * Note that frame types are "sticky": a frame's type will not automatically
 * change to `PGT_FREE` when it's type reference count drops to 0. The type of
 * the frame must be reset using the appropriate undeclare call for its current
 * type.
 */
typedef enum frame_type_t {
  PGT_FREE,     ///< Frame is not currently used as any type.
  PGT_LOCKED,   ///< Frame is currently locked.
  PGT_UNUSABLE, ///< Frame is not present or is reserved by firmware.
  PGT_DATA,     ///< Frame is used as writable data.
  PGT_SVA,      ///< Frame is used internally by SVA.
  PGT_GHOST,    ///< Frame is used for ghost memory.
  PGT_CODE,     ///< Frame is used for code.
  PGT_L1,       ///< Frame is used as an L1 page table.
  PGT_L2,       ///< Frame is used as an L2 page table.
  PGT_L3,       ///< Frame is used as an L3 page table.
  PGT_L4,       ///< Frame is used as an L4 page table.
  PGT_EPTL1,    ///< Frame is used as an L1 extended page table.
  PGT_EPTL2,    ///< Frame is used as an L2 extended page table.
  PGT_EPTL3,    ///< Frame is used as an L3 extended page table.
  PGT_EPTL4,    ///< Frame is used as an L4 extended page table.
  PGT_SML1,     ///< Frame is used as an L1 page table for secure memory.
  PGT_SML2,     ///< Frame is used as an L2 page table for secure memory.
  PGT_SML3      ///< Frame is used as an L3 page table for secure memory.
} frame_type_t;

/**
 * Frame descriptor metadata.
 *
 * There is one element of this structure for each physical frame of memory in
 * the system.  It records information about the physical memory (and the data
 * stored within it) that SVA needs to perform its MMU safety checks.
 */
typedef struct frame_desc_t {
#if 0 // The value stored in this field is never actually used
  /**
   * If the page is a page table page, mark the virtual address to which it is
   * mapped.
   */
  uintptr_t pgVaddr;
#endif

  /**
   * This frame's type.
   */
  frame_type_t type : 8;

#define FR_REF_COUNT_BITS 12
#define FR_REF_COUNT_MAX ((1U << FR_REF_COUNT_BITS) - 1)

  /**
   * Number of uses of this frame.
   */
  unsigned ref_count : FR_REF_COUNT_BITS;

  /**
   * Number of uses of this frame that force its current type.
   */
  unsigned type_count : FR_REF_COUNT_BITS;
} frame_desc_t;

/**
 * Size in bytes of the maximum supported amount of physical memory
 */
static const unsigned long memSize = 0x0000002000000000u; /* 128GB */

/**
 * Array describing the physical frames.
 *
 * Used by SVA's MMU and EPT intrinsics.
 *
 * The index is the physical frame number.
 */
extern frame_desc_t frame_desc[memSize / FRAME_SIZE];

/**
 * Get the frame metadata for the specified frame.
 *
 * @param mapping Either the physical address of the frame or a page table entry
 *                which maps the frame
 * @return        The frame metadata for the frame specified in `mapping`
 */
frame_desc_t* get_frame_desc(unsigned long mapping);

/**
 * Change the type of a frame after performing validity checks.
 *
 * @param frame The frame to change to a new type
 * @param type  The new type to which to change `frame`
 */
void frame_morph(frame_desc_t* frame, frame_type_t type);

/**
 * Lock a frame.
 *
 * A locked frame cannot have its type changed except by `frame_unlock`.
 *
 * @param frame The frame to lock
 */
void frame_lock(frame_desc_t* frame);

/**
 * Unlock a frame and change its type to the one specified.
 *
 * @param frame The frame to unlock
 * @param type  The new type for the frame
 */
void frame_unlock(frame_desc_t* frame, frame_type_t type);

/**
 * Take a reference to a frame with the specified type.
 *
 * Panics if the type of the frame is not the correct type.
 *
 * @param frame The frame to which the caller is taking a reference
 * @param type  The frame type as which the caller wants to use `frame`
 */
void frame_take(frame_desc_t* frame, frame_type_t type);

/**
 * Take a reference to a frame with the specified type.
 *
 * Unlike `frame_take`, this function forces the frame to the specified type.
 * It is critical that the caller will clean up any mappings which are illegal
 * for the frame's new type.
 *
 * NB: This function is not thread-safe; use during init only.
 *
 * @param frame The frame to which the caller is taking a reference
 * @param type  The frame type as which the caller wants to use `frame`
 */
void frame_take_force(frame_desc_t* frame, frame_type_t type);

/**
 * Drop a reference to a frame with the specified type.
 *
 * Panics if the type of the frame is not the correct type.
 *
 * @param frame The frame to which the caller is dropping a reference
 * @param type  The frame type as which the caller used `frame`
 */
void frame_drop(frame_desc_t* frame, frame_type_t type);

/**
 * Drop a reference to a frame which had its type reset by `frame_take_force`.
 *
 * When a frame has its type changed by `frame_take_force`, this should be used
 * to drop any remaining unsafe references.
 *
 * NB: This function is not thread-safe; use during init only.
 *
 * @param frame The frame to which the caller is dropping a reference
 */
void frame_drop_force(frame_desc_t* frame);

/**
 * Get the name of a frame type.
 *
 * @param type  A frame type
 * @return      A string containing the name of the frame type `type`
 */
static inline const char* frame_type_name(frame_type_t type) {
#define FR_TY(t) case PGT_##t: return #t;
  switch (type) {
    FR_TY(FREE);
    FR_TY(UNUSABLE);
    FR_TY(DATA);
    FR_TY(SVA);
    FR_TY(GHOST);
    FR_TY(CODE);
    FR_TY(L1);
    FR_TY(L2);
    FR_TY(L3);
    FR_TY(L4);
    FR_TY(EPTL1);
    FR_TY(EPTL2);
    FR_TY(EPTL3);
    FR_TY(EPTL4);
    FR_TY(SML1);
    FR_TY(SML2);
    FR_TY(SML3);
  default:
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: invalid frame type %d\n", type);
  }
#undef FR_TY
}

#endif /* SVA_FRAME_META_H */
