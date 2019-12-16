/*===- frame_meta.c - SVA Execution Engine  =--------------------------------===
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

#include <sva/frame_meta.h>
#include <sva/assert.h>

frame_desc_t __svadata frame_desc[memSize / FRAME_SIZE];

/**
 * Determine if a frame type is a secure memory type.
 *
 * @param type  A frame type
 * @return      Whether `type` is a secure memory frame type
 */
bool frame_type_is_secmem(frame_type_t type) {
  switch (type) {
  case PGT_SVA:
  case PGT_GHOST:
  case PGT_SML1:
  case PGT_SML2:
  case PGT_SML3:
    /*
     * The page table types are counted as secure memory in order to defend
     * against side channel attacks.
     */
    return true;
  default:
    return false;
  }
}

/**
 * Determine if two frame types are compatible, i.e. if a frame that has one
 * type can be used as another.
 *
 * @param current The current type of the frame
 * @param use     The type as which the frame is intended to be used
 * @return        Whether a frame with type `current` can be used as `use`
 */
static bool frame_types_compatible(frame_type_t current, frame_type_t use) {
  if (current == use) {
    return true;
  }

  if (use != PGT_FREE) {
    /*
     * Use of a frame in multiple ways at once is always forbidden, unless one
     * of those ways is as a read-only data frame.
     *
     * Note that `PGT_FREE` here isn't used to mean that the frame is actually
     * free, but that the use doesn't force a particular type (because it is
     * used as read-only data).
     */
    return false;
  }

  /*
   * The kernel isn't allowed to use frames with a secure memory type at all in
   * order to protect the confidentiality of the data they contain.
   */
  return !frame_type_is_secmem(current);
}

/**
 * Increment a frame's reference count.
 *
 * @param frame The frame whose reference count is to be incremented
 */
static void frame_ref_inc(frame_desc_t* frame) {
  unsigned int count = frame->ref_count;
  SVA_ASSERT(count < FR_REF_COUNT_MAX,
    "SVA: FATAL: Overflow in frame 0x%lx reference count\n",
    frame - frame_desc);

  frame->ref_count = count + 1;
}

/**
 * Increment a frame's type count.
 *
 * @param frame The frame whose type count is to be incremented
 */
static void frame_tref_inc(frame_desc_t* frame) {
  unsigned int count = frame->type_count;
  SVA_ASSERT(count < FR_REF_COUNT_MAX,
    "SVA: FATAL: Overflow in frame 0x%lx type count\n",
    frame - frame_desc);
  SVA_ASSERT(count + 1 <= frame->ref_count,
    "SVA: Internal error: Frame 0x%lx type count above reference count\n",
    frame - frame_desc);

  frame->type_count = count + 1;
}

/**
 * Decrement a frame's reference count.
 *
 * @param frame The frame whose reference count is to be decremented
 */
static void frame_ref_dec(frame_desc_t* frame) {
  unsigned int count = frame->ref_count;
  SVA_ASSERT(count > 0,
    "SVA: Internal error: Frame 0x%lx reference count below 0\n",
    frame - frame_desc);

  frame->ref_count = count - 1;
}

/**
 * Decrement a frame's type count.
 *
 * @param frame The frame whose type count is to be decremented
 */
static void frame_tref_dec(frame_desc_t* frame) {
  unsigned int count = frame->type_count;
  SVA_ASSERT(count > 0,
    "SVA: Internal error: Frame 0x%lx type count below 0\n",
    frame - frame_desc);
  SVA_ASSERT(count <= frame->ref_count,
    "SVA: Internal error: Frame 0x%lx type count above reference count\n",
    frame - frame_desc);

  frame->type_count = count - 1;
}

frame_desc_t* get_frame_desc(unsigned long mapping) {
  size_t frameIndex = PG_ENTRY_FRAME(mapping) / FRAME_SIZE;
  return frameIndex < ARRAY_SIZE(frame_desc) ? &frame_desc[frameIndex] : NULL;
}

void frame_morph(frame_desc_t* frame, frame_type_t type) {
  if (frame->type == PGT_FREE) {
    /*
     * A free frame can become any other type, with the exception that it must
     * have 0 total reference count to be used for secure memory.
     */
    if (frame_type_is_secmem(type)) {
      SVA_ASSERT(frame->ref_count == 0,
        "SVA: FATAL: Attempt to use frame 0x%lx as secure memory, "
        "but there are still %d references to it\n",
        frame - frame_desc, frame->ref_count);
    }
  } else {
    /*
     * We only support typed frames becoming free, not changing to a new type.
     * This restriction probably isn't strictly necessary, but there's no reason
     * to add extra complexity by lifting it.
     */
    SVA_ASSERT(type == PGT_FREE,
      "SVA: FATAL: Frame 0x%lx must first be free (currently %s) "
      "to become non-free type %s\n",
      frame - frame_desc, frame_type_name(frame->type), frame_type_name(type));

    /*
     * A frame must have 0 type count to become free. If the type count is not
     * 0, it means there are still uses of the frame that force it's current
     * type, and making the frame free is unsafe.
     */
    SVA_ASSERT(frame->type_count == 0,
      "SVA: FATAL: Attempt to free frame 0x%lx with %d uses as type %s\n",
      frame - frame_desc, frame->type_count, frame_type_name(frame->type));

    /*
     * A few frame types are never allowed to be changed.
     */
    switch (frame->type) {
    /*
     * Unusable frames are unusable; they can never become anything else.
     */
    case PGT_UNUSABLE:
      SVA_ASSERT_UNREACHABLE("SVA: FATAL: Attempt to free frame 0x%lx "
        "with unfreeable type %s\n",
        frame - frame_desc, frame_type_name(frame->type));
    default:
      break;
    }
  }

  frame->type = type;
}

void frame_take(frame_desc_t* frame, frame_type_t type) {
  SVA_ASSERT(frame_types_compatible(frame->type, type),
    "SVA: FATAL: Invalid use of frame 0x%lx (with type %s) as type %s\n",
    frame - frame_desc, frame_type_name(frame->type), frame_type_name(type));

  frame_ref_inc(frame);
  if (type != PGT_FREE) {
    frame_tref_inc(frame);
  }
}

void frame_take_force(frame_desc_t* frame, frame_type_t type) {
  frame_type_t old_type = frame->type;

  frame->type = type;

  frame_ref_inc(frame);
  if (type == old_type) {
    if (type != PGT_FREE) {
      frame_tref_inc(frame);
    }
  } else {
    /*
     * The type changed: reset the type count
     */
    frame->type_count = type == PGT_FREE ? 0 : 1;
  }
}

void frame_drop(frame_desc_t* frame, frame_type_t type) {
  SVA_ASSERT(frame_types_compatible(frame->type, type),
    "SVA: Internal error: dropping frame 0x%lx (with type %s) as type %s\n",
    frame - frame_desc, frame_type_name(frame->type), frame_type_name(type));

  /*
   * Decrement the type count *before* the reference count to avoid the type
   * count temporarily being higher than the reference count.
   */
  if (type != PGT_FREE) {
    frame_tref_dec(frame);
  }
  frame_ref_dec(frame);
}
