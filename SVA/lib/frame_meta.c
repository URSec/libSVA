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

frame_type_t frame_get_type(const frame_desc_t* frame) {
  frame_desc_t desc;
  __atomic_load(frame, &desc, __ATOMIC_ACQUIRE);
  return desc.type;
}

/**
 * Frame update callback.
 *
 * The callback is passed the current value of the frame metadata, the frame's
 * index, and an additional argument whose interpretation is specific to the
 * callback. It is expected to return the new frame metadata.
 */
typedef frame_desc_t (*update_fn)(frame_desc_t, size_t, uintptr_t);

/**
 * Atomically update frame metadata.
 *
 * This function will atomically load the current frame metadata, apply the
 * specified update to it, and then attempt to store it via compare-and-swap.
 * If the attempt to store the updated metadata fails, the update process is
 * attempted again until it succeedes.
 *
 * Additionally, if the frame is currently locked and the update does not
 * unlock the frame, the update is not performed until the frame is unlocked.
 *
 * @param frame     The frame to update
 * @param update_fn The update operation to perform
 * @param arg       An argument to pass to `update_fn`
 */
static void frame_update(frame_desc_t* frame, update_fn update, uintptr_t arg) {
  frame_desc_t old, new;
  __atomic_load(frame, &old, __ATOMIC_ACQUIRE);
  do {
    new = update(old, frame - frame_desc, arg);
  } while (!__atomic_compare_exchange(
              frame, &old, &new, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

static frame_desc_t
frame_morph_inner(frame_desc_t frame, size_t idx, uintptr_t type_) {
  frame_type_t type = type_;

  if (frame.type == type) {
    /*
     * The frame is already the requested type. We allow this "change" because
     * it makes dealing with certain races much simpler. In particular, if two
     * threads need to set a page to the same type, they don't need to decide
     * which of them should do it. Of course, we can't allow this for locked
     * frames, as doing so would defeat the purpose of locking.
     */

    // TODO: Wait until the frame becomes unlocked
    SVA_ASSERT(type != PGT_LOCKED,
      "SVA: FATAL: Attempt to lock already-locked frame 0x%lx\n", idx);

    return frame;
  }

  if (frame.type == PGT_FREE) {
    /*
     * A free frame can become any other type, with the exception that it must
     * have 0 total reference count to be used for secure memory.
     */
    if (frame_type_is_secmem(type)) {
      SVA_ASSERT(frame.ref_count == 0,
        "SVA: FATAL: Attempt to use frame 0x%lx as secure memory, "
        "but there are still %d references to it\n",
        idx, frame.ref_count);
    }
  } else {
    /*
     * We only support typed frames becoming free, not changing to a new type.
     * This restriction probably isn't strictly necessary, but there's no reason
     * to add extra complexity by lifting it.
     */
    SVA_ASSERT(type == PGT_FREE || type == PGT_LOCKED,
      "SVA: FATAL: Frame 0x%lx must first be free (currently %s) "
      "to become non-free type %s\n",
      idx, frame_type_name(frame.type), frame_type_name(type));

    /*
     * A frame must have 0 type count to become free. If the type count is not
     * 0, it means there are still uses of the frame that force its current
     * type, and making the frame free is unsafe.
     */
    SVA_ASSERT(frame.type_count == 0,
      "SVA: FATAL: Attempt to free frame 0x%lx with %d uses as type %s\n",
      idx, frame.type_count, frame_type_name(frame.type));

    /*
     * A few frame types are never allowed to be changed.
     */
    switch (frame.type) {
    /*
     * Unusable frames are unusable; they can never become anything else.
     */
    case PGT_UNUSABLE:
      SVA_ASSERT_UNREACHABLE("SVA: FATAL: Attempt to free frame 0x%lx "
        "with unfreeable type %s\n",
        idx, frame_type_name(frame.type));
    default:
      break;
    }
  }

  frame.type = type;

  return frame;
}

void frame_morph(frame_desc_t* frame, frame_type_t type) {
  frame_update(frame, frame_morph_inner, type);
}

static frame_desc_t
frame_lock_inner(frame_desc_t frame, size_t idx, uintptr_t old_type_) {
  frame_type_t* old_type = (frame_type_t*)old_type_;
  *old_type = frame.type;
  return frame_morph_inner(frame, idx, PGT_LOCKED);
}

frame_type_t frame_lock(frame_desc_t* frame) {
  frame_type_t old_type;
  frame_update(frame, frame_lock_inner, (uintptr_t)&old_type);
  return old_type;
}

static frame_desc_t
frame_unlock_inner(frame_desc_t frame, size_t idx, uintptr_t type_) {
  SVA_ASSERT(frame.type == PGT_LOCKED,
    "SVA: Internel error: Attempt to unlock frame 0x%lx, "
    "but it is not currently locked.\n", idx);

  frame.type = PGT_FREE;
  return frame_morph_inner(frame, idx, type_);
}

void frame_unlock(frame_desc_t* frame, frame_type_t type) {
  frame_update(frame, frame_unlock_inner, type);
}

struct take_drop_args {
  struct refcount_pair* old_refcounts;
  frame_type_t type;
};

static frame_desc_t
frame_take_inner(frame_desc_t frame, size_t idx, uintptr_t args_) {
  struct take_drop_args* args = (struct take_drop_args*)args_;

  frame_type_t type = args->type;

#ifdef SVA_DEBUG_CHECKS
  SVA_ASSERT(type != PGT_LOCKED,
    "SVA: Internal error: Attempt to take frame 0x%lx as locked type.\n", idx);
#endif

  SVA_ASSERT(frame_types_compatible(frame.type, type),
    "SVA: FATAL: Invalid use of frame 0x%lx (with type %s) as type %s\n",
    idx, frame_type_name(frame.type), frame_type_name(type));

  args->old_refcounts->ref_count = frame.ref_count;
  args->old_refcounts->type_count = frame.type_count;

  frame_ref_inc(&frame);
  if (type != PGT_FREE) {
    frame_tref_inc(&frame);
  }

  return frame;
}

struct refcount_pair frame_take(frame_desc_t* frame, frame_type_t type) {
  struct refcount_pair old_refcounts;

  frame_update(frame, frame_take_inner,
               (uintptr_t)&(struct take_drop_args){ &old_refcounts, type });

  return old_refcounts;
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

static frame_desc_t
frame_drop_inner(frame_desc_t frame, size_t idx, uintptr_t args_) {
  struct take_drop_args* args = (struct take_drop_args*)args_;

  frame_type_t type = args->type;

#ifdef SVA_DEBUG_CHECKS
  SVA_ASSERT(type != PGT_LOCKED,
    "SVA: Internal error: Attempt to take frame 0x%lx as locked type.\n", idx);
#endif

  SVA_ASSERT(frame_types_compatible(frame.type, type),
    "SVA: Internal error: dropping frame 0x%lx (with type %s) as type %s\n",
    idx, frame_type_name(frame.type), frame_type_name(type));

  args->old_refcounts->ref_count = frame.ref_count;
  args->old_refcounts->type_count = frame.type_count;

  /*
   * Decrement the type count *before* the reference count to avoid the type
   * count temporarily being higher than the reference count.
   */
  if (type != PGT_FREE) {
    frame_tref_dec(&frame);
  }
  frame_ref_dec(&frame);

  return frame;
}

struct refcount_pair frame_drop(frame_desc_t* frame, frame_type_t type) {
  struct refcount_pair old_refcounts;

  frame_update(frame, frame_drop_inner,
               (uintptr_t)&(struct take_drop_args){ &old_refcounts, type });

  return old_refcounts;
}

void frame_drop_force(frame_desc_t* frame) {
  /*
   * Only decrement the reference count: the type count is reset by
   * `frame_take_force`, so any references we are dropping are not contributing
   * to the type count.
   */
  frame_ref_dec(frame);
}
