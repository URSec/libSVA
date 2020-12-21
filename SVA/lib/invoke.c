/*===- invoke.c - SVA Execution Engine  -------------------------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 * Copyright 2019-2020 The University of Rochester.
 * Copyright 2006-2009 University of Illinois.
 * Portions Copyright 1997 Andi Kleen <ak@muc.de>.
 * Portions Copyright 1997 Linus Torvalds.
 * 
 *===------------------------------------------------------------------------===
 *
 * This is the code for the SVA Execution Engine that manages invoke/unwind
 * functionality.
 *
 *===------------------------------------------------------------------------===
 */

#include <sva/invoke.h>
#include <sva/assert.h>
#include <sva/self_profile.h>
#include <sva/icontext.h>
#include <sva/uaccess.h>
#include <sva/util.h>
#include <sva/callbacks.h>
#include <sva/offsets.h>

/**
 * Initialize and install an invoke frame.
 *
 * @param frame The invoke frame to create
 */
static void invoke_frame_setup(struct invoke_frame* frame) {
  struct CPUState* cpup = getCPUState();

  /*
   * Get the pointer to the most recent invoke frame.
   */
  struct invoke_frame* gip = cpup->gip;

  /*
   * Mark the frame as having its fixup address stored in `%rbx`.
   */
  frame->cpinvoke = INVOKE_FIXUP;
  frame->next = gip;

  /*
   * Make it the top invoke frame.
   */
  cpup->gip = frame;
}

/**
 * Uninstall an invoke frame
 *
 * @param frame The invoke frame to destroy
 */
static void invoke_frame_teardown(struct invoke_frame* frame) {
  struct CPUState* cpup = getCPUState();

  /*
   * Pop off the invoke frame.
   */
  cpup->gip = frame->next;
}

bool sva_iunwind(void) {
  /* Assembly code that finishes the unwind */
  extern void sva_invoke_except(void);

  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Disable interrupts.
   */
  uintptr_t rflags = sva_enter_critical();

  /*
   * Get the pointer to the most recent invoke frame and interrupt context.
   */
  struct CPUState* cpup = getCPUState();
  struct invoke_frame* gip = cpup->gip;
  sva_icontext_t* ip = cpup->newCurrentIC;

  /*
   * Do nothing if there is no invoke stack.
   */
  if (!gip) {
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(iunwind, 1);
    return false;
  }

  /*
   * Check the invoke frame for read access.
   */
  sva_check_memory_read (gip, sizeof (struct invoke_frame));

  /*
   * Check the interrupt context pointer for write access.
   */
  sva_check_memory_write (ip, sizeof (sva_icontext_t));

  /*
   * Adjust the program state so that it resumes inside the invoke instruction.
   */
  switch (gip->cpinvoke) {
    case INVOKE_NORMAL:
      ip->rip = (uintptr_t)sva_invoke_except;
      break;

#if 0
    case INVOKE_MEMCPY_W:
      ip->rcx = (ip->rcx) << 2;
    case INVOKE_MEMCPY_B:
#endif
    case INVOKE_STRNCPY:
      ip->rip = gip->rbx;
      break;
    case INVOKE_FIXUP:
      /*
       * Fixup address stored in `%rbx`
       */
      ip->rip = ip->rbx;
      break;
    default:
      SVA_ASSERT_UNREACHABLE(
        "SVA: Internal error: Invalid invoke frame type %ld\n",
        gip->cpinvoke);
  }

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT_MULTI(iunwind, 2);
  return true;
}

size_t memcpy_safe(void __noderef* dst, const void __noderef* src, size_t len) {
  /// Our invoke frame.
  struct invoke_frame frame;

  invoke_frame_setup(&frame);

  size_t remaining;

  stac();
  asm volatile (
    /*
     * Set our fixup target.
     */
    "lea 1f(%%rip), %%rbx\n\t"

    /*
     * Perform the memcpy.
     */
    "rep movsb\n"

    /*
     * The fixup target. In this case, there is nothing to do.
     */
    "1:\n\t"
    : "+D"(dst), "+S"(src), "=c"(remaining)
    : "c"(len)
    : "rbx", "memory");
  clac();

  invoke_frame_teardown(&frame);

  return remaining;
}

size_t sva_invokememcpy(char __kern* dst, const char __kern* src, size_t count) {
  /*
   * Make sure we aren't copying from secure memory.
   */
  if (!is_valid_kernel_ptr(src, count)) {
    return 0;
  }

  /*
   * Make sure we aren't copying to secure memory.
   */
  if (!is_valid_kernel_ptr(dst, count)) {
    return 0;
  }

  return count - memcpy_safe((void __noderef*)dst, (void __noderef*)src, count);
}

size_t sva_invokememset(char __kern* dst, char val, size_t count) {
  /*
   * Make sure we aren't copying to secure memory.
   */
  if (!is_valid_kernel_ptr(dst, count)) {
    return 0;
  }

  /// Our invoke frame.
  struct invoke_frame frame;

  invoke_frame_setup(&frame);

  size_t remaining;

  stac();
  asm volatile (
    /*
     * Set our fixup target.
     */
    "lea 1f(%%rip), %%rbx\n\t"

    /*
     * Perform the memset.
     */
    "rep stosb\n"

    /*
     * The fixup target. In this case, there is nothing to do.
     */
    "1:\n\t"
    : "+D"(dst), "=c"(remaining)
    : "a"(val), "c"(count)
    : "rbx", "memory");
  clac();

  invoke_frame_teardown(&frame);

  return count - remaining;
}
