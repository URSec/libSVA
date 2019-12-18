/*===- invoke.c - SVA Execution Engine  -------------------------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the GNU General Public License Version 2. See the file named COPYING for
 * details.  Note that the code is provided with no warranty.
 *
 * Copyright 2006-2009 University of Illinois.
 * Portions Copyright 1997 Andi Kleen <ak@muc.de>.
 * Portions Copyright 1997 Linus Torvalds.
 * 
 *===------------------------------------------------------------------------===
 *
 * The code from the Linux kernel was brought in and modified on 2006/05/09.
 * The code was primarily used for its fast strncpy() and strnlen()
 * implementations; the code for handling MMU faults during the memory
 * operations were modified for sva_invokestrncpy() and possibly modified for
 * sva_invokestrnlen().
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
#include <sva/state.h>
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

void sva_iunwind(void) {
  /* Assembly code that finishes the unwind */
  extern void sva_invoke_except(void);

  uint64_t tsc_tmp = 0;
  if (tsc_read_enable_sva)
    tsc_tmp = sva_read_tsc();

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
    record_tsc(sva_iunwind_1_api, sva_read_tsc() - tsc_tmp);
    return;
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
  record_tsc(sva_iunwind_2_api, sva_read_tsc() - tsc_tmp);
}

size_t sva_invokememcpy(char* dst, const char* src, size_t count) {
  /*
   * Make sure we aren't copying from secure memory.
   */
  sva_check_buffer((uintptr_t)src, count);

  /*
   * Make sure we aren't copying to secure memory.
   */
  sva_check_buffer((uintptr_t)dst, count);

  /// Our invoke frame.
  struct invoke_frame frame;

  invoke_frame_setup(&frame);

  size_t remaining;

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
    : "c"(count)
    : "rbx", "memory");

  invoke_frame_teardown(&frame);

  return count - remaining;
}

size_t sva_invokememset(char* dst, char val, size_t count) {
  /*
   * Make sure we aren't copying to secure memory.
   */
  sva_check_buffer((uintptr_t)dst, count);

  /// Our invoke frame.
  struct invoke_frame frame;

  invoke_frame_setup(&frame);

  size_t remaining;

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

  invoke_frame_teardown(&frame);

  return count - remaining;
}

uintptr_t sva_invokestrncpy(char* dst, const char* src, size_t count) {
  /*
   * NOTE:
   *  This function contains inline assembly code from the original i386 Linux
   *  2.4.22 kernel code.  I believe it originates from the
   *  __do_strncpy_from_user() macro in arch/i386/lib/usercopy.c.
   */

  /*
   * TODO:
   *  It is not clear whether this version will be as fast as the x86_64 version
   *  in FreeBSD 9.0; this version is an x86_64 port of the original Linux 2.4.22
   *  code for 32-bit processors.
   */

  uint64_t tsc_tmp = 0;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;

  /* Return value */
  uintptr_t res;

  /* Other variables */
  uintptr_t __d0, __d1, __d2;

  /*
   * Determine if there is anything to copy.  If not, then return now.
   */
  if (count == 0)
  {
    usersva_to_kernel_pcid();
    record_tsc(sva_invokestrncpy_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
    return 0;
  }

  invoke_frame_setup(&frame);

  /* Perform the strncpy */
  __asm__ __volatile__(
    " leaq 2f(%%rip), %%rbx\n"
    "0: lodsb\n"
    " stosb\n"
    " testb %%al,%%al\n"
    " jz 1f\n"
    " decq %1\n"
    " jnz 0b\n"
    " jmp 1f\n"
    "2: movq $0xffffffffffffffff, %0\n"
    " jmp 3f\n"
    "1: subq %1,%0\n"
    "3:\n"
    : "=d"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1), "=&D" (__d2)
    : "i"(0), "0"(count), "1"(count), "3"(src), "4"(dst)
    : "rbx", "memory");

  invoke_frame_teardown(&frame);

  usersva_to_kernel_pcid();
  record_tsc(sva_invokestrncpy_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return res;
}

