/*===- state.c - SVA Execution Engine  ------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Provide intrinsics for manipulating the LLVA machine state.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include <sva/types.h>
#if 1
#include <sva/config.h>
#endif
#include <sva/cfi.h>
#include <sva/callbacks.h>
#include <sva/fpu.h>
#include <sva/util.h>
#include <sva/state.h>
#include <sva/icontext.h>
#include <sva/interrupt.h>
#include <sva/invoke.h>
#include <sva/mmu.h>
#include <sva/mmu_intrinsics.h>
#include <sva/mpx.h>
#include <sva/self_profile.h>
#include <sva/uaccess.h>
#include <sva/x86.h>
#include "thread_stack.h"

/*****************************************************************************
 * Externally Visibile Utility Functions
 ****************************************************************************/

void
installNewPushTarget (void) {
  /* Get the current SVA thread */
  struct SVAThread * threadp = getCPUState()->currentThread;

  /* Get the current interrput context */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /*
   * Make sure we have room for another target.
   */
  if (threadp->numPushTargets == maxPushTargets)
    return;

  /*
   * Add the new target.
   */
  threadp->validPushTargets[(threadp->numPushTargets)++] = (void *) icp->rdi;
  return;
}

/*****************************************************************************
 * Intrinsics for User-Space Applications
 ****************************************************************************/

void
getThreadRID (void) {
  /* Get the current interrput context */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /* Set the rax register with the pointer to the secret key */
  icp->rax = getCPUState()->currentThread->rid;
  return;
}

/*****************************************************************************
 * Interrupt Context Intrinsics
 ****************************************************************************/

bool sva_was_privileged (void) {
  const uint16_t userCodeSegmentMask = 0x03;

  kernel_to_usersva_pcid();

  /*
   * Lookup the most recent interrupt context for this processor and see if
   * it's ring 3.
   */
  bool was_privileged =
    (getCPUState()->newCurrentIC->cs & userCodeSegmentMask) != 3;

  usersva_to_kernel_pcid();
  return was_privileged;
}

/*
 * Intrinsic: sva_icontext_getpc()
 *
 * Description:
 *  Get the native code program counter value out of the interrupt context.
 */
uintptr_t
sva_icontext_getpc (void) {
  SVA_PROF_ENTER();

  struct CPUState * cpuState = getCPUState();

  SVA_PROF_EXIT(icontext_getpc);
  return cpuState->newCurrentIC->rip;
}

uintptr_t sva_get_current(void) {
  return (uintptr_t)getCPUState()->currentThread;
}

/*****************************************************************************
 * Miscellaneous State Manipulation Functions
 ****************************************************************************/

/**
 * Check if a target is a valid push target for a thread.
 *
 * @param thread  The thread
 * @param target  The target
 * @return        Whether `target` is a valid push target for `thread`
 */
static bool is_valid_push_target(struct SVAThread* thread, uintptr_t target) {
  if (thread->numPushTargets > 0) {
    for (size_t index = 0; index < thread->numPushTargets; ++index) {
      if (thread->validPushTargets[index] == (void*)target) {
        return true;
      }
    }

    /*
     * `target` was not found in the thread's valid push targets.
     */
    return false;
  } else {
    /*
     * The thread has not registered any valid push targets; assume any target is
     * valid.
     */
    return true;
  }
}

void sva_ipush_function5(void (*newf)(),
                         uintptr_t p1,
                         uintptr_t p2,
                         uintptr_t p3,
                         uintptr_t p4,
                         uintptr_t p5)
{
  /*
   * TODO:
   *  o This intrinsic should check whether newf is a valid function for the
   *    appropriate mode (user or kernel).
   *
   *  o This intrinsic could conceivably cause a memory fault (either by
   *    accessing a stack page that isn't paged in, or by overwriting the
   *    stack). This should be addressed at some point.
   */
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Verify that the target function is in the list of valid function targets.
   * Note that if no push targets have been specified, then any target is valid.
   */
  if (!is_valid_push_target(threadp, (uintptr_t)newf)) {
    panic("SVA: Pushing bad value %p\n", newf);
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(ipush_function5, 1);
    return;
  }

  if (!is_valid_push_target(threadp, p5)) {
    panic("SVA: Pushing bad sighandler value %lx\n", p5);
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(ipush_function5, 2);
    return;
  }

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));
  sva_check_memory_write (ep->rsp, sizeof (uintptr_t));

  /*
   * Place the arguments into the proper registers.
   */
  ep->rdi = p1;
  ep->rsi = p2;
  ep->rdx = p3;
  ep->rcx = p4;
  ep->r8  = p5;

  /*
   * Push a return program counter value on to the stack.  It should cause a
   * fault if the function returns.
   */
  *(--(ep->rsp)) = 0x0fec;

  /*
   * Set the return function to be the specificed function.
   */
  ep->rip = (uintptr_t) newf;

  /*
   * Mark the interrupt context as valid; if an sva_ialloca previously
   * invalidated it, an sva_ipush_function() makes it valid again.
   */
  ep->valid = true;

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  SVA_PROF_EXIT_MULTI(ipush_function5, 3);
}

/*
 * Intrinsic: sva_ipush_function0 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  newf     - The function to call.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function0 (void (*newf)(void)) {
  sva_ipush_function5 (newf, 0, 0, 0, 0, 0);
  return;
}

/*
 * Intrinsic: sva_ipush_function1 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  newf     - The function to call.
 *  param    - The parameter to send to the function.
 *
 * TODO:
 *  This currently only takes a function that takes a single integer
 *  argument.  Eventually, this should take any function.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function1 (void (*newf)(int), uintptr_t param) {
  sva_ipush_function5 (newf, param, 0, 0, 0, 0);
  return;
}

bool sva_ipush_function(uintptr_t fn, uint16_t cs) {
  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Disable interrupts.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context.
   */
  struct CPUState* cpu_state = getCPUState();
  struct SVAThread* thread = cpu_state->currentThread;
  sva_icontext_t* ic = cpu_state->newCurrentIC;

  /*
   * Make sure we aren't setting a privileged code segment.
   */
  if ((cs & 0x3) != 3) {
    printf("SVA: WARNING: "
      "Attempt to set a handler with a privileged code segment\n");
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(ipush_function5, 1);
    return false;
  }

  /*
   * Verify that the target function is in the list of valid function targets.
   * Note that if no push targets have been specified, then any target is valid.
   */
  if (!is_valid_push_target(thread, fn)) {
    printf("SVA: WARNING: Bad handler target 0x%016lx\n", fn);
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(ipush_function5, 2);
    return false;
  }

  /*
   * Set the interrupt context to return to the specified location.
   */
  ic->rip = fn;
  ic->cs = cs;

  ic->rflags &= ~(EFLAGS_AC | EFLAGS_TF | EFLAGS_RF | EFLAGS_NT | EFLAGS_VM);

  /*
   * Mark the interrupt context as valid; if an sva_ialloca previously
   * invalidated it, an sva_ipush_function() makes it valid again.
   */
  ic->valid = true;

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical(rflags);

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT_MULTI(ipush_function5, 3);
  return true;
}

/*****************************************************************************
 * Integer State
 ****************************************************************************/

/*
 * Function: checkIntegerForLoad ()
 *
 * Description:
 *  Perform all necessary checks on an integer state to make sure that it can
 *  be loaded on to the processor.
 *
 * Inputs:
 *  p - A pointer to the integer state to load.
 *
 * TODO:
 *  The checking code must also verify that there is enough stack space before
 *  proceeding.  Otherwise, state could get really messy.
 */
static inline void
checkIntegerForLoad (sva_integer_state_t * p) {
  (void)p;

#if 0
  /* Current code segment */
  unsigned int cs;

  /* Data segment to use for this privilege level */
  unsigned int ds = 0x18;

  /* Flags whether the input has been validated */
  unsigned int validated = 0;

  /* System call disable mask */
  extern unsigned int sva_sys_disabled;
#endif
#if 0
  /* Disable interrupts */
  __asm__ __volatile__ ("cli");
#endif

#if 0
  do
  {
#ifdef SC_INTRINCHECKS
    extern MetaPoolTy IntegerStatePool;
    struct node {
      void* left;
      void* right;
      char* key;
      char* end;
      void* tag;
    };
    struct node * np;
    unsigned long start;

    /*
     * Verify that the memory was part of a previous integer state.
     */
    np = getBounds (&IntegerStatePool, buffer);
    start = np->key;
    pchk_drop_obj (&IntegerStatePool, buffer);
    if (start != buffer)
      poolcheckfail ("Integer Check Failure", (unsigned)buffer, (void*)__builtin_return_address(0));
#endif

    /*
     * Verify that we won't fault if we read from the buffer.
     */
    sva_check_memory_read (buffer, sizeof (sva_integer_state_t));

    /*
     * Verify that we can access the stack pointed to inside the buffer.
     */
    sva_check_memory_write ((p->rsp) - 2, 8);

    /*
     * Grab the current code segment.
     */
    __asm__ __volatile__ ("movl %%cs, %0\n" : "=r" (cs));
    cs &= 0xffff;

    /*
     * If we're not operating at the same privilege level as when this state
     * buffer was saved, then generate an exception.
     */
    if (cs != (p->cs)) {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }

#if 0
    /*
     * Configure the data segment to match the code segment, in case it somehow
     * became corrupted.
     */
    ds = ((cs == 0x10) ? (0x18) : (0x2B));
#endif

    /*
     * Validation is finished.  Continue.
     */
    validated = 1;
  } while (!validated);
#endif
  return;
}

/**
 * Performs a validity check on a thread pointer.
 *
 * Currently, this only checks if the pointer is non-null and if it is in a
 * valid pool (if SVA_CHECK_INTEGER is enabled).
 *
 * @param newThread         The thread to check
 * @param expectStackSwitch Whether or not the caller expects to switch kernel
 *                          stacks
 * @return                  True if the new thread is valid, otherwise false
 */
static bool checkThreadForLoad(struct SVAThread* newThread,
                               bool expectStackSwitch) {
  /*
   * If there is no place for new state, flag an error.
   */
  if (!newThread) {
    panic("sva_swap_integer: Invalid new-thread pointer");
  }

  /*
   * Check that the state is valid for loading and simultaneously mark it
   * invalid so that no one else loads it.
   */
  bool valid = __atomic_exchange_n(&newThread->integerState.valid, false, __ATOMIC_ACQUIRE);
  if (!valid) {
    printf("SVA: WARNING: Attempt to load thread that isn't valid "
           "or is currently active\n");
    return false;
  }

#if SVA_CHECK_INTEGER
  /*
   * Determine whether the integer state is valid.
   */
  if ((pchk_check_int(new)) == 0) {
    poolcheckfail("sva_swap_integer: Bad integer state",
                  (unsigned)old,
                  (void*)__builtin_return_address(0));
    return false;
  }
#endif

  /*
   * We will switch kernel stacks if the kernel stack pointer in the saved state
   * is non-zero. Make sure it matches up with the caller's expectation.
   */
  bool stackSwitch = newThread->integerState.kstackp != 0;
  if (stackSwitch != expectStackSwitch) {
    printf("SVA: Given context with%s a kernel stack when a stack switch was "
           "%sexpected!\n",
           stackSwitch ? "" : "out",
           expectStackSwitch ? "" : "un");
    return false;
  }

  if (!expectStackSwitch) {
    if (getCPUState()->gip != NULL) {
      printf("SVA: Attempt to swap user integer state with an active invoke "
             "frame!\n");
      return false;
    }

    if (sva_was_privileged()) {
      printf("SVA: Attempt to swap user integer state when kernel was "
             "interrupted!\n");
      return false;
    }
  }

  return true;
}

/*
 * Function: flushSecureMemory()
 *
 * Description:
 *  This function flushes TLB entries and caches for a thread's secure memory.
 */
static inline void
flushSecureMemory(struct SVAThread* oldThread, struct SVAThread* newThread) {
/*
 * In the Xen port, the SVA VM's internal memory is also mapped by the PTE that
 * gets cleared below. Since Xen PV guests aren't using ghost memory, we can
 * just avoid doing this for now.
 */
#ifndef XEN
  if (vg && oldThread->secmemSize > 0) {
    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t* root_pgtable = __va((uintptr_t)get_root_pagetable());
    pml4e_t* secmemp = &root_pgtable[PG_L4_ENTRY(GHOSTMEMSTART)];

    /*
     * Mark the secure memory is unmapped in the page tables.
     */
    unprotect_paging();
    *secmemp = 0;
    protect_paging();
  }
#else
  /* Silence an unused parameter warning. */
  (void)oldThread;
#endif

  /*
   * Invalidate all TLBs (including those with the global flag).  We do this
   * by first turning on and then turning off the PCID extension.  According
   * to the Intel Software Architecture Reference Manual, Volume 3,
   * Section 4.10.4, this will do the invalidation that we want.
   *
   * Experiments show that invalidating all of the TLBs is faster than
   * invalidating every page individually.  Since we usually flush on a context
   * switch, we just flushed all the TLBs anyway by changing CR3.  Therefore,
   * we lose speed by not flushing everything again.
   */
  uint64_t cr4 = read_cr4();
  write_cr4(cr4 | CR4_PCIDE);
  write_cr4(cr4 & ~CR4_PCIDE);

#ifdef SVA_LLC_PART
  if (vg && newThread != NULL &&
      oldThread->secmemSize > 0 && newThread->secmemSize > 0 &&
      oldThread->secmemPML4e != newThread->secmemPML4e)
    wbinvd();
#else
  /* Silence an unused parameter warning. */
  (void)newThread;
#endif
}

bool load_segment(enum sva_segment_register reg, uintptr_t val,
                  bool preserve_base)
{
  struct CPUState* st = getCPUState();

#define load_seg(seg) ({                                                      \
  bool res;                                                                   \
                                                                              \
  /*                                                                          \
   * Set up the exception frame.                                              \
   */                                                                         \
  struct invoke_frame frame;                                                  \
  frame.cpinvoke = INVOKE_FIXUP;                                              \
  frame.next = st->gip;                                                       \
  st->gip = &frame;                                                           \
                                                                              \
  asm volatile (                                                              \
    /*                                                                        \
     * Initialize the fixup address.                                          \
     */                                                                       \
    "lea 2f(%%rip), %%rbx\n\t"                                                \
                                                                              \
    /*                                                                        \
     * Attempt to load the segment register.                                  \
     */                                                                       \
    "1: mov %w0, %%"#seg"\n\t"                                                \
    "jmp 3f\n"                                                                \
                                                                              \
    /*                                                                        \
     * Recover if the segment load faulted by loading a null selector.        \
     */                                                                       \
    "2:\n\t"                                                                  \
    "xor %0, %0\n\t"                                                          \
    "xor %1, %1\n\t"                                                          \
    "jmp 1b\n"                                                                \
    "3:"                                                                      \
    : "=r"(val), "=r"(res)                                                    \
    : "0"(val), "1"(true)                                                     \
    : "rbx", "memory");                                                       \
                                                                              \
  /*                                                                          \
   * Tear down the exception frame.                                           \
   */                                                                         \
  st->gip = frame.next;                                                       \
                                                                              \
  res;                                                                        \
})                                                                            \

  switch (reg) {
  case SVA_SEG_CS:
  case SVA_SEG_SS:
    // Not supported
    return false;

  case SVA_SEG_DS:
    return load_seg(ds);
  case SVA_SEG_ES:
    return load_seg(es);

  case SVA_SEG_FS: {
    uintptr_t current_fs_base = rdfsbase();

    bool success = load_seg(fs);
    if (success && !preserve_base) {
      st->newCurrentIC->fsbase = rdfsbase();
    }

    wrfsbase(current_fs_base);
    return success;
  }
  case SVA_SEG_GS: {
    uintptr_t current_gs_base = rdgsbase();

    bool success = load_seg(gs);
    if (success && !preserve_base) {
      st->newCurrentIC->gsbase = rdgsbase();
    }

    wrgsbase(current_gs_base);
    return success;
  }

  case SVA_SEG_FS_BASE:
    st->newCurrentIC->fsbase = val;
    return true;
  case SVA_SEG_GS_BASE:
    st->newCurrentIC->gsbase = val;
    return true;

  default:
    // Invalid segment register
    return false;
  }
#undef load_seg
}

/**
 * Saves the active user segment selectors.
 *
 * @param state The integer state to which to save the segments.
 */
static void save_user_segments(sva_integer_state_t* state) {
#define get_seg(seg) ({                       \
  uint16_t sel;                               \
  asm ("mov %%"#seg", %k0" : "=r"(sel));      \
  sel;                                        \
})

  state->ds = get_seg(ds);
  state->es = get_seg(es);
  state->fs = get_seg(fs);
  state->gs = get_seg(gs);

#undef get_seg
}

/**
 * Load the saved user segment selectors.
 *
 * If loading any of the selectors faults, it will be loaded with a null
 * selector.
 *
 * @param state The integer state in which the selectors are saved
 * @return      Whether segment loading was successful
 */
static bool load_user_segments(sva_integer_state_t* state) {
  bool success = true;

  success &= load_segment(SVA_SEG_DS, state->ds, true);
  success &= load_segment(SVA_SEG_ES, state->es, true);
  success &= load_segment(SVA_SEG_FS, state->fs, true);
  success &= load_segment(SVA_SEG_GS, state->gs, true);

  return success;
}

/**
 * Saves the current CPU state onto a thread.
 *
 * Note: If we are switching kernel stacks, this function returns twice: once
 * normally and once when we wake up again.
 *
 * @param oldThread   The thread to which to save the current state
 * @param switchStack Whether or not to perform a kernel stack switch
 * @return            False if we returned normally, True if we just woke up
 *                    from a contetx switch
 */
static bool __attribute__((returns_twice))
saveThread(struct SVAThread* oldThread, bool switchStack) {
  /* Function for saving state */
  extern unsigned int __attribute__((returns_twice))
  save_integer(sva_integer_state_t* buffer);

  struct CPUState* cpup = getCPUState();
  sva_integer_state_t* old = &oldThread->integerState;

  /*
   * Save the value of the current kernel stack pointer, IST3, currentIC, and
   * the pointer to the global invoke frame pointer.
   */
  old->ist3      = cpup->tssp->ist3;
  old->currentIC = cpup->newCurrentIC;

  save_user_segments(old);

  if (switchStack) {
#ifdef SVA_SPLIT_STACK
    old->protected_stack = cpup->tssp->rsp0;
#endif
    old->kstackp   = cpup->kernel_stacks.entry_stack;
    old->ifp       = cpup->gip;

    /*
     * Save the current integer state.  Note that returning from save_integer()
     * with a non-zero value means that we've just woken up from a context
     * switch.
     */
    if (save_integer(old)) {
      /*
       * We've awakened.
       */
#if SVA_CHECK_INTEGER
      /*
       * Mark the integer state invalid and return to the caller.
       */
      pchk_drop_int (old);

      /*
       * Determine what stack we're running on now.
       */
      pchk_update_stack ();
#endif

      return true;
    }
  } else {
#ifdef SVA_SPLIT_STACK
    old->protected_stack = 0;
#endif
    old->kstackp = 0;
    old->ifp = NULL;
  }

#ifdef SVA_LAZY_FPU
  /*
   * Turn off access to the Floating Point Unit (FPU).  We will leave this
   * state on the CPU but force a trap if another process attempts to use it.
   *
   * We place this code here since, when Virtual Ghost is enabled, the call to
   * unprotect_paging() and protect_paging() will flush the pipeline with a
   * write to CR0.  This code may also cause a pipeline flush, so we place it
   * close to the other pipeline flushing code to reduce the amount of code
   * executed between flushes.
   */
  fpu_disable();
#else
  xsave(&old->fpstate.inner);
#endif

  /*
   * Mark the saved integer state as valid.
   */
  __atomic_store_n(&old->valid, true, __ATOMIC_RELEASE);

  return false;
}

/**
 * Loads a thread onto the CPU.
 *
 * @param newThread The thread to load
 * @return          If the load failed, false; If the load succeeded, true if
 *                  it didn't switch kernel stacks (if it does switch kernel
 *                  stacks, it won't return)
 */
static bool loadThread(struct SVAThread* newThread) {
  extern void __attribute__((noreturn)) load_integer(sva_integer_state_t* p);

  struct CPUState* cpup = getCPUState();
  sva_integer_state_t* new = &newThread->integerState;

  /*
   * Verify that we can load the new integer state.
   */
  checkIntegerForLoad(new);

  /*
   * Switch the CPU over to using the new set of interrupt contexts.
   */
  cpup->currentThread = newThread;
  cpup->tssp->ist3    = new->ist3;
  cpup->newCurrentIC  = new->currentIC;

  /*
   * A NULL kernel stack indicates that this integer state was switched from
   * without a kernel stack switch, so we can't switch kernel stacks when
   * switching back to it.
   */
  if (new->kstackp != 0) {
#ifdef SVA_SPLIT_STACK
    cpup->tssp->rsp0 = new->protected_stack;
#endif
    cpup->kernel_stacks.entry_stack = new->kstackp;
    cpup->gip = new->ifp;
  }

  /*
   * If the new state uses secure memory, we need to map it into the page
   * table.  Note that we refetch the state information from the CPUState
   * to ensure that we're not accessing stale local variables.
   */
  if (vg && newThread->secmemSize > 0) {
    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t* root_pgtable = __va((uintptr_t)get_root_pagetable());
    pml4e_t* secmemp = &root_pgtable[PG_L4_ENTRY(GHOSTMEMSTART)];

    /*
     * Restore the PML4E entry for the secure memory region.
     */
    uintptr_t mask = PG_P | PG_W | PG_U;
    if ((newThread->secmemPML4e & mask) != mask) {
      panic ("SVA: Not Present: %lx %lx\n", newThread->secmemPML4e, mask);
    }
    unprotect_paging();
    *secmemp = newThread->secmemPML4e;
    protect_paging();
  }

  bool segments_succeeded = load_user_segments(new);

#ifndef SVA_LAZY_FPU
  xrestore(&new->fpstate.inner);

#ifdef MPX
  /*
   * `xrestore` clobbered our MPX bound registers, so reinitialize them for
   * SFI. No need to worry abount clobbering userspace's bound registers: they
   * are saved on the interrupt stack and will be restored when we iret.
   */
  mpx_bnd_init();
#endif
#endif

  /* We only save the GPRs during a context switch if we are switching kernel
   * stacks, so only load them if we have a stack to switch to. */
  if (new->kstackp != 0) {
    // TODO: report potential failure of segment load to kernel

    /*
     * Load the rest of the integer state.
     */
    load_integer(new);
  } else {
    /*
     * We successfully loaded the new thread.
     */
    return segments_succeeded;
  }
}

uintptr_t sva_swap_integer(uintptr_t newint, uintptr_t __kern* statep) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /* Old interrupt flags */
  uintptr_t rflags = sva_enter_critical();

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Get a pointer to the memory buffer into which the integer state should be
   * stored.  There is one such buffer for every SVA thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;

  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread * newThread = validateThreadPointer(newint);
  if (!checkThreadForLoad(newThread, /* expectStackSwitch */ true)) {
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(swap_integer, 1);
    return 0;
  }

  /*
   * If the current state is using secure memory, we need to flush out the TLBs
   * and caches that might contain it.
   */
  flushSecureMemory(oldThread, newThread);

  if (saveThread(oldThread, /* switchStack */ true)) {
    /*
     * We've awakened.
     */

    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(swap_integer, 2);
    return 1;
  }

  /*
   * Inform the caller of the location of the last state saved.
   */
  if (statep != NULL) {
    sva_copy_to_kernel(statep, &oldThread, sizeof(oldThread));
  }

  /*
   * Now, load the new thread onto the CPU. Note that this will not return to
   * point unless it fails: if it succeeds, it will cause `save_integer` to
   * appear to return a second time.
   */
  loadThread(newThread);

  /*
   * The context switch failed.
   */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT_MULTI(swap_integer, 3);
  return 0; 
}

bool sva_swap_user_integer(uintptr_t newint, uintptr_t __kern* statep) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /* Old interrupt flags */
  uintptr_t rflags = sva_enter_critical();

  /* Pointer to the current CPU State */
  struct CPUState* cpup = getCPUState();

  /*
   * Get a pointer to the memory buffer into which the integer state should be
   * stored.  There is one such buffer for every SVA thread.
   */
  struct SVAThread* oldThread = cpup->currentThread;

  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread* newThread = validateThreadPointer(newint);
  if (!checkThreadForLoad(newThread, /* expectStackSwitch */ false)) {
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(swap_user_integer, 1);
    return false;
  }

  /*
   * If the current state is using secure memory, we need to flush out the TLBs
   * and caches that might contain it.
   */
  flushSecureMemory(oldThread, newThread);

  saveThread(oldThread, /* switchStack */ false);

  /*
   * Inform the caller of the location of the last state saved.
   */
  if (statep != NULL) {
    sva_copy_to_kernel(statep, &oldThread, sizeof(oldThread));
  }

  /*
   * Now, load the new thread onto the CPU.
   */
  if (loadThread(newThread)) {
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(swap_user_integer, 2);
    return true;
  } else {
    /*
     * The context switch failed.
     */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(swap_user_integer, 3);
    return false;
  }
}

static bool ialloca_common(void __user* stack, void __kern* data,
                           size_t size, size_t align)
{
  /**
   * The most recent interrupt context.
   */
  sva_icontext_t* icontextp = getCPUState()->newCurrentIC;

  /*
   * If we interrupted a privileged context, then don't do an ialloca.
   */
  if (sva_was_privileged()) {
    printf("SVA: WARNING: "
      "Attempt to perform an ialloca on a privilaged context\n");
    return false;
  }

  /*
   * Check if the alignment is within range.
   */
  if (align > 10) {
    printf("SVA: WARNING: ialloca alignment too large\n");
    return false;
  }

  /*
   * Mark the interrupt context as invalid.  We don't want it to be placed
   * back on to the processor until an sva_ipush_function() pushes a new stack
   * frame on to the stack.
   */
  icontextp->valid = false;

  /*
   * Align the pointer.
   */
  uintptr_t rsp = (uintptr_t)stack & ~((1L << align) - 1);

  /*
   * Perform the alloca.
   */
  rsp -= size;
  stack = (void __user*)rsp;

  /*
   * Copy data in from the initializer.
   */
  if (data) {
    if (sva_copy_kernel_to_user(stack, data, size)) {
      return false;
    }
  }

  /*
   * Save the result back into the Interrupt Context.
   */
  icontextp->rsp = (unsigned long*)stack;

  return true;
}

bool sva_ialloca(void __kern* data, size_t size, size_t align) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Disable interrupts.
   */
  unsigned long rflags = sva_enter_critical();

  /**
   * The most recent interrupt context.
   */
  sva_icontext_t* icontextp = getCPUState()->newCurrentIC;

  bool res = ialloca_common((void __user*)icontextp->rsp, data, size, align);

  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(ialloca);
  return res;
}

bool sva_ialloca_switch_stack(uintptr_t stack, uint16_t stack_seg)
{
  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Disable interrupts.
   */
  unsigned long rflags = sva_enter_critical();

  bool res = false;

  /**
   * The most recent interrupt context.
   */
  sva_icontext_t* icontextp = getCPUState()->newCurrentIC;

  /*
   * Check that we aren't trying to set a privileged stack segment.
   */
  if ((stack_seg & 0x3) != 3) {
    printf("SVA: WARNING: icontext stack switch to privileged segment 0x%hx\n",
           stack_seg);
    goto out;
  }

  /*
   * Mark the interrupt context as invalid.  We don't want it to be placed
   * back on to the processor until an sva_ipush_function() pushes a new stack
   * frame on to the stack.
   */
  icontextp->valid = false;
  icontextp->rsp = (unsigned long*)stack;
  icontextp->ss = stack_seg;

  res = true;

out:
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(ialloca);
  return res;
}

/*
 * Intrinsic: sva_load_icontext()
 *
 * Description:
 *  This intrinsic takes state saved by the Execution Engine during an
 *  interrupt and loads it into the latest interrupt context.
 */
void
sva_load_icontext (void) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();
 
  /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * Verify that the interrupt context represents user-space state.
   */
  if (sva_was_privileged ()) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      SVA_PROF_EXIT_MULTI(load_icontext, 1);
      return;
  }

  /*
   * Verify that we have a free interrupt context to use.
   */
  if (threadp->savedICIndex < 1) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      SVA_PROF_EXIT_MULTI(load_icontext, 2);
      return;
  }

  /*
   * Load the interrupt context.
   */
  *icontextp = threadp->savedInterruptContexts[--(threadp->savedICIndex)];

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  SVA_PROF_EXIT_MULTI(load_icontext, 3);
}

/*
 * Intrinsic: sva_save_icontext()
 *
 * Description:
 *  Save the most recent interrupt context into SVA memory so that it can be
 *  restored later.
 *
 * Return value:
 *  0 - An error occured.
 *  1 - No error occured.
 */
unsigned char
sva_save_icontext (void) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();
 
 /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * Verify that the interrupt context represents user-space state.
   */
  if (sva_was_privileged ()) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      SVA_PROF_EXIT_MULTI(save_icontext, 1);
      return 0;
  }

  /*
   * Verify that we have a free interrupt context to use.
   */
  if (threadp->savedICIndex > maxIC) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      SVA_PROF_EXIT_MULTI(save_icontext, 2);
      return 0;
  }

  /*
   * Save the interrupt context.
   */
  threadp->savedInterruptContexts[threadp->savedICIndex] = *icontextp;

  /*
   * Increment the saved interrupt context index and save it in a local
   * variable.
   */
  unsigned char savedICIndex = ++(threadp->savedICIndex);

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();  

  SVA_PROF_EXIT_MULTI(save_icontext, 3);
  return savedICIndex;
}

void svaDummy(void) {
  panic("SVA: svaDummy: Return to user space!\n");
}

uintptr_t sva_create_icontext(uintptr_t start, uintptr_t arg1, uintptr_t arg2,
                              uintptr_t arg3, uintptr_t stack)
{
  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Disable interrupts.
   */
  uintptr_t rflags = sva_enter_critical();

  /*
   * Allocate a new SVA thread.
   */
  struct SVAThread* newThread = findNextFreeThread();

  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_write(newThread, sizeof(struct SVAThread));

  /*
   * Initialize the interrupt context of the new thread.  Note that we use
   * the last IC.
   *
   * FIXME: The check on cpup->newCurrentIC is really a hack.  We should really
   *        fix the code to ensure that newCurrentIC is always set correctly
   *        and that the first interrupt context is at the end of the interrupt
   *        context list.
   */
  sva_icontext_t* ic = newThread->interruptContexts + maxIC - 1;

  /*
   * Initialze the integer state of the new thread of control.
   */
  memset(ic, 0, sizeof(sva_icontext_t));
  ic->rip = start;
  ic->cs  = SVA_USER_CS_64;
  ic->rdi = arg1;
  ic->rsi = arg2;
  ic->rdx = arg3;
  ic->rflags = EFLAGS_IF;
  ic->rsp = (uintptr_t*)stack;
  ic->ss  = SVA_USER_SS_64;
  ic->valid = true;

  newThread->integerState.currentIC = ic;
  newThread->integerState.ist3 = (uintptr_t)ic;
  newThread->integerState.kstackp = 0;
#ifdef SVA_SPLIT_STACK
  newThread->integerState.protected_stack = 0;
#endif

  xinit(&newThread->integerState.fpstate.inner);

  /*
   * Mark the new thread as valid for loading.
   */
  newThread->integerState.valid = true;

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(init_stack);
  return (uintptr_t)newThread;
}

void sva_reinit_icontext(void* handle, bool priv, uintptr_t stackp,
                         uintptr_t arg)
{
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();
  /* Old interrupt flags */
  uintptr_t rflags;

  /* Function entry point */
  void * func = handle;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Validate the translation handle.
   */
  struct translation * transp = (struct translation *)(handle);
  if (vg) {
    if ((translations <= transp) && (transp < translations + 4096)) {
      if (((uint64_t)transp - (uint64_t)translations) % sizeof (struct translation)) {
        panic ("SVA: Invalid translation handle: %p %p %lx\n", transp, translations, sizeof (struct translation));
        usersva_to_kernel_pcid();
        SVA_PROF_EXIT_MULTI(reinit_icontext, 1);
        return;
      }
    } else {
      panic ("SVA: Out of range translation handle: %p %p %lx\n", transp, translations, sizeof (struct translation));
      usersva_to_kernel_pcid();
      SVA_PROF_EXIT_MULTI(reinit_icontext, 2);
      return;
    }

    if (transp->used != 2)
      panic ("SVA: Bad transp: %d\n", transp->used);

    /* Grab the function to call from the translation handle */
    func = transp->entryPoint;
  }

  /*
   * Get the most recent interrupt context.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));

  /*
   * Remove mappings to the secure memory for this thread.
   */
  if (vg && (threadp->secmemSize)) {

    ghostFree(threadp, (void*)GHOSTMEMSTART, threadp->secmemSize);

    /*
     * Delete the secure memory mappings from the SVA thread structure.
     */
    threadp->secmemSize = 0;
    threadp->secmemPML4e = 0;

    /*
     * Flush the secure memory page mappings.
     */
    flushSecureMemory(threadp, NULL);
  }

  /*
   * Clear out any function call targets.
   */
  threadp->numPushTargets = 0;

  /*
   * Setup the call to the new function.
   */
  ep->rip = (uintptr_t) func;
  ep->rsp = (uintptr_t *)stackp;
  ep->rdi = arg;

  /*
   * Setup the segment registers for the proper mode.
   */
  if (priv) {
    panic ("SVA: sva_reinit_context: No support for creating kernel state.\n");
  } else {
    ep->cs = SVA_USER_CS_64;
    ep->ss = SVA_USER_SS_64;
    ep->rflags = (rflags & 0xfffu);
    load_segment(SVA_SEG_DS, SVA_USER_DS_64, false);
    load_segment(SVA_SEG_ES, SVA_USER_ES_64, false);
    load_segment(SVA_SEG_FS, SVA_USER_FS_64, false);
    load_segment(SVA_SEG_GS, SVA_USER_GS_64, false);
  }

  /*
   * Now that ghost memory has been reinitialized, install the key for this
   * bitcode file into the ghost memory and then invalidate the translation
   * handle since we've now used it.
   */
  if (vg) {
    memcpy (&(threadp->ghostKey), &(transp->key), sizeof (sva_key_t));
    transp->used = 0;
  }

  /* Re-enable interupts if they were enabled before */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT_MULTI(reinit_icontext, 3);
  return;
}

void sva_release_stack(uintptr_t id) {
  SVA_PROF_ENTER();
 
  kernel_to_usersva_pcid();
 
  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread * newThread = validateThreadPointer(id);
  if (! newThread) {
	 panic("sva_release_stack: Invalid thread pointer");
	 return;
  }

  sva_integer_state_t * new =  newThread ? &(newThread->integerState) : 0;

  /*
   * Ensure that we're not trying to release an active state.
   * Active states always have `valid` set to `false`.
   */
  if (!__atomic_load_n(&new->valid, __ATOMIC_ACQUIRE)) {
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT_MULTI(release_stack, 1);
    return;
  }

  /*
   * Release ghost memory belonging to the thread that we are deallocating.
   */
  if (vg) {
    ghostFree(newThread, (void*)GHOSTMEMSTART, newThread->secmemSize);
  }

  /*
   * Mark the thread as available for reuse.
   */
  newThread->used = 0;

  /* Push the thread into the stack of free threads since it can be reused */
  ftstack_push(newThread);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT_MULTI(release_stack, 2);
}

#if 0
uintptr_t sva_init_stack(unsigned char* start_stackp,
                         uintptr_t length,
                         void* func,
                         uintptr_t arg1,
                         uintptr_t arg2,
                         uintptr_t arg3)
{
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();
 
  /* Working memory pointer */
  sva_icontext_t * icontextp;
  /* Working integer state */
  sva_integer_state_t * integerp;

  /* Function to use to return from system call */
  extern void sva_iret(void);

  /* Arguments allocated on the new stack */
  struct frame {
    /* Dummy return pointer ignored by load_integer() */
    void * dummy;

    /* Return pointer for the function frame */
    void * return_rip;
  } * args;

  /* Old interrupt flags */
  uintptr_t rflags;

  /* End of stack */
  unsigned char * stackp = 0;

  /* Length of Stack */
  uintptr_t stacklen = length;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();
  
  /*
   * Find the last byte on the stack.
   */
  stackp = start_stackp + stacklen;

  /*
   * Verify that the stack is big enough.
   */
  if (stacklen < sizeof (struct frame)) {
    panic ("sva_init_stack: Invalid stacklen: %lu!\n", stacklen);
  }

  /*
   * Verify that the function is a kernel function.
   */
  uintptr_t f = (uintptr_t)(func);
  if ((f <= SECMEMEND) || (*((unsigned int *)(f)) != CHECKLABEL)) {
    panic ("sva_init_stack: Invalid function %p\n", func);
  }

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Verify that no interrupts or traps have occurred (other than a system call
   * into the kernel).
   */
#if 0
  if (cpup->newCurrentIC < &(cpup->currentThread->interruptContexts[maxIC - 1]))
    panic ("Invalid IC!\n");
#endif

  /*
   * Get access to the old thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;

  /*
   * Allocate a new SVA thread.
   */
  struct SVAThread * newThread = findNextFreeThread();


  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_read  (oldThread, sizeof (struct SVAThread));
  sva_check_memory_write (newThread, sizeof (struct SVAThread));

  /*
   * Copy over the secure memory mappings from the old thread to the new
   * thread.
   */
  if (vg) {
    newThread->secmemSize = oldThread->secmemSize;
    newThread->secmemPML4e = oldThread->secmemPML4e;
  }

  /*
   * Copy over the valid list of push targets for sva_ipush().
   */
  if (oldThread->numPushTargets) {
    unsigned index = 0;
    newThread->numPushTargets = oldThread->numPushTargets;
    for (index = 0; index < oldThread->numPushTargets; ++index) {
      newThread->validPushTargets[index] = oldThread->validPushTargets[index];
    }
  }

  /*
   * Allocate the call frame for the call to the system call.
   */
  stackp -= sizeof (struct frame);
  args = (struct frame *)stackp;

  /*
   * Initialize the arguments to the system call.  Also setup the interrupt
   * context and return function pointer.
   */
  args->return_rip = (void*)sva_iret;

  /*
   * Initialze the integer state of the new thread of control.
   */
  integerp = &(newThread->integerState);
  integerp->rip = (uintptr_t) func;
  integerp->rdi = arg1;
  integerp->rsi = arg2;
  integerp->rdx = arg3;
  integerp->rsp = (uintptr_t *) stackp;
  integerp->cs  = SVA_USER_CS_64;
  integerp->ss  = SVA_USER_SS_64;
  integerp->valid = true;
  integerp->rflags = 0x202;
#if 0
  integerp->ist3 = integerp->kstackp;
#endif
#if 1
  integerp->kstackp = (uintptr_t) stackp;
#ifdef SVA_SPLIT_STACK
  integerp->protected_stack = (uintptr_t)create_sva_stack(false);
#endif
#endif

  /*
   * Copy our extended states to the new thread.
   */
  xsave(&integerp->fpstate.inner);

  /*
   * Initialize the interrupt context of the new thread.  Note that we use
   * the last IC.
   *
   * FIXME: The check on cpup->newCurrentIC is really a hack.  We should really
   *        fix the code to ensure that newCurrentIC is always set correctly
   *        and that the first interrupt context is at the end of the interrupt
   *        context list.
   */
  icontextp = integerp->currentIC = newThread->interruptContexts + maxIC - 1;
  *icontextp = *(cpup->newCurrentIC);
#if 0
  printf("Before set the return value to zero, check rax, rax = 0x%lx\n",icontextp->rax);
#endif  
  /*
   * Set the return value to zero.
   *
   * FIXME: This is a hack.  Ideally, the return value setting code should do
   *        this.
   */
  icontextp->rax = 0;

  /*
   * If the parent thread is an initial thread for this CPU, we always
   * permit it to create a new child process.  Otherwise, the existing
   * thread's Interrupt Context must have the fork bit set to create a new
   * child thread.
   *
   * When creating the child thread, disable its fork bit so that the child
   * cannot be duplicated.  Disable the fork bit in the parent thread's
   * Interrupt Context as well so that it cannot be duplicated multiple times
   * for a single call to fork().
   */
  if (oldThread->isInitialForCPU || cpup->newCurrentIC->can_fork) {
    /* Mark the new Interrupt Context as valid */
    icontextp->valid = true;

    /* Disable the fork bit in both the old and new Interrupt Contexts. */
    icontextp->can_fork = false;
    cpup->newCurrentIC->can_fork = false;
  } else {
    /*
     * Print an error and then permit the child process to be created anyway.
     * This makes the error more of a warning since we allow the system to
     * continue executing anyway.
     */
    printf("SVA: Error!  Kernel performing unauthorized fork()!\n");
    icontextp->valid = true;
  }

  if(vg && (oldThread->secmemSize))
  {
    /* If the system call is fork or pdfork, COW on the ghost memory of the parent process;
     * If the system call is rfork and the flags indicate the child process will be 
     * a separate process and have its own address space, COW on the ghost memory of
     * the parent process*/	
    if((cpup->newCurrentIC->rax == 2) || (cpup->newCurrentIC->rax == 518) || \
       ((cpup->newCurrentIC->rax == 251) && (cpup->newCurrentIC->rdi & RFPROC) \
       && !(cpup->newCurrentIC->rdi & RFMEM)))	
      ghostmemCOW(oldThread, newThread);
  }
  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(init_stack);
  return (unsigned long) newThread;
}
#endif

void __attribute__((noreturn)) sva_reinit_stack(void (*func)(void)) {
  extern void sva_iret(void); // Interrupt return

  kernel_to_usersva_pcid();

  if (!is_valid_kernel_fn((void __kern*)func)) {
      printf("Attempt to jump to invalid target %p\n", func);
      BUG();
  }

  /*
   * Get a pointer to the bottom of the stack.
   */
  uintptr_t rsp;
  register uintptr_t unprotected_stack asm ("r15") = 0;
  if (sva_was_privileged()) {
      rsp = align_down((uintptr_t)getCPUState()->newCurrentIC->rsp, 16);
#ifdef SVA_SPLIT_STACK
      unprotected_stack = align_down(getCPUState()->newCurrentIC->r15, 16);
#endif
  } else {
#ifdef SVA_SPLIT_STACK
      rsp = getCPUState()->tssp->rsp0;
      unprotected_stack = getCPUState()->kernel_stacks.entry_stack;
#else
      rsp = getCPUState()->kernel_stacks.entry_stack;
#endif
  }

  /*
   * Push a return address.
   */
  void (**ret)(void) = (void (**)(void))rsp - 1;
  *ret = sva_iret;
  rsp = (uintptr_t)ret;

  usersva_to_kernel_pcid();

  asm volatile ("movq %[sp], %%rsp\n\t"

		/*
		 * Note: our stack frame is now dead. This means that any
		 * inputs used after this point must be registers or
		 * immediates.
		 */

                "jmp *%[target]"
                : : [sp]"r"(rsp), "r"(unprotected_stack), [target]"r"(func)
                : "memory");

  __builtin_unreachable();
}
