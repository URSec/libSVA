/*===- interrupt.c - SVA Execution Engine  --------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements the SVA instructions for registering interrupt and
 * exception handlers.
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/icontext.h>
#include <sva/interrupt.h>
#include <sva/self_profile.h>
#include <sva/state.h>
#include <sva/keys.h>
#include <sva/util.h>
#include <sva/x86.h>

#include "thread_stack.h"

/* Debug flags for printing data */
#define DEBUG       0

/* Definitions of LLVA specific exceptions */
#define sva_syscall_exception   (31)
#define sva_interrupt_exception (30)
#define sva_exception_exception (29)
#define sva_state_exception     (28)
#define sva_safemem_exception   (27)

extern bool trap_pfault_ghost(unsigned int vector, void* fault_addr);

static bool pre_syscall();

void (*interrupt_table[257])();

bool (*sva_interrupt_table[257])() = {
  [14] = trap_pfault_ghost,
  [256] = pre_syscall,
};

/*
 * Default LLVA interrupt, exception, and system call handlers.
 */
void
default_interrupt (unsigned int number, uintptr_t address) {
#if 1
  printf ("SVA: default interrupt handler: %u 0x%lx\n", number, address);
#else
  __asm__ __volatile__ ("hlt");
#endif
  return;
}

bool pre_syscall(void) {
#ifdef FreeBSD
  /*
   * Set the "can fork" flag if this is a fork syscall.
   *   2 - fork()
   *  66 - vfork()
   * 251 - rfork()
   * 518 - pdfork()
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;
  int syscall_number = ic->rax;
  ic->can_fork = syscall_number == 2 || syscall_number == 66 ||
                 syscall_number == 251 || syscall_number == 518;
#endif
  return false;
}

void
invalidIC (unsigned int vector) {
  extern void assertGoodIC (void);

  /*
   * Check that the interrupt context is okay (other than its valid field not
   *  being one
   */
  assertGoodIC();

  /* Print out the interrupt context */
  extern int sva_print_icontext (char * s);
  if (vector == 256)
    sva_print_icontext ("invalidIC:sys");
  else
    sva_print_icontext ("invalidIC:trap");

  panic ("SVA: Invalid Interrupt Context\n");
  __asm__ __volatile__ ("hlt\n");
  return;
}

/*
 * Intrinsic: sva_getCPUState()
 *
 * Description:
 *  Initialize and return a pointer to the per-processor CPU state for this
 *  processor.
 *
 * Input:
 *  tssp - A pointer to the TSS that is currently maintained by the system
 *         software.
 *
 * Notes:
 *  This intrinsic is only here to bootstrap the implementation of SVA.  Once
 *  the SVA interrupt handling code is working properly, this intrinsic should
 *  be removed.
 */
void *
sva_getCPUState (tss_t * tssp) {
  SVA_PROF_ENTER();

  static const size_t PREALLOC_PERCPU_BLOCKS = 16;

  /**
   * Pre-allocated per-CPU blocks.
   */
  static struct CPUState __svadata preallocCPUStates[PREALLOC_PERCPU_BLOCKS]
    __attribute__((aligned(16)));

  /** Index of next available CPU state */
  static size_t __svadata nextIndex = 0;

  /**
   * BSP's stack for paranoid exceptions (NMIs, #MCs, #DFs, and #DBs).
   *
   * This is statically allocated to avoid the need to request memory from the
   * kernel during SVA initialization.
   */
  static char __svadata bsp_paranoid_exception_stack[PARANOID_STACK_SIZE]
    __attribute__((aligned(PARANOID_STACK_SIZE)));

  if (nextIndex < PREALLOC_PERCPU_BLOCKS) {
    /*
     * Fetch an unused CPUState from the set of those available.
     */
    size_t index = __atomic_fetch_add(&nextIndex, 1, __ATOMIC_RELAXED);
    struct CPUState* cpup = &preallocCPUStates[index];

    /*
     * The first thread to be allocated is the initial thread that starts
     * SVA for this processor (CPU).  Create an initial thread for this CPU
     * and mark it as an initial thread for this CPU.
     */
    struct SVAThread* st = cpup->currentThread = findNextFreeThread();
    st->isInitialForCPU = 1;

    /*
     * Flag that the floating point unit has not been used.
     */
    cpup->fp_used = 0;

    /* No one has used the floating point unit yet */
    cpup->prevFPThread = 0;

    /*
     * Initialize a dummy interrupt context so that it looks like we
     * started the processor by taking a trap or system call.  The dummy
     * Interrupt Context should cause a fault if we ever try to put it back
     * on to the processor.
     */
    cpup->newCurrentIC = cpup->currentThread->interruptContexts + (maxIC - 1);
    cpup->newCurrentIC->rip     = 0xfead;
    cpup->newCurrentIC->cs      = SVA_USER_CS_64;
    cpup->gip                   = 0;

    /*
     * Initialize the TSS pointer so that the SVA VM can find it when needed.
     */
    cpup->tssp = tssp;

    /*
     * Setup the Interrupt Stack Table (IST) entry so that the hardware places
     * the stack frame inside SVA memory.
     */
    tssp->ist3 = ((uintptr_t) (st->integerState.ist3));
    /* TODO: SMP support */
    /** The size of a individual exception's portion of the paranoid stack. */
    size_t part_size = PARANOID_STACK_SIZE / 8;
    tssp->ist4 = (uintptr_t)&bsp_paranoid_exception_stack[1 * part_size];
    tssp->ist5 = (uintptr_t)&bsp_paranoid_exception_stack[2 * part_size];
    tssp->ist6 = (uintptr_t)&bsp_paranoid_exception_stack[3 * part_size];
    tssp->ist7 = (uintptr_t)&bsp_paranoid_exception_stack[4 * part_size];

    /*
     * Return the CPU State to the caller.
     */

    SVA_PROF_EXIT_MULTI(getCPUState, 1);
    return cpup;
  } else {
    // TODO: allocate more per-cpu blocks

    SVA_PROF_EXIT_MULTI(getCPUState, 2);
    panic("SVA: FATAL: Out of per-cpu blocks\n");
  }
}

#ifdef FreeBSD

void
sva_icontext_setretval (unsigned long high,
                        unsigned long low,
                        unsigned char error) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();
  /*
   * FIXME: This should ensure that the interrupt context is for a system
   *        call.
   *
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t * icontextp = getCPUState()->newCurrentIC;

  /*
   * Set the return value.  The high order bits go in %edx, and the low
   * order bits go in %eax.
   */
  icontextp->rdx = high;
  icontextp->rax = low;

  /*
   * Set or clear the carry flags of the EFLAGS register depending on whether
   * the system call succeeded for failed.
   */
  if (error) {
    icontextp->rflags |= 1;
  } else {
    icontextp->rflags &= 0xfffffffffffffffeu;
  }

  usersva_to_kernel_pcid();

  SVA_PROF_EXIT(icontext_setretval);
}

#else

bool sva_icontext_setretval(unsigned long ret) {
  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;

  /*
   * Check that this interrupt context is indeed for a syscall.
   */
  if (ic->trapno != 256) {
    printf("SVA: WARNING: Set return non-syscall\n");
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT(icontext_setretval);
    return false;
  }

  /*
   * Set the return value.
   */
  ic->rax = ret;

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(icontext_setretval);
  return true;
}

#endif

bool sva_icontext_setsyscallargs(uint64_t regs[6]) {
  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;

  /*
   * Check that this interrupt context is indeed for a syscall.
   */
  if (ic->trapno != 256) {
    printf("SVA: WARNING: Set return non-syscall\n");
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT(icontext_setretval);
    return false;
  }

  ic->rdi = regs[0];
  ic->rsi = regs[1];
  ic->rdx = regs[2];
  ic->r10 = regs[3];
  ic->r8 = regs[4];
  ic->r9 = regs[5];

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(icontext_setretval);
  return true;
}

bool sva_icontext_restart(void) {
  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;

  /*
   * Check that this interrupt context is indeed for a syscall.
   */
  if (ic->trapno != 256) {
    printf("SVA: WARNING: Restart non-syscall\n");
    usersva_to_kernel_pcid();
    SVA_PROF_EXIT(icontext_restart);
    return false;
  }

  /*
   * Modify the saved `%rip` register so that it re-executes the syscall
   * instruction.  We do this by reducing it by 2 bytes.
   */
  ic->rip -= 2;

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(icontext_restart);
  return true;
}

/*
 * Intrinsic: sva_register_general_exception()
 *
 * Description:
 *  Register a fault handler with the Execution Engine.  The handlers for these
 *  interrupts do not take any arguments.
 *
 * Return value:
 *  0 - No error
 *  1 - Some error occurred.
 */
unsigned char
sva_register_general_exception (unsigned char number,
                                genfault_handler_t handler) {
  SVA_PROF_ENTER();

  /*
   * First, ensure that the exception number is within range.
   */
#if 0
  if (number > 31) {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
    return 1;
  }

  /*
   * Ensure that this is not one of the special handlers.
   */
  switch (number) {
    case 8:
    case 10:
    case 11:
    case 12:
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
      return 1;
      break;

    default:
      break;
  }
#endif

  /*
   * Put the handler into our dispatch table.
   */
  interrupt_table[number] = handler;

  SVA_PROF_EXIT(register_general_exception);
  return 0;
}

/*
 * Intrinsic: sva_register_memory_exception()
 *
 * Description:
 *  Register a fault with the Execution Engine.  This fault handler will need
 *  the memory address that was used by the instruction when the fault occurred.
 */
unsigned char
sva_register_memory_exception (unsigned char number, memfault_handler_t handler) {
  /*
   * Ensure that this is not one of the special handlers.
   */
#if 0
  switch (number) {
    case 14:
    case 17:
      /*
       * Put the interrupt handler into our dispatch table.
       */
      interrupt_table[number] = handler;
      return 0;

    default:
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
      return 1;
  }
#endif

  interrupt_table[number] = handler;

  return 0;
}

/*
 * Intrinsic: sva_register_interrupt ()
 *
 * Description:
 *  This intrinsic registers an interrupt handler with the Execution Engine.
 */
unsigned char
sva_register_interrupt (unsigned char number, interrupt_handler_t interrupt) {
  SVA_PROF_ENTER();

  /*
   * Ensure that the number is within range.
   */
#if 0
  if (number < 32) {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_interrupt_exception));
    return 1;
  }
#endif

  /*
   * Put the handler into the system call table.
   */
  interrupt_table[number] = interrupt;

  SVA_PROF_EXIT(register_interrupt);
  return 0;
}

#if 0
/**************************** Inline Functions *******************************/

/*
 * Intrinsic: sva_load_lif()
 *
 * Description:
 *  Enables or disables local processor interrupts, depending upon the flag.
 *
 * Inputs:
 *  0  - Disable local processor interrupts
 *  ~0 - Enable local processor interrupts
 */
void
sva_load_lif (unsigned int enable)
{
  if (enable)
    __asm__ __volatile__ ("sti":::"memory");
  else
    __asm__ __volatile__ ("cli":::"memory");
}
                                                                                
/*
 * Intrinsic: sva_save_lif()
 *
 * Description:
 *  Return whether interrupts are currently enabled or disabled on the
 *  local processor.
 */
unsigned int
sva_save_lif (void)
{
  unsigned int eflags;

  /*
   * Get the entire eflags register and then mask out the interrupt enable
   * flag.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  return (eflags & 0x00000200);
}

unsigned int
sva_icontext_lif (void * icontextp)
{
  sva_icontext_t * p = icontextp;
  return (p->eflags & 0x00000200);
}

/*
 * Intrinsic: sva_nop()
 *
 * Description:
 *  Provides a volatile operation that does nothing.  This is useful if you
 *  want to wait for an interrupt but don't want to actually do anything.  In
 *  such a case, you need a "filler" instruction that can be interrupted.
 *
 * TODO:
 *  Currently, we're going to use this as an optimization barrier.  Do not move
 *  loads and stores around this.  This is okay, since LLVM will enforce the
 *  same restriction on the LLVM level.
 */
void
sva_nop (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}

void
sva_nop1 (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}
#endif
