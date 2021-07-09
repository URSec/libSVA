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

#include <sva/apic.h>
#include <sva/assert.h>
#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/frame_meta.h>
#include <sva/icontext.h>
#include <sva/interrupt.h>
#include <sva/mmu.h>
#include <sva/page.h>
#include <sva/page_walk.h>
#include <sva/percpu.h>
#include <sva/self_profile.h>
#include <sva/state.h>
#include <sva/tlb.h>
#include <sva/keys.h>
#include <sva/uaccess.h>
#include <sva/util.h>
#include <sva/x86.h>

#include "thread_stack.h"

#include <errno.h>

/* Debug flags for printing data */
#define DEBUG       0

/* Definitions of LLVA specific exceptions */
#define sva_syscall_exception   (31)
#define sva_interrupt_exception (30)
#define sva_exception_exception (29)
#define sva_state_exception     (28)
#define sva_safemem_exception   (27)

extern bool trap_pfault_ghost(unsigned int vector, void* fault_addr);

static bool tlb_flush(void);
static bool pre_syscall(void);

void (*interrupt_table[257])();

bool (*sva_interrupt_table[257])() = {
  [14] = trap_pfault_ghost,
  [TLB_FLUSH_VECTOR] = tlb_flush,
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

bool tlb_flush(void) {
#ifdef XEN
  /*
   * We are borrowing Xen's LAPIC error vector for this since Xen doesn't have
   * any unused vectors. This shouldn't cause too many problems as Xen is
   * designed to not cause APIC errors in the first place, but this does mean
   * that we need to check if this interrupt is from an APIC error (instead of
   * the usual cause: TLB flush IPI) and if so allow Xen to handle it.
   */
  if (!apic_isr_test(TLB_FLUSH_VECTOR)) {
    /*
     * The ISR bit is set when this interrupt was caused by an IPI or external
     * interrupt, but not when it was caused by an APIC error.
     */
    return false;
  }
#endif

#if 0
  printf("SVA: CPU %u flushing TLB\n", (unsigned int)rdmsr(MSR_X2APIC_ID));
#endif

  invtlb_everything();

  /*
   * Synchronizes with the acquire fence in `invtlb_global`.
   */
  __atomic_fetch_add(&invtlb_cpus_acked, 1, __ATOMIC_RELEASE);

  apic_eoi();

  return true;
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

#if 0
  /*
   * We use the special syscall number 0xf00dbeef to permit userspace (or Xen
   * PV guest) clients to request that SVA perform special debugging
   * operations.
   */
  sva_icontext_t *ic = getCPUState()->newCurrentIC;
  if (ic->rax == 0xf00dbeef) {
    void handle_vmcsdebug_hypercall(sva_icontext_t *ic);
    handle_vmcsdebug_hypercall(ic);

    /* SVA handled this trap, don't pass it on to the system software */
    return true;
  }
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

int sva_icontext_setretval(unsigned long ret) {
  int __sva_intrinsic_result = 0;

  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;

  /*
   * Check that this interrupt context is indeed for a syscall.
   */
  SVA_CHECK(ic->trapno == 256, EACCES);

  /*
   * Set the return value.
   */
  ic->rax = ret;

__sva_fail:
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(icontext_setretval);
  return __sva_intrinsic_result;
}

#endif

int sva_icontext_setsyscallargs(const uint64_t __kern* regs) {
  int __sva_intrinsic_result = 0;

  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;

  /*
   * Check that this interrupt context is indeed for a syscall.
   */
  SVA_CHECK(ic->trapno == 256, EACCES);

  uint64_t regs_buf[6];
  SVA_CHECK(
    sva_copy_from_kernel(regs_buf, regs, sizeof(regs_buf)) == 0, EFAULT);

  ic->rdi = regs_buf[0];
  ic->rsi = regs_buf[1];
  ic->rdx = regs_buf[2];
  ic->r10 = regs_buf[3];
  ic->r8 = regs_buf[4];
  ic->r9 = regs_buf[5];

__sva_fail:
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(icontext_setretval);
  return __sva_intrinsic_result;
}

int sva_icontext_restart(void) {
  int __sva_intrinsic_result = 0;

  SVA_PROF_ENTER();
  kernel_to_usersva_pcid();

  /*
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t* ic = getCPUState()->newCurrentIC;

  /*
   * Check that this interrupt context is indeed for a syscall.
   */
  SVA_CHECK(ic->trapno == 256, EACCES);

  /*
   * Modify the saved `%rip` register so that it re-executes the syscall
   * instruction.  We do this by reducing it by 2 bytes.
   */
  ic->rip -= 2;

__sva_fail:
  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(icontext_restart);
  return __sva_intrinsic_result;
}

bool sva_register_general_exception(unsigned int vector,
                                    genfault_handler_t handler)
{
  SVA_PROF_ENTER();

  /*
   * First, ensure that the exception number is within range.
   */
  if (vector == 14 || vector >= 32) {
    return false;
  }

#if 0
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
  __atomic_store_n(&interrupt_table[vector], handler, __ATOMIC_RELAXED);

  SVA_PROF_EXIT(register_general_exception);
  return true;
}

bool sva_register_memory_exception(unsigned int vector,
                                   memfault_handler_t handler)
{
  /*
   * Ensure that this is a page fault handler.
   */
  if (vector != 14) {
    return false;
  }
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

  /*
   * Put the handler into our dispatch table.
   */
  __atomic_store_n(&interrupt_table[vector], handler, __ATOMIC_RELAXED);

  SVA_PROF_EXIT(register_memory_exception);
  return true;
}

bool sva_register_interrupt(unsigned int vector, interrupt_handler_t handler) {
  SVA_PROF_ENTER();

  /*
   * Ensure that the number is within range.
   */
  if (vector < 32 || vector >= 256) {
    return false;
  }

  /*
   * Put the handler into our dispatch table.
   */
  __atomic_store_n(&interrupt_table[vector], handler, __ATOMIC_RELAXED);

  SVA_PROF_EXIT(register_interrupt);
  return true;
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
