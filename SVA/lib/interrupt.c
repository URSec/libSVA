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

extern char __svadata __sva_percpu_region_base[];

/**
 * Allocate and map per-cpu structures.
 *
 * This function will both allocate frames for use as per-cpu data and map them
 * into secure memory.
 *
 * @return  A (virtual address) pointer to the per-cpu data region
 */
static void* alloc_percpu_region(size_t cpu_idx) {
  void* percpu_region = __sva_percpu_region_base + cpu_idx * PERCPU_REGION_SIZE;

  if (cpu_idx == 0) {
    /*
     * The direct map (which we need in order to walk page tables) isn't set up
     * yet. However, we know that the BSP's per-cpu region is already
     * allocated, so just return it.
     */
    return percpu_region;
  }

  cr3_t root = get_root_pagetable();
  pdpte_t* l3_table = NULL;
  pde_t* l2_table = NULL;
  pte_t* l1_table = NULL;

  int found = walk_page_table(root, (uintptr_t)percpu_region,
                              NULL, &l3_table, &l2_table, &l1_table, NULL);

  switch (found) {
  case -5:
  case -4:
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Secure memory region not mapped\n");
  case -3: {
    /*
     * No L3 entry for the address; allocate an L2 table.
     */
    uintptr_t l2_frame = alloc_frame();
    frame_desc_t* l2_desc = get_frame_desc(l2_frame);
    frame_morph(l2_desc, PGT_SML2);
    frame_take(l2_desc, PGT_SML2);
    l3_table[PG_L3_OFFSET(percpu_region)] =
      l2_frame | PG_P | PG_W | PG_NX | PG_G;
    /* fallthrough */
  }
  case -2: {
    /*
     * No L2 entry for the address; allocate an L1 table.
     */
    uintptr_t l1_frame = alloc_frame();
    frame_desc_t* l1_desc = get_frame_desc(l1_frame);
    frame_morph(l1_desc, PGT_SML1);
    frame_take(l1_desc, PGT_SML1);
    l2_table[PG_L2_OFFSET(percpu_region)] =
      l1_frame | PG_P | PG_W | PG_NX | PG_G;
    /* fallthrough */
  }
  case -1: {
    /*
     * Allocate and map the new per-cpu region.
     */
    for (int i = 0; i < 5; ++i) {
      /*
       * The low 3 pages are unused.
       */
      size_t idx = PG_L1_OFFSET(percpu_region) + 3 + i;

      uintptr_t frame = alloc_frame();
      frame_desc_t* frame_desc = get_frame_desc(frame);
      frame_morph(frame_desc, PGT_SVA);
      frame_take(frame_desc, PGT_SVA);

      /*
       * Map the page (rw-, supervisor, global).
       */
      l1_table[idx] = frame | PG_P | PG_W | PG_NX | PG_G;
    }
    break;
  }
  default:
#if 0
    SVA_ASSERT_UNREACHABLE("SVA: FATAL: Per-CPU region already allocated?\n");
#else
    break;
#endif
  }

  return percpu_region;
}

/**
 * Allocate the initial thread for the current CPU.
 *
 * @return  An initial thread for the CPU
 */
static struct SVAThread* alloc_initial_thread(void) {
  struct SVAThread* st = findNextFreeThread();
  st->isInitialForCPU = 1;
  return st;
}

/**
 * Create the per-cpu structures in the per-cpu region.
 *
 * This includes the `CPUState` structure, the TSS, and the "TLS area" that can
 * be directly accessed off of the `%gs` segment.
 *
 * @param percpu_region The previously allocated per-cpu region
 */
static void create_percpu_structures(void* percpu_region) {
  char* percpu_region_cur = (char*)percpu_region + PERCPU_REGION_SIZE;

  /*
   * Place a pointer to the TLS area at the very end of the per-cpu region, so
   * that it can be easily accessed during paranoid entry.
   */
  uintptr_t* gsbase_paranoid_pointer = (uintptr_t*)percpu_region_cur - 1;
  percpu_region_cur = (char*)gsbase_paranoid_pointer;

  /*
   * Allocate the CPU state structure.
   */
  struct CPUState* cpu_state = (struct CPUState*)percpu_region_cur - 1;
  percpu_region_cur = (char*)cpu_state;

  /*
   * Allocate the TLS area.
   */
  size_t offset = (uintptr_t)percpu_region_cur % alignof(struct sva_tls_area);
  percpu_region_cur -= offset;
  struct sva_tls_area* tls_area = (struct sva_tls_area*)percpu_region_cur - 1;
  percpu_region_cur = (char*)tls_area;

  /*
   * Allocate the TSS.
   */
  percpu_region_cur -= sizeof(tss_t);
  /* Align the TSS to 16 bytes. */
  percpu_region_cur = (char*)((uintptr_t)percpu_region_cur & -16);
  tss_t* tss = (tss_t*)percpu_region_cur;

  char* paranoid_stacks = percpu_region;

  /*
   * Initialize the structures.
   */
  cpu_state->tssp = tss;
  cpu_state->gip = NULL;

  tls_area->cpu_state = cpu_state;
  wrgsbase((uintptr_t)tls_area);
  *gsbase_paranoid_pointer = (uintptr_t)tls_area;

  tss->ist4 = (uintptr_t)&paranoid_stacks[4 * PARANOID_STACK_SIZE];
  tss->ist5 = (uintptr_t)&paranoid_stacks[5 * PARANOID_STACK_SIZE];
  tss->ist6 = (uintptr_t)&paranoid_stacks[6 * PARANOID_STACK_SIZE];
  tss->ist7 = (uintptr_t)&paranoid_stacks[7 * PARANOID_STACK_SIZE];
}

#ifdef XEN
static void xen_tss_hack(const tss_t* tss) {
  struct gdtr {
    size_t limit:16;
    uintptr_t base;
  } __attribute__((packed)) gdtr;
  asm ("sgdt %0" : "=m"(gdtr));

  struct tss_desc {
    size_t limit_low:16;
    uintptr_t base_low:24;
    unsigned int type:5;
    unsigned int dpl:2;
    bool present:1;
    size_t limit_high:4;
    bool avail:1;
    unsigned int _reserved0:2;
    bool granularity:1;
    uintptr_t base_high:40;
    unsigned int _reserved1:8;
    unsigned int type_upper:5;
    unsigned int _reserved2:19;
  } __attribute__((aligned(8), packed)) desc = {
    .base_low = (uintptr_t)tss,
    .base_high = (uintptr_t)tss >> 24,
    .limit_low = 0x67,
    .limit_high = 0,
    .granularity = 0,
    .type = 0b01001,
    .type_upper = 0,
    .dpl = 0,
    .present = true,
    .avail = 0,
    ._reserved0 = 0,
    ._reserved1 = 0,
    ._reserved2 = 0,
  };

  _Static_assert(sizeof(struct tss_desc) == 16,
                 "TSS descriptor incorrect size");

  const uint16_t xen_tss_desc = 0xe040;

  *((struct tss_desc*)(gdtr.base + (xen_tss_desc & ~0x7))) = desc;
  asm volatile ("ltr %w0" :: "rm"(xen_tss_desc));
}
#endif

/**
 * Initialize the per-processor CPU state for this processor.
 *
 * @param tssp  A pointer to this CPU's TSS
 * @return      A pointer to the new CPU state for this CPU
 */
void* sva_getCPUState(tss_t* tssp) {
  SVA_PROF_ENTER();

  /** Next CPU index */
  static size_t __svadata nextIndex = 0;

  /*
   * NB: No danger of overflow, as it would require a machine with over 4
   * billion (32-bit) or 18 quintillion (64-bit) CPUs.
   */
  size_t index = __atomic_fetch_add(&nextIndex, 1, __ATOMIC_RELAXED);

  void* percpu_region = alloc_percpu_region(index);

  /*
   * Initialize the per-cpu region.
   */
  create_percpu_structures(percpu_region);

  /*
   * Once `create_percpu_structures` returns, everything is in place for
   * `getCPUState` to work properly.
   */
  struct CPUState* cpup = getCPUState();

  /*
   * The first thread to be allocated is the initial thread that starts
   * SVA for this processor (CPU).  Create an initial thread for this CPU
   * and mark it as an initial thread for this CPU.
   */
  struct SVAThread* st = alloc_initial_thread();
  sva_icontext_t* ic = &st->interruptContexts[maxIC - 1];

  /*
   * Initialize a dummy interrupt context so that it looks like we
   * started the processor by taking a trap or system call.  The dummy
   * Interrupt Context should cause a fault if we ever try to put it back
   * on to the processor.
   */
  ic->rip     = 0xfead;
  ic->cs      = SVA_USER_CS_64;

  /*
   * Set our initial thread and interrupt context.
   */
  cpup->currentThread = st;
  cpup->newCurrentIC = ic;

  /*
   * Flag that the floating point unit has not been used.
   */
  cpup->fp_used = false;
  cpup->prevFPThread = NULL;

  /*
   * Set the kernel entry stack pointer.
   */
  cpup->tssp->rsp0 = tssp->rsp0;

  /*
   * Poison the stack pointers for entering rings 1 and 2.
   */
  cpup->tssp->rsp1 = 0xdead57ac00000000UL;
  cpup->tssp->rsp2 = 0xdead57ac00000000UL;

  /*
   * Load the kernel's IST values. TODO: Maintain these in a separate structure.
   */
  cpup->tssp->ist1 = tssp->ist1;
  cpup->tssp->ist2 = tssp->ist2;

  /*
   * Setup the Interrupt Stack Table (IST) entry so that the hardware places
   * the stack frame inside SVA memory.
   */
  cpup->tssp->ist3 = (uintptr_t)st->integerState.ist3;

#ifdef XEN
  /*
   * Xen TSS hack: Since we currently allow Xen to manage the global descriptor
   * table for the benefit of PV guests, we overwrite Xen's TSS entry in its
   * GDT.
   */
  xen_tss_hack(cpup->tssp);
#else
  // TODO: Create and load the new TSS descriptor
#error Unimplemented
#endif

  /*
   * Save the sequential index we assigned to this processor so that, going
   * forward, we can quickly identify which processor we're running on
   * without resorting to an expensive serializing CPUID instruction to query
   * the APIC ID.
   */
  cpup->processor_id = index;

  /*
   * Flag that VMX has not yet been initialized for this processor, and
   * initialize any other VMX-related fields whose values need to be
   * initially defined.
   */
  cpup->vmx_initialized = 0;
  cpup->active_vm = 0;

  /*
   * Return the CPU State to the caller.
   */
  SVA_PROF_EXIT_MULTI(getCPUState, 1);
  return cpup;
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
