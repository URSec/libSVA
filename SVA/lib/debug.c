/*===- debug.c - SVA Execution Engine  ------------------------------------===
  RETTARGET
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Debugging code for the Execution Engine when linked into the operating
 * system kernel.
 *
 *===----------------------------------------------------------------------===
 */

#include <stddef.h>

#include <sva/types.h>
#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/fpu.h>
#include <sva/state.h>
#include <sva/icontext.h>
#include <sva/interrupt.h>
#include <sva/mmu.h>
#include <sva/msr.h>
#include <sva/self_profile.h>
#include <sva/util.h>
#include <sva/vmx.h>
#include <sva/vmx_intrinsics.h>
#include <sva/mpx.h>

#ifdef __FreeBSD__
#include <machine/frame.h>
#endif

#ifdef XEN
#include <xen/arch-x86/xen.h>
#endif

/*****************************************************************************
 * Assertion Code
 ****************************************************************************/

int sva_print_icontext (char * s);

void
assertGoodIC (void) {
  /*
   * Get the CPU State and latest Interrupt Context
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = getCPUState()->newCurrentIC;

  if ((p < cpup->currentThread->interruptContexts) ||
      (cpup->currentThread->interruptContexts + maxIC < p)) {
    panic ("SVA: Out of Bounds IC: %p %p %p\n", p, cpup->currentThread->interruptContexts, cpup->currentThread->interruptContexts + maxIC);
  }

  /*
   * Loop through and see if the interrupt context is one of the entries in the
   * set of ICs for this thread.
   */
  sva_icontext_t * ip;
  unsigned char found = 0;
  for (ip = cpup->currentThread->interruptContexts; ip <= cpup->currentThread->interruptContexts + maxIC; ++ip) {
    if (ip == p) {
      found = 1;
      break;
    }
  }

  if (!found) {
    sva_print_icontext ("assertGoodIC");
    panic ("SVA: assertGoodIC: Misaligned IC!\n");
  }

  if (!p->valid) {
    sva_print_icontext("assertGoodIC");
    panic("SVA: assertGoodIC: Bad IC\n");
  }
  return;
}

/*****************************************************************************
 * Cheater's Code
 ****************************************************************************/

#ifdef XEN

/**
 * Load a segment register or %fs/%gs base.
 *
 * @param reg The segment register to load
 * @param val The value to load into the segment register
 * @return    Whether or not the value was successfully loaded
 */
bool sva_load_segment(enum sva_segment_register reg, uintptr_t val) {
  kernel_to_usersva_pcid();

  if (sva_was_privileged()) {
    /*
     * We can only set user-space context.
     */
    usersva_to_kernel_pcid();
    return false;
  }

  /*
   * Check that the selector is for user-mode (has its RPL = 3).
   */
  switch (reg) {
  case SVA_SEG_CS:
  case SVA_SEG_SS:
  case SVA_SEG_DS:
  case SVA_SEG_ES:
  case SVA_SEG_FS:
  case SVA_SEG_GS:
    if (val != 0 && (val & 0x3) != 0x3) {
      usersva_to_kernel_pcid();
      return false;
    }
  default:
    break;
  }

  uint64_t rflags = sva_enter_critical();

  bool success = load_segment(reg, val, false);

  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();
  return success;
}

/**
 * Get the segment selectors which were saved when the current thread was
 * context-switched out.
 *
 * This is useful for reporting errors when segment loading fails.
 *
 * @param regs  Xen's copy of the user registers.
 */
void sva_get_segments(struct cpu_user_regs* regs) {
  kernel_to_usersva_pcid();

  sva_integer_state_t* st = &getCPUState()->currentThread->integerState;

  regs->ds = st->ds;
  regs->es = st->es;
  regs->fs = st->fs;
  regs->gs = st->gs;

  usersva_to_kernel_pcid();
}

/*
 * Function: sva_cpu_user_regs()
 *
 * Description:
 *  Convert the state as represented by the Execution Engine back into Xen's
 *  cpu_user_regs structure.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 */
void sva_cpu_user_regs(struct cpu_user_regs* regs, uintptr_t* fsbase, uintptr_t* gsbase) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Fetch the currently available interrupt context.
   */
  sva_icontext_t* p = getCPUState()->newCurrentIC;

  regs->error_code = p->code;
  regs->entry_vector = p->trapno;
  regs->rip = p->rip;
  regs->cs = p->cs;

  regs->rax = p->rax;
  regs->rbx = p->rbx;
  regs->rcx = p->rcx;
  regs->rdx = p->rdx;
  regs->rsp = (uintptr_t)p->rsp;
  regs->rbp = p->rbp;
  regs->rsi = p->rsi;
  regs->rdi = p->rdi;
  regs->r8 = p->r8;
  regs->r9 = p->r9;
  regs->r10 = p->r10;
  regs->r11 = p->r11;
  regs->r12 = p->r12;
  regs->r13 = p->r13;
  regs->r14 = p->r14;
  regs->r15 = p->r15;

  regs->rflags = p->rflags;

  regs->ss = p->ss;

  if (fsbase != NULL) {
    *fsbase = p->fsbase;
  }
  if (gsbase != NULL) {
    *gsbase = p->gsbase;
  }

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(trapframe);
}

/*
 * Function: sva_icontext()
 *
 * Description:
 *  Convert the state as represented by Xen's cpu_user_regs structure back
 *  into the interrupt context.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 */
void sva_icontext(struct cpu_user_regs* regs, uintptr_t* fsbase, uintptr_t* gsbase) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Fetch the currently available interrupt context.
   */
  sva_icontext_t* p = getCPUState()->newCurrentIC;

  p->code = regs->error_code;
  p->trapno = regs->entry_vector;
  p->rip = regs->rip;
  p->cs = regs->cs;

  p->rax = regs->rax;
  p->rbx = regs->rbx;
  p->rcx = regs->rcx;
  p->rdx = regs->rdx;
  p->rsp = (unsigned long*)regs->rsp;
  p->rbp = regs->rbp;
  p->rsi = regs->rsi;
  p->rdi = regs->rdi;
  p->r8 = regs->r8;
  p->r9 = regs->r9;
  p->r10 = regs->r10;
  p->r11 = regs->r11;
  p->r12 = regs->r12;
  p->r13 = regs->r13;
  p->r14 = regs->r14;
  p->r15 = regs->r15;

  p->rflags = regs->rflags;

  p->ss = regs->ss;

  if (fsbase != NULL) {
    p->fsbase = *fsbase;
  }
  if (gsbase != NULL) {
    p->gsbase = *gsbase;
  }

  p->valid = true;

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(trapframe);
}

#endif /* XEN */

#ifdef __FreeBSD__

/*
 * Function: sva_trapframe()
 *
 * Description:
 *  Convert the state as represented by the Execution Engine back into FreeBSD's
 *  trapframe structure.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 */
void
sva_trapframe (struct trapframe * tf) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Fetch the currently available interrupt context.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = getCPUState()->newCurrentIC;

#if 0
  printf ("SVA: (%p): %p: %p %p\n\n", cpup,
                                      cpup->newCurrentIC,
                                      cpup->interruptContexts + maxIC,
                                      cpup->interruptContexts + maxIC - 1);
#endif

  /*
   * Store the fields into the trap frame.  Omit those belonging to the
   * application if Virtual Ghost is enabled.
   */
  if (copyICToTrapFrame) {
    tf->tf_rdi = p->rdi;
    tf->tf_rsi = p->rsi;
    tf->tf_rcx = p->rcx;
    tf->tf_r8  = p->r8;
    tf->tf_r9  = p->r9;
    tf->tf_rax = p->rax;
    tf->tf_rbx = p->rbx;
    tf->tf_rdx = p->rdx;
    tf->tf_rbp = p->rbp;
    tf->tf_r10 = p->r10;
    tf->tf_r11 = p->r11;
    tf->tf_r12 = p->r12;
    tf->tf_r13 = p->r13;
    tf->tf_r14 = p->r14;
    tf->tf_r15 = p->r15;
  }

  tf->tf_trapno = p->trapno;

  if (copyICToTrapFrame) {
    tf->tf_fs = p->fs;
    tf->tf_gs = p->gs;
    tf->tf_es = p->es;
#if 0
    tf->tf_ds = p->ds;
#else
    tf->tf_ds = 0;
#endif
  }

  /* Set the address that caused the page fault to zero */
  tf->tf_addr = 0;

  /* Set the error code */
  tf->tf_err = p->code;

  /* Only save the program counter if Virtual Ghost is disabled */
  if (copyICToTrapFrame) {
    tf->tf_rip = p->rip;
    tf->tf_rsp = (unsigned long)(p->rsp);
  }

  /* Limit the status flags that the process is allowed to see */
  if (copyICToTrapFrame) {
    tf->tf_rflags = p->rflags;
  } else {
    tf->tf_rflags = (p->rflags) & EFLAGS_IF;
  }
  tf->tf_ss = p->ss;
  tf->tf_cs = p->cs;


  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(trapframe);
}

/*
 * Function: sva_syscall_trapframe()
 *
 * Description:
 *  Convert the state as represented by the Execution Engine back into FreeBSD's
 *  trapframe structure.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 *
 *  This version of the function does some translating between registers.
 */
void
sva_syscall_trapframe (struct trapframe * tf) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Fetch the currently available interrupt context.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = getCPUState()->newCurrentIC;

#if 0
  printf ("SVA: (%p): %p: %p %p\n\n", cpup,
                                      cpup->newCurrentIC,
                                      cpup->interruptContexts + maxIC,
                                      cpup->interruptContexts + maxIC - 1);
#endif

  /*
   * Store the fields into the trap frame.
   */
  tf->tf_rdi = p->rdi;
  tf->tf_rsi = p->rsi;
  tf->tf_rdx = p->rdx;
  tf->tf_rcx = p->r10;  /* Done for system call ABI */
  tf->tf_r8  = p->r8;
  tf->tf_r9  = p->r9;
  tf->tf_rax = p->rax;

  if (copyICToTrapFrame) {
    tf->tf_rbx = p->rbx;
    tf->tf_rbp = p->rbp;
    tf->tf_r10 = p->r10;
    tf->tf_r11 = p->r11;
    tf->tf_r12 = p->r12;
    tf->tf_r13 = p->r13;
    tf->tf_r14 = p->r14;
    tf->tf_r15 = p->r15;
  }

  tf->tf_trapno = p->trapno;
  tf->tf_err = p->code;
  tf->tf_addr = 0;

  if (copyICToTrapFrame) {
    tf->tf_fs = p->fs;
    tf->tf_gs = p->gs;
    tf->tf_es = p->es;
    tf->tf_ds = p->ds;
  }

  /* Don't leak the program counter if Virtual Ghost is enabled */
  tf->tf_cs = p->cs;
  if (copyICToTrapFrame) {
    tf->tf_rip = p->rcx;
  }
  if (copyICToTrapFrame) {
    tf->tf_rflags = p->r11;
  } else {
    tf->tf_rflags = ((p->r11) & EFLAGS_IF);
  }

  if (copyICToTrapFrame) {
    tf->tf_rsp = (unsigned long)(p->rsp);
  }
  tf->tf_ss = p->ss;

  usersva_to_kernel_pcid();
  SVA_PROF_EXIT(syscall_trapframe);
}

#if 0
/*
 * Function: sva_icontext()
 *
 * Description:
 *  Convert the state as represented by the FreeBSD's trapframe structure back
 *  into the interrupt context.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 */
void
sva_icontext (struct trapframe * tf) {
  /*
   * Fetch the currently free interrupt context.
   */
  sva_icontext_t * p = getCPUState()->newCurrentIC;

  /*
   * Store the fields into the trap frame.
   */
  p->rdi = tf->tf_rdi;
  p->rsi = tf->tf_rsi;
  p->rcx = tf->tf_rcx;
  p->r8  = tf->tf_r8;
  p->r9  = tf->tf_r9;
  p->rax = tf->tf_rax;
  p->rbx = tf->tf_rbx;
  p->rcx = tf->tf_rcx;
  p->rdx = tf->tf_rdx;
  p->rbp = tf->tf_rbp;
  p->r10 = tf->tf_r10;
  p->r11 = tf->tf_r11;
  p->r12 = tf->tf_r12;
  p->r13 = tf->tf_r13;
  p->r14 = tf->tf_r14;
  p->r15 = tf->tf_r15;

  p->trapno = tf->tf_trapno;


  p->fs = tf->tf_fs;
  p->gs = tf->tf_gs;
  p->es = tf->tf_es;

  p->code = tf->tf_err;
  p->rip = tf->tf_rip;
  p->cs = tf->tf_cs;
  p->rflags = tf->tf_rflags;
  p->rsp = (unsigned long *)(tf->tf_rsp);
  p->ss = tf->tf_ss;

  return;
}
#endif

#endif /* __FreeBSD__ */

static void print_icontext(const char* s, sva_icontext_t* p) {
  printf("SVA: in %s\n", s);
  printf("rip: 0x%lx   rsp: %p   rbp: 0x%lx \n", p->rip, p->rsp, p->rbp);
  printf("rax: 0x%lx   rbx: 0x%lx   rcx: 0x%lx \n", p->rax, p->rbx, p->rcx);
  printf("rdx: 0x%lx   rsi: 0x%lx   rdi: 0x%lx \n", p->rdx, p->rsi, p->rdi);
  printf("SVA: icontext  cs: 0x%hx\n", p->cs);
  printf("SVA: icontext  rflags  : 0x%lx\n", p->rflags);
  printf("SVA: icontext  code    : 0x%x\n", p->code);
  printf("SVA: icontext  trapno  : 0x%x\n", p->trapno);
  printf("----------------------------------------------------------------\n");
}

int
sva_print_icontext (char * s) {

  kernel_to_usersva_pcid();
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * p = cpup->newCurrentIC;
  printf ("SVA: %s: (%p): %p: %p\n\n", s, cpup,
                                       cpup->newCurrentIC,
                                       cpup->currentThread->interruptContexts + maxIC - 1);
  print_icontext (s, p);
  pml4e_t* root_pgtable = (pml4e_t*)getVirtual((uintptr_t)get_root_pagetable());
  pml4e_t* secmemp = &root_pgtable[PG_L4_ENTRY(SECMEMSTART)];
  printf ("SVA: secmem: %lx %lx\n", threadp->secmemPML4e, *secmemp);

  usersva_to_kernel_pcid();
  return 0;
}

void
sva_print_integer (uintptr_t integer) {
  struct SVAThread * thread = (struct SVAThread *)(integer);
  sva_integer_state_t * intp =  thread ? &(thread->integerState) : 0;
  if (!intp) return;
  printf ("SVA: integer: int3: %lx\tkstackp: %lx\n", intp->ist3, intp->kstackp);
  uintptr_t start, field;
  start = (uintptr_t) (thread);
  field = (uintptr_t) &(thread->interruptContexts[maxIC]);
  printf ("SVA: integer: %lx\n", field - start);
  printf ("SVA: integer: sizeof Thread: %lx\n", sizeof (struct SVAThread));
  printf ("SVA: integer: sizeof IC: %lx\n", sizeof (struct sva_icontext));
  return;
}

void
sva_print_ist3 (unsigned long id) {
  struct CPUState * cpup = getCPUState();
  printf ("SVA: %ld: ist3 = %p: %lx\n", id, &(cpup->tssp->ist3), cpup->tssp->ist3);
  if (cpup->tssp->ist3 == 0) {
    __asm__ __volatile__ ("xchg %%bx, %%bx\n" :: "a" (id));
  }
  return;
}

void
sva_print_inttable (void) {
  extern void default_interrupt (unsigned int number, void * icontext);
  for (unsigned index = 0; index < 256; ++index) {
    if (interrupt_table[index] != default_interrupt)
      printf ("SVA: %d: %p\n", index, interrupt_table[index]);
  }
  return;
}

void
sva_checkptr (uintptr_t p) {
  SVA_PROF_ENTER();

  //
  // If we're in kernel memory but not above the secure memory region, hit a
  // breakpoint.
  //
  if (p >= 0xffffff8000000000) {
    if (!(p & 0x0000008000000000u)) {
      bochsBreak();
      __asm__ __volatile__ ("int $3\n");
    }
  }

  SVA_PROF_EXIT(checkptr);
}

/*
 * Debug intrinsic: sva_print_vmx_msrs()
 *
 * Description:
 *  Print the values of various VMX-related MSRs to the kernel console.
 *
 *  We also print some control and debug registers, as well as some MSRs not
 *  directly related to VMX (but related to aspects of the system that are
 *  relevant to VMX operation).
 *
 *  This is for use during early development. It is not part of the designed
 *  SVA-VMX interface and will be removed.
 */
void
sva_print_vmx_msrs(void) {
  printf("\n------------------------------\n");
  printf("VMX-related MSRs\n");
  printf("\n------------------------------\n");

  printf("VMX_BASIC: 0x%lx\n", rdmsr(MSR_VMX_BASIC));
  printf("VMX_PINBASED_CTLS: 0x%lx\n", rdmsr(MSR_VMX_PINBASED_CTLS));
  printf("VMX_PROCBASED_CTLS: 0x%lx\n", rdmsr(MSR_VMX_PROCBASED_CTLS));
  printf("VMX_EXIT_CTLS: 0x%lx\n", rdmsr(MSR_VMX_EXIT_CTLS));
  printf("VMX_ENTRY_CTLS: 0x%lx\n", rdmsr(MSR_VMX_ENTRY_CTLS));
  printf("VMX_MISC: 0x%lx\n", rdmsr(MSR_VMX_MISC));
  printf("VMX_CR0_FIXED0: 0x%lx\n", rdmsr(MSR_VMX_CR0_FIXED0));
  printf("VMX_CR0_FIXED1: 0x%lx\n", rdmsr(MSR_VMX_CR0_FIXED1));
  printf("VMX_CR4_FIXED0: 0x%lx\n", rdmsr(MSR_VMX_CR4_FIXED0));
  printf("VMX_CR4_FIXED1: 0x%lx\n", rdmsr(MSR_VMX_CR4_FIXED1));
  printf("VMX_VMCS_ENUM: 0x%lx\n", rdmsr(MSR_VMX_VMCS_ENUM));
  printf("VMX_PROCBASED_CTLS2: 0x%lx\n", rdmsr(MSR_VMX_PROCBASED_CTLS2));
  printf("VMX_EPT_VPID_CAP: 0x%lx\n", rdmsr(MSR_VMX_EPT_VPID_CAP));
  printf("VMX_TRUE_PINBASED_CTLS: 0x%lx\n", rdmsr(MSR_VMX_TRUE_PINBASED_CTLS));
  printf("VMX_TRUE_PROCBASED_CTLS: 0x%lx\n", rdmsr(MSR_VMX_TRUE_PROCBASED_CTLS));
  printf("VMX_TRUE_EXIT_CTLS: 0x%lx\n", rdmsr(MSR_VMX_TRUE_EXIT_CTLS));
  printf("VMX_TRUE_ENTRY_CTLS: 0x%lx\n", rdmsr(MSR_VMX_TRUE_ENTRY_CTLS));
  printf("VMX_VMFUNC: 0x%lx\n", rdmsr(MSR_VMX_VMCS_ENUM));

  printf("\n");
  printf("CR0: 0x%lx\n", read_cr0());
  printf("CR4: 0x%lx\n", read_cr4());
  printf("IA32_EFER: 0x%lx\n", rdmsr(MSR_EFER));
  printf("IA32_DEBUGCTL: 0x%lx\n", rdmsr(MSR_DEBUGCTL));
  printf("IA32_SYSENTER_CS: 0x%lx\n", rdmsr(MSR_SYSENTER_CS));
  printf("IA32_SYSENTER_ESP: 0x%lx\n", rdmsr(MSR_SYSENTER_ESP));
  printf("IA32_SYSENTER_EIP: 0x%lx\n", rdmsr(MSR_SYSENTER_EIP));

  uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
  asm __volatile__ (
      "mov %%dr0, %0\n"
      "mov %%dr1, %1\n"
      "mov %%dr2, %2\n"
      "mov %%dr3, %3\n"
      "mov %%dr6, %4\n"
      "mov %%dr7, %5\n"
      : "=r" (dr0), "=r" (dr1), "=r" (dr2), "=r" (dr3), "=r" (dr6), "=r" (dr7)
      );
  printf("DR0: 0x%lx\n", dr0);
  printf("DR1: 0x%lx\n", dr1);
  printf("DR2: 0x%lx\n", dr2);
  printf("DR3: 0x%lx\n", dr3);
  printf("DR6: 0x%lx\n", dr6);
  printf("DR7: 0x%lx\n", dr7);

  printf("\n");
  /* Use CPUID to query the physical-address width of the processor. */
  uint16_t cpuid_addrwidth;
  asm __volatile__ (
      "cpuid"
      : "=a" (cpuid_addrwidth)
      : "a" (0x80000008)
      : "ebx", "ecx", "edx"
      );
  uint8_t paddrwidth = (uint8_t) cpuid_addrwidth;
  uint8_t laddrwidth = (uint8_t) (cpuid_addrwidth >> 8);
  printf("CPU physical-address width (MAXPHYADDR): 0x%hhx\n", paddrwidth);
  printf("CPU linear-address width: 0x%hhx\n", laddrwidth);

#ifdef SVA_LLC_PART
  /* Use CPUID to determine limits on RMID and COS features */
  uint64_t max_rmid, max_cos;
  asm __volatile__ (
      "movl $0x0f, %%eax\n"
      "movl $0x1, %%ecx\n"
      "cpuid\n"
      "movq %%rcx, %[max_rmid]\n"
      "movl $0x10, %%eax\n"
      "movl $0x1, %%ecx\n"
      "cpuid\n"
      "movq %%rcx, %[max_cos]\n"
      : [max_rmid] "=rm" (max_rmid), [max_cos] "=rm" (max_cos)
      :
      : "rax", "rbx", "rcx", "rdx", "cc"
      );
  printf("Highest allowed RMID: 0x%lx\n", max_rmid);
  printf("Highest allowed COS: 0x%lx\n", max_cos);
#endif

  printf("\n------------------------------\n");
}

/*
 * Function: print_vmcs_field_name()
 *
 * Given an entry in the enum sva_vmcs_field, prints the human-readable name
 * for the field. (For use in debugging printouts.)
 *
 * Prints using the kernel's printf() function and does not prepend or append
 * any spacing (including newlines).
 *
 * If given an enum value it doesn't recognize, prints its hexadecimal
 * numeric value in brackets, e.g. "<0xffff>".
 *
 * Doesn't print anything if the preprocessor variable SVAVMX_DEBUG is 0.
 *
 * Parameters:
 *  - field: the enum field to be interpreted. Should correspond to an
 *    unsigned 16-bit ingeger value. This is true of all valid VMCS field
 *    encodings as defined by Intel (and as used in SVA).
 */
void
print_vmcs_field_name(enum sva_vmcs_field field) {
  if (!SVAVMX_DEBUG)
    return;

  switch (field) {
    /* 16-bit guest-state fields */
    case VMCS_GUEST_ES_SEL:
      printf("GUEST_ES_SEL");
      break;
    case VMCS_GUEST_CS_SEL:
      printf("GUEST_CS_SEL");
      break;
    case VMCS_GUEST_SS_SEL:
      printf("GUEST_SS_SEL");
      break;
    case VMCS_GUEST_DS_SEL:
      printf("GUEST_DS_SEL");
      break;
    case VMCS_GUEST_FS_SEL:
      printf("GUEST_FS_SEL");
      break;
    case VMCS_GUEST_GS_SEL:
      printf("GUEST_GS_SEL");
      break;
    case VMCS_GUEST_LDTR_SEL:
      printf("GUEST_LDTR_SEL");
      break;
    case VMCS_GUEST_TR_SEL:
      printf("GUEST_TR_SEL");
      break;
    case VMCS_GUEST_INTERRUPT_STATUS:
      printf("GUEST_INTERRUPT_STATUS");
      break;
    case VMCS_GUEST_PML_INDEX:
      printf("GUEST_PML_INDEX");
      break;

    /* 64-bit guest-state fields */
    case VMCS_VMCS_LINK_PTR:
      printf("VMCS_LINK_PTR");
      break;
    case VMCS_GUEST_IA32_DEBUGCTL:
      printf("GUEST_IA32_DEBUGCTL");
      break;
    case VMCS_GUEST_IA32_PAT:
      printf("GUEST_IA32_PAT");
      break;
    case VMCS_GUEST_IA32_EFER:
      printf("GUEST_IA32_EFER");
      break;
    case VMCS_GUEST_IA32_PERF_GLOBAL_CTRL:
      printf("GUEST_IA32_PERF_GLOBAL_CTRL");
      break;
    case VMCS_GUEST_PDPTE0:
      printf("GUEST_PDPTE0");
      break;
    case VMCS_GUEST_PDPTE1:
      printf("GUEST_PDPTE1");
      break;
    case VMCS_GUEST_PDPTE2:
      printf("GUEST_PDPTE2");
      break;
    case VMCS_GUEST_PDPTE3:
      printf("GUEST_PDPTE3");
      break;
    case VMCS_GUEST_IA32_BNDCFGS:
      printf("GUEST_IA32_BNDCFGS");
      break;

    /* 32-bit guest-state fields */
    case VMCS_GUEST_ES_LIMIT:
      printf("GUEST_ES_LIMIT");
      break;
    case VMCS_GUEST_CS_LIMIT:
      printf("GUEST_CS_LIMIT");
      break;
    case VMCS_GUEST_SS_LIMIT:
      printf("GUEST_SS_LIMIT");
      break;
    case VMCS_GUEST_DS_LIMIT:
      printf("GUEST_DS_LIMIT");
      break;
    case VMCS_GUEST_FS_LIMIT:
      printf("GUEST_FS_LIMIT");
      break;
    case VMCS_GUEST_GS_LIMIT:
      printf("GUEST_GS_LIMIT");
      break;
    case VMCS_GUEST_LDTR_LIMIT:
      printf("GUEST_LDTR_LIMIT");
      break;
    case VMCS_GUEST_TR_LIMIT:
      printf("GUEST_TR_LIMIT");
      break;
    case VMCS_GUEST_GDTR_LIMIT:
      printf("GUEST_GDTR_LIMIT");
      break;
    case VMCS_GUEST_IDTR_LIMIT:
      printf("GUEST_IDTR_LIMIT");
      break;
    case VMCS_GUEST_ES_ACCESS_RIGHTS:
      printf("GUEST_ES_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_CS_ACCESS_RIGHTS:
      printf("GUEST_CS_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_SS_ACCESS_RIGHTS:
      printf("GUEST_SS_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_DS_ACCESS_RIGHTS:
      printf("GUEST_DS_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_FS_ACCESS_RIGHTS:
      printf("GUEST_FS_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_GS_ACCESS_RIGHTS:
      printf("GUEST_GS_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_LDTR_ACCESS_RIGHTS:
      printf("GUEST_LDTR_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_TR_ACCESS_RIGHTS:
      printf("GUEST_TR_ACCESS_RIGHTS");
      break;
    case VMCS_GUEST_INTERRUPTIBILITY_STATE:
      printf("GUEST_INTERRUPTIBILITY_STATE");
      break;
    case VMCS_GUEST_ACTIVITY_STATE:
      printf("GUEST_ACTIVITY_STATE");
      break;
    case VMCS_GUEST_SMBASE:
      printf("GUEST_SMBASE");
      break;
    case VMCS_GUEST_IA32_SYSENTER_CS:
      printf("GUEST_IA32_SYSENTER_CS");
      break;
    case VMCS_VMX_PREEMPT_TIMER_VAL:
      printf("VMX_PREEMPT_TIMER_VAL");
      break;

    /* Natural-width guest-state fields */
    case VMCS_GUEST_CR0:
      printf("GUEST_CR0");
      break;
    case VMCS_GUEST_CR3:
      printf("GUEST_CR3");
      break;
    case VMCS_GUEST_CR4:
      printf("GUEST_CR4");
      break;
    /* ALL YOUR BASE ARE BELONG TO US */
    case VMCS_GUEST_ES_BASE:
      printf("GUEST_ES_BASE");
      break;
    case VMCS_GUEST_CS_BASE:
      printf("GUEST_CS_BASE");
      break;
    case VMCS_GUEST_SS_BASE:
      printf("GUEST_SS_BASE");
      break;
    case VMCS_GUEST_DS_BASE:
      printf("GUEST_DS_BASE");
      break;
    case VMCS_GUEST_FS_BASE:
      printf("GUEST_FS_BASE");
      break;
    case VMCS_GUEST_GS_BASE:
      printf("GUEST_GS_BASE");
      break;
    case VMCS_GUEST_LDTR_BASE:
      printf("GUEST_LDTR_BASE");
      break;
    case VMCS_GUEST_TR_BASE:
      printf("GUEST_TR_BASE");
      break;
    case VMCS_GUEST_GDTR_BASE:
      printf("GUEST_GDTR_BASE");
      break;
    case VMCS_GUEST_IDTR_BASE:
      printf("GUEST_IDTR_BASE");
      break;
    case VMCS_GUEST_DR7:
      printf("GUEST_DR7");
      break;
    case VMCS_GUEST_RSP:
      printf("GUEST_RSP");
      break;
    case VMCS_GUEST_RIP:
      printf("GUEST_RIP");
      break;
    case VMCS_GUEST_RFLAGS:
      printf("GUEST_RFLAGS");
      break;
    case VMCS_GUEST_PENDING_DBG_EXCEPTIONS:
      printf("GUEST_PENDING_DBG_EXCEPTIONS");
      break;
    case VMCS_GUEST_IA32_SYSENTER_ESP:
      printf("GUEST_IA32_SYSENTER_ESP");
      break;
    case VMCS_GUEST_IA32_SYSENTER_EIP:
      printf("GUEST_IA32_SYSENTER_EIP");
      break;

    /* 16-bit host-state fields */
    case VMCS_HOST_ES_SEL:
      printf("HOST_ES_SEL");
      break;
    case VMCS_HOST_CS_SEL:
      printf("HOST_CS_SEL");
      break;
    case VMCS_HOST_SS_SEL:
      printf("HOST_SS_SEL");
      break;
    case VMCS_HOST_DS_SEL:
      printf("HOST_DS_SEL");
      break;
    case VMCS_HOST_FS_SEL:
      printf("HOST_FS_SEL");
      break;
    case VMCS_HOST_GS_SEL:
      printf("HOST_GS_SEL");
      break;
    case VMCS_HOST_TR_SEL:
      printf("HOST_TR_SEL");
      break;

    /* 64-bit host-state fields */
    case VMCS_HOST_IA32_PAT:
      printf("HOST_IA32_PAT");
      break;
    case VMCS_HOST_IA32_EFER:
      printf("HOST_IA32_EFER");
      break;
    case VMCS_HOST_IA32_PERF_GLOBAL_CTRL:
      printf("HOST_IA32_PERF_GLOBAL_CTRL");
      break;

    /* 32-bit host-state fields */
    case VMCS_HOST_IA32_SYSENTER_CS:
      printf("HOST_IA32_SYSENTER_CS");
      break;

    /* Natural-width host-state fields */
    case VMCS_HOST_CR0:
      printf("HOST_CR0");
      break;
    case VMCS_HOST_CR3:
      printf("HOST_CR3");
      break;
    case VMCS_HOST_CR4:
      printf("HOST_CR4");
      break;
    case VMCS_HOST_FS_BASE:
      printf("HOST_FS_BASE");
      break;
    case VMCS_HOST_GS_BASE:
      printf("HOST_GS_BASE");
      break;
    case VMCS_HOST_TR_BASE:
      printf("HOST_TR_BASE");
      break;
    case VMCS_HOST_GDTR_BASE:
      printf("HOST_GDTR_BASE");
      break;
    case VMCS_HOST_IDTR_BASE:
      printf("HOST_IDTR_BASE");
      break;
    case VMCS_HOST_IA32_SYSENTER_ESP:
      printf("HOST_IA32_SYSENTER_ESP");
      break;
    case VMCS_HOST_IA32_SYSENTER_EIP:
      printf("HOST_IA32_SYSENTER_EIP");
      break;
    case VMCS_HOST_RSP:
      printf("HOST_RSP");
      break;
    case VMCS_HOST_RIP:
      printf("HOST_RIP");
      break;

    /* 16-bit control fields */
    case VMCS_VPID:
      printf("VPID");
      break;
    case VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR:
      printf("POSTED_INTERRUPT_NOTIFICATION_VECTOR");
      break;
    case VMCS_EPTP_INDEX:
      printf("EPTP_INDEX");
      break;

    /* 64-bit control fields */
    case VMCS_IOBITMAP_A_ADDR:
      printf("IOBITMAP_A_ADDR");
      break;
    case VMCS_IOBITMAP_B_ADDR:
      printf("IOBITMAP_B_ADDR");
      break;
    case VMCS_MSR_BITMAPS_ADDR:
      printf("MSR_BITMAPS_ADDR");
      break;
    case VMCS_VMEXIT_MSR_STORE_ADDR:
      printf("VMEXIT_MSR_STORE_ADDR");
      break;
    case VMCS_VMEXIT_MSR_LOAD_ADDR:
      printf("VMEXIT_MSR_LOAD_ADDR");
      break;
    case VMCS_VMENTRY_MSR_LOAD_ADDR:
      printf("VMENTRY_MSR_LOAD_ADDR");
      break;
    case VMCS_EXECUTIVE_VMCS_PTR:
      printf("EXECUTIVE_VMCS_PTR");
      break;
    case VMCS_PML_ADDR:
      printf("PML_ADDR");
      break;
    case VMCS_TSC_OFFSET:
      printf("TSC_OFFSET");
      break;
    case VMCS_VIRTUAL_APIC_ADDR:
      printf("VIRTUAL_APIC_ADDR");
      break;
    case VMCS_APIC_ACCESS_ADDR:
      printf("APIC_ACCESS_ADDR");
      break;
    case VMCS_POSTED_INTERRUPT_DESC_ADDR:
      printf("POSTED_INTERRUPT_DESC_ADDR");
      break;
    case VMCS_VM_FUNC_CTRLS:
      printf("VM_FUNC_CTRLS");
      break;
    case VMCS_EPT_PTR:
      printf("EPT_PTR");
      break;
    case VMCS_EOI_EXIT_BITMAP_0:
      printf("EOI_EXIT_BITMAP_0");
      break;
    case VMCS_EOI_EXIT_BITMAP_1:
      printf("EOI_EXIT_BITMAP_1");
      break;
    case VMCS_EOI_EXIT_BITMAP_2:
      printf("EOI_EXIT_BITMAP_2");
      break;
    case VMCS_EOI_EXIT_BITMAP_3:
      printf("EOI_EXIT_BITMAP_3");
      break;
    case VMCS_EPTP_LIST_ADDR:
      printf("EPTP_LIST_ADDR");
      break;
    case VMCS_VMREAD_BITMAP_ADDR:
      printf("VMREAD_BITMAP_ADDR");
      break;
    case VMCS_VMWRITE_BITMAP_ADDR:
      printf("VMWRITE_BITMAP_ADDR");
      break;
    case VMCS_VIRT_EXCEPTION_INFO_ADDR:
      printf("VIRT_EXCEPTION_INFO_ADDR");
      break;
    case VMCS_XSS_EXITING_BITMAP:
      printf("XSS_EXITING_BITMAP");
      break;
    case VMCS_ENCLS_EXITING_BITMAP:
      printf("ENCLS_EXITING_BITMAP");
      break;
    case VMCS_TSC_MULTIPLIER:
      printf("TSC_MULTIPLIER");
      break;

    /* 32-bit control fields */
    case VMCS_PINBASED_VM_EXEC_CTRLS:
      printf("PINBASED_VM_EXEC_CTRLS");
      break;
    case VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:
      printf("PRIMARY_PROCBASED_VM_EXEC_CTRLS");
      break;
    case VMCS_EXCEPTION_BITMAP:
      printf("EXCEPTION_BITMAP");
      break;
    case VMCS_PAGE_FAULT_ERROR_CODE_MASK:
      printf("PAGE_FAULT_ERROR_CODE_MASK");
      break;
    case VMCS_PAGE_FAULT_ERROR_CODE_MATCH:
      printf("PAGE_FAULT_ERROR_CODE_MATCH");
      break;
    case VMCS_CR3_TARGET_COUNT:
      printf("CR3_TARGET_COUNT");
      break;
    case VMCS_VM_EXIT_CTRLS:
      printf("VM_EXIT_CTRLS");
      break;
    case VMCS_VM_EXIT_MSR_STORE_COUNT:
      printf("VM_EXIT_MSR_STORE_COUNT");
      break;
    case VMCS_VM_EXIT_MSR_LOAD_COUNT:
      printf("VM_EXIT_MSR_LOAD_COUNT");
      break;
    case VMCS_VM_ENTRY_CTRLS:
      printf("VM_ENTRY_CTRLS");
      break;
    case VMCS_VM_ENTRY_MSR_LOAD_COUNT:
      printf("VM_ENTRY_MSR_LOAD_COUNT");
      break;
    case VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD:
      printf("VM_ENTRY_INTERRUPT_INFO_FIELD");
      break;
    case VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE:
      printf("VM_ENTRY_EXCEPTION_ERROR_CODE");
      break;
    case VMCS_VM_ENTRY_INSTR_LENGTH:
      printf("VM_ENTRY_INSTR_LENGTH");
      break;
    case VMCS_TPR_THRESHOLD:
      printf("TPR_THRESHOLD");
      break;
    case VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS:
      printf("SECONDARY_PROCBASED_VM_EXEC_CTRLS");
      break;
    case VMCS_PLE_GAP:
      printf("PLE_GAP");
      break;
    case VMCS_PLE_WINDOW:
      printf("PLE_WINDOW");
      break;

    /* Natural-width control fields */
    case VMCS_CR0_GUESTHOST_MASK:
      printf("CR0_GUESTHOST_MASK");
      break;
    case VMCS_CR4_GUESTHOST_MASK:
      printf("CR4_GUESTHOST_MASK");
      break;
    case VMCS_CR0_READ_SHADOW:
      printf("CR0_READ_SHADOW");
      break;
    case VMCS_CR4_READ_SHADOW:
      printf("CR4_READ_SHADOW");
      break;
    case VMCS_CR3_TARGET_VAL0:
      printf("CR3_TARGET_VAL0");
      break;
    case VMCS_CR3_TARGET_VAL1:
      printf("CR3_TARGET_VAL1");
      break;
    case VMCS_CR3_TARGET_VAL2:
      printf("CR3_TARGET_VAL2");
      break;
    case VMCS_CR3_TARGET_VAL3:
      printf("CR3_TARGET_VAL3");
      break;

    /* 16-bit read-only data fields */
    /* (none at this time) */

    /* 64-bit read-only data fields */
    case VMCS_GUEST_PHYS_ADDR:
      printf("GUEST_PHYS_ADDR");
      break;
    case VMCS_VM_INSTR_ERROR:
      printf("VM_INSTR_ERROR");
      break;
    case VMCS_VM_EXIT_REASON:
      printf("VM_EXIT_REASON");
      break;
    case VMCS_VM_EXIT_INTERRUPTION_INFO:
      printf("VM_EXIT_INTERRUPTION_INFO");
      break;
    case VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE:
      printf("VM_EXIT_INTERRUPTION_ERROR_CODE");
      break;
    case VMCS_IDT_VECTORING_INFO_FIELD:
      printf("IDT_VECTORING_INFO_FIELD");
      break;
    case VMCS_IDT_VECTORING_ERROR_CODE:
      printf("IDT_VECTORING_ERROR_CODE");
      break;
    case VMCS_VM_EXIT_INSTR_LENGTH:
      printf("VM_EXIT_INSTR_LENGTH");
      break;
    case VMCS_VM_EXIT_INSTR_INFO:
      printf("VM_EXIT_INSTR_INFO");
      break;

    /* Natural-width read-only data fields */
    case VMCS_EXIT_QUAL:
      printf("EXIT_QUAL");
      break;
    case VMCS_IO_RCX:
      printf("IO_RCX");
      break;
    case VMCS_IO_RSI:
      printf("IO_RSI");
      break;
    case VMCS_IO_RDI:
      printf("IO_RDI");
      break;
    case VMCS_IO_RIP:
      printf("IO_RIP");
      break;
    case VMCS_GUEST_LINEAR_ADDR:
      printf("GUEST_LINEAR_ADDR");
      break;

    default:
      printf("<0x%hx>", (unsigned short)field);
      break;
  }
}

/*
 * Function: print_vmcs_field()
 *
 * Prints a VMCS field value in human-readable form.
 *
 * Prints using the kernel's printf() function. The output may be multi-line,
 * and a newline is printed after the last line.
 *
 * Doesn't print anything if the preprocessor variable SVAVMX_DEUBG is 0.
 *
 * Parameters:
 *  - field: the VMCS field whose specification should be used to interpret
 *           the given field value.
 *  - value: the value of the VMCS field to be printed.
 *
 *    Note: different VMCS fields have different widths. They can be 16 bits,
 *    32 bits, 64 bits, or "natural width" (width of the host platform, which
 *    in our case always means 64 bits since this version of SVA does not run
 *    on 32-bit x86). If we are printing a field narrower than 64 bits, the
 *    higher bits will be ignored.
 */
void
print_vmcs_field(enum sva_vmcs_field field, uint64_t value) {
  if (!SVAVMX_DEBUG)
    return;

  switch (field) {
    case VMCS_PINBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_pinbased_vm_exec_ctrls ctrls;
        uint32_t value_lower32 = (uint32_t) value;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = value_lower32;

        printf("External-interrupt exiting: %u\n", ctrls.ext_int_exiting);
        printf("Reserved bits 1-2: %u\n", ctrls.reserved1_2);
        printf("NMI exiting: %u\n", ctrls.nmi_exiting);
        printf("Reserved bit 4: %u\n", ctrls.reserved4);
        printf("Virtual NMIs: %u\n", ctrls.virtual_nmis);
        printf("Activate VMX-preemption timer: %u\n",
            ctrls.activate_vmx_preempt_timer);
        printf("Process posted interrupts: %u\n", ctrls.process_posted_ints);
        printf("Reserved bits 8-31: %u\n", ctrls.reserved8_31);

        break;
      }

    case VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:
      {
        struct vmcs_primary_procbased_vm_exec_ctrls ctrls;
        uint32_t value_lower32 = (uint32_t) value;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = value_lower32;

        printf("Reserved bits 0-1: %u\n", ctrls.reserved0_1);
        printf("Interrupt-window exiting: %u\n", ctrls.int_window_exiting);
        printf("Use TSC offsetting: %u\n", ctrls.use_tsc_offsetting);
        printf("Reserved bits 4-6: %u\n", ctrls.reserved4_6);
        printf("HLT exiting: %u\n", ctrls.hlt_exiting);
        printf("Reserved bit 8: %u\n", ctrls.reserved8);
        printf("INVLPG exiting: %u\n", ctrls.invlpg_exiting);
        printf("MWAIT exiting: %u\n", ctrls.mwait_exiting);
        printf("RDPMC exiting: %u\n", ctrls.rdpmc_exiting);
        printf("RDTSC exiting: %u\n", ctrls.rdtsc_exiting);
        printf("Reserved bits 13-14: %u\n", ctrls.reserved13_14);
        printf("CR3-load exiting: %u\n", ctrls.cr3_load_exiting);
        printf("CR3-store exiting: %u\n", ctrls.cr3_store_exiting);
        printf("Reserved bits 17-18: %u\n", ctrls.reserved17_18);
        printf("CR8-load exiting: %u\n", ctrls.cr8_load_exiting);
        printf("CR8-store exiting: %u\n", ctrls.cr8_store_exiting);
        printf("Use TPR shadow: %u\n", ctrls.use_tpr_shadow);
        printf("NMI-window exiting: %u\n", ctrls.nmi_window_exiting);
        printf("MOV-DR exiting: %u\n", ctrls.mov_dr_exiting);
        printf("Unconditional I/O exiting: %u\n", ctrls.uncond_io_exiting);
        printf("Use I/O bitmaps: %u\n", ctrls.use_io_bitmaps);
        printf("Reserved bit 26: %u\n", ctrls.reserved26);
        printf("Use MSR bitmaps: %u\n", ctrls.use_msr_bitmaps);
        printf("MONITOR exiting: %u\n", ctrls.monitor_exiting);
        printf("PAUSE exiting: %u\n", ctrls.pause_exiting);
        printf("Activate secondary controls: %u\n",
            ctrls.activate_secondary_ctrls);

        break;
      }

    case VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS:
      {
        struct vmcs_secondary_procbased_vm_exec_ctrls ctrls;
        uint32_t value_lower32 = (uint32_t) value;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = value_lower32;

        printf("Virtualize APIC accesses: %u\n",
            ctrls.virtualize_apic_accesses);
        printf("Enable EPT: %u\n", ctrls.enable_ept);
        printf("Descriptor-table exiting: %u\n",
            ctrls.descriptor_table_exiting);
        printf("Enable RDTSCP: %u\n", ctrls.enable_rdtscp);
        printf("Virtualize x2APIC mode: %u\n", ctrls.virtualize_x2apic_mode);
        printf("Enable VPID: %u\n", ctrls.enable_vpid);
        printf("WBINVD exiting: %u\n", ctrls.wbinvd_exiting);
        printf("Unrestricted guest: %u\n", ctrls.unrestricted_guest);
        printf("APIC-register virtualization: %u\n",
            ctrls.apic_register_virtualization);
        printf("Virtual-interrupt delivery: %u\n",
            ctrls.virtual_int_delivery);
        printf("PAUSE-loop exiting: %u\n", ctrls.pause_loop_exiting);
        printf("RDRAND exiting: %u\n", ctrls.rdrand_exiting);
        printf("Enable INVPCID: %u\n", ctrls.enable_invpcid);
        printf("Enable VM functions: %u\n", ctrls.enable_vmfunc);
        printf("VMCS shadowing: %u\n", ctrls.vmcs_shadowing);
        printf("Enable ENCLS exiting: %u\n", ctrls.enable_encls_exiting);
        printf("RDSEED exiting: %u\n", ctrls.rdseed_exiting);
        printf("Enable PML: %u\n", ctrls.enable_pml);
        printf("EPT-violation #VE: %u\n", ctrls.ept_violation_ve);
        printf("Conceal VMX non-root operation from Intel PT: %u\n",
            ctrls.conceal_nonroot_from_pt);
        printf("Enable XSAVES/XRSTORS: %u\n", ctrls.enable_xsaves_xrstors);
        printf("Reserved bit 21: %u\n", ctrls.reserved21);
        printf("Mode-based execute control for EPT: %u\n",
            ctrls.mode_based_exec_ctrl_ept);
        printf("Reserved bits 23-24: %u\n", ctrls.reserved23_24);
        printf("Use TSC scaling: %u\n", ctrls.use_tsc_scaling);
        printf("Reserved bits 26-31: %u\n", ctrls.reserved26_31);

        break;
      }
    case VMCS_VM_EXIT_CTRLS:
      {
        struct vmcs_vm_exit_ctrls ctrls;
        uint32_t value_lower32 = (uint32_t) value;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = value_lower32;

        printf("Reserved bits 0-1: %u\n", ctrls.reserved0_1);
        printf("Save debug controls: %u\n", ctrls.save_debug_ctrls);
        printf("Reserved bits 3-8: %u\n", ctrls.reserved3_8);
        printf("Host address-space size: %u\n",
            ctrls.host_addr_space_size);
        printf("Reserved bits 10-11: %u\n", ctrls.reserved10_11);
        printf("Load IA32_PERF_GLOBAL_CTRL: %u\n",
            ctrls.load_ia32_perf_global_ctrl);
        printf("Reserved bits 13-14: %u\n", ctrls.reserved13_14);
        printf("Acknowledge interrupt on exit: %u\n",
            ctrls.ack_int_on_exit);
        printf("Reserved bits 16-17: %u\n", ctrls.reserved16_17);
        printf("Save IA32_PAT: %u\n", ctrls.save_ia32_pat);
        printf("Load IA32_PAT: %u\n", ctrls.load_ia32_pat);
        printf("Save IA32_EFER: %u\n", ctrls.save_ia32_efer);
        printf("Load IA32_EFER: %u\n", ctrls.load_ia32_efer);
        printf("Save VMX-preemption timer value: %u\n",
            ctrls.save_vmx_preempt_timer);
        printf("Clear IA32_BNDCFGS: %u\n", ctrls.clear_ia32_bndcfgs);
        printf("Conceal VM exits from Intel PT: %u\n",
            ctrls.conceal_vmexit_from_pt);
        printf("Reserved bits 25-31: %u\n", ctrls.reserved25_31);

        break;
      }
    case VMCS_VM_ENTRY_CTRLS:
      {
        struct vmcs_vm_entry_ctrls ctrls;
        uint32_t value_lower32 = (uint32_t) value;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = value_lower32;

        printf("Reserved bits 0-1: %u\n", ctrls.reserved0_1);
        printf("Load debug controls: %u\n", ctrls.load_debug_ctrls);
        printf("Reserved bits 3-8: %u\n", ctrls.reserved3_8);
        printf("IA-32e mode guest: %u\n", ctrls.ia32e_mode_guest);
        printf("Entry to SMM: %u\n", ctrls.entry_to_smm);
        printf("Deactivate dual-monitor treatment of SMM: %u\n",
            ctrls.deact_dual_mon_treatment);
        printf("Reserved bit 12: %u\n", ctrls.reserved12);
        printf("Load IA32_PERF_GLOBAL_CTRL: %u\n",
            ctrls.load_ia32_perf_global_ctrl);
        printf("Load IA32_PAT: %u\n", ctrls.load_ia32_pat);
        printf("Load IA32_EFER: %u\n", ctrls.load_ia32_efer);
        printf("Load IA32_BNDCFGS: %u\n", ctrls.load_ia32_bndcfgs);
        printf("Conceal VM entries from Intel PT: %u\n",
            ctrls.conceal_vmentry_from_pt);
        printf("Reserved bits 18-31: %u\n", ctrls.reserved18_31);

        break;
      }
    case VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD:
      {
        struct vmcs_vm_entry_interrupt_info_field ctrls;
        uint32_t value_lower32 = (uint32_t) value;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = value_lower32;

        printf("Interrupt/exception vector: %u\n", ctrls.vector);

        printf("Interruption type: %u (", ctrls.int_type);
        switch (ctrls.int_type) {
          /* See section 24.8.3 of Intel manual */
          case 0:
            printf("External interrupt");
            break;
          case 1:
            printf("Reserved");
            break;
          case 2:
            printf("Non-maskable interrupt (NMI)");
            break;
          case 3:
            printf("Hardware exception");
            break;
          case 4:
            printf("Software interrupt");
            break;
          case 5:
            printf("Privileged software exception");
            break;
          case 6:
            printf("Software exception");
            break;
          case 7:
            printf("Other event");
            break;
          /*
           * No default case needed since we have covered all values of this
           * 3-bit field.
           */
        }
        printf(")\n");

        printf("Deliver error code: %u\n", ctrls.deliver_error_code);
        printf("Reserved bits 12-30: %u\n", ctrls.reserved12_30);
        printf("Valid: %u\n", ctrls.valid);

        break;
      }

    default:
      printf("[Unrecognized VMCS field; value = 0x%lx]\n", value);
      break;
  }
}

/*
 * Debug intrinsic: sva_print_vmcs_allowed_settings()
 *
 * Description:
 *  Prints the allowed settings of various VMCS controls as reported by the
 *  processor in various MSRs. This allows us to determine the "safe default"
 *  settings of reserved bits that we need to enforce in sva_writevmcs().
 *
 *  This is for use during early development. It is not part of the designed
 *  SVA-VMX interface and will be removed.
 */
void
sva_print_vmcs_allowed_settings() {
  printf("\n==============================\n");
  printf("Allowed settings of VMCS controls\n");
  printf("\n==============================\n");

  /*
   * If bit 55 of the MSR IA32_VMX_BASIC is 1, the "TRUE" versions of the
   * VMCS control capability MSRs are safe to read and allow determination of
   * whether the processor supports zero-settings of bits that were reserved
   * to 1 on older processors.
   *
   * If the "TRUE" versions of the MSRs exist, we will read those instead of
   * the regular ones. The "TRUE" MSRs override the less-precise information
   * in the regular ones.
   *
   * Confused yet? :-) Like most confusing aspects of the x86 ISA, this was a
   * concession to backwards compatibility. Intel really didn't do a good job
   * planning ahead on how they were going to make future use of
   * originally-reserved bits when they first designed VMX. They seem to have
   * learned from this mistake by the time they added the secondary
   * VM-execution controls field later on, because they kept things simpler
   * and made all of its reserved bits default to 0 instead of varying
   * per-bit.
   */
  uint64_t vmx_basic = rdmsr(MSR_VMX_BASIC);
  unsigned char safe_to_read_true_msrs = 0;
  if (vmx_basic & 0x0080000000000000)
    safe_to_read_true_msrs = 1;

  /**** Pin-based VM-execution controls ****/
  uint64_t pinbased_allowed_msr;
  if (safe_to_read_true_msrs)
    pinbased_allowed_msr = rdmsr(MSR_VMX_TRUE_PINBASED_CTLS);
  else
    pinbased_allowed_msr = rdmsr(MSR_VMX_PINBASED_CTLS);

  /*
   * These capability MSRs for 32-bit VMCS fields follow a standard format:
   * the lower 32 bits of the MSR report the allowed 0-settings of the
   * control's bits, and the upper 32 bits report the allowed 1-settings.
   *
   * A 0 bit in the 0-settings (lower) section of the MSR means that a
   * 0-setting is allowed for that bit; a 1 bit means that a 0-setting is
   * disallowed.
   *
   * A 1 bit in the 1-settings (upper) section of the MSR means that a
   * 1-setting is allowed for that bit; a 0 bit means that a 1-setting is
   * disallowed.
   */
  uint32_t pinbased_allowed_0 = (uint32_t) pinbased_allowed_msr;
  uint32_t pinbased_allowed_1 = (uint32_t) (pinbased_allowed_msr >> 32);

  /* Print the allowed settings */
  printf("----------\n");
  printf("Allowed 0-settings of VMCS_PINBASED_VM_EXEC_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_PINBASED_VM_EXEC_CTRLS, pinbased_allowed_0);

  printf("----------\n");
  printf("Allowed 1-settings of VMCS_PINBASED_VM_EXEC_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_PINBASED_VM_EXEC_CTRLS, pinbased_allowed_1);

  /**** Primary processor-based VM-execution controls ****/
  uint64_t prim_procbased_allowed_msr;
  if (safe_to_read_true_msrs)
    prim_procbased_allowed_msr = rdmsr(MSR_VMX_TRUE_PROCBASED_CTLS);
  else
    prim_procbased_allowed_msr = rdmsr(MSR_VMX_PROCBASED_CTLS);

  uint32_t prim_procbased_allowed_0 = (uint32_t) prim_procbased_allowed_msr;
  uint32_t prim_procbased_allowed_1 =
    (uint32_t) (prim_procbased_allowed_msr >> 32);

  printf("----------\n");
  printf("Allowed 0-settings of VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS,
      prim_procbased_allowed_0);

  printf("----------\n");
  printf("Allowed 1-settings of VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS,
      prim_procbased_allowed_1);

  /**** Secondary processor-based VM-execution controls ****/
  /*
   * Intel used the newer, more sane scheme of defaulting all reserved bits
   * to 0 for this one, so there's no need to conditionally read a "TRUE"
   * version of the capability MSR.
   */
  uint64_t sec_procbased_allowed_msr = rdmsr(MSR_VMX_PROCBASED_CTLS2);

  uint32_t sec_procbased_allowed_0 = (uint32_t) sec_procbased_allowed_msr;
  uint32_t sec_procbased_allowed_1 =
    (uint32_t) (sec_procbased_allowed_msr >> 32);

  printf("----------\n");
  printf("Allowed 0-settings of VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS,
      sec_procbased_allowed_0);

  printf("----------\n");
  printf("Allowed 1-settings of VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS,
      sec_procbased_allowed_1);

  /**** VM-exit controls ****/
  uint64_t exit_ctrls_allowed_msr;
  if (safe_to_read_true_msrs)
    exit_ctrls_allowed_msr = rdmsr(MSR_VMX_TRUE_EXIT_CTLS);
  else
    exit_ctrls_allowed_msr = rdmsr(MSR_VMX_EXIT_CTLS);

  uint32_t exit_ctrls_allowed_0 = (uint32_t) exit_ctrls_allowed_msr;
  uint32_t exit_ctrls_allowed_1 = (uint32_t) (exit_ctrls_allowed_msr >> 32);

  printf("----------\n");
  printf("Allowed 0-settings of VMCS_VM_EXIT_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_VM_EXIT_CTRLS, exit_ctrls_allowed_0);

  printf("----------\n");
  printf("Allowed 1-settings of VMCS_VM_EXIT_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_VM_EXIT_CTRLS, exit_ctrls_allowed_1);

  /**** VM-entry controls ****/
  uint64_t entry_ctrls_allowed_msr;
  if (safe_to_read_true_msrs)
    entry_ctrls_allowed_msr = rdmsr(MSR_VMX_TRUE_ENTRY_CTLS);
  else
    entry_ctrls_allowed_msr = rdmsr(MSR_VMX_ENTRY_CTLS);

  uint32_t entry_ctrls_allowed_0 = (uint32_t) entry_ctrls_allowed_msr;
  uint32_t entry_ctrls_allowed_1 = (uint32_t) (entry_ctrls_allowed_msr >> 32);

  printf("----------\n");
  printf("Allowed 0-settings of VMCS_VM_ENTRY_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_VM_ENTRY_CTRLS, entry_ctrls_allowed_0);

  printf("----------\n");
  printf("Allowed 1-settings of VMCS_VM_ENTRY_CTRLS:\n");
  printf("----------\n");
  print_vmcs_field(VMCS_VM_ENTRY_CTRLS, entry_ctrls_allowed_1);

  printf("\n==============================\n");
}

/*
 * Debug intrinsic: sva_print_mpx_regs()
 *
 * Description:
 *  Prints the values of the MPX bounds registers BND0-BND3 and the MPX
 *  supervisor-mode configuration MSR IA32_BNDCFGS.
 *
 *  This is for use during development. It is not part of the designed SVA
 *  interface and will be removed.
 */
void
sva_print_mpx_regs(void) {
#ifdef MPX
  /* Store the MPX bounds registers into memory. */
  uint64_t bnd0[2], bnd1[2], bnd2[2], bnd3[2];
  asm __volatile__ (
      "bndmov %%bnd0, (%[bnd0])\n"
      "bndmov %%bnd1, (%[bnd1])\n"
      "bndmov %%bnd2, (%[bnd2])\n"
      "bndmov %%bnd3, (%[bnd3])\n"
      : : [bnd0] "r" (bnd0),
          [bnd1] "r" (bnd1),
          [bnd2] "r" (bnd2),
          [bnd3] "r" (bnd3)
      );

  /* Store XCR0 into memory. */
  uint64_t xcr0;
  xcr0 = xgetbv();

  printf("MPX bounds registers:\n");
  printf("BND0: 0x%lx-0x%lx\tBND1: 0x%lx-0x%lx\n",
      bnd0[0], bnd0[1], bnd1[0], bnd1[1]);
  printf("BND2: 0x%lx-0x%lx\tBND3: 0x%lx-0x%lx\n",
      bnd2[0], bnd2[1], bnd3[0], bnd3[1]);

  printf("MSR IA32_BNDCFGS: 0x%lx\n", rdmsr(MSR_IA32_BNDCFGS));
  printf("XCR0: 0x%lx\n", xcr0);
#endif
}

#if SVA_DEBUG_GSBASE
/*
 * Debug intrinsic: sva_verify_gsbase()
 *
 * Description:
 *  Check that the value of GSBASE is correctly set to point to SVA's
 *  per-CPU data structure.
 *
 *  If it's been clobbered by some other value, print an error message
 *  accordingly and return false. Otherwise, return true.
 *
 *  This is meant to be called from various places in Xen where we suspect it
 *  might be clobbering GSBASE. It is also safe to call from within SVA.
 *
 * Arguments:
 *  * context_msg: A string which will be included within brackets at the end
 *    of the error message that is printed. Useful for indicating some
 *    context about where the check was performed.
 *
 * Return value:
 *  True if GSBASE correctly points to SVA's TLS; false otherwise.
 *
 * SIDE EFFECTS:
 *  * Will restore GSBASE to point to SVA's per-CPU data structure if it didn't
 *    point to it when the intrinsic was called.
 *
 *  * CR4.FSGSBASE will be enabled if it wasn't when the intrinsic was
 *    called.
 */
int
sva_verify_gsbase(const char *const context_msg) {
  /* First enable FSGSBASE in CR4 if it isn't already. */
  write_cr4(read_cr4() | CR4_FSGSBASE);

  uintptr_t gsbase;
  asm volatile (
      "rdgsbase %0\n"
      : "=r" (gsbase));

  extern char TLSBlock[];
  if (gsbase != (uintptr_t)TLSBlock) {
    /* Fix up GSBASE so we can call printk() without crashing (since printk
     * causes interrupts to come in). */
    asm volatile (
        "wrgsbase %0\n"
        : : "r" (TLSBlock));

    /* Print an error message, then dump the CPU state to console. */
    printk("Xen stole our GSBASE and set it to: 0x%lx; "
        "it really should be: 0x%p. [%s]\n",
        gsbase, TLSBlock, context_msg);

    /* Return false to indicate that GSBASE was clobbered. */
    return 0;
  }

  /* Return true to indicate GSBASE correctly pointed to SVA's TLS. */
  return 1;
}
#endif /* SVA_DEBUG_GSBASE */

/*
 * Debug intrinsic: sva_get_vmcs_paddr()
 *
 * Description:
 *  Gets the raw physical address pointer to the Virtual Machine Control
 *  Structure (VMCS) for a virtual machine managed by SVA.
 *
 *  The VMCS lives in secure memory, so in theory the OS/hypervisor shouldn't
 *  care what address it's at, because it can't access it anyway. However,
 *  during the process of porting Xen to SVA, it is necessary to let Xen
 *  continue to use its own code to access an SVA-managed VMCS. (This,
 *  obviously, will only work with the SFI checks turned off or otherwise
 *  neutered.)
 *
 *  This is for use during early development. It is not part of the designed
 *  SVA-VMX interface and will be removed.
 */
uintptr_t
sva_get_vmcs_paddr(int vmid) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_get_vmcs_paddr(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * If this VM's VMCS pointer is null, then this VMID does not correspond to
   * a VM that is actually allocated. (It may have been freed, or never
   * allocated in the first place.)
   */
  if (usevmx) {
    if (!vm_descs[vmid].vmcs_paddr) {
      panic("Fatal error: tried to access a VM ID that is not allocated "
            "(vmcs_paddr = 0)!\n");
    }
  }

  uintptr_t retval = vm_descs[vmid].vmcs_paddr;

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return retval;
}

/*
 * Debug intrinsic: sva_get_vmid_from_vmcs()
 *
 * Description:
 *  Given the physical address of a Virtual Machine Control Structure (VMCS),
 *  find and return SVA's numeric VMID corresponding to that VMCS.
 *
 *  This is feasible since SVA maintains a one-to-one correspondence between
 *  VMIDs and VMCSes. (It's not especially efficient since we need to do a
 *  brute-force search through the VM descriptor array, but that's fine for a
 *  stopgap intrinsic like this. There are only 128 entries in the array.)
 *
 *  This is for use during early development. It is not part of the designed
 *  SVA-VMX interface and will be removed.
 *
 *  (Used by Xen temporarily until we transition Xen to keeping track of
 *  VMIDs instead of VMCs addresses.)
 *
 * Return value:
 *  The VMID corresponding to the given VMCS physical address, if it exists.
 *
 *  If no VM matching the given VMCS pointer was found in SVA's VM descriptor
 *  array, a negative value is returned, indicating an error.
 */
int
sva_get_vmid_from_vmcs(uintptr_t vmcs_paddr) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_get_vmid_from_vmcs(): Shade not yet initialized on this processor!\n");

  /*
   * Search SVA's VM descriptor array to find the VM whose VMCS pointer
   * matches the one we've been given.
   *
   * (We skip the entry at index 0 since VPID=0 is used to tag the host's
   * entries in the TLB, and thus SVA will never assign a VM an ID of 0.)
   */
  int vmid = -1;
  for (int i = 1; i < MAX_VMS; i++) {
    if (vm_descs[i].vmcs_paddr == vmcs_paddr) {
      vmid = i;
      break;
    }
  }

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return vmid;
}
