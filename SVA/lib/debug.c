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

#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/state.h>
#include <sva/interrupt.h>
#include <sva/mmu.h>
#include <sva/util.h>
#include <sva/vmx.h>
#include <sva/vmx_intrinsics.h>
#include <machine/frame.h>

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

  if (p->valid != 1) {
    sva_print_icontext ("assertGoodIC");
    panic ("SVA: assertGoodIC: Bad IC: %lx\n", p->valid);
  }
  return;
}

/*****************************************************************************
 * Cheater's Code
 ****************************************************************************/

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
  /*
   * Fetch the currently available interrupt context.
   */
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
  	tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();

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
  record_tsc(sva_trapframe_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
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
  /*
   * Fetch the currently available interrupt context.
   */
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();

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
  record_tsc(sva_syscall_trapframe_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
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

static void
print_icontext (char * s, sva_icontext_t * p) {
  printf ("rip: 0x%lx   rsp: 0x%lx   rbp: 0x%lx \n", p->rip, p->rsp, p->rbp);
  printf ("rax: 0x%lx   rbx: 0x%lx   rcx: 0x%lx \n", p->rax, p->rbx, p->rcx);
  printf ("rdx: 0x%lx   rsi: 0x%lx   rdi: 0x%lx \n", p->rdx, p->rsi, p->rdi);
  printf ("SVA: icontext  cs: 0x%lx\n", p->cs);
  printf ("SVA: icontext  rflags  : 0x%lx\n", p->rflags);
  printf ("SVA: icontext  code    : 0x%lx\n", p->code);
  printf ("SVA: icontext  trapno  : 0x%lx\n", p->trapno);
  printf ("SVA: icontext  invokep : 0x%lx\n", p->invokep);
  printf ("es: 0x%x   fs: 0x%x    ds: 0x%x   gs: 0x%x \n", p->es, p->fs, p->ds, p->gs);
  printf ("----------------------------------------------------------------\n");
  return;
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
  pml4e_t * secmemp = (pml4e_t *) getVirtual ((uintptr_t)(get_pagetable() + secmemOffset));
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
  printf ("SVA: %d: ist3 = %p: %lx\n", id, &(cpup->tssp->ist3), cpup->tssp->ist3);
  if (cpup->tssp->ist3 == 0) {
    __asm__ __volatile__ ("xchg %%bx, %%bx\n" :: "a" (id));
  }
  return;
}

void
sva_print_inttable (void) {
  extern void default_interrupt (unsigned int number, void * icontext);
  extern void * interrupt_table[256];
  unsigned index = 0;
  for (unsigned index = 0; index < 256; ++index) {
    if (interrupt_table[index] != default_interrupt)
      printf ("SVA: %d: %lx\n", index, interrupt_table[index]);
  }
  return;
}

void
sva_checkptr (uintptr_t p) {
  //
  // If we're in kernel memory but not above the secure memory region, hit a
  // breakpoint.
  //
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  if (p >= 0xffffff8000000000) {
    if (!(p & 0x0000008000000000u)) {
      bochsBreak();
      __asm__ __volatile__ ("int $3\n");
    }
  }

  record_tsc(sva_checkptr_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_print_vmx_msrs()
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
  printf("CR0: 0x%lx\n", _rcr0());
  printf("CR4: 0x%lx\n", _rcr4());
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

  switch(field) {
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
      printf("VMCS_EXIT_MSR_LOAD_COUNT");
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

