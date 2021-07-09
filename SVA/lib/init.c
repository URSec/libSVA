/*===- init.c - SVA Execution Engine  ---------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This is code to initialize the SVA Execution Engine.  It is inherited from
 * the original SVA system.
 *
 *===----------------------------------------------------------------------===
 */

/*-
 * Copyright (c) 1989, 1990 William F. Jolitz
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  from: @(#)segments.h  7.1 (Berkeley) 5/9/91
 * $FreeBSD: release/9.0.0/sys/amd64/include/segments.h 227946 2011-11-24 18:44:14Z rstone $
 */

/*-
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: release/9.0.0/sys/amd64/include/cpufunc.h 223796 2011-07-05 18:42:10Z jkim $
 */

#include <sva/init.h>
#include <sva/types.h>
#include <sva/apic.h>
#include <sva/config.h>
#include <sva/fpu.h>
#include <sva/frame_meta.h>
#include <sva/icontext.h>
#include <sva/state.h>
#include <sva/util.h>
#include <sva/mmu.h>
#include <sva/interrupt.h>
#include <sva/invoke.h>
#include <sva/mpx.h>
#include <sva/msr.h>
#include <sva/page.h>
#include <sva/page_walk.h>
#include <sva/percpu.h>
#include <sva/self_profile.h>

#include "thread_stack.h"

#include <string.h>
#include <limits.h>

static void fptrap (unsigned int vector);
static void init_dispatcher ();

/* Default LLVA interrupt, exception, and system call handlers */
extern void default_interrupt (unsigned int number, void * icontext);

unsigned int __svadata cpu_online_count;

/*
 * Taken from FreeBSD: amd64/segments.h
 *
 * Gate descriptors (e.g. indirect descriptors, trap, interrupt etc. 128 bit)
 * Only interrupt and trap gates have gd_ist.
 */
struct  gate_descriptor {
  unsigned long gd_looffset:16; /* gate offset (lsb) */
  unsigned long gd_selector:16; /* gate segment selector */
  unsigned long gd_ist:3;   /* IST table index */
  unsigned long gd_xx:5;    /* unused */
  unsigned long gd_type:5;    /* segment type */
  unsigned long gd_dpl:2;   /* segment descriptor priority level */
  unsigned long gd_p:1;   /* segment descriptor present */
  unsigned long gd_hioffset:48 __attribute__ ((__packed__));  /* gate offset (msb) */
  unsigned long sd_xx1:32;
} __attribute__ ((packed));

/* Taken from FreeBSD: amd64/segments.h */
#define GSEL(s,r) (((s)<<3) | r)      /* a global selector */
#ifdef XEN
#define GCODE_SEL 0x1c01 /* Xen Code Descriptor */
#else
#define GCODE_SEL 4 /* Kernel Code Descriptor */
#endif

/*
 * Structure: sva_idt
 *
 * Description:
 *  This is the x86 interrupt descriptor table.  We use it to hold all of the
 *  interrupt vectors internally within the Execution Engine.
 *
 *  Note that we need one of these per processor.
 */
static struct gate_descriptor __svadata sva_idt[256];

/* Taken from segments.h in FreeBSD */
static const unsigned int SDT_SYSIGT=14;  /* system 64 bit interrupt gate */

void
sva_debug (void) {
  printf ("SVA: Debug!\n");
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

/**
 * Initialize SVA's TLS and set up %gs.base
 */
static void init_TLS(tss_t *tss) {
  sva_getCPUState(tss);
}

/**
 * Install the specified handler into the x86 Interrupt Descriptor Table (IDT)
 * as an interrupt.
 *
 * Note: This is based off of the amd64 setidt() code in FreeBSD.
 *
 * @param number    The interrupt vector
 * @param interrupt A pointer to the interrupt handler
 * @param priv      The x86_64 privilege level which can access this interrupt
 * @param ist_index The IST index to use for the interrupt
 */
static void register_x86_interrupt(int number, void (*interrupt)(void),
                                   unsigned char priv, size_t ist_index) {
  /*
   * First determine which interrupt table we should be modifying.
   */
  struct gate_descriptor *ip = &sva_idt[number];

  /*
   * Add the entry into the table.
   */
  ip->gd_looffset = (uintptr_t)interrupt;
  ip->gd_selector = GSEL(GCODE_SEL, 0);
  ip->gd_ist = ist_index;
  ip->gd_xx = 0;
  ip->gd_type = SDT_SYSIGT;
  ip->gd_dpl = priv;
  ip->gd_p = 1;
  ip->gd_hioffset = ((uintptr_t)interrupt)>>16 ;
}

/*
 * Function: fptrap()
 *
 * Description:
 *  This function captures FP traps and flags use of the FP unit accordingly.
 */
static void fptrap(unsigned int __attribute__((unused)) vector) {
#ifdef SVA_DEBUG_CHECKS
  /*
   * Currently, we only support user-space applications using the floating
   * point unit.  If the kernel uses the floating point unit, panic the
   * system.
   */
  if (sva_was_privileged()) {
    panic ("SVA: Kernel attempted to use Floating Point Unit!");
  }
#endif

#ifdef SVA_LAZY_FPU
  /*
   * Get the thread that last used the FPU.  If there is no such thread
   * (which happens if this is the first thread using the FPU) or if that
   * thread is the current thread, then just enable the FPU.
   */
  struct SVAThread * runningThread    = getCPUState()->currentThread;
  struct SVAThread * previousFPThread = getCPUState()->prevFPThread;
  if ((!previousFPThread) || (previousFPThread == runningThread)) {
    fpu_enable();
    return;
  }

  /*
   * This is the implementation of saving the floating point state lazily.
   * Since we're in an fptrap, we need to save the floating point state of the 
   * thread that was the last one to use the floating point unit.
   */
  sva_integer_state_t * prev = &(previousFPThread->integerState);
  xsave(&prev->fpstate.inner);

  /*
   * Flag that the floating point unit has now been used.
   */
  getCPUState()->fp_used = 1;


  /*
   * Load the floating point state for the current thread and mark this thread
   * as the last one to use the floating point unit.
   */
  sva_integer_state_t * intstate = &(runningThread->integerState);
  xrestore(&intstate->fpstate.inner);
  getCPUState()->prevFPThread = runningThread;

  /*
   * Turn off the TS bit in CR0; this allows the FPU to proceed with floating
   * point operations.
   */
  fpu_enable();
#else
  /*
   * Hmm... this shouldn't have happened.
   */

  /*
   * FIXME: We can recover more cleanly here than just panicking.
   */
  panic("SVA: Unexpected #NM; %%cr0 = %lx\n", read_cr0());
#endif
}

/*
 * Function: init_interrupt_table()
 *
 * Description:
 *  This function initializes the table of system software functions to call
 *  when an interrupt or trap occurs.  Since the system software hasn't set up
 *  any callback functions, we use a default handler that belongs to SVA.
 */
static void
init_interrupt_table (unsigned int procID) {
  extern void sva_syscall(void);

  (void)procID;

  for (int index = 0; index < 256; index++) {
    interrupt_table[index] = default_interrupt;
  }
  interrupt_table[256] = sva_syscall;
}

/*
 * Function: init_idt()
 *
 * Description:
 *  Initialize the x86 Interrupt Descriptor Table (IDT) to some nice default
 *  values for the specified processor.
 *
 * Inputs:
 *  procID - The ID of the processor which should have its IDT initialized.
 */
static void
init_idt (unsigned int procID) {
  (void)procID;

  /* Argument to lidt/sidt taken from FreeBSD. */
  static struct region_descriptor {
    unsigned long rd_limit:16;    /* segment extent */
    unsigned long rd_base :64 __attribute__ ((packed));  /* base address  */
  } __attribute__ ((packed)) sva_idtreg;

  /* Kernel's idea of where the IDT is */
#ifdef FreeBSD
  extern void * idt;
#endif

  /*
   * Make sure that fsgsbase support is enabled.
   */
  write_cr4(read_cr4() | CR4_FSGSBASE);

  /*
   * Load our descriptor table on to the processor. NB: The IDT limit is
   * actually the last addressable byte and should therefore be set to
   * `sizeof(sva_idt) - 1`.
   */
  sva_idtreg.rd_limit = sizeof(sva_idt) - 1;
  sva_idtreg.rd_base = (uintptr_t) &(sva_idt[0]);
  __asm__ __volatile__ ("lidt %0" : : "m" (sva_idtreg));
#ifdef FreeBSD
  idt = (void *) sva_idtreg.rd_base;
#endif

  return;
}

/*
 * Initialize various things that needs to be initialized for the FPU.
 */
static void init_fpu(void) {
  uint64_t cr0 = read_cr0();

  /*
   * Unset the emulation bit and set the monitor bit.
   */
  cr0 &= ~(CR0_EM);
  cr0 |= CR0_MP;

#if defined(SVA_LAZY_FPU) || defined(SVA_DEBUG_CHECKS)
  /*
   * Set the task-switched bit to trigger a fault the next time the FPU is used.
   */
  cr0 |= CR0_TS;
#else
  /*
   * Clear the task-switched bit.
   */
  cr0 &= ~CR0_TS;
#endif

  write_cr0(cr0);

  /*
   * Enable SSE and XSave support.
   */
  write_cr4(read_cr4() | CR4_OSFXSR | CR4_OSXSAVE | CR4_OSXMMEXCPT);

  /*
   * Register the co-processor trap so that we know when an FP operation has
   * been performed.
   */
  sva_register_general_exception(0x7, fptrap);

  /*
   * TODO: Determine available features from CPUID.
   */
  xsave_features = XCR0_X87 | XCR0_SSE | XCR0_AVX | XCR0_MPXBND | XCR0_MPXCSR |
                   XCR0_AVX512MASK | XCR0_AVX512HIGH256 | XCR0_AVX512HIGHZMM;

  xsetbv(xsave_features);
}

/**
 * Initialize the Intel MPX bounds checking registers for use with software
 * fault isolation (SFI).
 */
static void init_mpx(void) {
#ifdef MPX
  /*
   * Enable bounds checking for kernel mode code.  We enable the
   * bndEnable bit to enable bounds checking and the bndPreserve bit to
   * ensure that control flow instructions do not clear the bounds registers.
   */
  wrmsr(MSR_IA32_BNDCFGS, BNDCFG_BNDENABLE | BNDCFG_BNDPRESERVE);

  /*
   * Initialize the bounds registers for SFI.
   */
  mpx_bnd_init();
#endif
}

/*
 * Function: testmpx()
 *
 * Description:
 *  This function can be called by the kernel to test the MPX functionality.
 */
void
testmpx (void) {
#ifdef MPX
  struct sillyStruct {
    unsigned long a;
    unsigned long b;
  } foo;

  /*
   * Load bounds information into the second bounds register (BND1).
   */
  __asm__ __volatile__ ("bndmk (%0,%1), %%bnd1\n"
                        :
                        : "a" (&foo), "d" (sizeof(foo) - 1));

  __asm__ __volatile__ ("bndcl %0, %%bnd0\n" :: "a" (&(testmpx)));
  __asm__ __volatile__ ("bndcu %0, %%bnd0\n" :: "a" (&(foo.b)));
#endif
  return;
}

/*
 * Intrinsic: sva_init_primary()
 *
 * Description:
 *  This routine initializes all of the information needed by the SVA
 *  Execution Engine.  We do things here like setting up the interrupt
 *  descriptor table.  Note that this should be called by the primary processor
 *  (the first one that starts execution on system boot).
 */
void
sva_init_primary () {
  SVA_PROF_ENTER();

  init_threads();

  /* Initialize the IDT of the primary processor */
  init_interrupt_table(0);
  init_dispatcher ();
  init_idt (0);
  register_syscall_handler();

  init_fpu();
  init_mpx();

  SVA_PROF_EXIT(init_primary);
}

/*
 * Intrinsic: sva_init_primary_xen()
 *
 * Description:
 *  This routine initializes all of the information needed by the SVA
 *  Execution Engine.  We do things here like setting up the interrupt
 *  descriptor table.  Note that this should be called by the primary processor
 *  (the first one that starts execution on system boot).
 */
void
sva_init_primary_xen(void __kern* tss) {
  SVA_PROF_ENTER();

  cpu_online_count = 1;

  init_threads();

  /*
   * Note: we must call init_TLS() to initialize SVA's per-CPU region for
   * this CPU *before* taking control of its IDT. This is because
   * alloc_percpu_region() (called downstream of init_TLS()) may need to
   * temporarily re-enable interrupts in order to call back into the OS to
   * request physical memory backing for the per-CPU region. Since the OS has
   * not yet had the opportunity to register its interrupt handlers with SVA
   * (it'll do that after sva_init_primary_xen() returns), any interrupts
   * that come in during that window would be taken by SVA's default
   * interrupt handler, which will likely lead to incorrect system behavior.
   * (Our default interrupt handler merely prints a message and discards the
   * interrupt.)
   */
  init_TLS((tss_t*)tss);

  /* Initialize the IDT of the primary processor */
  init_interrupt_table(0);
  init_dispatcher();
  init_idt(0);
  register_syscall_handler();

  init_fpu();
  init_mpx();

  SVA_PROF_EXIT(init_primary);
}

static init_fn __svadata ap_startup_callback;
void* __svadata ap_startup_stack;

void __attribute__((noreturn)) sva_init_secondary(void) {
  SVA_PROF_ENTER();

  init_fn startup_cb = ap_startup_callback;
  __atomic_fetch_add(&cpu_online_count, 1, __ATOMIC_RELEASE);

  SVA_PROF_EXIT(init_secondary);
  startup_cb();
}

#ifdef XEN
void sva_init_secondary_xen(void __kern* tss) {
  SVA_PROF_ENTER();

  init_TLS((tss_t*)tss);

  init_idt(0);
  register_syscall_handler();
  init_fpu();
  init_mpx();

  SVA_PROF_EXIT(init_secondary);
}
#endif

void register_syscall_handler(void) {
  extern void SVAsyscall(void);

  wrmsr(MSR_FMASK, EFLAGS_IF | EFLAGS_IOPL(3) | EFLAGS_AC | EFLAGS_DF |
                   EFLAGS_NT | EFLAGS_VM | EFLAGS_TF | EFLAGS_RF);
  wrmsr(MSR_STAR, ((uint64_t)GSEL(GCODE_SEL, 0) << SYSCALL_CS_SHIFT) |
                  ((uint64_t)SVA_USER_CS_32 << SYSRET_CS_SHIFT));
  wrmsr(MSR_LSTAR, (uintptr_t)&SVAsyscall);
#if 0
  wrmsr(MSR_CSTAR, (uintptr_t)&SVAsyscall);
#else
  /* For now, we don't handle syscalls from 32-bit code */
  wrmsr(MSR_CSTAR, (uintptr_t)NULL);
#endif

  /*
   * We don't handle sysenter.
   */
  wrmsr(MSR_IA32_SYSENTER_CS, 0);
  wrmsr(MSR_IA32_SYSENTER_EIP, 0);
  wrmsr(MSR_IA32_SYSENTER_ESP, 0);
}

#define REGISTER_EXCEPTION(number)                                      \
  extern void trap##number(void);                                       \
  register_x86_interrupt ((number),trap##number, 0, 3);

#define REGISTER_SWEXCEPTION(number)                                    \
  extern void trap##number(void);                                       \
  register_x86_interrupt((number), trap##number, 3, 3);

#define REGISTER_PARANOID_EXCEPTION(number, ist_index)                  \
  extern void trap##number(void);                                       \
  register_x86_interrupt((number), trap##number, 0, (ist_index));

#define REGISTER_INTERRUPT(number)                                      \
  extern void interrupt##number(void);                                  \
  register_x86_interrupt ((number),interrupt##number, 0, 3);

static void
init_dispatcher ()
{
  /* Register the secure memory allocation and deallocation traps */
  extern void trap123(void);
  extern void trap124(void);
  extern void trap125(void);
  extern void trap126(void);
  extern void trap127(void);
  extern void SVAbadtrap(void);
  extern unsigned char * allocSecureMemory (uintptr_t size);
  extern void freeSecureMemory (unsigned char * p, uintptr_t size);
  extern void installNewPushTarget (void * f);
  extern void getThreadSecret();
  extern void getThreadRID();

  /*
   * Register the bad trap handler for all interrupts and traps.
   */
  for (unsigned index = 0; index < 255; ++index) {
    register_x86_interrupt(index, SVAbadtrap, 0, 3);
  }

  /* Register general exception */
  REGISTER_EXCEPTION(0);
  REGISTER_PARANOID_EXCEPTION(1, 4);
  REGISTER_PARANOID_EXCEPTION(2, 7);
  REGISTER_SWEXCEPTION(3);
  REGISTER_SWEXCEPTION(4);
  REGISTER_EXCEPTION(5);
  REGISTER_EXCEPTION(6);
  REGISTER_EXCEPTION(7);
  REGISTER_PARANOID_EXCEPTION(8, 5);
  REGISTER_EXCEPTION(9);
  REGISTER_EXCEPTION(10);
  REGISTER_EXCEPTION(11);
  REGISTER_EXCEPTION(12);
  REGISTER_EXCEPTION(13);
  REGISTER_EXCEPTION(14);   /* Page fault trap */
  REGISTER_EXCEPTION(15);
  REGISTER_EXCEPTION(16);
  REGISTER_EXCEPTION(17);   /* Alignment trap */
  REGISTER_PARANOID_EXCEPTION(18, 6);
  REGISTER_EXCEPTION(19);
  REGISTER_EXCEPTION(20);
  REGISTER_EXCEPTION(21);
  REGISTER_EXCEPTION(22);
  REGISTER_EXCEPTION(23);
  REGISTER_EXCEPTION(24);
  REGISTER_EXCEPTION(25);
  REGISTER_EXCEPTION(26);
  REGISTER_EXCEPTION(27);
  REGISTER_EXCEPTION(28);
  REGISTER_EXCEPTION(29);
  REGISTER_EXCEPTION(30);
  REGISTER_EXCEPTION(31);

  /* Register interrupt handlers */
  REGISTER_INTERRUPT(32)
  REGISTER_INTERRUPT(33)
  REGISTER_INTERRUPT(34)
  REGISTER_INTERRUPT(35)
  REGISTER_INTERRUPT(36)
  REGISTER_INTERRUPT(37)
  REGISTER_INTERRUPT(38)
  REGISTER_INTERRUPT(39)
  REGISTER_INTERRUPT(40)
  REGISTER_INTERRUPT(41)
  REGISTER_INTERRUPT(42)
  REGISTER_INTERRUPT(43)
  REGISTER_INTERRUPT(44)
  REGISTER_INTERRUPT(45)
  REGISTER_INTERRUPT(46)
  REGISTER_INTERRUPT(47)
  REGISTER_INTERRUPT(48)
  REGISTER_INTERRUPT(49)
  REGISTER_INTERRUPT(50)
  REGISTER_INTERRUPT(51)
  REGISTER_INTERRUPT(52)
  REGISTER_INTERRUPT(53)
  REGISTER_INTERRUPT(54)
  REGISTER_INTERRUPT(55)
  REGISTER_INTERRUPT(56)
  REGISTER_INTERRUPT(57)
  REGISTER_INTERRUPT(58)
  REGISTER_INTERRUPT(59)
  REGISTER_INTERRUPT(60)
  REGISTER_INTERRUPT(61)
  REGISTER_INTERRUPT(62)
  REGISTER_INTERRUPT(63)
  REGISTER_INTERRUPT(64)
  REGISTER_INTERRUPT(65)
  REGISTER_INTERRUPT(66)
  REGISTER_INTERRUPT(67)
  REGISTER_INTERRUPT(68)
  REGISTER_INTERRUPT(69)
  REGISTER_INTERRUPT(70)
  REGISTER_INTERRUPT(71)
  REGISTER_INTERRUPT(72)
  REGISTER_INTERRUPT(73)
  REGISTER_INTERRUPT(74)
  REGISTER_INTERRUPT(75)
  REGISTER_INTERRUPT(76)
  REGISTER_INTERRUPT(77)
  REGISTER_INTERRUPT(78)
  REGISTER_INTERRUPT(79)
  REGISTER_INTERRUPT(80)
  REGISTER_INTERRUPT(81)
  REGISTER_INTERRUPT(82)
  REGISTER_INTERRUPT(83)
  REGISTER_INTERRUPT(84)
  REGISTER_INTERRUPT(85)
  REGISTER_INTERRUPT(86)
  REGISTER_INTERRUPT(87)
  REGISTER_INTERRUPT(88)
  REGISTER_INTERRUPT(89)
  REGISTER_INTERRUPT(90)
  REGISTER_INTERRUPT(91)
  REGISTER_INTERRUPT(92)
  REGISTER_INTERRUPT(93)
  REGISTER_INTERRUPT(94)
  REGISTER_INTERRUPT(95)
  REGISTER_INTERRUPT(96)
  REGISTER_INTERRUPT(97)
  REGISTER_INTERRUPT(98)
  REGISTER_INTERRUPT(99)
  REGISTER_INTERRUPT(100)
  REGISTER_INTERRUPT(101)
  REGISTER_INTERRUPT(102)
  REGISTER_INTERRUPT(103)
  REGISTER_INTERRUPT(104)
  REGISTER_INTERRUPT(105)
  REGISTER_INTERRUPT(106)
  REGISTER_INTERRUPT(107)
  REGISTER_INTERRUPT(108)
  REGISTER_INTERRUPT(109)
  REGISTER_INTERRUPT(110)
  REGISTER_INTERRUPT(111)
  REGISTER_INTERRUPT(112)
  REGISTER_INTERRUPT(113)
  REGISTER_INTERRUPT(114)
  REGISTER_INTERRUPT(115)
  REGISTER_INTERRUPT(116)
  REGISTER_INTERRUPT(117)
  REGISTER_INTERRUPT(118)
  REGISTER_INTERRUPT(119)
  REGISTER_INTERRUPT(120)
  REGISTER_INTERRUPT(121)
  REGISTER_INTERRUPT(122)
#if 0
  REGISTER_INTERRUPT(123)
  REGISTER_INTERRUPT(124)
  REGISTER_INTERRUPT(125)
  REGISTER_INTERRUPT(126)
  REGISTER_INTERRUPT(127)
#endif
  REGISTER_INTERRUPT(128)
  REGISTER_INTERRUPT(129)
  REGISTER_INTERRUPT(130)
  REGISTER_INTERRUPT(131)
  REGISTER_INTERRUPT(132)
  REGISTER_INTERRUPT(133)
  REGISTER_INTERRUPT(134)
  REGISTER_INTERRUPT(135)
  REGISTER_INTERRUPT(136)
  REGISTER_INTERRUPT(137)
  REGISTER_INTERRUPT(138)
  REGISTER_INTERRUPT(139)
  REGISTER_INTERRUPT(140)
  REGISTER_INTERRUPT(141)
  REGISTER_INTERRUPT(142)
  REGISTER_INTERRUPT(143)
  REGISTER_INTERRUPT(144)
  REGISTER_INTERRUPT(145)
  REGISTER_INTERRUPT(146)
  REGISTER_INTERRUPT(147)
  REGISTER_INTERRUPT(148)
  REGISTER_INTERRUPT(149)
  REGISTER_INTERRUPT(150)
  REGISTER_INTERRUPT(151)
  REGISTER_INTERRUPT(152)
  REGISTER_INTERRUPT(153)
  REGISTER_INTERRUPT(154)
  REGISTER_INTERRUPT(155)
  REGISTER_INTERRUPT(156)
  REGISTER_INTERRUPT(157)
  REGISTER_INTERRUPT(158)
  REGISTER_INTERRUPT(159)
  REGISTER_INTERRUPT(160)
  REGISTER_INTERRUPT(161)
  REGISTER_INTERRUPT(162)
  REGISTER_INTERRUPT(163)
  REGISTER_INTERRUPT(164)
  REGISTER_INTERRUPT(165)
  REGISTER_INTERRUPT(166)
  REGISTER_INTERRUPT(167)
  REGISTER_INTERRUPT(168)
  REGISTER_INTERRUPT(169)
  REGISTER_INTERRUPT(170)
  REGISTER_INTERRUPT(171)
  REGISTER_INTERRUPT(172)
  REGISTER_INTERRUPT(173)
  REGISTER_INTERRUPT(174)
  REGISTER_INTERRUPT(175)
  REGISTER_INTERRUPT(176)
  REGISTER_INTERRUPT(177)
  REGISTER_INTERRUPT(178)
  REGISTER_INTERRUPT(179)
  REGISTER_INTERRUPT(180)
  REGISTER_INTERRUPT(181)
  REGISTER_INTERRUPT(182)
  REGISTER_INTERRUPT(183)
  REGISTER_INTERRUPT(184)
  REGISTER_INTERRUPT(185)
  REGISTER_INTERRUPT(186)
  REGISTER_INTERRUPT(187)
  REGISTER_INTERRUPT(188)
  REGISTER_INTERRUPT(189)
  REGISTER_INTERRUPT(190)
  REGISTER_INTERRUPT(191)
  REGISTER_INTERRUPT(192)
  REGISTER_INTERRUPT(193)
  REGISTER_INTERRUPT(194)
  REGISTER_INTERRUPT(195)
  REGISTER_INTERRUPT(196)
  REGISTER_INTERRUPT(197)
  REGISTER_INTERRUPT(198)
  REGISTER_INTERRUPT(199)
  REGISTER_INTERRUPT(200)
  REGISTER_INTERRUPT(201)
  REGISTER_INTERRUPT(202)
  REGISTER_INTERRUPT(203)
  REGISTER_INTERRUPT(204)
  REGISTER_INTERRUPT(205)
  REGISTER_INTERRUPT(206)
  REGISTER_INTERRUPT(207)
  REGISTER_INTERRUPT(208)
  REGISTER_INTERRUPT(209)
  REGISTER_INTERRUPT(210)
  REGISTER_INTERRUPT(211)
  REGISTER_INTERRUPT(212)
  REGISTER_INTERRUPT(213)
  REGISTER_INTERRUPT(214)
  REGISTER_INTERRUPT(215)
  REGISTER_INTERRUPT(216)
  REGISTER_INTERRUPT(217)
  REGISTER_INTERRUPT(218)
  REGISTER_INTERRUPT(219)
  REGISTER_INTERRUPT(220)
  REGISTER_INTERRUPT(221)
  REGISTER_INTERRUPT(222)
  REGISTER_INTERRUPT(223)
  REGISTER_INTERRUPT(224)
  REGISTER_INTERRUPT(225)
  REGISTER_INTERRUPT(226)
  REGISTER_INTERRUPT(227)
  REGISTER_INTERRUPT(228)
  REGISTER_INTERRUPT(229)
  REGISTER_INTERRUPT(230)
  REGISTER_INTERRUPT(231)
  REGISTER_INTERRUPT(232)
  REGISTER_INTERRUPT(233)
  REGISTER_INTERRUPT(234)
  REGISTER_INTERRUPT(235)
  REGISTER_INTERRUPT(236)
  REGISTER_INTERRUPT(237)
  REGISTER_INTERRUPT(238)
  REGISTER_INTERRUPT(239)
  REGISTER_INTERRUPT(240)
  REGISTER_INTERRUPT(241)
  REGISTER_INTERRUPT(242)
  REGISTER_INTERRUPT(243)
  REGISTER_INTERRUPT(244)
  REGISTER_INTERRUPT(245)
  REGISTER_INTERRUPT(246)
  REGISTER_INTERRUPT(247)
  REGISTER_INTERRUPT(248)
  REGISTER_INTERRUPT(249)
  REGISTER_INTERRUPT(250)
  REGISTER_INTERRUPT(251)
  REGISTER_INTERRUPT(252)
  REGISTER_INTERRUPT(253)
  REGISTER_INTERRUPT(254)
  REGISTER_INTERRUPT(255)

  /*
   * Register the secure memory allocation and deallocation handlers.
   */
  register_x86_interrupt(0x7b, trap123, 3, 3);
  register_x86_interrupt(0x7c, trap124, 3, 3);
  register_x86_interrupt(0x7d, trap125, 3, 3);
  register_x86_interrupt(0x7e, trap126, 3, 3);
  register_x86_interrupt(0x7f, trap127, 3, 3);
  register_hypercall(0x7b, getThreadRID);
  register_hypercall(0x7c, getThreadSecret);
  register_hypercall(0x7d, installNewPushTarget);
  register_hypercall(0x7e, freeSecureMemory);
  register_hypercall(0x7f, (void(*)())allocSecureMemory);
}

static bool create_startup_region(paddr_t start_page) {
  extern const char ap_start[];
  extern const char ap_start_gdt[];
  extern const char ap_start_gdt_desc[];
  extern const char ap_start_pt[];
  extern const char ap_start_end[];
  extern void __attribute__((noreturn)) ap_start_64(void);

  unsigned char* start_page_dm = __va(start_page);
  size_t start_area_len = ap_start_end - ap_start;
  memcpy(start_page_dm, ap_start, start_area_len);

  /*
   * Handle relocation of the GDT base.
   */
  unsigned int* gdt_base_ptr =
    (unsigned int*)(start_page_dm + (ap_start_gdt_desc - ap_start) + 2);
  *gdt_base_ptr += start_page;

  /*
   * Inform the AP of the location of our root page table.
   */
  cr3_t root_pt = get_root_pagetable();
  unsigned int* root_pt_ptr =
    (unsigned int*)(start_page_dm + (ap_start_pt - ap_start));
  *root_pt_ptr = root_pt;

  /*
   * Write the call gate for the jump to 64-bit mode into the GDT.
   */
  unsigned long* gdt_ptr =
    (unsigned long*)(start_page_dm + (ap_start_gdt - ap_start));
  struct call_gate* jmp_64_gate = (struct call_gate*)&gdt_ptr[2];
  *jmp_64_gate = (struct call_gate) {
    .target_low = (uintptr_t)ap_start_64,
    .target_high = (uintptr_t)ap_start_64 >> 16,
    .target_sel = GSEL(0x1, 0),
    .type_lower = 0b01100,
    .type_upper = 0,
    .present = true,
    .dpl = 0,
    ._reserved0 = 0,
    ._reserved1 = 0,
    ._reserved2 = 0,
  };

  return true;
}

bool sva_launch_ap(uint32_t apic_id, paddr_t start_page,
                   init_fn init, void* stack)
{
  if (start_page >= 0x100000UL /* 1MB */) {
    printf("SVA: WARNING: AP start page address (0x%lx) "
           "higher than 1MB limit\n",
           start_page);
    return false;
  }
  if (start_page & (PG_L1_SIZE - 1)) {
    printf("SVA: WARNING: AP start page address (0x%lx) not properly aligned\n",
           start_page);
    return false;
  }

  paddr_t start_page_phys = __pa(start_page);
  if (start_page_phys != start_page) {
    printf("SVA: WARNING: AP start page (at 0x%lx) not identity mapped\n",
           start_page);
    return false;
  }

  cr3_t root_pt = get_root_pagetable();
  if (root_pt >= 0x100000000UL /* 4GB */) {
    printf("SVA: WARNING: "
           "Root page table (at 0x%lx) for AP start is higher than 4GB limit\n",
           root_pt);
    return false;
  }

  /*
   * Take another reference to the root page table on behalf of the processor
   * we are starting.
   */
  frame_take(get_frame_desc(root_pt), PGT_L4);

  /*
   * TODO: Check and (somehow?) lock the entry mapping the AP startup code.
   */

  ap_startup_callback = init;
  ap_startup_stack = stack;
  int current_online_cpus = cpu_online_count;

  create_startup_region(start_page);

  /*
   * Send INIT IPI.
   */
  printf("SVA: DEBUG: Sending INIT to processor %u\n", apic_id);
  apic_send_ipi(MAKE_INIT_IPI(apic_id));

  /*
   * Send de-assert INIT IPI.
   */
  apic_send_ipi(MAKE_INIT_DEASSERT_IPI());

  /*
   * Send Startup IPI.
   */
  printf("SVA: DEBUG: Sending startup IPI to processor %u\n", apic_id);
  apic_send_ipi(MAKE_STARTUP_IPI(apic_id, start_page));

  /*
   * Wait up to 30 million clocks (about 10ms on most CPUs) for acknowledgement
   * from the AP.
   */
  bool ack = false;
  unsigned long start = sva_read_tsc();
  do {
    int new_online_cpus = __atomic_load_n(&cpu_online_count, __ATOMIC_RELAXED);
    if (new_online_cpus > current_online_cpus) {
      ack = true;
    } else {
      pause();
    }
  } while (!ack && sva_read_tsc() < start + 30000000);

  if (!ack) {
    printf("SVA: WARNING: Failed to start CPU %x\n", apic_id);
  }

  return ack;
}
