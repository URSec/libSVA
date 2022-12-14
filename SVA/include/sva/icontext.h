/*===- icontext.h - SVA Interrupts ------------------------------------------===
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header files defines functions and macros used by the SVA Execution
 * Engine for managing interrupt contexts.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_ICONTEXT_H
#define SVA_ICONTEXT_H

#include <sva/fpu_types.h>
#include <sva/mmu_types.h>
#include <sva/keys.h>
#include <sva/offsets.h>
#include <sva/state.h>
#include <sva/x86.h>

/*
 * Standalone declaration so we don't have to pull in all of vmx.h just to
 * include a member of this type in struct CPUState
 */
struct vm_desc_t;

/**
 * Switch to the kernel's cache domain.
 */
extern void usersva_to_kernel_pcid(void);

/**
 * Switch to the SVA cache domain.
 */
extern void kernel_to_usersva_pcid(void);

/* Processor privilege level */
typedef unsigned char priv_level_t;

/* Stack Pointer Typer */
typedef uintptr_t * sva_sp_t;

/*
 * Structure: invoke_frame
 *
 * Description:
 *  This structure contains all of the information necessary to return
 *  state to the exceptional basic block when an unwind needs to be performed.
 *  Note that it contains all of the registers that a called function must
 *  save for its caller.
 */
struct invoke_frame {
  /* Callee saved registers */
  uintptr_t rbp;
  uintptr_t rbx;
  uintptr_t r12;
  uintptr_t r13;
  uintptr_t r14;
  uintptr_t r15;

  /* Pointer to the next invoke frame in the list */
  struct invoke_frame * next;

  long cpinvoke;
};

/**
 * Saved interrupt context.
 *
 *  This structure is what is saved by the Execution Engine when an interrupt,
 *  exception, or system call occurs.  It must ensure that all state that is
 *    (a) Used by the interrupted process, and
 *    (b) Potentially used by the kernel
 *  is saved and accessible until *the handler routine returns*.  On the
 *  x86_64, this means that we have to save *all* GPR's.
 *
 *  As the Execution Engine gets smarter, we might be able to skip saving some
 *  of these, or on hardware with shadow register sets, we might be able to
 *  forgo it at all.
 *
 * Notes:
 *  o) This structure *must* have a length equal to an even number of quad
 *     words.
 */
typedef struct sva_icontext {
#ifdef MPX
  /* Bound registers */
  mpx_bndreg bnd0;
  mpx_bndreg bnd1;
#endif

  /**
   * Whether the interrupt context is valid (can be returned to).
   */
  bool valid: 1;
  bool can_fork: 1;

  /* Segment bases */
  uint64_t fsbase;
  uint64_t gsbase;

  uint64_t rdi;
  uint64_t rsi;

  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;

  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;

  /*
   * Keep this register right here.  We'll use it in assembly code, and we
   * place it here for easy saving and recovery.
   */
  uint64_t rbp;

  /**
   * Error code.
   *
   * Only pushed automatically by some exceptions.
   */
  uint32_t code;

  /**
   * Hardware trap number.
   *
   * We use the upper 32 bits of the error code slot, which are not used by
   * hardware.
   */
  uint32_t trapno;

  /*
   * These values are automagically saved by the x86_64 hardware upon an
   * interrupt or exception.
   */
  uint64_t rip;
  uint16_t cs;
  uint64_t rflags;
  uint64_t* rsp;
  uint16_t ss;
} __attribute__ ((aligned (16))) sva_icontext_t;

/*
 * `sizeof(sva_icontext_t)` must be a multiple of 16 bytes so that the *end* of
 * the struct is 16-byte aligned, as required by hardware.
 */
_Static_assert(sizeof(sva_icontext_t) % 16 == 0, "Interrupt stack misaligned");

/*
 * Structure: sva_integer_state_t
 *
 * Description:
 *  This is all of the hardware state needed to represent an LLVM program's
 *  control flow, stack pointer, and integer registers.
 *
 * TODO:
 *  The stack pointer should probably be removed.
 */
typedef struct {
  /** Flag for whether the integer state is valid to be loaded */
  unsigned long valid;

  /** `%ds` segment selector */
  unsigned short ds;

  /** `%es` segment selector */
  unsigned short es;

  /** `%fs` segment selector */
  unsigned short fs;

  /** `%gs` segment selector */
  unsigned short gs;

#ifdef SVA_SPLIT_STACK
  /** Protected stack pointer */
  uintptr_t protected_stack;
#endif

  /** Kernel stack pointer */
  unsigned long kstackp;

  /** Current interrupt context location */
  sva_icontext_t* currentIC;

  /** Current setting of IST3 in the TSS */
  unsigned long ist3;

  /** x86 eXtended states (Xstates) */
  union xsave_area_max fpstate;

  /**
   * Whether this thread's `.ext` field is active.
   *
   * If `false`, the value of `this->ext` is undefined.
   */
  bool has_ext_state;

  /**
   * Context-switched control registers and MSRs.
   */
  struct {
    /** Last #PF linear address */
    uint64_t cr2;

    /* TODO: also handle CR8 */

    /**
     * GS Shadow register
     */
    uint64_t gs_shadow;

    /**
     * Extended Control Register 0 (XCR0)
     *
     * This governs the use of the XSAVE feature and enables/disables MPX
     * (since MPX is an XSAVE-enabled feature).
     */
    uint64_t xcr0;

    /**
     * XSS MSR (Extended Supervisor State Mask)
     *
     * This is the counterpart to XCR0 for XSAVE features which are accessible
     * only in supervisor mode (i.e., via the XSAVES version of the
     * instruction).
     *
     * As of this writing (2020-10-20), the only such feature is "Trace Packet
     * Configuration State", which neither SVA nor Xen cares about using in
     * host (VMX root) mode; however, Xen supports the use of XSS features by
     * guests, so we must context-switch it.
     */
    uint64_t xss;

    /**
     * Contains segment selectors loaded by `syscall` and `sysret`.
     *
     * Note that the base/limit/etc. of these descriptors are loaded with fixed
     * values, this MSR merely defines the numeric value to which the selectors
     * are set.
     */
    uint64_t star;

    /**
     * Syscall target address.
     */
    uint64_t lstar;

    /**
     * Not used on Intel CPUs (all of our test machines are Intel).
     */
    uint64_t cstar;

    /**
     * Mask of values to clear in `%rflags` when `syscall` is executed.
     */
    uint64_t fmask;
  } ext;

  /** Pointer to invoke frame */
  struct invoke_frame* ifp;
} sva_integer_state_t;

/* The maximum number of interrupt contexts per CPU */
static const unsigned char maxIC = 32;

/* The maximum number of valid function targets */
static const unsigned char maxPushTargets = 16;

/*
 * Struct: SVAThread
 *
 * Description:
 *  This structure describes one "thread" of control in SVA.  It is an
 *  interrupt context, an integer state, and a flag indicating whether the
 *  state is available or free.
 */
struct SVAThread {
  /* Interrupt contexts for this thread */
  sva_icontext_t interruptContexts[maxIC + 1];

  /* Interrupt contexts used for signal handler dispatch */
  sva_icontext_t savedInterruptContexts[maxIC + 1];

  /* Function pointers valid for sva_ipush_function */
  void * validPushTargets[maxPushTargets];

  /* Number of push targets */
  unsigned char numPushTargets;

  /* Integer state for this thread for context switching */
  sva_integer_state_t integerState;

  /* PML4e used for mapping secure memory */
  pml4e_t secmemPML4e;

  /* Amount of contiguous, allocated secure memory */
  uintptr_t secmemSize;

  /* Index of currently available saved Interrupt Context */
  unsigned char savedICIndex;

  /* Flag whether the thread is in use */
  unsigned char used;

  /* Flags whether the SVA State is the first thread for a CPU */
  unsigned char isInitialForCPU;

  /* Copy of the thread's private key */
  sva_key_t ghostKey;

  /* Randomly created identifier */
  uintptr_t rid;

} __attribute__ ((aligned (16)));

/**
 * Stack pointers for entry into the kernel
 */
struct kernel_stacks {
  /** Stack pointer for normal entry from userspace */
  uintptr_t entry_stack;

  /** Stack pointer for entry from NMI */
  uintptr_t nmi_stack;

  /** Stack pointer for entry from MCE */
  uintptr_t mce_stack;

  /** Stack pointer for entry from #DF (debug fault) */
  uintptr_t debug_fault_stack;

  /** Fallback stack pointer (for double faults) */
  uintptr_t fallback_stack;
};

/**
 * The stack on VM exit.
 */
struct vm_exit_stack {
  /** Pointer to the real stack. */
  uintptr_t real_stack;
};

/*
 * Structure: CPUState
 *
 * Description:
 *  This is a structure containing the per-CPU state of each processor in the
 *  system.  We gather this here so that it's easy to find them from the %GS
 *  register.
 */
struct CPUState {
  /* Pointer to the thread currently on the processor */
  struct SVAThread * currentThread;

  /* Per-processor TSS segment */
  tss_t * tssp;

  /* New current interrupt Context */
  sva_icontext_t * newCurrentIC;

  /* Processor's Global Invoke Pointer: points to the first invoke frame */
  struct invoke_frame * gip;

  /* Pointer to thread that was the last one to use the Floating Point Unit */
  struct SVAThread * prevFPThread;

  /* Flags whether the floating point unit has been used */
  unsigned char fp_used;

  /** Stack pointers for kernel entry stacks */
  struct kernel_stacks kernel_stacks;

  /*
   * A unique identifier for this processor, sequentially (and atomically)
   * assigned when SVA is initialized on each processor. Stored here so that
   * it can be looked up cheaply without resorting to a slow (serializing)
   * CPUID instruction to query the processor's APIC ID.
   */
  size_t processor_id;

  /*
   * Flags whether the sva_initvmx() intrinsic has been called to enable VMX
   * support (via the VMXON instruction) for this processor. No other Shade
   * intrinsic may be called until this has been done.
   */
  unsigned char vmx_initialized;

  /*
   * Physical address of the VMXON region set aside for this processor to
   * use. This is a special region of memory that "the logical processor uses
   * to support VMX operation" (see section 24.11.5 in the Intel reference
   * manual, Oct. 2017).
   *
   * sva_initvmx() allocates the VMXON frame for a processor from SVA's
   * secure-memory frame cache, and puts it into use by issuing the VMXON
   * instruction.
   *
   * All we need to do is allocate it, initialize one of its fields, and pass
   * its physical address as an argument to the VMXON instruction, which enters
   * VMX operation on the active logical processor. From that point, this
   * region belongs entirely to the processor and we're not supposed to touch
   * it (unless and until we switch VMX support back off using the VMXOFF
   * instruction).
   *
   * The VMXON region has (by definition) the same size (at most 4 kB) and
   * alignment (4 kB-aligned) requirements as a VMCS. (Conventionally, a
   * hypervisor just allocates a full 4 kB frame for simplicity.) However,
   * unlike the VMCS, there is only one VMXON region per logical processor,
   * not per virtual machine. It also does not have any of the memory type
   * (cacheability properties) restrictions that a VMCS has.
   *
   * At present, SVA provides no facility for subsequently issuing VMXOFF, so
   * the CPU will remain in VMX mode (and this VMXON frame will remain in
   * use) until system shutdown. Technically, therefore, there's no need for
   * SVA to save this pointer beyond the scope of sva_initvmx(). We
   * nonetheless store it here in per-CPU data to make things easier "just in
   * case" we ever need/want to implement a VMXOFF intrinsic.
   */
  uintptr_t vmxon_frame_paddr;

  /*
   * The processor's "VMCS revision identifier" needs to be written to a
   * field at the beginning of each VMCS or VMXON frame before it can be used
   * by the processor.
   *
   * It is determined by reading the lower 32 bits (actually the lower 31,
   * but the 32nd is guaranteed by the ISA to read as 0) of the capability
   * reporting MSR IA32_VMX_BASIC.
   *
   * Its value should be constant for a particular logical processor, so we
   * read its value once in sva_initvmx() and store it here so that we don't
   * have to perform a (potentially slow) RDMSR each time the system software
   * wants to create a new VMCS with sva_allocvm().
   *
   * Note that we must save this per-CPU, rather than as a single global,
   * because it could potentially be different in a multi-processor machine
   * where not all the processors are the same model.
   *
   * (It's not clear how much of a performance impact this would actually
   * have in practice, since it seems unlikely that a hypervisor will be
   * creating/destroying vCPUs fast enough for this to actually matter; but
   * since we included sva_allocvm() in our microbenchmarking of Shade's
   * overheads on VMX operations in the VEE '19 paper, and may do so again in
   * the next paper, best to minimize unnecessary overhead so as to not
   * create a number that "looks bad" in the paper even though nobody likely
   * cares in practice.)
   *
   * (Field name capitalized since this should be considered a constant once
   * it's set in sva_initvmx().)
   */
   uint32_t VMCS_REV_ID;

   /*
    * Pointer to the vm_desc_t structure for the VM that is currently active
    * (and whose VMCS has been loaded with VMPTRLD) on this processor.
    *
    * Null indicates no VM is currently active.
    */
   struct vm_desc_t *active_vm;

   /**
    * VM exit stack.
    *
    * Putting this here rather than using the real stack pointer on entry
    * allows us to `vmwrite` to the host `%rsp` VMCS field at VMCS load time
    * rather than VM entry time.
    *
    * This is safe because interrupts are disabled on VM exit and we
    * immediately return to the real stack.
    */
   struct vm_exit_stack vm_exit_stack;
};

struct sva_tls_area {
  /** Pointer to this CPU's `struct CPUState`. */
  struct CPUState* cpu_state;

  /* Syscall scratch space. */
  unsigned long rsp;
  unsigned long rbp;
  unsigned long gsbase;

  unsigned long _unused;

  /* WRMSR scratch space. */
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
};

/*
 * Function: getCPUState()
 *
 * Description:
 *  This function finds the CPU state for the current process.
 */
static inline struct CPUState *
getCPUState(void) {
  /*
   * Use an offset from the GSBASE register to look up the processor CPU
   * state for this processor.
   */
  struct CPUState * cpustate;
  asm ("movq %%gs:%c1, %0\n"
       : "=r" (cpustate)
       : "i"(TLS_CPUSTATE));
  return cpustate;
}

/*
 * Function: getProcessorID()
 *
 * Description:
 *  Determine the processor ID of the current processor.
 *
 * Return value:
 *  A unique index value identifying each processor by the order in which SVA
 *  was initialized on it. The first processor (i.e. the one on which
 *  sva_init_primary() was called) has ID 0; the second (i.e. the first on
 *  which sva_init_secondary() was called) has ID 1; and so forth.
 *
 *  For speed, this identifier is looked up from a per-CPU field (i.e. off
 *  GSBASE), which is set during SVA initialization to the same index value
 *  used to determine the location of the processor's per-CPU data within the
 *  virtual address region SVA uses for that purpose.
 *
 *  (Technically, we could compute it by pointer arithmetic by subtracting
 *  __sva_percpu_region_base from the GSBASE pointer returned by
 *  getCPUState(). We chose rather to store it as a per-CPU field to avoid
 *  making this code unintuitively fragile to changes in how SVA allocates
 *  per-CPU regions. If the difference between a GSBASE register lookup vs. a
 *  memory lookup off GSBASE is enough to make your code materially slower,
 *  you should probably reconsider your code...or change this function to do
 *  the pointer arithmetic instead. :-))
 */
static inline size_t
getProcessorID(void) {
  return getCPUState()->processor_id;
}

extern uintptr_t sva_icontext_getpc (void);

/**
 * Get a handle to the currently running thread.
 *
 * @return  A handle to the current thread
 */
extern uintptr_t sva_get_current(void);

/*
 * FIXME: This is a hack because we don't have invokememcpy() implemented yet.
 */
static inline unsigned char
hasGhostMemory (void) {
  struct CPUState * cpup = getCPUState();
  if (cpup->currentThread && cpup->currentThread->secmemSize)
    return 1;
  return 0;
}

/**
 * Get a thread's userspace `icontext`.
 */
static inline sva_icontext_t* user_ctxt(struct SVAThread* thread) {
  return &thread->interruptContexts[maxIC - 1];
}

/**
 * Initialize a thread's ext state and mark it as active.
 */
static inline void thread_ext_state_init(struct SVAThread* thread) {
  thread->integerState.ext = (__typeof__(thread->integerState.ext)){
    /*
     * NB: x86 does not allow this register to have a value of `0`, so we
     * instead set it to the minimal allowed value.
     */
    .xcr0 = XCR0_X87 | XCR0_SSE,
  };
  thread->integerState.has_ext_state = true;
}

/**
 * Copy the parent's page table of ghost memory to the child. Write protect
 * these page table entries for both the parent and the child.
 *
 * @param oldThread The SVAThread for the parent process
 * @param newThread The SVAThread for the child process
 */
extern void ghostmemCOW(struct SVAThread* oldThread,
                        struct SVAThread* newThread);

/*****************************************************************************
 * Utility Functions
 *  These functions should not be called by the kernel; they are not SVA-OS
 *  intrinsics.
 ****************************************************************************/

/**
 * Load a segment register or %fs/%gs base.
 *
 * @param reg           The segment register to load
 * @param val           The value to load into the segment register
 * @param preserve_base Whether to preserve the `%fs`/`%gs` segment base when
 *                      loading the selector
 * @return              Whether or not the value was successfully loaded
 */
bool load_segment(enum sva_segment_register reg, uintptr_t val,
                  bool preserve_base);

#endif /* SVA_ICONTEXT_H */
