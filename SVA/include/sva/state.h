/*===- state.h - SVA Interrupts   -------------------------------------------===
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header files defines functions and macros used by the SVA Execution
 * Engine for managing processor state.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_STATE_H
#define _SVA_STATE_H

#include "sva/x86.h"
#include "sva/mmu_types.h"
#include "sva/keys.h"
#include "sva/offsets.h"

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
 * Structure: sva_fp_state_t
 *
 * Description:
 *  This structure defines the processor's native floating point state.  This
 *  structure can store the x86 X87, XMM, and SSE registers.
 */
typedef struct {
  unsigned char words[512];
  unsigned char present;
} __attribute__ ((aligned (16))) sva_fp_state_t;

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

/* Constants for the different Interrupt Context flags in the valid field */
static const unsigned long IC_is_valid = 0x00000001u;
static const unsigned long IC_can_fork = 0x00000002u;

/*
 * Structure: icontext_t
 *
 * Description:
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
 *     words.  The SVA interrupt handling code depends upon this behavior.
 */
typedef struct sva_icontext {
  /* Invoke Pointer */
  void * invokep;                     // 0x00

  /* Segment selector registers */
  unsigned short fs;                  // 0x08
  unsigned short gs;
  unsigned short es;
  unsigned short ds;

  /* Segment bases */
  unsigned long fsbase;               // 0x10
  unsigned long gsbase;               // 0x18

  unsigned long rdi;                  // 0x20
  unsigned long rsi;                  // 0x28

  unsigned long rax;                  // 0x30
  unsigned long rbx;                  // 0x38
  unsigned long rcx;                  // 0x40
  unsigned long rdx;                  // 0x48

  unsigned long r8;                   // 0x50
  unsigned long r9;                   // 0x58
  unsigned long r10;                  // 0x60
  unsigned long r11;                  // 0x68
  unsigned long r12;                  // 0x70
  unsigned long r13;                  // 0x78
  unsigned long r14;                  // 0x80
  unsigned long r15;                  // 0x88

  /*
   * Keep this register right here.  We'll use it in assembly code, and we
   * place it here for easy saving and recovery.
   */
  unsigned long rbp;                  // 0x90

  /* Hardware trap number */
  unsigned long trapno;               // 0x98

  /*
   * These values are automagically saved by the x86_64 hardware upon an
   * interrupt or exception.
   */
  unsigned long code;                 // 0xa0
  unsigned long rip;                  // 0xa8
  unsigned long cs;                   // 0xb0
  unsigned long rflags;               // 0xb8
  unsigned long * rsp;                // 0xc0
  unsigned long ss;                   // 0xc8

  /* Flags whether the interrupt context is valid */
  unsigned long valid;                // 0xd0
  sva_fp_state_t * fpstate;           // 0xd8
} __attribute__ ((aligned (16))) sva_icontext_t;

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
  /* Invoke Pointer */
  void * invokep;                     // 0x00

  /* Segment selector registers */
  unsigned short fs;                  // 0x08
  unsigned short gs;
  unsigned short es;
  unsigned short ds;

  /* Segment bases */
  unsigned long fsbase;               // 0x10
  unsigned long gsbase;               // 0x18

  unsigned long rdi;                  // 0x20
  unsigned long rsi;                  // 0x28

  unsigned long rax;                  // 0x30
  unsigned long rbx;                  // 0x38
  unsigned long rcx;                  // 0x40
  unsigned long rdx;                  // 0x48

  unsigned long r8;                   // 0x50
  unsigned long r9;                   // 0x58
  unsigned long r10;                  // 0x60
  unsigned long r11;                  // 0x68
  unsigned long r12;                  // 0x70
  unsigned long r13;                  // 0x78
  unsigned long r14;                  // 0x80
  unsigned long r15;                  // 0x88

  /*
   * Keep this register right here.  We'll use it in assembly code, and we
   * place it here for easy saving and recovery.
   */
  unsigned long rbp;                  // 0x90

  /* Hardware trap number */
  unsigned long trapno;               // 0x98

  /*
   * These values are automagically saved by the x86_64 hardware upon an
   * interrupt or exception.
   */
  unsigned long code;                 // 0xa0
  unsigned long rip;                  // 0xa8
  unsigned long cs;                   // 0xb0
  unsigned long rflags;               // 0xb8
  unsigned long * rsp;                // 0xc0
  unsigned long ss;                   // 0xc8

  /* Flag for whether the integer state is valid */
  unsigned long valid;                // 0xd0

  /* Store another RIP value for the second return */
  unsigned long hackRIP;              // 0xd8

  /* Kernel stack pointer */
  unsigned long kstackp;              // 0xe0

  /* CR3 register */
  unsigned long cr3;                  // 0xe8

  /* Current interrupt context location */
  sva_icontext_t * currentIC;         // 0xf0

  /* Current setting of IST3 in the TSS */
  unsigned long ist3;                // 0xf8

  /* Floating point state */
  sva_fp_state_t fpstate;            // 0x100

  /* Pointer to invoke frame */
  struct invoke_frame * ifp;
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

  /* Floating point states associated with Interrput Contexts */
  sva_fp_state_t ICFP[maxIC + 1];

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

  /* Index of next available FP for Interrupt Contexts */
  unsigned char ICFPIndex;

  /* Flag whether the thread is in use */
  unsigned char used;

  /* Flags whether the SVA State is the first thread for a CPU */
  unsigned char isInitialForCPU;

  /* Copy of the thread's private key */
  sva_key_t ghostKey;

  /* Randomly created identifier */
  uintptr_t rid;

} __attribute__ ((aligned (16)));

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
};

/*
 * Function: get_cpuState()
 *
 * Description:
 *  This function finds the CPU state for the current process.
 */
static inline struct CPUState *
getCPUState(void) {
  /*
   * Use an offset from the GS register to look up the processor CPU state for
   * this processor.
   */
  struct CPUState * cpustate;
  __asm__ __volatile__ ("movq %%gs:%c1, %0\n"
                        : "=r" (cpustate)
                        : "i"(TLS_CPUSTATE));
  return cpustate;
}

/*
 * Intrinsic: sva_was_privileged()
 *
 * Description:
 *  This intrinsic flags whether the most recent interrupt context was running
 *  in a privileged state before the interrupt/exception occurred.
 *
 * Return value:
 *  true  - The processor was in privileged mode when interrupted.
 *  false - The processor was in user-mode when interrupted.
 */
static inline unsigned char
sva_was_privileged (void) {
  kernel_to_usersva_pcid();

  /* Constant mask for user-space code segments */
  const uintptr_t userCodeSegmentMask = 0x03;

  /*
   * Get the CPUState for the current processor.
   */
  struct CPUState * cpup = getCPUState();

  /*
   * Get the current interrupt context.  Use inline assembly to prevent
   * the SVA instrumentation from preventing us from reading the data.
   */
  sva_icontext_t * currentIC;
  __asm__ __volatile__ ("movq %1, %0\n"
                       : "=r" (currentIC)
                       : "m" ((cpup->newCurrentIC)));

  /*
   * Get the code segment out of the interrupt context.
   */
  uintptr_t cs;
  __asm__ __volatile__ ("movq %1, %0\n"
                       : "=r" (cs)
                       : "m" ((currentIC->cs)));

  usersva_to_kernel_pcid();
  /*
   * Lookup the most recent interrupt context for this processor and see
   * if it's code segment has the user-mode segment bits turned on.  Apparently
   * all FreeBSD user-space code segments have 3 as the last digit.
   */
  return (!(cs & userCodeSegmentMask));
}

extern uintptr_t sva_icontext_getpc (void);

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
 * Copy the parent's page table of ghost memory to the child. Write protect
 * these page table entries for both the parent and the child.
 *
 * @param oldThread The SVAThread for the parent process
 * @param newThread The SVAThread for the child process
 */
extern void ghostmemCOW(struct SVAThread* oldThread,
                        struct SVAThread* newThread);

#if 0
/* Prototypes for Execution Engine Functions */
extern unsigned char * sva_get_integer_stackp  (void * integerp);
extern void            sva_set_integer_stackp  (sva_integer_state_t * p, sva_sp_t sp);

extern void sva_push_syscall   (unsigned int sysnum, void * exceptp, void * fn);

extern void sva_load_kstackp (sva_sp_t);
extern sva_sp_t sva_save_kstackp (void);
#endif

/*****************************************************************************
 * Global State
 ****************************************************************************/

/**
 * Save the current integer state and swap in a new one.
 *
 * @param[in]  new    The new integer state to load on to the processor
 * @param[out] state  The integer state which was saved
 * @return            Whether state swapping succeeded
 */
extern uintptr_t sva_swap_integer(uintptr_t new, uintptr_t* state);

/**
 * Save the current user integer state and swaps in a new one without modifying
 * the kernel integer state.
 *
 * This can be used in place of `sva_swap_integer` when it is desirable to
 * switch user contexts while maintaining the same kernel context.
 *
 * @param[in]  new    The new integer state to load on to the processor
 * @param[out] state  The integer state which was saved
 * @return            Whether the state swap succeeded
 */
extern bool sva_swap_user_integer(uintptr_t new, uintptr_t* state);

/**
 * Create a new kernel stack and initialize it to call the specified function.
 *
 * @param start_stackp  A pointer to the *top* of the kernel stack.
 * @param length        Length of the kernel stack in bytes
 * @param func          The kernel function to execute on the new stack
 * @param arg1          The first argument to the function
 * @param arg2          The second argument to the function
 * @param arg3          The third argument to the function
 * @return              A handle which can be passed to sva_swap_integer() to
 *                      begin execution of the thread
 */
extern uintptr_t sva_init_stack(unsigned char* sp,
                                uintptr_t length,
                                void* f,
                                uintptr_t arg1,
                                uintptr_t arg2,
                                uintptr_t arg3);

/**
 * Reset the kernel stack to the most recent interrupt context and jump to the
 * specified function.
 *
 * @param func The kernel function to execute on the reset stack
 */
extern __attribute__((__noreturn__)) void sva_reinit_stack(void (*func)(void));

/**
 * Create a new thread.
 *
 * Does not create a new kernel stack for this thread. It therefore must be
 * switched to using `sva_swap_user_integer`.
 *
 * @param start The entry point of the new thread
 * @param arg1  The first argument to `start`
 * @param arg2  The secord argument to `start`
 * @param arg3  The third argument to `start`
 * @param stack The new thread's stack
 * @return      A handle for the new thread
 */
extern uintptr_t sva_create_icontext(uintptr_t start, uintptr_t arg1,
                                     uintptr_t arg2, uintptr_t arg3,
                                     uintptr_t stack);

/**
 * Reinitialize an interrupt context so that, upon return, it begins to execute
 * code at a new location.
 *
 * This supports the exec() family of system calls.
 *
 * @param handle  An identifier representing the entry point
 * @param priv    A flag that, when set, indicates that the code will be
 *                executed in the processor's privileged mode
 * @param stack   The value to set for the stack pointer
 * @param arg     The argument to pass to the function
 */
extern void sva_reinit_icontext(void* handle, bool priv,
                                uintptr_t stack, uintptr_t arg);

/**
 * Discard integer state and kernel stack.
 *
 * @param id  A handle to the integer state to discard
 */
extern void sva_release_stack (uintptr_t id);

/*****************************************************************************
 * Individual State Components
 ****************************************************************************/

/**
 * Set the active interrupt context to return to the specified location.
 *
 * If the current thread is ghosting, this will ensure that the location
 * specified is a valid target.
 *
 * @param fn  The target function
 * @param p1  The first argument to pass to the function
 * @param p2  The second argument to pass to the function
 * @param p3  The third argument to pass to the function
 * @param p4  The fourth argument to pass to the function
 * @param p5  The fifth argument to pass to the function
 * @return    Whether the operation was successful
 */
extern void sva_ipush_function5(void (*f)(),
                                uintptr_t p1,
                                uintptr_t p2,
                                uintptr_t p3,
                                uintptr_t p4,
                                uintptr_t p5);

/**
 * Set the active interrupt context to return to the specified location.
 *
 * If the current thread is ghosting, this will ensure that the location
 * specified is a valid target.
 *
 * @param fn  The target location
 * @param cs  The target code segment selector
 * @return    Whether the operation was successful
 */
extern bool sva_ipush_function(uintptr_t fn, uint16_t cs);

/**
 * Allocate an object of the specified size on the current stack belonging to
 * the most recent Interrupt Context and copy data into it.
 *
 * @param data  A pointer to the data with which to initialize the allocation;
 *              if this is `NULL`, no initialization is performed
 * @param size  The number of bytes to allocate on the stack
 * @param align The power of two alignment to use for the memory object
 * @return      Whether the allocation succeeded.
 */
extern bool sva_ialloca(void* data, size_t size, size_t align);

/**
 *
 * Allocate an object of the specified size on the specified stack
 * and copy data into it.
 *
 * Modifies the interrupt context to use the new stack upon return.
 *
 * @param stack     The new stack to use
 * @param stack_seg The segment selector for the new stack
 * @param size      The number of bytes to allocate on the stack
 * @param align     The power of two alignment to use for the memory object
 * @param data      A pointer to the data with which to initialize the
 *                  allocation; if this is `NULL`, then no initialization is
 *                  performed
 * @return          Whether the allocation succeeded.
 */
extern bool sva_ialloca_newstack(uintptr_t stack, uint16_t stack_seg,
                                 void* data, size_t size, size_t align);

/*****************************************************************************
 * Utility Functions
 *  These functions should not be called by the kernel; they are not SVA-OS
 *  intrinsics.
 ****************************************************************************/

/*
 * Function: load_fp()
 *
 * Description:
 *  This function loads floating point state back on to the processor.
 */
static inline void
load_fp (sva_fp_state_t * buffer) {
  /*
   * Save the state of the floating point unit.
   */
  if (buffer->present)
    __asm__ __volatile__ ("fxrstor %0" : "=m" (buffer->words));
  return;
}

/*
 * Function: save_fp()
 *
 * Description:
 *  Save the processor's current floating point state into the specified
 *  buffer.
 *
 * Inputs:
 *  buffer - A pointer to the buffer in which to save the data.
 */
static inline void
save_fp (sva_fp_state_t * buffer) {
  __asm__ __volatile__ ("fxsave %0" : "=m" (buffer->words) :: "memory");
  buffer->present = 1;
}



#endif
