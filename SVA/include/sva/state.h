/*===- state.h - SVA State intrinsics ---------------------------------------===
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

#ifndef SVA_STATE_H
#define SVA_STATE_H

#include <sva/types.h>

/**
 * An opaque handle to an SVA thread.
 *
 * In practice, this is currently a pointer to a `struct SVAThread`.
 */
typedef uintptr_t sva_thread_handle_t;

/**
 * Identifier for a register in the user context.
 *
 * Note that not all "types" of user context support all registers. For example,
 * only VMs have the syscall MSRs as part of their user context.
 */
enum sva_reg {
  SVA_REG_RAX, SVA_REG_RBX, SVA_REG_RCX, SVA_REG_RDX,
  SVA_REG_RBP, SVA_REG_RSI, SVA_REG_RDI,
  SVA_REG_R8,  SVA_REG_R9,  SVA_REG_R10, SVA_REG_R11,
  SVA_REG_R12, SVA_REG_R13, SVA_REG_R14, SVA_REG_R15,

  SVA_REG_CR2,

  SVA_REG_XCR0, SVA_REG_MSR_XSS,

  SVA_REG_MSR_FMASK, SVA_REG_MSR_STAR, SVA_REG_MSR_LSTAR,

  /*
   * In a classic example of ISA-minimalism lawyering on Intel's part, they
   * decided to leave the GS Shadow register - by itself - to be manually
   * switched between host and guest values by the hypervisor on VM entry and
   * exit, despite the fact that *every other part* of the segment registers
   * (including the non-shadow GS Base) corresponds to a field in the VMCS
   * and is switched automatically by the processor as part of VM entry/exit.
   *
   * Thus, we take care of switching GS Shadow in sva_runvm() along with the
   * GPRs and other non-VMCS-resident control registers/MSRs enumerated here.
   */
  SVA_REG_GS_SHADOW,
};

enum sva_segment_register {
  SVA_SEG_CS,
  SVA_SEG_SS,
  SVA_SEG_DS,
  SVA_SEG_ES,
  SVA_SEG_FS,
  SVA_SEG_FS_BASE,
  SVA_SEG_GS,
  SVA_SEG_GS_BASE,
};

/**
 * Determine if the most recent interrupt context is privileged (CPL < 3).
 *
 * @return  Whether the most recent interrupt context was privileged.
 */
extern bool sva_was_privileged(void);

extern uintptr_t sva_icontext_getpc (void);

/**
 * Get a handle to the currently running thread.
 *
 * @return  A handle to the current thread
 */
extern uintptr_t sva_get_current(void);

/**
 * Get the current value of a user register.
 *
 * Not available for ghosting threads.
 *
 * @param reg The register to get
 * @return    The current value of the register on success or an error code
 *
 * Errors:
 *  EINVAL  An invalid register was specified
 *  EFAULT  Writing to the out parameter failed
 *  EPERM   Attempted to call this intrinsic on a ghosting thread
 */
extern sva_result_t sva_uctx_get_reg(enum sva_reg reg);

/**
 * Set the current value of a user register.
 *
 * Not available for ghosting threads.
 *
 * @param reg The register to set
 * @param in  The new value of the register
 * @return    0 on success or an error code
 *
 * Errors:
 *  EINVAL  An invalid register was specified
 *  EPERM   Attempted to call this intrinsic on a ghosting thread
 */
extern sva_error_t sva_uctx_set_reg(enum sva_reg reg, uint64_t in);

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
extern uintptr_t sva_swap_integer(uintptr_t new, uintptr_t __kern* state);

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
extern bool sva_swap_user_integer(uintptr_t new, uintptr_t __kern* state);

/*
 * FIXME: Currently disabled due to no callers (no way to test).
 */
#if 0
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
#endif

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
extern bool sva_ialloca(void __kern* data, size_t size, size_t align);

/**
 *
 * Switch the active interrupt context's stack.
 *
 * Must be followed by `sva_ialloca` and `sva_ipush_function`.
 *
 * @param stack     The new stack to use
 * @param stack_seg The segment selector for the new stack
 * @return          Whether the stack switch succeeded
 */
extern bool sva_ialloca_switch_stack(uintptr_t stack, uint16_t stack_seg);

#endif /* SVA_STATE_H */
