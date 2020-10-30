/*===- interrupt.h - SVA Interrupts   ---------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header files defines functions and macros used by the SVA Execution
 * Engine for handling interrupts.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_INTERRUPT_H
#define _SVA_INTERRUPT_H

#if 0
#include <sva/config.h>
#include <sva/exceptions.h>
#endif
#include <sva/state.h>
#include <sva/x86.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void * sva_getCPUState (tss_t * tssp);

/** Table of functions that handle traps and interrupts */
extern void (*interrupt_table[257])();

#ifdef FreeBSD

/**
 * Set the return value of a system call.\
 *
 * This intrinsic mimics the syscall convention of FreeBSD.
 */
void sva_icontext_setretval(unsigned long, unsigned long, unsigned char error);

#else

/**
 * Set the return value of a system call.
 *
 * @param ret The syscall return vaule
 * @return    0 on success, or an error code
 *
 * Errors:
 *  EACCES  The current interrupt context is not for a syscall
 */
int sva_icontext_setretval(unsigned long ret);

#endif

/**
 * Set the values of the syscall argument registers.
 *
 * @param regs  The values of the argument registers
 * @return      0 on success, or an error code
 *
 * Errors:
 *  EACCES  The current interrupt context is not for a syscall
 */
int sva_icontext_setsyscallargs(uint64_t regs[6]);

/**
 * Modify a user-space interrupt context so that it restarts a system call.
 *
 * System call restart is implemented by rewinding `%rip` by 2 bytes.
 *
 * @return  0 on success, or an error code
 *
 * Errors:
 *  EACCES  The current interrupt context is not for a syscall
 */
int sva_icontext_restart(void);

/* Types for handlers */
typedef void (*genfault_handler_t)(unsigned int vector);
typedef void (*memfault_handler_t)(unsigned int vector, void * mp);
typedef void (*interrupt_handler_t)(unsigned int vector);
typedef void * syscall_t;

/**
 * Register a fault handler with the Execution Engine.
 *
 * @param vector  The exception vector for which to register a handler
 * @param handler The handler for the exception
 * @return        Whether registering the handler succeeded
 */
extern bool sva_register_general_exception(unsigned int vector,
                                           genfault_handler_t handler);

/**
 * Register a page fault handler with the Execution Engine.
 *
 * @param vector  The exception vector for which to register a handler
 * @param handler The handler for the exception
 * @return        Whether registering the handler succeeded
 */
extern bool sva_register_memory_exception(unsigned int vector,
                                          memfault_handler_t handler);

/**
 * Register an interrupt handler with the Execution Engine.
 *
 * @param vector  The interrupt vector for which to register a handler
 * @param handler The handler for the interrupt
 * @return        Whether registering the handler succeeded
 */
extern bool sva_register_interrupt(unsigned int vector,
                                   interrupt_handler_t handler);

extern unsigned char
sva_register_syscall (unsigned char, syscall_t);

/**************************** Inline Functions *******************************/

/*
 * Intrinsic: register_hypercall()
 *
 * Description:
 *  Register a handler for an SVA hypercall.
 *
 * Return value:
 *  None.
 */
static inline void
register_hypercall (unsigned char number, void (*handler)()) {
  /*
   * Put the handler into our dispatch table.
   */
  interrupt_table[number] = handler;
  return;
}

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
static inline void
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
static inline unsigned int
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

#if 0
static inline unsigned int
sva_icontext_lif (void * icontextp)
{
  sva_icontext_t * p = (sva_icontext_t *)icontextp;
  return (p->eflags & 0x00000200);
}
#endif

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
static inline void
sva_nop (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}

#ifdef __cplusplus
}
#endif

#endif
