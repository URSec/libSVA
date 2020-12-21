/*===- invokeasm.S - Execution Engine Invoke Assembly Code ----------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This is x64_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 *===----------------------------------------------------------------------===
 */

#include "icat.h"
#include "sva/offsets.h"
#include "sva/cfi.h"
#include "sva/asmconfig.h"

.bundle_align_mode 5

ENTRY(sva_invoke)
  cache_part_switch sva stack

  /*
   * Create the new invoke frame.  Note that we save the registers that
   * are saved and restored by callee functions.  This is because callees may
   * not be able to restore these registers in the case of an unwind.
   */
  movq %gs:TLS_CPUSTATE, %rax
  pushq $INVOKE_NORMAL
  pushq CPU_GIP(%rax)
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %rbx
  pushq %rbp

  /*
   * Save the location of the invoke frame into the CPUState.
   */
  movq  %rsp, CPU_GIP(%rax)

  /*
   * Save the pointer to the return value memory location into a callee saved
   * register.
   */
  movq %rcx, %rbx

  cache_part_switch os stack

  /*
   * Call the function.
   *
   * TODO: Add a CFI check here.
   */
  CALLQ(*%r8)
  movq %rax, %rsi
  movq %rbx, %rdi

  cache_part_switch sva

  /*
   * Regular Return
   */

  /* Restore the saved registers */
  popq %rbp
  popq %rbx
  popq %r12
  popq %r13
  popq %r14
  popq %r15

  /* Remove the saved gip pointer */
  movq %gs:TLS_CPUSTATE, %rax
  popq CPU_GIP(%rax)

  /* Store the return value into the memory location */
  movq %rsi, (%rsp)
  movq %rsp, %rsi
  movl $8, %edx
  CALLQ(sva_copy_to_kernel)
  movq %rax, %rsi

  /* Remove the last bit of the invoke frame */
  popq %rcx

  cache_part_switch os

  /* Set the return value */
  xorl %eax, %eax
  testq %rsi, %rsi
  setnz %al
  negq %rax

  /* Return */
  RETQ
END(sva_invoke)

  /*
   * Exceptional (unwind) return path
   */
ENTRY(sva_invoke_except)
  /*
   * Move the stack pointer back to the most recently created invoke frame.
   */
  movq %gs:TLS_CPUSTATE, %rax
  movq CPU_GIP(%rax), %rsp

  /*
   * Restore the register stored within the invoke frame.
   */
  popq %rbp
  popq %rbx
  popq %r12
  popq %r13
  popq %r14
  popq %r15

  /*
   * Pop the top-most invoke frame off of the invoke frame linked list.
   */
  movq %gs:TLS_CPUSTATE, %rax
  popq CPU_GIP(%rax)

  /*
   * Remove the last invoke frame field.
   */
  addq $8, %rsp

  /* Return 1 to the caller */
  movq $1, %rax
  RETQ
END(sva_invoke_except)
