/*===- msr.h - SVA Execution Engine Assembly --------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the Rochester Security Group and is distributed
 * under the University of Illinois Open Source License. See LICENSE.TXT for
 * details.
 *
 *===------------------------------------------------------------------------===
 *
 * This file contains macros to assist with the use of the x86 `wrmsr`
 * instruction, in particular in cases where it is necessary to save and restore
 * the registers used by the instruction.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_MSR_H
#define _SVA_MSR_H

#ifdef __ASSEMBLER__

/**
 * Save registers that are clobbered during an MSR write.
 *
 * @param loc The location to save the registers: can be "none" (meaning no
 *            registers are saved), "stack" (registers are pushed to the stack),
 *            or "tls" (registers are saved to thread-local storaged, accessed
 *            through the `%gs` segment)
 */
.macro save_msr_regs loc
.ifeqs "\loc", "none"
.else
.ifeqs "\loc", "stack"
  pushq %rax
  pushq %rcx
  pushq %rdx
.else
.ifeqs "\loc", "tls"
  movq %rax, %gs:0x288
  movq %rcx, %gs:0x290
  movq %rdx, %gs:0x298
.else
  .err Invalid register save location for wrmsr
.endif
.endif
.endif
.endm

/**
 * Restore registers from a previous `save_msr_regs` invocation.
 *
 * @param loc The location from which registers should be restored; see
 *            `save_msr_regs` for details
 */
.macro restore_msr_regs loc
.ifeqs "\loc", "none"
.else
.ifeqs "\loc", "stack"
  popq %rdx
  popq %rcx
  popq %rax
.else
.ifeqs "\loc", "tls"
  movq %gs:0x298, %rdx
  movq %gs:0x290, %rcx
  movq %gs:0x288, %rax
.else
  .err Invalid register save location for wrmsr
.endif
.endif
.endif
.endm

/**
 * Write a value to an MSR.
 *
 * @param msr     The MSR to write
 * @param lo      The low 32 bits of the value to be written
 * @param hi      The high 32 bits of the value to be written
 * @param saveloc How to save and restore clobbered registers; see
 *                `save_msr_regs` for details
 */
.macro WRMSR msr:req, lo:req, hi:req, saveloc=none
  save_msr_regs \saveloc
  movl \msr, %ecx
  movl \lo, %eax
  movl \hi, %edx
  wrmsr
  restore_msr_regs \saveloc
.endm

/**
 * Write a 32-bit value to an MSR.
 *
 * @param msr     The MSR to write
 * @param val     The value to be written, must be less than 2^32
 * @param saveloc How to save and restore clobbered registers; see
 *                `save_msr_regs` for details
 */
.macro WRMSRL msr:req, val:req, saveloc=none
  WRMSR \msr, \val, $0, \saveloc
.endm

/**
 * Write a value to an MSR.
 *
 * This macro takes a 64-bit value to write to the MSR, which means that it must
 * first split the value into its low and high 32-bit halves.
 *
 * @param msr      The MSR to write
 * @param combined The value to be written
 * @param saveloc  How to save and restore clobbered registers; see
 *                 `save_msr_regs` for details
 */
.macro WRMSRQ msr:req, combined:req, saveloc=none
  save_msr_regs \saveloc
  movl \msr, %ecx
  movq \combined, %rax
  movq %rax, %rdx
  shrq %rdx, $32
  wrmsr
  restore_msr_regs \saveloc
.endm

#endif /* __ASSEMBLER__ */

#endif /* _SVA_MSR_H */
