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

.macro WRMSR msr:req, lo:req, hi:req, saveloc=none
  save_msr_regs \saveloc
  movl \msr, %ecx
  movl \lo, %eax
  movl \hi, %edx
  wrmsr
  restore_msr_regs \saveloc
.endm

.macro WRMSRL msr:req, lo:req, saveloc=none
  WRMSR \msr, \lo, $0, \saveloc
.endm

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
