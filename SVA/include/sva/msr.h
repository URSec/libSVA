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

#include <sva/offsets.h>

#define MSR_EFER 0xc0000080

#define EFER_SCE 0x1
#define EFER_LME 0x100
#define EFER_NXE 0x800

#define SVA_EFER (EFER_LME | EFER_NXE | EFER_SCE)

#define MSR_SPEC_CTRL 0x00000048
#define MSR_PRED_CMD  0x00000049
#define MSR_FLUSH_CMD 0x0000010b

#define MSR_IA32_SYSENTER_CS  0x00000174
#define MSR_IA32_SYSENTER_ESP 0x00000175
#define MSR_IA32_SYSENTER_EIP 0x00000176

#define MSR_IA32_PAT 0x277

#define MSR_STAR  0xc0000081
#define MSR_LSTAR 0xc0000082
#define MSR_CSTAR 0xc0000083
#define MSR_FMASK 0xc0000084

#define SYSCALL_CS_SHIFT 32
#define SYSRET_CS_SHIFT  48

#define MSR_FS_BASE         0xc0000100
#define MSR_GS_BASE         0xc0000101
#define MSR_SHADOW_GS_BASE  0xc0000102

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
  movq %rax, %gs:TLS_MSR_RAX
  movq %rcx, %gs:TLS_MSR_RCX
  movq %rdx, %gs:TLS_MSR_RDX
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
  movq %gs:TLS_MSR_RDX, %rdx
  movq %gs:TLS_MSR_RCX, %rcx
  movq %gs:TLS_MSR_RAX, %rax
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
.macro WRMSR_LO msr:req, val:req, saveloc=none
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
.macro WRMSRL msr:req, combined:req, saveloc=none
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
