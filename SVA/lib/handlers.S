/*===- handlers.S - SVA Execution Engine Assembly --------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This is x86_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 *===----------------------------------------------------------------------===
 */

/*****************************************************************************
 * Macros
 ****************************************************************************/

#include "icat.h"
#include <sva/offsets.h>
#include <sva/cfi.h>
#include <sva/asmconfig.h>
#include <sva/asm-macros.h>
#include <sva/cr.h>
#include <sva/page.h>
#include <sva/secmem.h>

.macro _TRAP name:req trapnum:req paranoid:req needsPushErrorCode:req
ENTRY(\name)
.if \needsPushErrorCode
  /* Push a zero code */
  pushq $0
.endif

  /* Push the trap number */
  movl $\trapnum, 4(%rsp)

.if \paranoid
  /* Call the paranoid trap code. */
  jmp TrapParanoid
.else
  /* Call the common trap code. */
  jmp Trap
.endif
END(\name)
.endm

/*
 * Macro: TRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that do not generate their own error code.
 */
.macro TRAP trapnum:req paranoid=0
  _TRAP trap\trapnum \trapnum paranoid=\paranoid needsPushErrorCode=1
.endm

/*
 * Macro: ECTRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that generate their own error code.
 */
.macro ECTRAP trapnum:req paranoid=0
  _TRAP trap\trapnum \trapnum paranoid=\paranoid needsPushErrorCode=0
.endm

/*
 * Macro: INTERRUPT()
 *
 * Description:
 *  Define the handler for an interrupt.  This is nearly identical to the
 *  trap code.  It is really only different because it was different in the
 *  original SVA system; the new system does not need to distinguish between
 *  an interrupt and a trap.
 */
.macro INTERRUPT interruptnum:req
  _TRAP interrupt\interruptnum \interruptnum paranoid=0 needsPushErrorCode=1
.endm

.bundle_align_mode 5

/*****************************************************************************
 * Text Section
 ****************************************************************************/
.text

/**
 * This function just generates a fault, allowing us to catch traps which SVA
 * isn't fielding.
 */
ENTRY(SVAbadtrap):
  /* Cause a breakpoint */
  sti
  int $0x03

  /* Return from the interrupt */
  iretq
END(SVAbadtrap)

/**
 * Common code for all interrupt and exception handlers.
 *
 * The error code and trap number should have already been pushed to the stack.
 */
ENTRY(Trap)
  cache_part_switch sva stack

#ifndef XEN /* Xen doesn't use a kernel stack segment */
  /*
   * Switch to the stack segment.
   */
  pushq %rax
  movw $0x28, %ax
  movw %ax, %ss
  popq %rax
#endif

  /* Save the GPRs */
  pushq %rbp
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8
  pushq %rdx
  pushq %rcx
  pushq %rbx
  pushq %rax
  pushq %rsi
  pushq %rdi

  /* Save the segment bases */
  rdgsbase %rax
  rdfsbase %rcx
  pushq %rax
  pushq %rcx

  /* Flag the interrupt context as valid */
  pushq $1

#ifdef MPX
  /* Save the MPX bound registers */
  subq $0x20, %rsp
  bndmov %bnd0, (%rsp)
  bndmov %bnd1, 0x10 (%rsp)

  /* Reset the MPX bounds register for SFI checks */
  movabsq $SECMEMEND - SECMEMSTART, %rax
  movq $-1, %rdx
  bndmk (%rax,%rdx), %bnd0

  xor %eax, %eax
  bndmk (%rax, %rdx), %bnd1
#endif

  testq $0x3, IC_CS(%rsp)
  jz 1f
  /* We came from user space: switch to the kernel %gs.base */
  swapgs
1:

  movq %gs:TLS_CPUSTATE, %rbp

#ifdef SVA_DEBUG_CHECKS
  /*
   * Configure the process to trigger a floating point fault while in
   * kernel mode.  This requires disabling the EM bit and enabling the MP and
   * TS bits in CR0.
   *
   * Record that no floating point state is saved (it is saved lazily).
   */
  testq $1, CPU_FPUSED(%rbp)
  jne 1f
  movq %cr0, %rsi
  andl $0xfffffffb, %esi
  orq  $0x0a, %rsi
  movq %rsi, %cr0
  movq $0, CPU_FPUSED(%rbp)
1:
#endif

  /*
   * Save the address of the current interrupt context into this processor's
   * CPU state.
   */
  movq %rsp, CPU_NEWIC(%rbp)

  /*
   * Move the trap number into the %rdi register.
   */
  movl IC_TRAPNO(%rsp), %edi

  /*
   * Move the address causing the fault (which may or may not be applicable)
   * into the %rsi register to make it the second argument.
   */
  movq %cr2, %rsi

#if 0
  /* Verify the Interrupt Context */
  CALLQ(assertGoodIC)
#endif

  /*
   * Modify the value in the Task State Segment (TSS) so that the next trap
   * or interrupt on this processor saves state into the next interrupt
   * context.
   */
  movq CPU_TSSP(%rbp), %rbx
  movq %rsp, TSS_IST3(%rbx)

  /*
   * Switch to the kernel stack.  If coming from user space, use the kernel
   * stack pointer specified by the kernel.  Otherwise, use the previous
   * kernel stack pointer.
   */
  testq $0x3, IC_CS(%rsp)
  cmovnzq CPU_KSTACK_ENTRY(%rbp), %rsp
  cmovzq IC_RSP(%rsp), %rsp
  andq	$-16, %rsp

  /*
   * Zero out live registers that could be spilled to the stack.  Without
   * memory safety, we can't guarantee that they're safe.
   *
   * We can leave the FP/SSE registers alone.  A read or write of those
   * registers will cause a floating point trap.  The SVA FP trap handler
   * will lazily save the floating point state and load the missing floating
   * point state.
   */
#ifdef VG
  xorq %r15, %r15
  xorq %r14, %r14
  xorq %r13, %r13
  xorq %r12, %r12
  xorq %r11, %r11
  xorq %r10, %r10
  xorq %r9,  %r9
  xorq %r8,  %r8
  xorq %rdx, %rdx
  xorq %rcx, %rcx
#endif

  /*
   * Save the exception vector and fault address.
   */
  movq %rdi, %rbp
  movq %rsi, %rbx

  /*
   * Call SVA's exception handler, if it exists.
   */
  leaq sva_interrupt_table(%rip), %rax
  movq (%rax, %rdi, 8), %rax
  testq %rax, %rax
  jz .Lcall_handler
  CALLQ(*%rax)

  /*
   * If SVA handled the exception/interrupt itself, don't call the kernel.
   */
  testl %eax, %eax
  jnz sva_iret

  /*
   * Restore the exception vector and fault address.
   */
  movq %rbp, %rdi
  movq %rbx, %rsi

.Lcall_handler:
  cache_part_switch os

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  leaq interrupt_table(%rip), %rax
  CALLQ(*(%rax,%rdi,8))

  /* Fall through */
END(Trap)

/**
 * Return from an interrupt/exception/syscall.
 */
ENTRY(sva_iret)
  /*
   * Disable interrupts.
   */
  cli
  cache_part_switch sva

  movq %gs:TLS_CPUSTATE, %rbp
  movq CPU_NEWIC(%rbp), %rbx

  /*
   * Verify that the interrupt context is valid (e.g., no sva_ialloca has been
   * performed without a subsequent sva_ipush_function).
   */
  movl IC_TRAPNO(%rbx), %edi
  testq $1, IC_VALID(%rbx)
  je invalidIC

  /*
   * Switch the stack pointer back to the interrupt context.
   */
  movq %rbx, %rsp

  /*
   * Pop off the most recent interrupt context.  This requires modifying
   * the newCurrentIC field of the CPUState as well as modifying the IST
   * in the TSS.
   */
  addq $IC_SIZE, CPU_NEWIC(%rbp)
  movq CPU_TSSP(%rbp), %rbx
  addq $IC_SIZE, TSS_IST3(%rbx)

#ifdef MPX
  /* Restore the MPX bound registers */
  bndmov IC_BND0(%rsp), %bnd0
  bndmov IC_BND1(%rsp), %bnd1
#endif

  /*
   * We need access to the TLS to determine if the application is ghosting, so
   * we delay restoring %gs.base until after the cache partition switch.
   */
  movq IC_FSBASE(%rsp), %rax
  wrfsbase %rax

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movq IC_RDI(%rsp), %rdi
  movq IC_RSI(%rsp), %rsi

  movq IC_RBX(%rsp), %rbx

  movq  IC_R8(%rsp), %r8
  movq  IC_R9(%rsp), %r9
  movq IC_R10(%rsp), %r10
  movq IC_R11(%rsp), %r11
  movq IC_R12(%rsp), %r12
  movq IC_R13(%rsp), %r13
  movq IC_R14(%rsp), %r14
  movq IC_R15(%rsp), %r15
  movq IC_RBP(%rsp), %rbp

  /* Determine whether we interrupted user or supervisor mode execution. */
  testq $0x3, IC_CS(%rsp)
  jz .Lsupervisor_return

  cache_part_switch app

  /* Switch back to the user %gs.base. */
  swapgs
  jmp .Liret

.Lsupervisor_return:
  cache_part_switch os

  /*
   * Return to the calling code.  On x86_64, this will restore the stack
   * pointer regardless of whether we came from user mode or kernel mode.
   */
.Liret:
  /*
   * Restore %gs.base
   */
  movq IC_GSBASE(%rsp), %rax
  wrgsbase %rax

  /*
   * Restore WRMSR-clobbered registers
   */
  movq IC_RAX(%rsp), %rax
  movq IC_RCX(%rsp), %rcx
  movq IC_RDX(%rsp), %rdx

  /*
   * If we entered via syscall, use the syscall return path
   */
  cmpl $256, IC_TRAPNO(%rsp)
  je .Lsysret

  /*
   * Remove the current interrupt context.
   */
  addq $(IC_TRSIZE + 0x8 /* trap number and error code */), %rsp

  iretq

.Lsysret:
  /*
   * `sysret` restores `%rip` from `%rcx` and `%rflags` from `%r11`.
   */
  movq IC_RIP(%rsp), %rcx
  movq IC_RFLAGS(%rsp), %r11

  /*
   * Restore the user-space stack pointer.
   */
  movq IC_RSP(%rsp), %rsp

  /*
   * Return to the calling code.
   */
  sysretq
END(sva_iret)

/**
 * Common code for paranoid exception handlers.
 *
 * The exceptions that wind up here are those that can occur at times when the
 * system is in a state that the ordinary trap handling code is not prepared
 * for, such as times where we have a kernel code segment but the user
 * `%gs.base` is still active. This includes NMIs and machine-check exceptions
 * which don't respect `%eflags.IF`, debug traps which can be delayed until
 * after kernel entry via a `mov %ss` or `pop %ss` shadow (see CVE-2018-8897),
 * and double faults which by there very nature occur at unpredictable times.
 *
 * Each exception which uses this mechanism is expected to use a separate IDT
 * entry than the one used by ordinary exceptions and interrupts, and this
 * stack is expected to be 8-page aligned and contain at its bottom a pointer
 * to the kernel TLS block (the value normally obtained from the shadow
 * `%gs.base`).
 */
ENTRY(TrapParanoid)
  cache_part_switch sva stack

#ifndef XEN /* Xen doesn't use a kernel stack segment */
  /*
   * Switch to the stack segment.
   */
  pushq %rax
  movw $0x28, %ax
  movw %ax, %ss
  popq %rax
#endif

  /* Save the GPRs */
  pushq %rbp
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8
  pushq %rdx
  pushq %rcx
  pushq %rbx
  pushq %rax
  pushq %rsi
  pushq %rdi

  /* Save the segment bases */
  rdgsbase %rax
  rdfsbase %rcx
  pushq %rax
  pushq %rcx

  /* Flag the interrupt context as valid */
  pushq $1

#ifdef MPX
  /* Save the MPX bound registers */
  subq $0x20, %rsp
  bndmov %bnd0, (%rsp)
  bndmov %bnd1, 0x10 (%rsp)

  /* Reset the MPX bounds register for SFI checks */
  movabsq $SECMEMEND - SECMEMSTART, %rax
  movq $-1, %rdx
  bndmk (%rax,%rdx), %bnd0

  xor %eax, %eax
  bndmk (%rax, %rdx), %bnd1
#endif

  /*
   * Load the TLS pointer from the bottom of the stack.
   */
  movq IC_SHADOW_GS_BASE(%rsp), %rax
  wrgsbase %rax

  movq %gs:TLS_CPUSTATE, %rbp

#ifdef SVA_DEBUG_CHECKS
  /*
   * Configure the process to trigger a floating point fault while in
   * kernel mode.  This requires disabling the EM bit and enabling the MP and
   * TS bits in CR0.
   *
   * Record that no floating point state is saved (it is saved lazily).
   */
  testq $1, CPU_FPUSED(%rbp)
  jne 1f
  movq %cr0, %rsi
  andl $0xfffffffb, %esi
  orq  $0x0a, %rsi
  movq %rsi, %cr0
  movq $0, CPU_FPUSED(%rbp)
1:
#endif

  /*
   * Save the address of the current interrupt context into this processor's
   * CPU state.
   */
  movq %rsp, CPU_NEWIC(%rbp)

  /*
   * Move the trap number into the %rdi register.
   */
  movl IC_TRAPNO(%rsp), %edi

  /*
   * Move the address causing the fault (which may or may not be applicable)
   * into the %rsi register to make it the second argument.
   */
  movq %cr2, %rsi

#if 0
  /* Verify the Interrupt Context */
  CALLQ(assertGoodIC)
#endif

  /*
   * Zero out live registers that could be spilled to the stack.  Without
   * memory safety, we can't guarantee that they're safe.
   *
   * We can leave the FP/SSE registers alone.  A read or write of those
   * registers will cause a floating point trap.  The SVA FP trap handler
   * will lazily save the floating point state and load the missing floating
   * point state.
   */
#ifdef VG
  xorq %r15, %r15
  xorq %r14, %r14
  xorq %r13, %r13
  xorq %r12, %r12
  xorq %r11, %r11
  xorq %r10, %r10
  xorq %r9,  %r9
  xorq %r8,  %r8
  xorq %rdx, %rdx
  xorq %rcx, %rcx
#endif

  /*
   * Switch to the kernel NMI stack.
   */
  movq CPU_TSSP(%rbp), %rbx
  movq CPU_KSTACK_NMI(%rbp), %rsp

  cache_part_switch os

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  leaq interrupt_table(%rip), %rax
  CALLQ(*(%rax,%rdi,8))

  /*
   * Disable interrupts.
   */
  cli
  cache_part_switch sva

  movq %gs:TLS_CPUSTATE, %rbp
  movq CPU_NEWIC(%rbp), %rbx

  /*
   * Verify that the interrupt context is valid (e.g., no sva_ialloca has been
   * performed without a subsequent sva_ipush_function).
   */
  movl IC_TRAPNO(%rbx), %edi
  testq $1, IC_VALID(%rbx)
  je invalidIC

  /*
   * Switch back to the paranoid stack.
   */
  movq %rbx, %rsp

  /*
   * Pop off the most recent interrupt context.
   */
  movq CPU_TSSP(%rbp), %rax
  movq TSS_IST3(%rax), %rax
  movq %rax, CPU_NEWIC(%rbp)

#ifdef MPX
  /* Restore the MPX bound registers */
  bndmov IC_BND0(%rsp), %bnd0
  bndmov IC_BND1(%rsp), %bnd1
#endif

  /*
   * We need access to the TLS to determine if the application is ghosting, so
   * we delay restoring %gs.base until after the cache partition switch.
   */
  movq IC_FSBASE(%rsp), %rax
  wrfsbase %rax

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movq IC_RDI(%rsp), %rdi
  movq IC_RSI(%rsp), %rsi

  movq IC_RBX(%rsp), %rbx

  movq  IC_R8(%rsp), %r8
  movq  IC_R9(%rsp), %r9
  movq IC_R10(%rsp), %r10
  movq IC_R11(%rsp), %r11
  movq IC_R12(%rsp), %r12
  movq IC_R13(%rsp), %r13
  movq IC_R14(%rsp), %r14
  movq IC_R15(%rsp), %r15
  movq IC_RBP(%rsp), %rbp

  /* Determine whether we interrupted user or supervisor mode execution. */
  testq $0x3, IC_CS(%rsp)
  jz .Lparanoid_supervisor_return

  cache_part_switch app

  jmp .Lparanoid_iret

.Lparanoid_supervisor_return:
  cache_part_switch os

  /*
   * Return to the calling code.  On x86_64, this will restore the stack
   * pointer regardless of whether we came from user mode or kernel mode.
   */
.Lparanoid_iret:
  /*
   * Restore %gs.base
   */
  movq IC_GSBASE(%rsp), %rax
  wrgsbase %rax

  /*
   * Restore WRMSR-clobbered registers
   */
  movq IC_RAX(%rsp), %rax
  movq IC_RCX(%rsp), %rcx
  movq IC_RDX(%rsp), %rdx

  /*
   * If we entered via syscall, use the syscall return path
   */
  cmpl $256, IC_TRAPNO(%rsp)

  /*
   * Remove the current interrupt context.
   */
  addq $(IC_TRSIZE + 0x8 /* trap number and error code */), %rsp

  iretq
END(TrapParanoid)

/**
 * Syscall entry point.
 *
 * This function is called by the processor by the syscall instruction.  When
 * we enter, we are still running on the application's stack.
 *
 * We assume that the syscall instruction was executed in user-mode.  SVA
 * should ensure that syscall is never generated for kernel code and that the
 * kernel cannot jump to user-space code containing the syscall sequence.
 *
 * The SVA CFI checks should prevent the kernel from jumping to a syscall
 * instruction that exists in kernel code because it will violate the
 * assumption that we need to use swapgs to configure the %GS register.
 */
ENTRY(SVAsyscall)
  /* ENSURE that interrupts are disabled */
  cli

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

  cache_part_switch sva tls

  /*
   * Save the stack pointer (%rsp) of the application.
   */
  movq %rsp, %gs:TLS_SC_RSP

  /*
   * Get the location of the Interrupt Context within the current thread and
   * make the stack pointer point to it.
   */
  movq %gs:TLS_CPUSTATE, %rsp
  movq CPU_TSSP(%rsp), %rsp
  movq TSS_IST3(%rsp), %rsp

  /* Push the user-space stack segment */
  pushq $SVA_USER_SS_64

  /* Push the user-space stack pointer (%rsp) */
  pushq %gs:TLS_SC_RSP

  /* Push the user-space status flags */
  pushq %r11

  /* Push the user-space code segment */
  pushq $SVA_USER_CS_64

  /* Push the user-space program counter (%rip) */
  pushq %rcx

  /* Push the syscall trap number and a zero code */
  pushq $0
  movl $256, 4(%rsp)

  /* `Trap` expects that we are still on the user `%gs.base` */
  swapgs

  jmp Trap
END(SVAsyscall)

/* Define the trap handlers */
TRAP 0
TRAP 1 paranoid=1
TRAP 2 paranoid=1
TRAP 3
TRAP 4
TRAP 5
TRAP 6
TRAP 7
ECTRAP 8 paranoid=1
TRAP 9
ECTRAP 10
ECTRAP 11
ECTRAP 12
ECTRAP 13
ECTRAP 14
TRAP 15
TRAP 16
ECTRAP 17
TRAP 18 paranoid=1
TRAP 19
TRAP 20
TRAP 21
TRAP 22
TRAP 23
TRAP 24
TRAP 25
TRAP 26
TRAP 27
TRAP 28
TRAP 29
TRAP 30
TRAP 31

/* Register all interrupts */
INTERRUPT 32
INTERRUPT 33
INTERRUPT 34
INTERRUPT 35
INTERRUPT 36
INTERRUPT 37
INTERRUPT 38
INTERRUPT 39
INTERRUPT 40
INTERRUPT 41
INTERRUPT 42
INTERRUPT 43
INTERRUPT 44
INTERRUPT 45
INTERRUPT 46
INTERRUPT 47
INTERRUPT 48
INTERRUPT 49
INTERRUPT 50
INTERRUPT 51
INTERRUPT 52
INTERRUPT 53
INTERRUPT 54
INTERRUPT 55
INTERRUPT 56
INTERRUPT 57
INTERRUPT 58
INTERRUPT 59
INTERRUPT 60
INTERRUPT 61
INTERRUPT 62
INTERRUPT 63
INTERRUPT 64
INTERRUPT 65
INTERRUPT 66
INTERRUPT 67
INTERRUPT 68
INTERRUPT 69
INTERRUPT 70
INTERRUPT 71
INTERRUPT 72
INTERRUPT 73
INTERRUPT 74
INTERRUPT 75
INTERRUPT 76
INTERRUPT 77
INTERRUPT 78
INTERRUPT 79
INTERRUPT 80
INTERRUPT 81
INTERRUPT 82
INTERRUPT 83
INTERRUPT 84
INTERRUPT 85
INTERRUPT 86
INTERRUPT 87
INTERRUPT 88
INTERRUPT 89
INTERRUPT 90
INTERRUPT 91
INTERRUPT 92
INTERRUPT 93
INTERRUPT 94
INTERRUPT 95
INTERRUPT 96
INTERRUPT 97
INTERRUPT 98
INTERRUPT 99
INTERRUPT 100
INTERRUPT 101
INTERRUPT 102
INTERRUPT 103
INTERRUPT 104
INTERRUPT 105
INTERRUPT 106
INTERRUPT 107
INTERRUPT 108
INTERRUPT 109
INTERRUPT 110
INTERRUPT 111
INTERRUPT 112
INTERRUPT 113
INTERRUPT 114
INTERRUPT 115
INTERRUPT 116
INTERRUPT 117
INTERRUPT 118
INTERRUPT 119
INTERRUPT 120
INTERRUPT 121
INTERRUPT 122
TRAP 123 /* Get Random Thread ID Trap */
TRAP 124 /* Get Thread Secret Trap */
TRAP 125 /* Install Push Target Trap */
TRAP 126 /* Secure Memory Free Trap */
TRAP 127 /* Secure Memory Allocation Trap */
INTERRUPT 128
INTERRUPT 129
INTERRUPT 130
INTERRUPT 131
INTERRUPT 132
INTERRUPT 133
INTERRUPT 134
INTERRUPT 135
INTERRUPT 136
INTERRUPT 137
INTERRUPT 138
INTERRUPT 139
INTERRUPT 140
INTERRUPT 141
INTERRUPT 142
INTERRUPT 143
INTERRUPT 144
INTERRUPT 145
INTERRUPT 146
INTERRUPT 147
INTERRUPT 148
INTERRUPT 149
INTERRUPT 150
INTERRUPT 151
INTERRUPT 152
INTERRUPT 153
INTERRUPT 154
INTERRUPT 155
INTERRUPT 156
INTERRUPT 157
INTERRUPT 158
INTERRUPT 159
INTERRUPT 160
INTERRUPT 161
INTERRUPT 162
INTERRUPT 163
INTERRUPT 164
INTERRUPT 165
INTERRUPT 166
INTERRUPT 167
INTERRUPT 168
INTERRUPT 169
INTERRUPT 170
INTERRUPT 171
INTERRUPT 172
INTERRUPT 173
INTERRUPT 174
INTERRUPT 175
INTERRUPT 176
INTERRUPT 177
INTERRUPT 178
INTERRUPT 179
INTERRUPT 180
INTERRUPT 181
INTERRUPT 182
INTERRUPT 183
INTERRUPT 184
INTERRUPT 185
INTERRUPT 186
INTERRUPT 187
INTERRUPT 188
INTERRUPT 189
INTERRUPT 190
INTERRUPT 191
INTERRUPT 192
INTERRUPT 193
INTERRUPT 194
INTERRUPT 195
INTERRUPT 196
INTERRUPT 197
INTERRUPT 198
INTERRUPT 199
INTERRUPT 200
INTERRUPT 201
INTERRUPT 202
INTERRUPT 203
INTERRUPT 204
INTERRUPT 205
INTERRUPT 206
INTERRUPT 207
INTERRUPT 208
INTERRUPT 209
INTERRUPT 210
INTERRUPT 211
INTERRUPT 212
INTERRUPT 213
INTERRUPT 214
INTERRUPT 215
INTERRUPT 216
INTERRUPT 217
INTERRUPT 218
INTERRUPT 219
INTERRUPT 220
INTERRUPT 221
INTERRUPT 222
INTERRUPT 223
INTERRUPT 224
INTERRUPT 225
INTERRUPT 226
INTERRUPT 227
INTERRUPT 228
INTERRUPT 229
INTERRUPT 230
INTERRUPT 231
INTERRUPT 232
INTERRUPT 233
INTERRUPT 234
INTERRUPT 235
INTERRUPT 236
INTERRUPT 237
INTERRUPT 238
INTERRUPT 239
INTERRUPT 240
INTERRUPT 241
INTERRUPT 242
INTERRUPT 243
INTERRUPT 244
INTERRUPT 245
INTERRUPT 246
INTERRUPT 247
INTERRUPT 248
INTERRUPT 249
INTERRUPT 250
INTERRUPT 251
INTERRUPT 252
INTERRUPT 253
INTERRUPT 254
INTERRUPT 255
