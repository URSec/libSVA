/*===- offsets.h - SVA Execution Engine Assembly ---------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file defines the offsets of fields in SVA data structures.  It is
 * primarily designed for assembly code that accesses these data structures.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _OFFSETS_H
#define _OFFSETS_H

/* Offsets for various fields in the SVA Interrupt Context */
#ifdef MPX

#define IC_BND0    0x00
#define IC_BND1    (IC_BND0 + 0x10)

#define IC_VALID   (IC_BND1 + 0x10)

#else

#define IC_VALID   0x00

#endif

#define IC_FSBASE  (IC_VALID + 0x8)
#define IC_GSBASE  (IC_FSBASE + 0x8)

#define IC_RDI     (IC_GSBASE + 0x8)
#define IC_RSI     (IC_RDI + 0x8)

#define IC_RAX     (IC_RSI + 0x8)
#define IC_RBX     (IC_RAX + 0x8)
#define IC_RCX     (IC_RBX + 0x8)
#define IC_RDX     (IC_RCX + 0x8)

#define IC_R8      (IC_RDX + 0x8)
#define IC_R9      (IC_R8 + 0x8)
#define IC_R10     (IC_R9 + 0x8)
#define IC_R11     (IC_R10 + 0x8)
#define IC_R12     (IC_R11 + 0x8)
#define IC_R13     (IC_R12 + 0x8)
#define IC_R14     (IC_R13 + 0x8)
#define IC_R15     (IC_R14 + 0x8)

#define IC_RBP     (IC_R15 + 0x8)

#define IC_CODE    (IC_RBP + 0x8)
#define IC_TRAPNO  (IC_CODE + 0x4)

#define IC_RIP     (IC_TRAPNO + 0x4)
#define IC_CS      (IC_RIP + 0x8)
#define IC_RFLAGS  (IC_CS + 0x8)
#define IC_RSP     (IC_RFLAGS + 0x8)
#define IC_SS      (IC_RSP + 0x8)

/* Size of the interrupt context */
#define IC_SIZE    (IC_SS + 0x8)

/* Size of the interrupt context allocated by trap dispatch software */
#define IC_TRSIZE  IC_CODE

#define IC_SHADOW_GS_BASE (IC_SIZE + 8)

#define IS_HACKRIP 0xd8

/* Offsets for fields in the TLS block (accessed off of %gs) */
#ifdef FreeBSD
/* SVA borrows FreeBSD's TLS */
#define TLS_BASE 0x260 /* TODO: find out what lives below this offset */
#else
#define TLS_BASE 0x0
#endif
#define TLS_CPUSTATE  (TLS_BASE + 0x0)
#define TLS_SC_RSP    (TLS_BASE + 0x8)
#define TLS_SC_RBP    (TLS_BASE + 0x10)
#define TLS_SC_GSBASE (TLS_BASE + 0x18)
#define TLS_MSR_RAX   (TLS_BASE + 0x28)
#define TLS_MSR_RCX   (TLS_BASE + 0x30)
#define TLS_MSR_RDX   (TLS_BASE + 0x38)

/* Offsets for various fields in the CPU State Structure */
#define CPU_THREAD 0x00
#define CPU_TSSP   0x08
#define CPU_NEWIC  0x10
#define CPU_GIP    0x18
#define CPU_FPUSED 0x28
#define CPU_KSTACK_ENTRY    0x30
#define CPU_KSTACK_NMI      0x38
#define CPU_KSTACK_MCE      0x40
#define CPU_KSTACK_DF       0x48
#define CPU_KSTACK_FALLBACK 0x50

/* Offsets into the Task State Segment */
#define TSS_RSP0 4
#define TSS_IST2 44
#define TSS_IST3 52

/* Types of Invoke Frames */
#define INVOKE_NORMAL   0
#define INVOKE_MEMCPY_W 1
#define INVOKE_MEMCPY_B 2
#define INVOKE_STRNCPY  3
#define INVOKE_MEMSET   2
#define INVOKE_FIXUP    4

/*
 * Entries in the Interrupt Descriptor Table (IDT)
 */
#define IDT_PF      14  /* #PF: Page Fault */

#endif /* _OFFSETS_H */
