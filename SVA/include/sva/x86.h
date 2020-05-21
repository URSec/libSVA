/*===- x86.h - SVA Execution Engine ----------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file defines structures used by the x86_64 architecture.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_X86_H
#define _SVA_X86_H

/*
 * NB: `SVA_USER_CS_32` is used to set the code and stack segments during
 * return-from-syscall. `sysret` also uses this selector +8 and +16 to set the
 * stack and 64-bit user code segments, respectively. Therefore, these segments
 * must be arranged as follows in the GDT:
 *
 * +--------------------------+
 * | 32-bit user code segment |
 * +--------------------------+
 * | user stack/data segment  |
 * +--------------------------+
 * | 64-bit user code segment |
 * +--------------------------+
 *
 * where `GCODE_USER_32_SEL` is the index for the 32-bit user code segment.
 *
 * In other words, we should have
 * SVA_USER_CS_32 + 16 == SVA_USER_SS_32 + 8 ==
 * SVA_USER_SS_64 + 8 == SVA_USER_CS_64
 */

#ifdef XEN

#define SVA_USER_CS_32 0xe023
#define SVA_USER_CS_64 0xe033
#define SVA_USER_SS_32 0xe02b
#define SVA_USER_SS_64 SVA_USER_SS_32
#define SVA_USER_DS_32 SVA_USER_SS_32
#define SVA_USER_DS_64 0x0
#define SVA_USER_ES_32 SVA_USER_SS_32
#define SVA_USER_ES_64 0x0
#define SVA_USER_FS_32 SVA_USER_SS_32
#define SVA_USER_FS_64 0x0
#define SVA_USER_GS_32 SVA_USER_SS_32
#define SVA_USER_GS_64 0x0

#else

#define SVA_USER_CS_32 0x33
#define SVA_USER_CS_64 0x43
#define SVA_USER_SS_32 0x3b
#define SVA_USER_SS_64 SVA_USER_SS_32
#define SVA_USER_DS_32 SVA_USER_SS_32
#define SVA_USER_DS_64 SVA_USER_SS_64
#define SVA_USER_ES_32 SVA_USER_SS_32
#define SVA_USER_ES_64 SVA_USER_SS_64
#define SVA_USER_FS_32 0x13
#define SVA_USER_FS_64 SVA_USER_FS_32
#define SVA_USER_GS_32 0x1b
#define SVA_USER_GS_64 SVA_USER_GS_32

#endif

/* Flags for x86 processor status register (EFLAGS and RFLAGS) */
#define EFLAGS_CF       (1U << 0)   /* carry flag */
/* Bit 1 is reserved (always 1) */
#define EFLAGS_PF       (1U << 2)   /* parity flag */
/* Bit 3 is reserved (always 0) */
#define EFLAGS_AF       (1U << 4)   /* auxilary carry flag */
/* Bit 5 is reserved (always 0) */
#define EFLAGS_ZF       (1U << 6)   /* zero flag */
#define EFLAGS_SF       (1U << 7)   /* sign flag */
#define EFLAGS_TF       (1U << 8)   /* trap (single step) flag */
#define EFLAGS_IF       (1U << 9)   /* external interrupt (IRQ) enable flag */
#define EFLAGS_DF       (1U << 10)  /* direction flag */
#define EFLAGS_OF       (1U << 11)  /* overflow flag */
#define EFLAGS_IOPL(pl) (pl << 12)  /* I/O privilege level (0 - 3) */
#define EFLAGS_NT       (1U << 14)  /* nested task */
/* Bit 15 is reserved (always 0 since 80286) */
#define EFLAGS_RF       (1U << 16)  /* resume flag (supress debug exceptions) */
#define EFLAGS_VM       (1U << 17)  /* virtual 8086 mode flag */
#define EFLAGS_AC       (1U << 18)  /* alignment check/SMAP supress flag */
#define EFLAGS_VIF      (1U << 19)  /* virtual interrupt flag */
#define EFLAGS_VIP      (1U << 20)  /* virtual interrupt pending */
#define EFLAGS_ID       (1U << 21)  /* cpuid-capable flag */
/* Bits 63 - 22 are reserved */

#ifndef __ASSEMBLER__

#include <sva/types.h> /* for uintptr_t */

/*
 * Struction: tss_t
 *
 * Description:
 *  This is an x86_64 Task State Segment.
 */
typedef struct {
  unsigned reserved0 __attribute__((packed));

  /*
   * Pointers to the kernel stack pointer when the interrupt stack table is not
   * used
   */
  uintptr_t rsp0 __attribute__((packed));
  uintptr_t rsp1 __attribute__((packed));
  uintptr_t rsp2 __attribute__((packed));
  uintptr_t reserved1 __attribute__((packed));

  /*
   * Interrupt Stack Table (IST) Pointers: Marks where the kernel stack should
   * be set on interrupt.
   */
  uintptr_t ist1 __attribute__((packed));
  uintptr_t ist2 __attribute__((packed));
  uintptr_t ist3 __attribute__((packed));
  uintptr_t ist4 __attribute__((packed));
  uintptr_t ist5 __attribute__((packed));
  uintptr_t ist6 __attribute__((packed));
  uintptr_t ist7 __attribute__((packed));

  uintptr_t reserved2 __attribute__((packed));
  uintptr_t reserved3 __attribute__((packed));

  /* I/O Permission Map */
  unsigned int iomap __attribute__((packed));
} tss_t;

struct call_gate {
  uintptr_t target_low: 16;
  uint16_t target_sel;
  unsigned int _reserved0: 8;
  unsigned int type_lower: 5;
  unsigned int dpl: 2;
  bool present: 1;
  uintptr_t target_high: 48;
  unsigned int _reserved1: 8;
  unsigned int type_upper: 5;
  unsigned int _reserved2: 19;
} __attribute__((packed, aligned(8)));

_Static_assert(sizeof(struct call_gate) == 16, "Call gate too large");

#endif /* !__ASSEMBLER__ */

#endif /* _SVA_X86_H */
