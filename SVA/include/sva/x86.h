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

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <sys/types.h>

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

/* Flags for x86 processor status register (EFLAGS and RFLAGS) */
static const unsigned EFLAGS_IF = (1u << 9);

/* Flags bits in x86_64 PTE entries */
static const unsigned PTE_PRESENT  = 0x0001u;
static const unsigned PTE_CANWRITE = 0x0002u;
static const unsigned PTE_CANUSER  = 0x0004u;
static const unsigned PTE_PS       = 0x0080u;

#endif /* !__ASSEMBLER__ */

#endif /* _SVA_X86_H */
