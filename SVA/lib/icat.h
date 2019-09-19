/*===- icat.h - SVA Execution Engine Assembly ------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the Rochester Security Group and is distributed
 * under the University of Illinois Open Source License. See LICENSE.TXT for
 * details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file defines constants and macros that SVA uses for configuring the
 * Intel Cache Allocation Technology (Intel CAT) feature.
 *
 * This file is designed to be used by both assembly and C code.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_ICAT_H
#define _SVA_ICAT_H

#include <sva/asmconfig.h>
#include <sva/msr.h>

/* Intel CAT MSR */
#define COS_MSR 0xc8f

/*
 * Cache Partitions ("Class-of-Service IDs") used by SVA
 *
 * NOTE: These conform to the undocumented, model-specific version of the
 * Intel CAT ISA implemented on Intel Core i7-6700 processors. On this
 * processor, the COS ID is configured by setting the *lower* 32 bits of
 * COS_MSR. Our development machine "marquez.cs.rochester.edu", which was
 * used to write the Apparition paper for Usenix Security '18, has an
 * i7-6700.
 *
 * On subsequent Xeon processors that implement the "official" version of
 * CAT, the COS ID is instead in the *upper* 32 bits of the MSR; the lower 32
 * bits are used instead for the Resource Management ID (RMID), a related
 * feature which SVA does not use. The lower 32 bits should be set to 0 when
 * RMIDs are not in use. See section 17.19 of the Intel architecture manual
 * (as of this writing, we are referring to the October 2017 edition) for
 * more details on the "official" CAT ISA that has beeen made permanent as a
 *
 * If/when we eventually get hardware that "officially" supports CAT or
 * unofficially supports the final version of the ISA, we should change these
 * constants accordingly. Don't forget to change the assembly code in
 * handlers.S and vmx.c that uses these constants directly with the WRMSR
 * instruction, since it (currently) assumes the upper 32 bits are zero.
 */
#define APP_COS 0
#define OS_COS  1
#define SVA_COS 2

#ifdef __ASSEMBLER__

#ifdef SVA_LLC_PART

.macro cache_part_switch to:req, saveloc=none
.ifeqs "\to", "sva"
  WRMSRL $COS_MSR, $SVA_COS, \saveloc
.else
.ifeqs "\to", "os"
  WRMSRL $COS_MSR, $OS_COS, \saveloc
.else
.ifeqs "\to", "app"
  save_msr_regs \saveloc

  /*
   * Test whether secmemSize is 0; if so, this is not a ghosting application,
   * and we should use the OS's LLC partition instead of a separate one for
   * the the application.
   */
  movq %gs:0x260, %rax
  movq CPU_THREAD(%rax), %rax
  movq 0x7d58(%rax), %rax
  testq %rax, %rax    /* sets zero flag if we should use OS partition */
  movl $OS_COS, %edx
  movl $APP_COS, %eax
  cmovzl %edx, %eax

  WRMSRL $COS_MSR, %eax, none

  restore_msr_regs \saveloc
.else
  .err Invalid cache partition
.endif
.endif
.endif
.endm

#else /* SVA_LLC_PART */

.macro cache_part_switch to:req, saveloc=none
.endm

#endif /* SVA_LLC_PART */

#endif /* __ASSEMBLER__ */

#endif /* _SVA_ICAT_H */
