/*===- tlb.h - SVA Execution Engine  =---------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2019.
 * All rights reserved.
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * Functions to flush the TLB.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_TLB_H
#define SVA_TLB_H

#include <sva/types.h>
#include <sva/cr.h>
#include <sva/vmx.h>

/**
 * Global TLB flush (except for this for pages marked PG_G)
 * Flush all TLB entries (except for this for global pages).
 */
static inline void invltlb(void) {
  write_cr3(read_cr3());
}

/**
 * Flush userspace TLB entries with kernel PCID (PCID 1).
 *
 * NOTE: this function has the side effect of changing the active PCID to 1!
 */
static inline void invltlb_kernel(void) {
  write_cr3(read_cr3() | 0x1);
}

/**
 * Invalidate all TLB entries (including global entries).
 *
 * Interrupts should have already been disabled when this function is invoked.
 */
static inline void invltlb_all(void) {
  /*
   * clear PGE of CR4 first and then write old PGE again to CR4 to flush TLBs.
   */
  unsigned long cr4;
  cr4 = read_cr4();
  write_cr4(cr4 & ~CR4_PGE);
  write_cr4(cr4);
}

/**
 * Invalidate all the TLB entries with a specific virtual address (including
 * global entries).
 *
 * @param addr  The virtual address for which to invalidate TLB entries
 */
static inline void invlpg(uintptr_t addr) {
  /*
   * NB: I had to look at the FreeBSD implementation of invlpg() to figure out
   * that you need to "dereference" the address to get the operand to the
   * inline asm constraint to work properly.  While perhaps not necessary
   * (because I don't think such a trivial thing can by copyrighted), the fact
   * that I referenced the FreeBSD code is why we have the BSD copyright and
   * attribute comment at the top of this file.
   */
  asm volatile("invlpg %0" : : "m" (*(char *)addr) : "memory");
}

/**
 * Invalidate all guest-physical mappings in the TLB.
 *
 * These mappings are created when a guest system performs accesses directly
 * based on a (guest-)physical address *without* going through its own
 * guest-side page tables.
 *
 * Note: This function does *not* invalidate "combined"
 * guest-virtual/guest-physical mappings, which are created when a
 * guest-system performs accesses using linear addresses (i.e., using
 * guest-side page tables layered on top of extended paging). To clear those,
 * call `invvpid_allcontexts()`.
 *
 * PRECONDITION:
 *  - SVA-VMX must have been successfully initialized, i.e., the SVA global
 *    variable "sva_vmx_initialized" should be true. Otherwise, the INVEPT
 *    instruction will not be valid to execute.
 */
static inline void invept_allcontexts(void) {
  SVA_ASSERT(sva_vmx_initialized,
      "SVA: Tried to call invept_allcontexts() without SVA-VMX being "
      "initialized. The INVEPT instruction is not valid unless the system "
      "is running in VMX operation.\n");

  /*
   * Set up a 128-bit "INVEPT descriptor" in memory which serves as one of
   * the arguments to INVEPT.
   *
   * The lower 64 bits would be expected to contain an EPTP (pointer to
   * top-level extended page table, i.e. the EPT equivalent of CR3) value if
   * we were doing a single-context invalidation (i.e. for just one VM).
   * However, for an all-context invalidation its value doesn't matter (but
   * we still need to pass it anyway).
   *
   * The upper 64 bits are reserved and must be set to 0 for safe forward
   * compatibility.
   *
   * Long story short: we're going to set the whole thing to zero here.
   */
  uint64_t invept_descriptor[2];
  invept_descriptor[0] = invept_descriptor[1] = 0;

  uint64_t rflags_invept;
  asm __volatile__ (
      "invept (%[desc]), %[type]\n"
      "pushfq\n"
      "popq %[rflags]\n"
      : [rflags] "=r" (rflags_invept)
      : [desc] "r" (invept_descriptor),
        [type] "r" (2ul) /* INVEPT type: all-contexts (global) invalidation */
      : "memory", "cc"
      );
  /*
   * If the operation didn't succeed, the processor didn't support INVEPT in
   * the all-context mode. We check for this when initializing SVA-VMX, so if
   * this happens, something has gone wrong.
   *
   * FIXME: we're not actually checking this yet in sva_initvmx(), so this
   * "impossible" assertion could actually be triggered on a processor that
   * doesn't support this.
   */
  SVA_ASSERT(query_vmx_result(rflags_invept) == VM_SUCCEED,
      "SVA: INVEPT returned an error code other than VM_SUCCEED. "
      "This shouldn't be possible since we checked that this operation "
      "is supported when initializing SVA-VMX. Something has gone terribly "
      "wrong.\n");
}

/**
 * Invalidate "combined" guest-virtual/guest-physical mappings in the TLB for
 * all VPIDs except VPID 0.
 *
 * NB: VPID 0 represents the host system; to flush host mappings, use
 * `invltlb_all()`.
 *
 * These mappings are created when a guest system performs accesses using
 * linear addresses (i.e., using guest-side page tables layered on top of
 * extended paging).
 *
 * Note: This function does *not* invalidate standalone guest-physical
 * mappings, which are created when a guest system performs accesses directly
 * based on a (guest-)physical address without going through its own page
 * tables. To clear those, call `invept_allcontexts()`.
 *
 * PRECONDITION:
 *  - SVA-VMX must have been successfully initialized, i.e., the SVA global
 *    variable "sva_vmx_initialized" should be true. Otherwise, the INVVPID
 *    instruction will not be valid to execute.
 */
static inline void invvpid_allcontexts(void) {
  SVA_ASSERT(sva_vmx_initialized,
      "SVA: Tried to call invvpid_allcontexts() without SVA-VMX being "
      "initialized. The INVVPID instruction is not valid unless the system "
      "is running in VMX operation.\n");

  /*
   * Set up a 128-bit "INVVPID descriptor" in memory which serves as one of
   * the arguments to INVVPID.
   *
   * - Bits 0-15 specify the VPID whose mappings should be cleared from the
   *   TLB. Its setting does not matter for "all-contexts" flushes as we are
   *   going to do here, which flush mappings for all VPIDs.
   *
   * - Bits 16-63 are reserved and must be set to 0 for safe forward
   *   compatibility.
   *
   * - Bits 64-127 specify a linear address whose mappings should be cleared
   *   from the TLB. Its setting does not matter for global flushes such as
   *   we are going to do here, which flush mappings for all linear
   *   addresses.
   *
   * Long story short: we're going to set the whole thing to zero here.
   */
  uint64_t invvpid_descriptor[2];
  invvpid_descriptor[0] = invvpid_descriptor[1] = 0;

  uint64_t rflags_invvpid;
  asm __volatile__ (
      "invvpid (%[desc]), %[type]\n"
      "pushfq\n"
      "popq %[rflags]\n"
      : [rflags] "=r" (rflags_invvpid)
      : [desc] "r" (invvpid_descriptor),
        [type] "r" (2ul) /* INVVPID type: all-contexts (global) invalidation */
      : "memory", "cc"
      );
  /*
   * If the operation didn't succeed, the processor didn't support INVVPID in
   * the all-context mode. We check for this when initializing SVA-VMX, so if
   * this happens, something has gone wrong.
   *
   * FIXME: we're not actually checking this yet in sva_initvmx(), so this
   * "impossible" assertion could actually be triggered on a processor that
   * doesn't support this.
   */
  SVA_ASSERT(query_vmx_result(rflags_invvpid) == VM_SUCCEED,
      "SVA: INVVPID returned an error code other than VM_SUCCEED. "
      "This shouldn't be possible since we checked that this operation "
      "is supported when initializing SVA-VMX. Something has gone terribly "
      "wrong.\n");
}

#endif /* SVA_TLB_H */
