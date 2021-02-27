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
#include <sva/icontext.h>
#include <sva/vmx_intrinsics.h>

#define TLB_FLUSH_VECTOR 254

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
 * Invalidate all TLB entries.
 *
 * Unlike `invltlb_all`, this also invalidates TLB entries for all
 * guest-physical address translations and guest-linear and combined
 * translations for all VPIDs (see Intel SDM vol. 3 § 28.3.3).
 */
static inline void invtlb_everything(void) {
  if (getCPUState()->vmx_initialized) {
    /*
     * FIXME: there is a slight theoretical security hole here, in that the
     * vmx_initialized flag is per-CPU, and we rely on the system software to
     * call sva_initvmx() on each of those CPUs individually. In theory, the
     * system software could trick us by initializing VMX on some CPUs but
     * not others, and then taking advantage of the fact that
     * initDeclaredPage() and get_frame_from_os() operations on the CPUs
     * where VMX is not initialized will neglect to flush EPT/VPID TLB
     * entries. We would need to think about this a bit more to determine
     * whether a feasible attack could actually arise from this, but this
     * comment stands for now out of an abundance of caution.
     *
     * In practice, this shouldn't be a problem as the system software will
     * typically initialize VMX on all CPUs during boot. As SVA provides no
     * mechanism to *disable* VMX on a CPU once it's enabled, an attacker
     * could not exploit this thereafter. With security measures such as
     * secure boot in place we can generally assume that such boot-time
     * initialization will be performed as intended since most attack
     * surfaces for compromise of the system software are not exposed until
     * after (or later in) boot.
     */

    /*
     * N.B.: We normally don't like to call externally-facing intrinsic
     * functions from *inside* SVA, for various reasons, but it should be
     * safe for thse intrinsics since they aren't complicated and won't
     * attempt to (re-)disable interrupts or otherwise mess with the
     * operating environment.
     */
    sva_flush_ept_all();
    sva_flush_vpid_all();
  }
  invltlb_all();
}

/**
 * The current number of CPUs that have ACKed a rendezvous.
 *
 * 0 when no rendezvous is in progress.
 */
extern unsigned int __svadata invtlb_cpus_acked;

/**
 * Flush TLBs of all online CPUs.
 */
void invtlb_global(void);

#endif /* SVA_TLB_H */
