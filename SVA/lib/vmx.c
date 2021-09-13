/*===- vmx.c - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the SVA research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements SVA's support for hardware-accelerated virtualization
 * (Intel VMX, and in the future AMD SVM).
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/vmx.h>
#include <sva/vmx_intrinsics.h>
#include <sva/apic.h>
#include <sva/fpu.h>
#include <sva/interrupt.h>
#include <sva/mmu.h>
#include <sva/mpx.h>
#include <sva/config.h>
#include <sva/init.h> // for register_syscall_handler()
#include <sva/uaccess.h>

#include "icat.h"

#include <errno.h>
#include <string.h>
#include <stddef.h> // for offsetof()

/*
 * Array of vm_desc_t structures for each VM allocated on the system.
 *
 * To keep things simple, we pre-allocate this as a statically sized array of
 * length MAX_VMS. This means there is a finite number of VMs that can be
 * operated simultaneously. This is an artificial limitation; if it ever
 * becomes an issue in practice, we can go through the trouble of making this
 * a dynamically-resizable array. But that's a royal pain in C, and these
 * structures are small, so it's probably better to just increase the limit.
 *
 * A VM's index within this array is used as its VM ID, i.e. the handle which
 * is returned by the sva_allocvm() intrinsic and used to refer to the VM in
 * future intrinsic calls.
 *
 * This array is zero-initialized by the first CPU to run sva_initvmx(),
 * which effectively marks all entries as unused (and the corresponding VM
 * IDs as free to be assigned).
 */
struct vm_desc_t __svadata vm_descs[MAX_VMS];

/*
 * A "dummy" EPT root page table in which all mappings are invalid.
 * (Zero-initialized by the first CPU to run sva_initvmx().)
 *
 * This is maintained in SVA internal memory and used by sva_allocvm() as the
 * initial EPT root page table for newly-created VM guests, so that the field
 * is never left unsafely uninitialized. It is expected that the system
 * software will use sva_load_eptable() to load a more meaningful root page
 * table before actually running the guest.
 *
 * Must be 4 kB aligned since it will be used as a page-table page.
 *
 * N.B.: As this lives within SVA internal memory, it is *not* subject to the
 * usual reference counting of page-table pages.
 */
uint8_t dummy_ept_root_table[4096] __svadata __attribute__((aligned(4096)));

static int run_vm(unsigned char use_vmresume);

/**
 * Allocate and initialize a VM's MSR exiting bitmaps.
 */
static int msr_bitmaps_init(vm_desc_t* vm);

/**
 * Free a VM's MSR exiting bitmaps.
 */
static int msr_bitmaps_free(vm_desc_t* vm);

/**
 * Allocate and initialize a VM's IO exiting bitmaps.
 */
static int io_bitmaps_init(vm_desc_t* vm);

/**
 * Free a VM's IO exiting bitmaps.
 */
static int io_bitmaps_free(vm_desc_t* vm);

static void vmcs_save_host_tls(void);

/*
 * Function: cpuid_1_ecx()
 *
 * Description:
 *  Queries "leaf 1" of the CPUID pages, i.e. executes CPUID with 1 in EAX.
 *  Returns the value of ECX (Feature Information) returned by CPUID.
 *
 * Return value:
 *  The contents of the ECX register after executing CPUID:1.
 */
static inline uint32_t
cpuid_1_ecx(void) {
  /* Note: normally, before using CPUID, one is supposed to execute it with
   * EAX = 0 first, which will return (in EAX) the highest leaf number that
   * this CPU supports. This prevents querying unsupported leaves.
   *
   * However, in this case it is safe to query leaf 1 unconditionally,
   * because it is supported on all processors that implement the CPUID
   * instruction. (Since we are in 64-bit mode, we know the CPUID instruction
   * is implemented.)
   */

  uint32_t cpuid_ecx = 0xdeadbeef, dummy;
  DBGPRNT(("Executing CPUID with 1 in EAX...\n"));
  asm __volatile__ (
      "cpuid"
      : "=a" (dummy), "=c" (cpuid_ecx)
      : "a" (1), "c" (0)
      : "ebx", "edx"
      );
  DBGPRNT(("Value of ECX after CPUID:1 = 0x%x\n", cpuid_ecx));

  return cpuid_ecx;
}

/*
 * Function: cpu_supports_vmx()
 *
 * Description:
 *  Checks whether the processor supports VMX using the CPUID instruction.
 *
 * Return value:
 *  True if the processor supports VMX, false otherwise.
 */
static inline unsigned char
cpu_supports_vmx(void) {
  uint32_t cpuid_ecx = cpuid_1_ecx();
  uint32_t supports_vmx = cpuid_ecx & CPUID_01H_ECX_VMX_BIT;

  return (supports_vmx ? 1 : 0);
}

/*
 * Function: cpu_permit_vmx()
 *
 * Description:
 *  Sets the IA32_FEATURE_CONTROL MSR to permit VMX operation on the current
 *  CPU.
 *
 *  This may have already been set one way or another (by other kernel code
 *  or by the BIOS), and the lock bit may be enabled. If it's locked in the
 *  "disallow VMX" position, then there's nothing we can do - we cannot use
 *  VMX.
 *
 *  The lock bit, once set, can only be cleared by a power-up reset. However,
 *  if it is the BIOS that is setting it (this is typically how a BIOS
 *  enforces a setting that disables VMX support), then it will likely be
 *  re-enabled at the next boot.
 *
 * Return value:
 *  True if we have successfully set and locked the CPU to "permit VMX" mode;
 *  false if it was already locked to disallow it (or if the CPU doesn't
 *  support VMX at all).
 */
static inline unsigned char
cpu_permit_vmx(void) {
  /* If the CPU does not support VMX at all, return false. */
  if (!cpu_supports_vmx())
    return 0;

  DBGPRNT(("Reading IA32_FEATURE_CONTROL MSR...\n"));
  uint64_t feature_control_data = rdmsr(MSR_FEATURE_CONTROL);
  DBGPRNT(("IA32_FEATURE_CONTROL MSR = 0x%lx\n", feature_control_data));

  uint64_t feature_control_locked =
    feature_control_data & FEATURE_CONTROL_LOCK_BIT;
  uint64_t feature_control_vmxallowed_outside_smx =
    feature_control_data & FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX_BIT;

  /* If the MSR is locked and in the "disallow VMX" setting, then there is
   * nothing we can do; we cannot use VMX.
   *
   * (If this is the case, it is probably due to a BIOS setting prohibiting
   * VMX.)
   *
   * NOTE: We don't mess with the neighboring "allow VMX within SMX mode"
   * bit. SVA doesn't (yet) support/use SMX in any way so this situation
   * isn't relevant to us. sva_initvmx() does a sanity check that the SMXE
   * bit in CR4 is not set (and panics otherwise) to make sure we're aware if
   * we ever get into that situation.
   */
  if (feature_control_locked && !feature_control_vmxallowed_outside_smx) {
    DBGPRNT(("CPU locked to disallow VMX!\n"));
    return 0;
  }

  /* If the lock bit is already set, but VMX is allowed, return success. */
  if (feature_control_locked) {
    DBGPRNT(("IA32_FEATURE_CONTROL was already locked, but allows VMX.\n"));
    return 1;
  }

  /* Otherwise, set the MSR to allow VMX, and then lock it.
   *
   * (The processor will not allow us to execute VMXON unless the setting is
   * locked, probably to prevent other kernel code from changing it while
   * we're using VMX.)
   */
  feature_control_data |= FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX_BIT;
  feature_control_data |= FEATURE_CONTROL_LOCK_BIT;

  DBGPRNT(("Writing new value of IA32_FEATURE_CONTROL MSR to permit VMX: "
      "0x%lx\n", feature_control_data));
  wrmsr(MSR_FEATURE_CONTROL, feature_control_data);

  /* Read back the MSR to confirm this worked. */
  if (rdmsr(MSR_FEATURE_CONTROL) != feature_control_data) {
    DBGPRNT(("Wrote new value to IA32_FEATURE_CONTROL MSR, but it didn't take.\n"));
    return 0;
  }

  /* We've succcessfully set this CPU to allow VMX. */
  return 1;
}

/*
 * Function: check_cr0_fixed_bits()
 *
 * Description:
 *  Checks that the value of Control Register 0 conforms to the bit settings
 *  required for VMX operation. (These requiremenst are given by the MSRs
 *  IA32_VMX_CR0_FIXED0 and IA32_VMX_CR0_FIXED1.)
 *
 * Return value:
 *  True if the current setting of CR0 is acceptable for entry into VMX
 *  operation; false otherwise.
 */
static inline unsigned char
check_cr0_fixed_bits(void) {
  uint64_t cr0_value = read_cr0();
  DBGPRNT(("Current value of CR0: 0x%lx\n", cr0_value));

  uint64_t fixed0_msr = rdmsr(MSR_VMX_CR0_FIXED0);
  uint64_t fixed1_msr = rdmsr(MSR_VMX_CR0_FIXED1);
  DBGPRNT(("IA32_VMX_CR0_FIXED0: 0x%lx\n", fixed0_msr));
  DBGPRNT(("IA32_VMX_CR0_FIXED1: 0x%lx\n", fixed1_msr));

  /* Check that the current value of CR0 confiorms to the fixed bits
   * specified by the MSRs.
   *
   * If a bit is 0 in IA32_VMX_CR0_FIXED0, then it is allowed to be 0 in CR0
   * during VMX operation.
   *
   * If a bit is 1 in IA32_VMX_CR0_FIXED1, then it is allowed to be 1 in CR0
   * during VMX operation.
   *
   * If this feels "backwards" relative to the names of the MSRs, I thought
   * so too. It's the way Intel defines it in the manual (section A.7, vol.
   * 3D, October 2017 edition). The MSRs define which bits are *allowed* to
   * be set a certain way, not which ones are *fixed* that way, as their
   * names would imply.
   *
   * The Intel manual also gives an alternate explanation that (to me anyway)
   * is easier to understand; this is how we perform the check below:
   *  * If a bit is 0 in both registers, it must be 0 in CR0.
   *  * If a bit is 1 in both registers, it must be 1 in CR0.
   *  * If its value differs between the two registers, then either value is
   *    permitted in CR0.
   */
  unsigned char value_ok = 1;

  uint64_t must_be_0 = fixed0_msr | fixed1_msr; // 0 if 0 in both MSRs
  uint64_t must_be_1 = fixed0_msr & fixed1_msr; // 1 if 1 in both MSRs

  /* Check bits that must be 0 */
  if ((cr0_value & must_be_0) != cr0_value) {
    /* The AND will be different from CR0's value iff any of the bits
     * that must be 0 are not actually 0. */
    DBGPRNT(("CR0 value invalid for VMX: some bits need to be 0.\n"));
    value_ok = 0;
  }

  /* Check bits that must be 1 */
  if ((cr0_value | must_be_1) != cr0_value) {
    /* The OR will be different from CR0's value iff any of the bits
     * that must be 1 are not actually 1. */
    DBGPRNT(("CR0 value invalid for VMX: some bits need to be 1.\n"));
    value_ok = 0;
  }

  return value_ok;
}

/*
 * Function: check_cr4_fixed_bits()
 *
 * Description:
 *  Checks that the value of Control Register 4 conforms to the bit settings
 *  required for VMX operation. (These requiremenst are given by the MSRs
 *  IA32_VMX_CR4_FIXED0 and IA32_VMX_CR4_FIXED1.)
 *
 * Return value:
 *  True if the current setting of CR4 is acceptable for entry into VMX
 *  operation; false otherwise.
 */
static inline unsigned char
check_cr4_fixed_bits(void) {
  uint64_t cr4_value = read_cr4();
  DBGPRNT(("Current value of CR4: 0x%lx\n", cr4_value));

  uint64_t fixed0_msr = rdmsr(MSR_VMX_CR4_FIXED0);
  uint64_t fixed1_msr = rdmsr(MSR_VMX_CR4_FIXED1);
  DBGPRNT(("IA32_VMX_CR4_FIXED0: 0x%lx\n", fixed0_msr));
  DBGPRNT(("IA32_VMX_CR4_FIXED1: 0x%lx\n", fixed1_msr));

  /* Check that the current value of CR4 confiorms to the fixed bits
   * specified by the MSRs.
   *
   * If a bit is 0 in IA32_VMX_CR4_FIXED0, then it is allowed to be 0 in CR4
   * during VMX operation.
   *
   * If a bit is 1 in IA32_VMX_CR4_FIXED1, then it is allowed to be 1 in CR4
   * during VMX operation.
   *
   * If this feels "backwards" relative to the names of the MSRs, I thought
   * so too. It's the way Intel defines it in the manual (section A.7, vol.
   * 3D, October 2017 edition). The MSRs define which bits are *allowed* to
   * be set a certain way, not which ones are *fixed* that way, as their
   * names would imply.
   *
   * The Intel manual also gives an alternate explanation that (to me anyway)
   * is easier to understand; this is how we perform the check below:
   *  * If a bit is 0 in both registers, it must be 0 in CR4.
   *  * If a bit is 1 in both registers, it must be 1 in CR4.
   *  * If its value differs between the two registers, then either value is
   *    permitted in CR4.
   */
  unsigned char value_ok = 1;

  uint64_t must_be_0 = fixed0_msr | fixed1_msr; // 0 if 0 in both MSRs
  uint64_t must_be_1 = fixed0_msr & fixed1_msr; // 1 if 1 in both MSRs

  /* Check bits that must be 0 */
  if ((cr4_value & must_be_0) != cr4_value) {
    /* The AND will be different from CR4's value iff any of the bits
     * that must be 0 are not actually 0. */
    DBGPRNT(("CR4 value invalid for VMX: some bits need to be 0.\n"));
    value_ok = 0;
  }

  /* Check bits that must be 1 */
  if ((cr4_value | must_be_1) != cr4_value) {
    /* The OR will be different from CR4's value iff any of the bits
     * that must be 1 are not actually 1. */
    DBGPRNT(("CR4 value invalid for VMX: some bits need to be 1.\n"));
    value_ok = 0;
  }

  return value_ok;
}

/*
 * Intrinsic: sva_initvmx()
 *
 * Description:
 *  Prepares the SVA Execution Engine to support VMX operations.  (This
 *  includes initializing internal data structures, setting control register
 *  bits, and issuing the VMXON instruction to enable hardware VMX support.)
 *
 *  **Must be called on a processor before any other Shade intrinsic can be
 *  used on that processor!**
 *
 * Return value:
 *  True if VMX initialization was successful (or initialization was not
 *  performed because it was already done earlier), false otherwise.
 */
unsigned char
sva_initvmx(void) {
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  if (getCPUState()->vmx_initialized) {
    printf("sva_initvmx(): Shade has already been initialized on this CPU.\n");

    /* Restore interrupts and return to the kernel page tables. */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();

    return 1;
  }

  /*
   * Perform initialization of global data structures related to SVA's VMX
   * support.
   *
   * These steps should only be performed once across all CPUs, so we
   * synchronize this on a global lock which indicates the status of the
   * process. If the system software happens to call sva_initvmx() on other
   * CPUs while this process is still ongoing on the first, the others will
   * wait until it is complete before proceeding.
   */
  static uint8_t __svadata vmx_structures_initialized = 0;
  uint8_t UNINIT = 0, INPROG = 1, DONE = 2;
  if (__atomic_compare_exchange(&vmx_structures_initialized,
                                &UNINIT, &INPROG,
                                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    /*
     * We are the first processor on which sva_initvmx() has been called and
     * are responsible for performing global initializations.
     */

    /*
     * Zero-initialize the array of virtual machine descriptors.
     *
     * This has the effect of marking all VM IDs as free to be assigned.
     *
     * NOTE: it is actually unnecessary to zero-fill this array here when we
     * are running under Xen, since Xen zero-initializes *all* of SVA's static
     * data when it allocates physical backing for it in map_sva_static_data()
     * (prior to calling sva_init_primary_xen()). We nonetheless leave this
     * code in place here so that we are not taken by surprise if this is not
     * true in future ports of other OSes to SVA. (I'm not sure to what extent
     * SVA static data is initialized under the FreeBSD 9 port.) There is no
     * need to *disable* this code under Xen since, although superfluous, it
     * runs only once during boot and doesn't appreciably slow things down.
     */
    printf("sva_initvmx(): initializing vm_descs array.\n");
    for (int i = 0; i < MAX_VMS; i++) {
      memset(&vm_descs[i], 0, sizeof(vm_desc_t));
    }

    /*
     * Zero-initialize a 4 kB physical memory frame to be used as a "safe"
     * initial root page table for newly-created VM guests.
     *
     * This frame is owned and controlled by SVA as internal secure memory,
     * i.e. the system software is not allowed to read or write it.
     * (Technically we just don't need it to be writable, but it's convenient
     * to just use the secmem frame allocator.) We initialize it to all zeroes
     * so that it represents an EPT L4 page-table page in which all mappings
     * are invalid (i.e., will cause an EPT page fault if a live guest
     * attempts to translate through them).
     *
     * sva_allocvm() will point each newly-created VM guest's EPT root
     * pointer (the EPT equivalent of CR3) to this frame. It is expected that
     * the system software will use sva_load_eptable() to load a meaningful
     * EPT root page table before actually running the guest.
     *
     * Using a "dummy" page table for the initial EPT root pointer like this
     * simplifies things by sparing us from having to deal with edge cases
     * related to it being uninitialized at any point in the VM's lifespan.
     * An earlier design of the Shade interface (from the VEE '19 paper)
     * instead solved this problem by expecting the system software to
     * provide a root page table as a parameter to sva_allocvm(), but that
     * wasn't a good fit for how Xen's code is structured (it performs VMCS
     * allocation prior to setting up page tables for a vCPU).
     */
    SVA_ASSERT(sizeof(dummy_ept_root_table) == 4096,
        "SVA: dummy EPT root page table should be 4 kB\n");
    memset(dummy_ept_root_table, 0, sizeof(dummy_ept_root_table));

    /* Set the lock to DONE to indicate that initialization is complete. */
    __atomic_store(&vmx_structures_initialized, &DONE, __ATOMIC_RELEASE);
  } else {
    /*
     * Another processor has claimed responsibility for global
     * initialization. If it hasn't yet finished doing so, spin until it has.
     *
     * (It's OK to spin here since sva_initvmx() is only called once per CPU
     * during boot and thus not especially performance sensitive. The
     * process should finish promptly enough for there to be no
     * human-perceptible impact on boot time.)
     */
    printf("sva_initvmx(): waiting for global structures initialization.\n");
    uint8_t lockval;
    do {
      __atomic_load(&vmx_structures_initialized, &lockval, __ATOMIC_ACQUIRE);
    } while (lockval != DONE);
  }

  /*
   * Check to see if VMX is supported by the CPU, and if so, set the
   * IA32_FEATURE_CONTROL MSR to permit VMX operation. If this does not
   * succeed (e.g. because the BIOS or other kernel code has blocked the
   * feature), return failure.
   */
  if (!cpu_permit_vmx()) {
    DBGPRNT(("CPU does not support VMX (or the feature is disabled in "
          "BIOS); cannot initialize SVA VMX support.\n"));

    /* Restore interrupts and return to the kernel page tables. */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();

    return 0;
  }

  /*
   * Sanity check: VMCS_ALLOC_SIZE should be exactly one frame (4 kB). If we
   * ever set VMCS_ALLOC_SIZE to something different, this code will need to
   * be restructured.
   */
  SVA_ASSERT(VMCS_ALLOC_SIZE == FRAME_SIZE,
      "SVA: VMX init error: "
      "VMCS_ALLOC_SIZE is not the same as X86_PAGE_SIZE!\n");

  /*
   * We hardcode the numeric values of the constants COS_MSR, OS_COS, and
   * SVA_COS (defined in icat.h) in inline assembly in the run_vm function,
   * because getting the constants into the inline assembly block would be
   * clumsy. The asserts here ensure that the hardcoded values match the
   * correct ones defined in icat.h.
   */
  SVA_ASSERT(COS_MSR == 0xc8f,
      "SVA: VMX init error: hardcoded constant COS_MSR inconsistent\n");
  SVA_ASSERT(OS_COS == 1,
      "SVA: VMX init error: hardcoded constant OS_COS inconsistent\n");
  SVA_ASSERT(SVA_COS == 2,
      "SVA: VMX init error: hardcoded constant SVA_COS inconsistent\n");

  uint64_t orig_cr4_value = read_cr4();
  DBGPRNT(("Original value of CR4: 0x%lx\n", orig_cr4_value));

  /*
   * Make sure that SMX (Intel Safer Mode Extensions) are not enabled. SVA
   * doesn't support/use SMX and doesn't make any attempt to support VMX
   * in conjunction with it.
   *
   * (The call to cpu_permit_vmx() above enables VMX outside of SMX operation
   * but doesn't check/set the corresponding bit to enable VMX in SMX
   * operation).
   */
  SVA_ASSERT(!(orig_cr4_value & CR4_ENABLE_SMX_BIT),
      "SVA: error: cannot enable VMX when SMX is enabled.\n");

  /*
   * Set the "enable VMX" bit in CR4. This enables VMX operation, allowing us
   * to enter VMX operation by executing the VMXON instruction. Once we have
   * done so, we cannot unset the "enable VMX" bit in CR4 unless we have
   * first exited VMX operation by executing the VMXOFF instruction.
   */
  uint64_t new_cr4_value = orig_cr4_value | CR4_ENABLE_VMX_BIT;
  DBGPRNT(("Setting new value of CR4 to enable VMX: 0x%lx\n", new_cr4_value));
  write_cr4(new_cr4_value);
  DBGPRNT(("Confirming new CR4 value: 0x%lx\n", read_cr4()));

  /*
   * Confirm that the values of CR0 and CR4 are allowed for entry into VMX
   * operation (i.e., they comport with MSRs which specify bits that must be
   * 0 or 1 in these registers during VMX operation).
   *
   * We have to do this *after* setting CR4.VMXE above, since -
   * unsurprisingly - that is one of the bits that is checked.
   */
  if (!check_cr0_fixed_bits() || !check_cr4_fixed_bits()) {
    /* The check failed; we cannot enter VMX mode. */
    DBGPRNT(("CR0 and/or CR4 not set correctly for VMX; "
        "cannot initialize SVA VMX support.\n"));

    /* Restore CR4 to its original value. */
    DBGPRNT(("Restoring CR4 to its original value: 0x%lx\n", orig_cr4_value));
    write_cr4(orig_cr4_value);
    DBGPRNT(("Confirming CR4 restoration: 0x%lx\n", read_cr4()));

    /* Restore interrupts and return to the kernel page tables. */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();

    return 0;
  }

  /*
   * Allocate a frame of physical memory to use for the VMXON region.
   * This should only be accessible to SVA (and the hardware), so we will NOT
   * map it into any kernel- or user-space page tables.
   *
   * NOTE: calling alloc_frame() may (temporarily) re-enable interrupts and
   * return control to the system software via the provideSVAMemory()
   * callback. We must, therefore, be sure the system is in a safe and
   * consistent state at this time. We are safe here because the only changes
   * we have made to system state so far has been to enable a few control
   * register/MSR bits to enable the processor to recognize VMX instructions.
   * As the system software cannot issue VMX instructions except via Shade
   * intrinsics, and all Shade intrinsics will safely fail if
   * getCPUState()->vmx_enabled is not set (which we have not done yet), our
   * security posture has therefore not changed from what it was before this
   * intrinsic was called.
   */
  getCPUState()->vmxon_frame_paddr = alloc_frame();

  /*
   * Initialize the VMXON region.
   *
   * The Intel manual only specifies that we should write the VMCS revision
   * identifier to bits 30:0 of the first 4 bytes of the VMXON region, and
   * that bit 31 should be cleared to 0. It says that we "need not initialize
   * the VMXON region in any other way." For good measure, though, we'll
   * zero-fill the rest of it.
   */
  unsigned char* vmxon_vaddr = __va(getCPUState()->vmxon_frame_paddr);

  DBGPRNT(("Zero-filling VMXON frame (paddr=0x%lx,vaddr=0x%p)...\n",
        getCPUState()->vmxon_frame_paddr, vmxon_vaddr));
  memset(vmxon_vaddr, 0, VMCS_ALLOC_SIZE);

  /*
   * Write the VMCS revision identifier to bits 30:0 of the first 4 bytes of
   * the VMXON region. The VMCS revision identifier is (conveniently) given
   * in bits 30:0 of the IA32_VMX_BASIC MSR, and bit 31 of that MSR is
   * guaranteed to always be 0, so we can just copy those lower 4 bytes to
   * the beginning of the VMXON region. (This also has the effect of saving a
   * 0 to bit 31, but that is a no-op since we just cleared the whole frame.)
   *
   * We save a copy of this value in per-CPU data so that we don't have to do
   * a (potentially slow) RDMSR each time we create a VMCS in sva_allocvm().
   * It's a "hardwired" property of a particular processor and therefore will
   * not change after boot (barring something like a microcode update, which
   * we presently don't support). (Note that we still need to save this
   * per-CPU, rather than globally, because we could potentially be running
   * on a multi-processor machine where not all the processors are the same
   * model.)
   */
  uint32_t vmcs_rev_id = (uint32_t) rdmsr(MSR_VMX_BASIC);
  getCPUState()->VMCS_REV_ID = vmcs_rev_id;

  *((uint32_t*) vmxon_vaddr) = vmcs_rev_id;

  /*
   * Enter VMX operation. This is done by executing the VMXON instruction,
   * passing the physical address of the VMXON region as a memory operand.
   */
  DBGPRNT(("Entering VMX operation...\n"));
  uint64_t rflags_vmxon;
  asm __volatile__ (
      "vmxon %1\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmxon)
      : "m" (getCPUState()->vmxon_frame_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmxon) == VM_SUCCEED) {
    DBGPRNT(("SVA VMX support successfully initialized.\n"));

    getCPUState()->vmx_initialized = 1;

    /* Restore interrupts and return to the kernel page tables. */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();

    return 1;
  } else {
    DBGPRNT(("Could not enter VMX host mode. "
          "SVA VMX support not initialized.\n"));

    /* Restore CR4 to its original value. */
    DBGPRNT(("Restoring CR4 to its original value: 0x%lx\n", orig_cr4_value));
    write_cr4(orig_cr4_value);
    DBGPRNT(("Confirming CR4 restoration: 0x%lx\n", read_cr4()));

    /*
     * Free the frame of SVA secure memory we allocated for the VMXON region.
     *
     * NOTE: it is safe to call free_frame() here for the same reasons
     * outlined in the comment on the preceding call to alloc_frame() above.
     */
    DBGPRNT(("Returning VMXON frame to SVA.\n"));
    free_frame(getCPUState()->vmxon_frame_paddr);

    /* Restore interrupts and return to the kernel page tables. */
    sva_exit_critical(rflags);
    usersva_to_kernel_pcid();

    return 0;
  }
}


/*
 * Intrinsic: sva_allocvm()
 *
 * Description:
 *  Allocates a virtual machine descriptor and numeric ID for a new virtual
 *  machine. Creates and initializes any auxiliary structures (such as the
 *  Virtual Machine Control Structure) necessary to load this VM onto the
 *  processor.
 *
 * Return value:
 *  A positive integer which will be used to identify this virtual
 *  machine in future invocations of VMX intrinsics. If the return value is
 *  negative, an error occurred and nothing was allocated.
 *
 *  Note that zero is not used as a VMID because we use the VMID as the VPID
 *  to tag TLB entries belonging to the VM; Intel reserves VPID=0 to tag the
 *  host's TLB entires (and asking the processor to launch a VM with VPID=0
 *  will result in an error). This intrinsic should *never* return zero.
 */
int
sva_allocvm(void) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_allocvm() intrinsic called.\n"));

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_allocvm(): Shade not yet initialized on this processor!\n");

  /*
   * Scan the vm_descs array for the first free slot, i.e., the first entry
   * containing a null vmcs_paddr pointer. This indicates an unused VM ID.
   * (All fields in vm_desc_t should be 0 if it is not assigned to a VM.)
   *
   * Although this is in theory inefficient (we may potentially need to scan
   * through the entire array), it is simple and we never have to worry about
   * fragmentation, since the first free ID is always chosen. Creating a new
   * VM is an infrequent operation and the number of active VMs will likely
   * be small in practice, rendering this moot.
   *
   * NOTE: We skip ID #0 because these IDs do double-duty as the VPID
   * (Virtual Processor ID) specified in the VMCS. (The purpose of the VPID
   * is to distinguish TLB entries corresponding to different VMs.) This
   * limits them to 16-bit positive integers, per Intel's specification. Note
   * especially that we cannot use the value 0, because that is used to tag
   * the host's TLB entries; an attempt to launch a VM with VPID=0 will
   * result in an error.
   */
  int vmid = -1;
  for (int i = 1; i < MAX_VMS; i++) {
    if (vm_descs[i].vmcs_paddr == 0) {
      /*
       * Attempt to take the lock for this VM descriptor before confirming
       * our selection of this slot. If we cannot take the lock, then it is
       * currently in use by another processor, even if the vmcs_paddr
       * pointer is null (the other processor may be in the middle of
       * performing sva_allocvm() or sva_freevm() on it), so we should move
       * on to the next one.
       *
       * Note that this can, in practice, mean that the system can run out of
       * VM descriptor slots due to contention even if there are (slightly)
       * fewer than MAX_VMS VMs active on the system. If this becomes a
       * problem in practice, we could address it by having the loop continue
       * back around repeatedly instead of giving up when it reaches the end
       * of the array. That would effectively turn this into a spin-wait.
       *
       * If you find this happening in practice, you should probably just
       * increase MAX_VMS, as it's exceedingly unlikely to happen unless
       * you're already too close to the limit for comfort.
       *
       * (Minor aside: vm_desc_lock() will also fail if the lock is already
       * held by *this* processor, but that would only be true at the same
       * time as vmcs_paddr == 0 if we were in the middle of executing
       * sva_allocvm() or sva_unloadvm() on this very processor...which we're
       * not, since we're here. :-))
       */
      if (vm_desc_lock(&vm_descs[i])) {
        DBGPRNT(("First free VM ID found: %d\n", i));

        vmid = i;
        break;
      }
    }
  }

  /* If there were no free slots, return failure. */
  if (vmid == -1) {
    DBGPRNT(("Error: all %d VM IDs are in use; cannot create a new VM.\n",
          MAX_VMS));

    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  struct vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Initialize the guest's XSAVE area so that we won't #GP when trying to
   * load it. The hypervisor may optionally call sva_setvmfpu() to provide an
   * initial state for the FPU before the first VM entry, but if it doesn't
   * (as is the case in Xen), we need to ensure that sane initial values are
   * in place.
   */
  xinit(&vm->state.fp.inner);

  /*
   * Mark that the initial values of VMCS controls have not yet been
   * installed so that we know we need to do so the first time the VMCS is
   * loaded.
   */
  vm->vmcs_ctrls_initialized = 0;

  /*
   * Mark that this VM has not yet been launched, i.e. its first VM entry
   * needs to use VMLAUNCH rather than VMRESUME.
   *
   * In practice, it isn't strictly necessary to clear this bit here, because
   * it should have been cleared by sva_unloadvm() when the last VM to occupy
   * this descriptor slot was unloaded before being freed with sva_freevm()
   * (sva_freevm() checks that the VMCS has been unloaded first).
   * Additionally, we know that this bit should be correctly set to 0 the
   * *first* time a descriptor slot is used after boot, since sva_initvmx()
   * clears the VM descriptor array to all zeros when it is called on the
   * first processor to wake up. Nonetheless, we explicitly clear the bit
   * here because it is better form to not make complicated assumptions about
   * the behavior of other code that may have used this
   * logically-uninitialized memory at previous points in time.
   */
  vm->is_launched = 0;

  /*
   * Initialize the Extended Page Table Pointer (EPTP) to point to a
   * known-safe page table page filled with all zeroes (i.e., all entries are
   * invalid and will cause an EPT fault if used for translation) which lives
   * within SVA internal memory.
   *
   * It is expected that the system software will use sva_load_eptable() to
   * load a meaningful EPT root page table before actaully running the guest.
   * Using a "dummy" initial page table like this simplifies the prevention
   * of edge cases that could arise from it being uninitialized, without
   * requiring the system software to specify a pre-created table at VMCS
   * allocation time. (That was how we did it in the original design from the
   * VEE '19 paper, but that wasn't a good fit with Xen because Xen allocates
   * the VMCS prior to setting up page tables for a vCPU.)
   *
   * N.B.: The flags mask of 0x5e should match that used by
   * sva_load_eptable(). See comments there for explanation.
   */
  paddr_t dummy_table_paddr = __pa(dummy_ept_root_table);
  SVA_ASSERT(dummy_table_paddr == PG_ENTRY_FRAME(dummy_table_paddr),
      "SVA: dummy EPT root page table must be 4 kB-aligned!\n");

  vm->eptp = 0x5e | dummy_table_paddr;

  /*
   * Initialize the vlAPIC mode setting to OFF.
   */
  vm->vlapic.mode = VLAPIC_OFF;
  vm->vlapic.posted_interrupts_enabled = false;

  /*
   * Initialize the MSR and IO extiing bitmaps.
   */
  msr_bitmaps_init(vm);
  io_bitmaps_init(vm);

  /*
   * Allocate a physical frame of SVA secure memory from the frame cache to
   * serve as this VM's Virtual Machine Control Structure.
   *
   * This frame is protected by SVA's SFI instrumentation, ensuring that
   * the OS cannot touch it without going through an SVA intrinsic.
   *
   * NOTE: calling alloc_frame() may (temporarily) re-enable interrupts and
   * return control to the system software via the provideSVAMemory()
   * callback. We must, therefore, be sure the system is in a safe and
   * consistent state at this time. We are safe here because the only thing
   * left uninitialized for this VM, at this point in the function, is the
   * VMCS itself. As the vmcs_paddr pointer has not yet been set, other SVA
   * code will not interpret this VM descriptor as representing a valid VM
   * and will refuse to operate on it.
   */
  vm->vmcs_paddr = alloc_frame();

  /* Zero-fill the VMCS frame, for good measure. */
  unsigned char* vmcs_vaddr = __va(vm->vmcs_paddr);
  memset(vmcs_vaddr, 0, VMCS_ALLOC_SIZE);

  /*
   * Write the processor's VMCS revision identifier to the first 31 bits of
   * the VMCS frame.
   *
   * The revision identifier can be obtained by reading bits 30:0 of the
   * IA32_VMX_BASIC capability reporting MSR. We did so previously in
   * sva_initvmx() for this logical processor, and saved a copy (as it won't
   * change after boot) in per-CPU data so we don't have to repeat the
   * (potentially slow) RDMSR each time we create a new VMCS.
   *
   * (Since we write this as a 32-bit value, this also has the effect of
   * clearing bit 31, i.e. the "shadow-VMCS indicator" field - but we want
   * that bit set to 0 anyway since this is not a shadow VMCS. Also, we just
   * memset() the whole thing to 0 above so it would've been that anyway. :-))
   */
  *((uint32_t*) vmcs_vaddr) = getCPUState()->VMCS_REV_ID;

  /*
   * Use the VMCLEAR instruction to initialize any processor
   * implementation-dependent fields in the VMCS.
   *
   * The VMCLEAR instruction is used both for initializing a new VMCS, and
   * for unloading an active VM from the processor. If I am interpreting the
   * Intel manual correctly, it *is* safe to use this instruction to
   * initialize a VMCS while a *different* VMCS is active on the processor.
   * That is, if the VMCS with address X is active on the processor,
   * executing "VMCLEAR Y" should not affect X's active status.
   *
   * I should note that the Intel manual is not exceptionally clear on this
   * point, and my interpretation may be wrong.
   */
  DBGPRNT(("Using VMCLEAR to initialize VMCS with paddr 0x%lx...\n",
        vm->vmcs_paddr));
  uint64_t rflags_vmclear;
  asm __volatile__ (
      "vmclear %1\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmclear)
      : "m" (vm->vmcs_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmclear) == VM_SUCCEED) {
    DBGPRNT(("Successfully initialized VMCS.\n"));
  } else {
    /*
     * TODO: rework the error handling here to follow a single path, as
     * Colin's done with other intrinsics
     */

    DBGPRNT(("Error: failed to initialize VMCS with VMCLEAR.\n"));

    /*
     * Return the VMCS frame to the frame cache, and set its pointer to null
     * so that this VM descriptor is once again interpreted as a free slot.
     *
     * NOTE: we must clear the vm->vmcs_paddr pointer *BEFORE* calling
     * free_frame(), because free_frame() may (temporarily) re-enable
     * interrupts and return control to the system software via the
     * releaseSVAMemory() callback. We must, therefore, ensure that the
     * system is in a safe and consistent state before doing so. If we were
     * to leave vm->vmcs_paddr set at this time, the OS could call
     * sva_loadvm() and trick SVA into loading this uninitialized VMCS onto
     * the processor, since sva_loadvm() determines whether a VM is valid for
     * loading by checking that the vm->vmcs_paddr is non-null.
     */
    DBGPRNT(("Returning VMCS frame 0x%lx to SVA.\n", vm->vmcs_paddr));
    uintptr_t vmcs_paddr = vm->vmcs_paddr;
    vm->vmcs_paddr = 0;
    free_frame(vmcs_paddr);

    /* Release the VM descriptor lock. */
    vm_desc_unlock(vm);

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  /* Release the VM descriptor lock. */
  vm_desc_unlock(vm);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  /* Success: return the VM ID. */
  return vmid;
}

/*
 * Intrinsic: sva_freevm()
 *
 * Description:
 *  Deallocates a virtual machine descriptor and its associated VMCS.
 *
 *  The VMCS frame will be returned to the frame cache, and the pointer to it
 *  in the VM descriptor will be cleared to null. This marks its numeric ID
 *  and slot in the vm_descs array as unused so they can be recycled.
 *
 * Arguments:
 *  - vmid: the numeric handle of the virtual machine to be deallocated.
 */
void
sva_freevm(int vmid) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_freevm() intrinsic called for VM ID: %d\n", vmid));

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_freevm(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  struct vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Attempt to acquire the VM descriptor lock.
   *
   * We use vm_desc_lock() here instead of vm_desc_ensure_lock() since we
   * must *not* free a VM that is inactive yet whose lock is still held by
   * this processor - as that means its VMCS still resides in CPU cache and
   * has not been flushed to memory. The system software must call
   * sva_unloadvm() to perform that flush before it can free this vmid.
   */
  SVA_ASSERT(vm_desc_lock(vm),
      "sva_freevm(): Could not acquire VM descriptor lock!\n");

  /*
   * If this VM's VMCS pointer is already null, this is a double free (or
   * freeing a VM ID which was never allocated).
   */
  if (usevmx) {
    if (!vm->vmcs_paddr) {
      panic("Fatal error: tried to free a VM which was already unallocated!\n");
    }
  }

  /* Don't free a VM which is still active on the processor. */
  if (usevmx) {
    if (getCPUState()->active_vm == vm) {
      panic("Fatal error: tried to free a VM which is active on the "
          "processor!\n");
    }
  }

  /*
   * Drop the MSR and IO exiting bitmaps.
   */
  msr_bitmaps_free(vm);
  io_bitmaps_free(vm);

  /*
   * Drop vlAPIC frames.
   */
  if (vm->vlapic.mode != VLAPIC_OFF) {
    frame_drop(get_frame_desc(vm->vlapic.virtual_apic_frame), PGT_DATA);
    if (vm->vlapic.mode == VLAPIC_APIC) {
      frame_drop(get_frame_desc(vm->vlapic.apic_access_frame), PGT_DATA);
    }
    if (vm->vlapic.posted_interrupts_enabled) {
      frame_desc_t* descriptor_frame_desc =
        get_frame_desc(vm->vlapic.posted_interrupt_descriptor);
      frame_drop(descriptor_frame_desc, PGT_DATA);
    }
  }

  /*
   * Decrement the refcount for the VM's top-level extended-page-table page
   * to reflect the fact that this VM is no longer using it.
   *
   * Skip this if the VM is still using the dummy table provided by
   * sva_allocvm() for safe initialization of newly created VMs.
   * (The dummy table lives in SVA internal memory and is not subject to the
   * usual PTP reference counting.)
   */
  bool ptp_is_dummy =
    PG_ENTRY_FRAME(vm->eptp) == __pa(dummy_ept_root_table);
  if (!ptp_is_dummy) {
    frame_desc_t *ptpDesc = get_frame_desc(vm->eptp);
    frame_drop(ptpDesc, PGT_EPTL4);
  }

  /*
   * Return the VMCS frame to the frame cache, and set its pointer to null
   * so that this VM descriptor is once again interpreted as a free slot.
   *
   * NOTE: calling free_frame() may (temporarily) re-enable interrupts and
   * return control to the system software via the releaseSVAMemory()
   * callback. We must, therefore, be sure the system is in a safe and
   * consistent state at this time. We are safe here because:
   *  1) We have already confirmed that this VMCS is not loaded on the
   *     processor.
   *  2) The OS could not re-load this VMCS during the callback by calling
   *     sva_loadvm(), because we hold the lock here.
   *  3) Any Shade intrinsics whose security assumptions could have been
   *     invalidated by aspects of this VM's state having been freed prior to
   *     this point (e.g., references to vlAPIC frames or the root EPTP
   *     having been dropped) operate only on a currently-loaded VMCS, and
   *     thus cannot act on the VM we are in the process of freeing.
   */
  DBGPRNT(("Returning VMCS frame 0x%lx to SVA.\n", vm->vmcs_paddr));
  free_frame(vm->vmcs_paddr);
  vm->vmcs_paddr = 0;

  /* Release the VM descriptor lock. */
  vm_desc_unlock(vm);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
}

/*
 * Intrinsic: sva_loadvm()
 *
 * Description:
 *  Makes the specified virtual machine active on the processor.
 *
 *  If another VM is already active on the processor, it will be made
 *  inactive but its VMCS will be permitted to remain in the processor's
 *  internal caches until it is either made active again (with sva_loadvm())
 *  or explicitly flushed to memory (with sva_unloadvm()). This allows
 *  multiple VMCSes to remain in cache simultaneously to avoid extreme
 *  performance penalties during hypervisor context switching.
 *
 * Arguments:
 *  - vmid: the numeric handle of the virtual machine to be made active.
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
 */
int
sva_loadvm(int vmid) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_loadvm() intrinsic called for VM ID: %d\n", vmid));

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_loadvm(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }
  /*
   * If this VM descriptor indicated by this ID has a null VMCS pointer, it
   * is not a valid descriptor. (i.e., it is an empty slot not assigned to
   * any VM)
   */
  if (usevmx) {
    if (!vm_descs[vmid].vmcs_paddr) {
      panic("Fatal error: tried to load an unallocated VM!\n");
    }
  }

  /*
   * Attempt to acquire the VM descriptor lock if the current processor
   * doesn't already own it.
   *
   * We use vm_desc_ensure_lock() here instead of vm_desc_lock() because we
   * expressly need to *allow* the (re-)loading of a VM whose VMCS which is
   * no longer active but still remains un-flushed in the current processor's
   * CPU cache (i.e., we VMPTRLDed a different VMCS but did not yet VMCLEAR
   * this one). In that case the VM's lock is still owned by this processor
   * (as it is not safe for another processor to load it until we've flushed
   * it back to memory) even though it is no longer the active VM.
   *
   * (This is *very* important for performance reasons so that a hypervisor
   * can context-switch between several VMs without having to flush and
   * re-load the VMCS each time. It actually makes a big difference; before
   * SVA supported this we were seeing a >4x slowdown over native Xen!)
   */
  if (!vm_desc_ensure_lock(&vm_descs[vmid])) {
    DBGPRNT(("sva_loadvm(): Could not acquire VM descriptor lock!\n"));

    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  /* Set the indicated VM as the active one. */
  getCPUState()->active_vm = &vm_descs[vmid];

  /*
   * Use the VMPTRLD instruction to make the indicated VM's VMCS active on
   * the processor.
   */
  DBGPRNT(("Using VMPTRLD to make active the VMCS at paddr 0x%lx...\n",
        getCPUState()->active_vm->vmcs_paddr));
  uint64_t rflags_vmptrld;
  asm __volatile__ (
      "vmptrld %1\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmptrld)
      : "m" (getCPUState()->active_vm->vmcs_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmptrld) == VM_SUCCEED) {
    DBGPRNT(("Successfully loaded VMCS onto the processor.\n"));
  } else {
    DBGPRNT(("Error: failed to load VMCS onto the processor.\n"));

    /* Unset the active_vm pointer. */
    getCPUState()->active_vm = 0;

    /*
     * Release the VM descriptor lock.
     *
     * Note that we only do this on the error path; it needs to stay held on
     * the success path since (in that case) the VMCS has been loaded and
     * will remain so when this intrinsic returns.
     */
    vm_desc_unlock(getCPUState()->active_vm);

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  /*
   * If this is the first time this VMCS has been loaded, initialize its
   * control fields to safe defaults to ensure that their uninitialized
   * contents do not contain values that sva_writevmcs()'s runtime checks
   * would normally prevent the hypervisor from writing to them.
   *
   * We had to wait until now to do this (instead of doing it immediately in
   * sva_allocvm()) because Intel's hardware interface doesn't let you write
   * to a VMCS that isn't currently active on the processor.
   */
  if (!getCPUState()->active_vm->vmcs_ctrls_initialized) {
    DBGPRNT(("sva_loadvm(): First time this VMCS has been loaded. "
          "Initializing VMCS controls...\n"));

    init_vmcs_ctrls();

    /*
     * Mark that we've initialized these fields so we don't try to do this
     * again the next time this VMCS is loaded.
     */
    getCPUState()->active_vm->vmcs_ctrls_initialized = 1;
  }

  /*
   * Note: SVA does not currently maintain its own GDT. The safety of doing
   * this here instead of immediately before VM entry relies on Xen using one
   * GDT per CPU while running VMX guests (which it does).
   */
  vmcs_save_host_tls();

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  /* Return success. */
  return 0;
}

/*
 * Intrinsic: sva_unloadvm()
 *
 * Description:
 *  Unload the specified virtual machine from the processor. This ensures
 *  that its VMCS is flushed from CPU caches to memory and renders it safe
 *  to be moved to a different processor.
 *
 * Arguments:
 *  - vmid: the numeric handle of the virtual machine to be made active.
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
 */
int
sva_unloadvm(int vmid) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_unloadvm() intrinsic called.\n"));

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_unloadvm(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }
  /*
   * If this VM descriptor indicated by this ID has a null VMCS pointer, it
   * is not a valid descriptor. (i.e., it is an empty slot not assigned to
   * any VM)
   */
  if (usevmx) {
    if (!vm_descs[vmid].vmcs_paddr) {
      panic("Fatal error: tried to unload an unallocated VM!\n");
    }
  }

  struct vm_desc_t *vm = &vm_descs[vmid];

  /*
   * Ensure that the current processor already holds the descriptor lock for
   * this VM, i.e., there is no possibility of its VMCS being loaded on
   * another CPU right now.
   *
   * A VMCS can only be loaded on one processor at a time, and we use this
   * lock to ensure that. This Intel manual isn't especially clear (so far as
   * I've found) on what would happen if we tried to VMCLEAR a VMCS currently
   * loaded on a *different* processor, but since VMCLEAR also "initializes
   * parts of the VMCS" (vol. 3C, ch. 30.3) in addition to flushing state
   * from the processor's cache, it seems probable that doing so could
   * precipitate the processor writing data to the VMCS in memory that might
   * conflict with what's in cache on the other CPU. Thus, it seems clear
   * that this would be a Bad Thing and we should not permit it.
   *
   * Note also that we do not attempt to *take* the lock here if we don't
   * have it, because there is no point in trying to VMCLEAR a VMCS which we
   * know we don't own and thus isn't in the current processor's cache.
   *
   * Callers attempting to use VMCLEAR to *initialize* a new VMCS do not need
   * to do so under Shade, because the sva_allocvm() intrinsic takes care of
   * that in conjunction with allocating the VMCS.
   *
   * N.B.: the processor ID in the lock field is shifted up by one so that
   * the 0 value can be used to indicate "not in use" (even though 0 is a
   * valid processor ID).
   */
  if (vm->in_use != getProcessorID() + 1) {
    printf("sva_unloadvm(): Attempted to unload a VM not currently owned by "
        "this processor. Use sva_allocvm() instead for initializing a new "
        "VMCS.\n");

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  /*
   * Use the VMCLEAR instruction to unload the current VM from the processor.
   */
  DBGPRNT(("Using VMCLEAR to unload VMCS with address 0x%lx from the "
        "processor...\n", vm->vmcs_paddr));
  uint64_t rflags_vmclear;
  asm __volatile__ (
      "vmclear %1\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmclear)
      : "m" (vm->vmcs_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmclear) == VM_SUCCEED) {
    DBGPRNT(("Successfully unloaded VMCS from the processor.\n"));

    /*
     * Mark the VM as "not launched". If we load it back onto the processor
     * in the future, we will need to use sva_launchvm() instead of
     * sva_resumevm() to resume its guest-mode operation.
     */
    vm->is_launched = 0;

    /*
     * If this VM was the active one on this processor, clear the active_vm
     * pointer to indicate no VM is currently active.
     */
    if (vm == getCPUState()->active_vm)
      getCPUState()->active_vm = 0;
  } else {
    printf("sva_unloadvm(): Error: VMCLEAR returned error condition.\n");

    /*
     * Note: we must *not* release the VM descriptor lock on this error path,
     * since the VMCS is (or at least may be) still loaded on the processor!
     */

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  /* Release the VM descriptor lock. */
  vm_desc_unlock(vm);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  /* Return success. */
  return 0;
}

/*
 * Intrinsic: sva_readvmcs()
 *
 * Description:
 *  Read a field from the Virtual Machine Control Structure for the virtual
 *  machine currently active on the processor.
 *
 *  Note: the VMCS fields can *only* be read/written for an *active* VM
 *  currently loaded on the processor. This is a design choice on Intel's
 *  part: we must use special instructions to do this, which only operate on
 *  an active VMCS.
 *
 * Arguments:
 *  - field: The field to be read.
 *
 *  - data: A pointer to a 64-bit integer location in which to store the
 *    value read from the VMCS field. (This is an "out-parameter".) A value
 *    may or may not be written to this field in the case that an error code
 *    indicating failure is returned (and if this does occur, the value
 *    written is undefined).
 *
 *    Note: different VMCS fields have different widths. They can be 16 bits,
 *    32 bits, 64 bits, or "natural width" (width of the host platform, which
 *    in our case always means 64 bits since this version of SVA does not run
 *    on 32-bit x86). If we are reading a field narrower than 64 bits, the
 *    value returned is zero-extended, i.e., the higher bits will be 0.
 *
 * Return value:
 *  An error code indicating the result of this operation:
 *     0: indicates the VMREAD was performed successfully.
 *
 *    -1: indicates failure due to there being no VMCS currently loaded to
 *        read from. (This corresponds to the VMfailInvalid error code
 *        returned by VMREAD in the native ISA. If SVA is working correctly,
 *        it will detect and return this condition via its own logic and
 *        never actually issue VMREAD on the processor.)
 *
 *    -2: indicates failure due to an invalid VMCS field having been
 *        specified. (This corresponds to the VMfailValid error code returned
 *        by VMREAD in the native ISA. Currently, you shouldn't see this in
 *        practice since SVA's VMCS read whitelist in readvmcs_checked()
 *        should only contain valid fields, and attempting to read from a
 *        field not on the whitelist results in a panic. We may potentially
 *        choose to loosen that failure condition in the future to return
 *        this error code instead of hard-panicking.)
 */
int
sva_readvmcs(enum sva_vmcs_field field, uint64_t __kern* data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

#if 0
  DBGPRNT(("sva_readvmcs() intrinsic called with field="));
  print_vmcs_field_name(field, SVAVMX_DEBUG);
  DBGPRNT((" (0x%lx), data=%p\n", field, data));
#endif

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_readvmcs(): Shade not yet initialized on this processor!\n");

  /*
   * If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (usevmx) {
    if (!getCPUState()->active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot read from VMCS.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  uint64_t out;

  /*
   * Perform the read if it won't leak sensitive information to the system
   * software (or if it can be sanitized).
   */
  int retval = readvmcs_checked(field, &out);

  if (retval == 0) {
    if (sva_copy_to_kernel(data, &out, sizeof(out))) {
      retval = -1;
    }
  }

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return retval;
}

/*
 * Intrinsic: sva_writevmcs()
 *
 * Description:
 *  Write to a field in the Virtual Machine Control Structure for the virtual
 *  machine currently active on the processor.
 *
 *  Note: the VMCS fields can *only* be read/written for an *active* VM
 *  currently loaded on the processor. This is a design choice on Intel's
 *  part: we must use special instructions to do this, which only operate on
 *  an active VMCS.
 *
 * Arguments:
 *  - field: The field to be written.
 *
 *  - data: The value to be written to the field.
 *
 *    Note: different VMCS fields have different widths. They can be 16 bits,
 *    32 bits, 64 bits, or "natural width" (width of the host platform, which
 *    in our case always means 64 bits since this version of SVA does not run
 *    on 32-bit x86). If we are writing a field narrower than 64 bits, the
 *    higher bits will be ignored.
 *
 * Return value:
 *  An error code indicating the result of this operation:
 *     0: indicates the VMWRITE was performed successfully.
 *
 *    -1: indicates failure due to there being no VMCS currently loaded to
 *        read from. (This corresponds to the VMfailInvalid error code
 *        returned by VMWRITE in the native ISA. If SVA is working correctly,
 *        it will detect and return this condition via its own logic and
 *        never actually issue VMWRITE on the processor.)
 *
 *    -2: indicates failure due to an invalid VMCS field having been
 *        specified. (This corresponds to the VMfailValid error code returned
 *        by VMWRITE in the native ISA. Currently, you shouldn't see this in
 *        practice since SVA's VMCS write whitelist in writevmcs_checked()
 *        should only contain valid fields, and attempting to write to a
 *        field not on the whitelist results in a panic. We may potentially
 *        choose to loosen that failure condition in the future to return
 *        this error code instead of hard-panicking.)
 */
int
sva_writevmcs(enum sva_vmcs_field field, uint64_t data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

#if 0
  DBGPRNT(("sva_writevmcs() intrinsic called with field="));
  print_vmcs_field_name(field, SVAVMX_DEBUG);
  DBGPRNT((" (0x%lx), data=0x%lx\n", field, data));
#endif

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_writevmcs(): Shade not yet initialized on this processor!\n");

  /*
   * If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (usevmx) {
    if (!getCPUState()->active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot write to VMCS.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  /*
   * Vet the value to be written to ensure that it will not compromise system
   * security, and perform the write.
   */
  int retval = writevmcs_checked(field, data);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return retval;
}

/*
 * Intrinsic: sva_launchvm()
 *
 * Description:
 *  Run the currently-loaded virtual machine in guest mode for the first time
 *  since it was loaded onto the processor.
 *
 *  NOTE: This intrinsic should only be used the *first* time a VM is run
 *  after it is loaded onto the processor. For subsequent re-entries to guest
 *  mode where the VM was not unloaded (with the sva_loadvm() intrinsic)
 *  since its last exit back to host mode, the sva_resumevm() intrinsic must
 *  be used instead.
 *
 *  sva_launchvm() will fail if it is called when sva_resumevm() should be
 *  used instead.
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  control has returned to host mode due to a VM exit. A negative value
 *  indicates that VM entry failed (i.e., we never left host mode).
 */
int
sva_launchvm(void) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_launchvm() intrinsic called.\n"));

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_launchvm(): Shade not yet initialized on this processor!\n");

  /*
   * If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (usevmx) {
    if (!getCPUState()->active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot launch VM.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  /*
   * If the VM has been launched before since being loaded onto the
   * processor, the sva_resumevm() intrinsic must be used instead of this
   * one.
   */
  if (usevmx) {
    if (getCPUState()->active_vm->is_launched) {
      DBGPRNT(("Error: Must use sva_resumevm() to enter a VM which "
               "was previously run since being loaded on the processor.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Mark the VM as launched. Until this VM is unloaded from the processor,
   * future entries to it must be performed using the sva_resumevm()
   * intrinsic.
   */
  getCPUState()->active_vm->is_launched = 1;

  /* Enter guest-mode execution (which will ultimately exit back into host
   * mode and return us here).
   *
   * This involves a lot of detailed assembly code to save/restore host
   * state, and all of it is the same as for sva_resumevm() (except that we
   * use the VMRESUME instruction instead of VMLAUNCH), so we perform this in
   * a common helper function.
   */
  int retval = run_vm(0 /* use_vmresume */);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return retval;
}

/*
 * Intrinsic: sva_resumevm()
 *
 * Description:
 *  Run the currently-loaded virtual machine in guest mode, given the
 *  assumption that it has done so once before since it was loaded onto the
 *  processor.
 *
 *  NOTE: This intrinsic should only be used for VM "re-entries", i.e., to
 *  enter guest mode after having previously done so (and subsequently
 *  exited) using sva_launchvm().
 *
 *  If you want to run a VM for the first time since loading it, you must use
 *  sva_launchvm() instead. This includes the case where a VM was previously
 *  loaded and run, but was since unloaded and reloaded from the processor;
 *  from the processor's perspective, it might as well be a new VM.
 *
 *  sva_resumevm() wil fail if it is called when sva_launchvm() should be
 *  used instead.
 *
 *  TODO: investigate whether it's possible to unify the launch/resumevm
 *  intrinsics without unduly complicating porting of existing hypervisors. I
 *  don't think this will be a problem, since the two separate interfaces
 *  appears to just be the processor exposing the fact that one is an
 *  optimized version of the other that keeps more cached state valid. We
 *  (SVA) have to keep track of whether the VM's been "launched" yet anyway,
 *  to check that the wrong intrinsic wasn't called, so we can just as easily
 *  make it one intrinsic that automatically does the right thing. (The code
 *  is basically unified already since they call the common helper run_vm().)
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  control has returned to host mode due to a VM exit. A negative value
 *  indicates that VM entry failed (i.e., we never left host mode).
 */
int
sva_resumevm(void) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

#if 0
  DBGPRNT(("sva_resumevm() intrinsic called.\n"));
#endif

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_resumevm(): Shade not yet initialized on this processor!\n");

  /*
   * If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (usevmx) {
    if (!getCPUState()->active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot resume VM.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  /*
   * If the VM has not previously been launched at least once since being
   * loaded onto the processor, the sva_launchvm() intrinsic must be used
   * instead of this one.
   */
  if (usevmx) {
    if (!getCPUState()->active_vm->is_launched) {
      DBGPRNT(("Error: Must use sva_launchvm() to enter a VM which hasn't "
               "previously been run since being loaded on the processor.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Enter guest-mode execution (which will ultimately exit back into host
   * mode and return us here).
   *
   * This involves a lot of detailed assembly code to save/restore host
   * state, and all of it is the same as for sva_launchvm() (except that we
   * use the VMLAUNCH instruction instead of VMRESUME), so we perform this in
   * a common helper function.
   */
  int retval = run_vm(1 /* use_vmresume */);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return retval;
}

/**
 * Initialize the host control register fields of the current VMCS, except
 * `%cr3`
 *
 * This does not initialize the host `%cr3` VMCS field. This field must be set
 * to the page table in use during VM entry. See `vmcs_save_host_pt`.
 */
static void vmcs_init_host_cr(void) {
  SVA_ASSERT(getCPUState()->active_vm != NULL,
      "Caller must have a VMCS loaded");
  BUG_ON(writevmcs_unchecked(VMCS_HOST_CR0, SVA_CR0));
  uint64_t host_cr4 = read_cr4();
  BUG_ON(writevmcs_unchecked(VMCS_HOST_CR4, host_cr4));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_IA32_EFER, SVA_EFER | EFER_LMA));
  uint64_t host_pat = rdmsr(MSR_IA32_PAT);
  BUG_ON(writevmcs_unchecked(VMCS_HOST_IA32_PAT, host_pat));

#if 0
  DBGPRNT(("run_vm: Saved host control registers.\n"));
#endif
}

/**
 * Initialize the host segment VMCS fields.
 */
static void vmcs_init_host_segments(void) {
  SVA_ASSERT(getCPUState()->active_vm != NULL,
      "Caller must have a VMCS loaded");

  extern char sva_idt[];

  BUG_ON(writevmcs_unchecked(VMCS_HOST_CS_SEL, SVA_KERNEL_CS));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_SS_SEL, 0));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_DS_SEL, 0));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_ES_SEL, 0));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_FS_SEL, 0));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_GS_SEL, 0));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_TR_SEL, SVA_TR));
#if 0
  DBGPRNT(("run_vm: Saved host segment selectors.\n"));
#endif

  /*
   * Interrupt descriptor table base.
   */
  BUG_ON(writevmcs_unchecked(VMCS_HOST_IDTR_BASE, (uintptr_t)&sva_idt));

#if 0
  DBGPRNT(("run_vm: Saved host FS, GS, and IDTR bases.\n"));
#endif
}

/**
 * Initialize the SYSENTER MSR VMCS fields.
 */
static void vmcs_init_host_sysenter(void) {
  SVA_ASSERT(getCPUState()->active_vm != NULL,
      "Caller must have a VMCS loaded");

  /*
   * FIXME: SVA always sets the SYSENTER MSRs to 0 since it does not support
   * that syscall mechanism (SYSCALL being preferred in 64-bit mode); we can
   * optimize here by just setting these three VMCS fields to 0 when we're
   * initializing the rest of the "set-and-forget" fields the first time
   * sva_loadvm() is called for this VMCS. That'll allow us to save three
   * RDMSRs and three VMCS writes. (Considering that MSR reads/writes seem to
   * be considered slow operations, and this is on the VM-exit-handling
   * critical path, this is probably a good idea.)
   */
  writevmcs_unchecked(VMCS_HOST_IA32_SYSENTER_CS, 0);
  writevmcs_unchecked(VMCS_HOST_IA32_SYSENTER_ESP, 0);
  writevmcs_unchecked(VMCS_HOST_IA32_SYSENTER_EIP, 0);

#if 0
  DBGPRNT(("Saved host SYSENTER MSRs.\n"));
#endif
}

/**
 * Save the current host page table pointer (`%cr3`) to the VMCS host state.
 */
static void vmcs_save_host_pt(void) {
  SVA_ASSERT(getCPUState()->active_vm != NULL,
      "Caller must have a VMCS loaded");
  uint64_t host_cr3 = read_cr3();
  BUG_ON(writevmcs_unchecked(VMCS_HOST_CR3, host_cr3));
}

/**
 * Save thread-local values to the VMCS host state.
 *
 * This includes the GDT and TSS bases as well as the `%fs` and `%gs` segment
 * bases.
 */
static void vmcs_save_host_tls(void) {
  SVA_ASSERT(getCPUState()->active_vm != NULL,
      "Caller must have a VMCS loaded");

  BUG_ON(writevmcs_unchecked(VMCS_HOST_FS_BASE, rdfsbase()));
  BUG_ON(writevmcs_unchecked(VMCS_HOST_GS_BASE, rdgsbase()));

  /*
   * The sgdt/sidt instructions store a 10-byte "pseudo-descriptor" into
   * memory. The first 2 bytes are the limit field adn the last 8 bytes are
   * the base-address field.
   */
  struct __packed {
    uint16_t limit;
    uintptr_t base;
  } gdtr;

  asm volatile (
      "sgdt %0\n"
      : "=m"(gdtr)
      );
  BUG_ON(writevmcs_unchecked(VMCS_HOST_GDTR_BASE, gdtr.base));

  BUG_ON(writevmcs_unchecked(VMCS_HOST_TR_BASE, (uintptr_t)getCPUState()->tssp));

#if 0
  DBGPRNT(("run_vm: Saved host GDT and TSS base.\n"));
#endif
}

/**
 * Apply any necessary special handling of VM exits before returning to the
 * hypervisor.
 *
 * @return  Whether SVA handled the exit
 */
static bool vmexit_handler(void) {
  uint64_t exit_reason;
  BUG_ON(readvmcs_unchecked(VMCS_VM_EXIT_REASON, &exit_reason));

  switch (exit_reason & 0xffffUL) {
  case VM_EXIT_EXTERNAL_INTERRUPT: {
    struct vmcs_vm_exit_ctrls ctrls;
    BUG_ON(vmcs_exitctrls_get(&ctrls));

    if (ctrls.ack_int_on_exit) {
      uint64_t info;
      BUG_ON(readvmcs_unchecked(VMCS_VM_EXIT_INTERRUPTION_INFO, &info));

      /* Ack interrupts on exit set, but interrupt info field is invalid? */
      BUG_ON(!(info & (1UL << 31)));

      uint8_t vector = info & 0xffUL;

      /*
       * Since this interrupt won't be delivered through the IDT, we need to
       * call our handler here.
       */
      if (sva_interrupt_table[vector]) {
        if (sva_interrupt_table[vector]()) {
          /*
           * The handler has reported that the exception doesn't need to go to
           * the kernel.
           */
          // TODO: Replace kernel's view of exit reason
          return true;
        }
      }
    }
  }
  }

  return false;
}

/**
 * Assembly VM entry/exit code.
 */
static unsigned long asm_run_vm(struct vmx_host_state_t* host_state, bool use_vmresume) {
  unsigned long vmexit_rflags;

  /*
   * This is where the magic happens.
   *
   * In this assembly section, we:
   *  - Save the host's general-purpose register state to the host_state
   *    structure.
   *
   *  - Use the VMWRITE instruction to set the RIP and RSP values that will
   *    be loaded by the processor on the next VM exit.
   *
   *  - Restore the guest's general-purpose register state from the active
   *    VM's descriptor (vm_desc_t structure).
   *
   *  - Execute VMLAUNCH/VMRESUME (as appropriate). This enters guest mode
   *    and runs the VM until an event occurs that triggers a VM exit.
   *
   *  - Return from VM exit. When we set the RIP value to be loaded earlier,
   *    we pointed it to the vmexit_landing_pad label, which is on the next
   *    instruction following VMLAUNCH/VMRESUME. This maintains a
   *    straight-line continuity of control flow, as if VMLAUNCH/VMRESUME
   *    fell through to the next instruction after VM exit instead of loading
   *    an arbitrary value into RIP. (This seems the most sane way to stitch
   *    things together, since it avoids breaking the control flow of the
   *    surrounding C function in a confusing way.)
   *
   *  - Save the current value of RFLAGS so we can pass it to
   *    query_vmx_result() to determine whether the VM entry succeeded (and
   *    thence a VM exit actually occurred).
   *
   *  - Save the guest's general-purpose register state.
   *
   *  - Restore the host's general-purpose register state.
   */
  asm volatile (
      /* Save host RFLAGS.
       * 
       * RFLAGS is cleared on every VM exit, so we need to restore it
       * ourselves.
       */
      "pushfq\n"

      /* RAX contains a pointer to the host_state structure.
       * Push it so that we can get it back after VM exit.
       */
      "pushq %%rax\n"

      /*** Save host GPRs ***/
      /* We don't need to save RAX, RBX, RCX, or RDX because we've used them
       * as input/output registers for this inline assembly block, i.e., we
       * know the compiler isn't keeping anything there.
       */
      "movq %%rbp,  %c[host_rbp](%%rax)\n"
      "movq %%rsi,  %c[host_rsi](%%rax)\n"
      "movq %%rdi,  %c[host_rdi](%%rax)\n"
      "movq %%r8,   %c[host_r8](%%rax)\n"
      "movq %%r9,   %c[host_r9](%%rax)\n"
      "movq %%r10,  %c[host_r10](%%rax)\n"
      "movq %%r11,  %c[host_r11](%%rax)\n"
      "movq %%r12,  %c[host_r12](%%rax)\n"
      "movq %%r13,  %c[host_r13](%%rax)\n"
      "movq %%r14,  %c[host_r14](%%rax)\n"
      "movq %%r15,  %c[host_r15](%%rax)\n"
      /* (Now all the GPRs are free for our own use in this code.) */

      /*** Use VMWRITE to set RIP and RSP to be loaded on VM exit ***/
      "vmwrite %%rsp, %%rbx\n" // Write RSP to VMCS_HOST_RSP
      "leaq vmexit_landing_pad(%%rip), %%rbp\n"
      "vmwrite %%rbp, %%rcx\n" // Write vmexit_landing_pad to VMCS_HOST_RIP

      /*** Determine whether we will be using VMLAUNCH or VMRESUME for VM
       *** entry, based on the value of use_vmresume. ***/
      "addb $0, %%dl\n"
      /* NOTE: the "addb" above sets the zero flag (ZF) if and only if
       * use_vmresume is 0, i.e., we should use VMLAUNCH.
       *
       * We had to wait until now to restore the guest's GPRs, because after
       * we've done so we'll have no free registers to work with (and any
       * values we had previously stored in them will be clobbered).
       *
       ******
       * IT IS IMPERATIVE THAT NO INSTRUCTIONS BETWEEN THIS POINT AND THE
       * "jnz do_vmresume" TOUCH THE ZERO FLAG. Otherwise, we will forget
       * whether we are launching or resuming the VM.
       ******
       *
       * Fortunately, we only need to use MOVs (and similar) to restore the
       * guest's register state, and none of those mess with the zero flag
       * (or any of the flags).
       *
       * (If this ever becomes a limitation, there is a way around this: we
       * could store the boolean use_vmresume in memory, and use the
       * "immediate + memory" form of ADD, which would have the same desired
       * effect on ZF. However, we would need to locate use_vmresume in a
       * statically addressible location, since we'd still have no free
       * registers to use for a pointer. This is clumsy and it'd be (perhaps
       * not meaningfully) slower, so let's not do it if we don't have to.)
       */

#ifdef SVA_LLC_PART
      /*** Switch to the OS cache partition for side-channel protection ***
       *
       * NOTE: we need to be careful what memory we "touch" between here and
       * VM entry. Anything that we touch gets pulled into the OS cache
       * partition, meaning it's exposed to side-channel attacks launched by
       * the OS or the VM guest.
       *
       * We have to do this before loading guest register state (and
       * likewise, switch back after saving guest register state after VM
       * exit) because we need to have EAX, EDX, and ECX free to issue the
       * WRMSR instruction that performs the partition switch. When guest
       * registers are loaded on the processor, we have no free registers
       * whatsoever.
       *
       * This should be safe so long as there is no sensitive information
       * stored within the same cache line(s) as the guest state structure
       * (active_vm->state). The guest state values themselves are not
       * sensitive because they're under control of the OS/hypervisor anyway.
       *
       * TODO: determine the actual cache line size of the hardware we're
       * using (or better, an upper limit on LLC cache line size for x86
       * processors if there is such a thing). We can then put that amount of
       * padding around the guest state structure to ensure no neighboring
       * sensitive information can potentially get exposed to side-channel
       * attacks.
       */
      /*
       * WRMSR will use EAX, EDX, and ECX as inputs. We used all three of
       * those as inputs to this assembly block. We finished using the values
       * in RCX and RDX above, so they're dead (free to overwrite). RAX still
       * stores a pointer to the active VM descriptor that we'll need below,
       * so we need to stash that somewhere else while we do the WRMSR.
       *
       * The hardcoded numeric values of the constants COS_MSR, OS_COS, and
       * (below after VM exit) SVA_COS are checked with asserts in
       * sva_initvmx() to ensure that they match the values defined in
       * icat.h.
       */
      "movq %%rax, %%rbp\n"     // stash active vm_desc ptr. in RBP
      "movq $0xc8f, %%rcx\n"    // MSR (COS_MSR = 0xc8f) to be written
      /* Write the constant OS_COS (1) to the MSR */
      "movq $1, %%rax\n"        // EAX = lower 32 bits to be written to MSR
      "movq $0, %%rdx\n"        // EDX = upper 32 bits to be written to MSR
      "wrmsr\n"
      "movq %%rbp, %%rax\n"     // restore active vm_desc ptr. in RAX
#endif /* #ifdef SVA_LLC_PART */

      /*** Restore guest register state ***
       * First, load a pointer to the active VM descriptor (which is stored
       * in the host_state structure). This is where the guest GPR
       * save/restore slots are located.
       */
      "movq %c[active_vm](%%rax), %%rax\n" // RAX <-- active_vm pointer

      /*** Restore guest CR2 ***
       *
       * Note: we do not need to save/restore the host CR2 because it should
       * always be dead (safe to clobber) here. CR2 should only ever have a
       * live value during the very short window of time between a page fault
       * being dispatched and the page-fault handler re-enabling interrupts.
       *
       * I can't think of a scenario in which it would ever be correct or
       * reasonable to call sva_launch/resumevm() during a page fault
       * handler. The system software shouldn't expect CR2 to be maintained
       * consistently outside of a page fault handler, so it should be fine
       * with it being randomly clobbered by sva_launch/resumevm().
       *
       * When we do "Virtual Ghost for VMs" in the future to protect VMs from
       * compromised host system software, we may need to *clear* CR2 after
       * VM exit to prevent sensitive guest state from being leaked (page
       * fault access patterns could be relevant in side-channel attacks),
       * but that's not a concern for now.
       */
      "movq %c[guest_cr2](%%rax), %%rbp\n" // move guest CR2 to temp reg
      "movq %%rbp, %%cr2\n"

      /*** Restore guest GPRs ***
       * We will restore RAX last, since we need a register in which to keep
       * the pointer to the active VM descriptor. (The instruction that
       * restores RAX will both use this pointer and overwrite it.)
       */
      "movq %c[guest_rbx](%%rax), %%rbx\n"
      "movq %c[guest_rcx](%%rax), %%rcx\n"
      "movq %c[guest_rdx](%%rax), %%rdx\n"
      "movq %c[guest_rbp](%%rax), %%rbp\n"
      "movq %c[guest_rsi](%%rax), %%rsi\n"
      "movq %c[guest_rdi](%%rax), %%rdi\n"
      "movq %c[guest_r8](%%rax),  %%r8\n"
      "movq %c[guest_r9](%%rax),  %%r9\n"
      "movq %c[guest_r10](%%rax), %%r10\n"
      "movq %c[guest_r11](%%rax), %%r11\n"
      "movq %c[guest_r12](%%rax), %%r12\n"
      "movq %c[guest_r13](%%rax), %%r13\n"
      "movq %c[guest_r14](%%rax), %%r14\n"
      "movq %c[guest_r15](%%rax), %%r15\n"
      /* Restore RAX */
      "movq %c[guest_rax](%%rax), %%rax\n" // replaces active_vm pointer
      /* All GPRs are now ready for VM entry. */

      /* If zero flag not set, use VMRESUME; otherwise use VMLAUNCH. */
      "jnz do_vmresume\n"
      "vmlaunch\n"
      /* NOTE: we need to place an explicit jump to vmexit_landing_pad
       * immediately after the VLAUNCH instruction to ensure consistent
       * behavior if the VM entry fails (and thus execution falls through to
       * the next instruction).
       */
      "jmp vmexit_landing_pad\n"

      "do_vmresume:\n"
      "vmresume\n"
      /* Here the fall-through is OK since vmexit_landing_pad is next. */

      /*** VM exits return here!!! ***/
      "vmexit_landing_pad:\n"

      /*** Save RFLAGS, which contains the VMX error code. ***/
      /* (We need to return this in RDX at the end of the asm block.) */
      "pushfq\n"

      /*** Get pointer to the active VM descriptor, using the host_state
       * pointer which we saved on the stack prior to VM entry.
       *
       * We have NO free registers at this point (all of them contain guest
       * values which we need to save). We therefore start by pushing RAX to
       * give us one to work with.
       *
       * Note: after pushing RAX, our stack looks like:
       *      (%rsp)  - saved guest RAX
       *     8(%rsp)  - RFLAGS saved after VM exit (VMX error code)
       *    16(%rsp)  - pointer to host_state saved before VM entry
       *    24(%rsp)  - host RFLAGS saved before VM entry
       * (Since we're not using a frame pointer, and are using push/pop
       * instructions i.e. a dynamic stack frame, we need to keep track of
       * this carefully.)
       */
      "pushq %%rax\n"
      "movq 16(%%rsp), %%rax\n"            // RAX <-- host_state pointer
      "movq %c[active_vm](%%rax), %%rax\n" // RAX <-- active_vm pointer

      /*** Save guest GPRs ***
       *
       * We save RBX first since we need another free register to save the
       * guest RAX we stashed away on the stack (since x86 doesn't do
       * memory-to-memory moves).
       */
      "movq %%rbx, %c[guest_rbx](%%rax)\n"
      "movq (%%rsp), %%rbx\n"              // We stashed guest RAX at (%rsp).
      "movq %%rbx, %c[guest_rax](%%rax)\n" // Save guest RAX
      "movq %%rcx, %c[guest_rcx](%%rax)\n"
      "movq %%rdx, %c[guest_rdx](%%rax)\n"
      "movq %%rbp, %c[guest_rbp](%%rax)\n"
      "movq %%rsi, %c[guest_rsi](%%rax)\n"
      "movq %%rdi, %c[guest_rdi](%%rax)\n"
      "movq %%r8,  %c[guest_r8](%%rax)\n"
      "movq %%r9,  %c[guest_r9](%%rax)\n"
      "movq %%r10, %c[guest_r10](%%rax)\n"
      "movq %%r11, %c[guest_r11](%%rax)\n"
      "movq %%r12, %c[guest_r12](%%rax)\n"
      "movq %%r13, %c[guest_r13](%%rax)\n"
      "movq %%r14, %c[guest_r14](%%rax)\n"
      "movq %%r15, %c[guest_r15](%%rax)\n"
      /* (Now all the GPRs are free for our own use in this code.) */

      /*** Save guest CR2 ***/
      "movq %%cr2, %%rbp\n" // move guest CR2 to temp reg
      "movq %%rbp, %c[guest_cr2](%%rax)\n"

#ifdef SVA_LLC_PART
      /*** Switch back to SVA cache partition for side-channel protection ***
       *
       * All registers are dead here so we're free to clobber RAX, RDX, and
       * RCX.
       */
      "movq $0xc8f, %%rcx\n"    // MSR (COS_MSR = 0xc8f) to be written
      /* Write the constant SVA_COS (2) to the MSR */
      "movq $2, %%rax\n"        // EAX = lower 32 bits to be written to MSR
      "movq $0, %%rdx\n"        // EDX = upper 32 bits to be written to MSR
      "wrmsr\n"
#endif

      /* (Re-)get the host_state pointer, which we couldn't keep earlier
       * because we had no free registers.
       */
      "movq 16(%%rsp), %%rax\n"

      /*** Restore host GPRs ***/
      "movq %c[host_rbp](%%rax), %%rbp\n"
      "movq %c[host_rsi](%%rax), %%rsi\n"
      "movq %c[host_rdi](%%rax), %%rdi\n"
      "movq %c[host_r8](%%rax),  %%r8\n"
      "movq %c[host_r9](%%rax),  %%r9\n"
      "movq %c[host_r10](%%rax), %%r10\n"
      "movq %c[host_r11](%%rax), %%r11\n"
      "movq %c[host_r12](%%rax), %%r12\n"
      "movq %c[host_r13](%%rax), %%r13\n"
      "movq %c[host_r14](%%rax), %%r14\n"
      "movq %c[host_r15](%%rax), %%r15\n"
      /*
       * (Note: from here to the end of the asm block, we are only free to
       * use the GPRs RAX, RBX, RCX, and RDX, as the rest of them, which we
       * just restored above, contain potentially-live values which "belong"
       * to the compiler. RBX and RDX are used as outputs from the asm block
       * and will be set below.)
       */

      /* Put the saved RFLAGS (VMX error code) into RDX for output from the
       * asm block.
       */
      "movq 8(%%rsp), %%rdx\n"
      /* Also put the earlier-saved host RFLAGS (which we're about to
       * restore) into RBX for output from the asm block (so we can print it).
       */
      "movq 24(%%rsp), %%rbx\n"

      /* Return the stack to the way it was when we entered the asm block,
       * and restore RFLAGS to what it was before VM entry.
       *
       * NOTE: interrupts are always blocked (disabled) on VM exit due to
       * RFLAGS being cleared by the processor. However, that doesn't
       * actually change anything because we were already in an SVA critical
       * section (interrupts disabled) for the duration of the
       * sva_launch/resumevm() intrinsic that called this function. If
       * interrupts were originally enabled prior to that intrinsic being
       * called, they'll be re-enabled when the intrinsic restores RFLAGS
       * before returning.
       */
      "addq $24, %%rsp\n" // Unwind the last three pushq's...
      "popfq\n"           // ...so we can pop the host RFLAGS below them.

      : "=d" (vmexit_rflags)
      : "a" (host_state), "b" (VMCS_HOST_RSP), "c" (VMCS_HOST_RIP),
        "d" (use_vmresume),
         /* Offsets of host_state elements */
         [active_vm] "i" (offsetof(vmx_host_state_t, active_vm)),
         [host_rbp] "i" (offsetof(vmx_host_state_t, rbp)),
         [host_rsi] "i" (offsetof(vmx_host_state_t, rsi)),
         [host_rdi] "i" (offsetof(vmx_host_state_t, rdi)),
         [host_r8]  "i" (offsetof(vmx_host_state_t, r8)),
         [host_r9]  "i" (offsetof(vmx_host_state_t, r9)),
         [host_r10] "i" (offsetof(vmx_host_state_t, r10)),
         [host_r11] "i" (offsetof(vmx_host_state_t, r11)),
         [host_r12] "i" (offsetof(vmx_host_state_t, r12)),
         [host_r13] "i" (offsetof(vmx_host_state_t, r13)),
         [host_r14] "i" (offsetof(vmx_host_state_t, r14)),
         [host_r15] "i" (offsetof(vmx_host_state_t, r15)),
         /* Offsets of guest state elements in vm_desc_t */
         [guest_rax] "i" (offsetof(vm_desc_t, state.rax)),
         [guest_rbx] "i" (offsetof(vm_desc_t, state.rbx)),
         [guest_rcx] "i" (offsetof(vm_desc_t, state.rcx)),
         [guest_rdx] "i" (offsetof(vm_desc_t, state.rdx)),
         [guest_rbp] "i" (offsetof(vm_desc_t, state.rbp)),
         [guest_rsi] "i" (offsetof(vm_desc_t, state.rsi)),
         [guest_rdi] "i" (offsetof(vm_desc_t, state.rdi)),
         [guest_r8]  "i" (offsetof(vm_desc_t, state.r8)),
         [guest_r9]  "i" (offsetof(vm_desc_t, state.r9)),
         [guest_r10] "i" (offsetof(vm_desc_t, state.r10)),
         [guest_r11] "i" (offsetof(vm_desc_t, state.r11)),
         [guest_r12] "i" (offsetof(vm_desc_t, state.r12)),
         [guest_r13] "i" (offsetof(vm_desc_t, state.r13)),
         [guest_r14] "i" (offsetof(vm_desc_t, state.r14)),
         [guest_r15] "i" (offsetof(vm_desc_t, state.r15)),
         [guest_cr2] "i" (offsetof(vm_desc_t, state.cr2))
      : "memory", "cc"
      );

  return vmexit_rflags;
}

/*
 * Function: run_vm()
 *
 * Description:
 *  Common helper function for sva_launchvm() and sva_resumevm().
 *
 *  Does the heavy lifting for the context switch into and back out of guest
 *  mode (VM entry/exit).
 *
 *  This entails:
 *  - Loading the extended page table pointer (EPTP) for the VM.
 *
 *  - Setting various VMCS fields containing host state to be restored on VM
 *    exit. These include the control registers, segment registers, the
 *    kernel program counter and stack pointer, and the MSRs that control
 *    fast system calls.
 *
 *  - Saving additional host state that will not automatically be restored by
 *    the processor on VM exit. This includes all the general purpose
 *    registers and floating-point state.
 *
 *  - Restoring guest state that is not automatically loaded by the processor
 *    on VM entry.
 *
 *  - Entering guest execution by executing the VMLAUNCH or VMRESUME
 *    instruction, as appropriate.
 *
 *  - Noting the state of RFLAGS after we come back from VMLAUNCH/VMRESUME so
 *    we can pass it to query_vmx_result().
 *
 *  - Saving guest state that is not automatically saved by the processor on
 *    VM exit.
 *
 *  - Restoring all saved host state.
 *
 *  - Finally, returning a result code to sva_launchvm/resumevm() which will
 *    be passed back to its caller.
 *
 * Preconditions:
 *  This should ONLY be called at the end of sva_launchvm/resumevm(),
 *  respectively. It assumes that all checks have already been done to ensure
 *  it is safe to do VM entry.
 *
 * Arguments:
 *  - use_vmresume: A boolean indicating whether we should perform the VM
 *  entry using the VMRESUME instruction instead of VMLAUNCH.
 *
 * Return value:
 *  An error code to be passed through to the respective intrinsic
 *  (sva_launchvm/resumevm()) which called this helper function.
 *
 *  0 indicates control has returned to host mode due to a VM exit. A
 *  negative value indicates that VM entry failed.
 */
static int
run_vm(unsigned char use_vmresume) {
entry:
  (void)0;

  /*
   * Allocate a host_state structure on the stack to give us a place to stash
   * various host state elements that need to be restored after VM exit.
   *
   * We aggregate these fields within a structure rather than as individual
   * local variables so that we can more conveniently remember where we left
   * them when we return to host mode in the VM entry/exit assembly block and
   * have (initially) no GPRs to work with. This way, we can stash a single
   * pointer to host_state on the stack before VM entry rather than having to
   * keep track of the RSP-relative positions of numerous registers
   * individually pushed onto the stack.
   *
   * struct vmx_host_state_t also includes, for similar convenience reasons,
   * a pointer to the active VM's VM descriptor (i.e. a copy of
   * getCPUState()->active_vm), which we save there at this time.
   *
   *   NOTE: This is a rather large allocation to make on the stack, as it
   *   contains an entire 4 kB union xsave_area_max! Since (at least under
   *   Xen) SVA only has 8 kB of stack space to work with (which it shares
   *   with any Xen code preceding it on the call stack), this is something
   *   to be careful about.
   *
   *   Our analysis is that this should be safe here as the only entry point
   *   for this function is from sva_launch/resumevm(), which don't put much
   *   on the stack themselves; and they in turn are called by Xen in
   *   vmx_do_vmentry_sva(), which itself doesn't put much on the stack and
   *   is called fresh off a reset_stack_and_jump() (i.e. an empty stack).
   *
   *   If run_vm() calls itself recursively (e.g. to re-enter the guest after
   *   intercepting a VM exit which SVA handled without involving the
   *   hypervisor), care should be taken to make sure the recursive call is
   *   suitable for tail-call optimization (and that the compiler actually
   *   applies that optimization).
   */
  struct vmx_host_state_t host_state;
  host_state.active_vm = getCPUState()->active_vm;

  /*
   * Initialize the XSAVE area within host_state. This is necessary to
   * prevent #GP when we re-load from it after VM exit (as, apparently, using
   * XSAVES to previously save state to this area is not sufficient to
   * guarantee all its fields are appropriately initialized).
   */
  xinit(&host_state.fp.inner);

  /*
   * Load the VM's extended page table pointer (EPTP) from the VM descriptor.
   *
   * This is the extended-paging equivalent of the CR3 register used in
   * normal paging.
   *
   * We can use an unchecked write here because the sva_load_eptable()
   * intrinsic has already ensured that the EPTP in the VM descriptor points
   * to a valid top-level extended page table.
   */
  writevmcs_unchecked(VMCS_EPT_PTR, host_state.active_vm->eptp);

  /*
   * Save host state in the VMCS that will be restored automatically by the
   * processor on VM exit.
   */
#if 0
  DBGPRNT(("run_vm: Saving host state...\n"));
#endif

  vmcs_save_host_pt();

  /*
   * In a classic example of ISA-minimalism lawyering on Intel's part, they
   * decided to leave the GS Shadow register - by itself - to be manually
   * switched between host and guest values by the hypervisor on VM entry and
   * exit, despite the fact that *every other part* of the segment registers
   * (including the non-shadow `%gs.base`) corresponds to a field in the VMCS
   * and is switched automatically by the processor as part of VM entry/exit.
   *
   * NB: The host value of this field corresponds to the current thread's
   * `%gs.base` when in userspace. However, the SVA threads that Xen uses to
   * run VMs don't have a real userspace context to return to. Therefore, there
   * is no need to save the current host value.
   *
   * TODO: Require that each VM have its own SVA thread. This will allow us to
   * context-switch certain pieces of state rather than loading and saving them
   * on every entry/exit.
   */
  wrgsshadow(host_state.active_vm->state.gs_shadow);

  /*
   * We've now saved all the host state fields that the processor restores
   * atomically from the VMCS on VM exit. From here to VM entry, we save host
   * and restore guest state that the ISA leaves for the system software to
   * swap instead of handling atomically as part of entry/exit.
   */

  /*
   * Restore guest SYSCALL-handling MSRs. (Unlike the SYSENTER MSRs we just
   * dealt with above, the processor does *not* handle these atomically as
   * part of entry/exit. I'm sure somebody at Intel has a good reason for
   * that...)
   *
   * We do *not* need to save the host's values for these because SVA sets
   * them to constant values at boot and never changes them. On VM exit,
   * we'll simply restore them to those known values.
   *
   * (Note: we do not need to worry about CSTAR, as it's only relevant on AMD
   * platforms. Intel never supported the SYSCALL instruction in 32-bit mode.
   * Thus, we can get away with just leaving the host's value (0) in place at
   * all times. This is consistent with how Xen expects CSTAR to work: it
   * never actually changes CSTAR on the physical hardware, but since it
   * takes a VM exit on all guest RD/WRMSRs to it, it provides read/write
   * consistency by keeping track of what the guest thinks its value is in
   * its own data structures for that guest. Since this MSR has no side
   * effects on Intel hardware, the guest doesn't know the difference, but
   * Xen doesn't have to waste time context-switching it.)
   */
  wrmsr(MSR_FMASK, host_state.active_vm->state.msr_fmask);
  wrmsr(MSR_STAR, host_state.active_vm->state.msr_star);
  wrmsr(MSR_LSTAR, host_state.active_vm->state.msr_lstar);

  /*
   * Save the host FP state. Note that we must do this while the host XCR0 is
   * still active so that we are saving the correct state components.
   */
  xsave(&host_state.fp.inner);

  /*
   * TODO: save host MPX bounds registers. We must do this here while the
   * host XCR0 is active since MPX is controlled by XCR0 and the guest might
   * not have MPX enabled.
   *
   * For now we can get away without doing this since only SVA is using MPX
   * in host mode and we just unconditionally re-set the one bounds register
   * it cares about after exit.
   */

#ifdef MPX
  /*
   * Restore guest MPX bounds registers. We must do this while the *host's*
   * XCR0 is active since we need to save/restore these whether or not the
   * guest has MPX enabled, and the BNDMOV instruction will cause a #UD if
   * XCR0.MPX is not enabled.
   */
  asm __volatile__ (
      "bndmov %[guest_bnd0], %%bnd0\n"
      "bndmov %[guest_bnd1], %%bnd1\n"
      "bndmov %[guest_bnd2], %%bnd2\n"
      "bndmov %[guest_bnd3], %%bnd3\n"
      : /* no outputs */
      : [guest_bnd0] "m" (host_state.active_vm->state.bnd0),
        [guest_bnd1] "m" (host_state.active_vm->state.bnd1),
        [guest_bnd2] "m" (host_state.active_vm->state.bnd2),
        [guest_bnd3] "m" (host_state.active_vm->state.bnd3)
      );
#endif /* end #ifdef MPX */

  /* Save host Extended Control Register 0 (XCR0) */
#if 0
  DBGPRNT(("Saving host XCR0...\n"));
#endif
  host_state.xcr0 = xgetbv();
#if 0
  DBGPRNT(("Host XCR0 saved: 0x%lx\n", host_state.xcr0));
#endif

  /*
   * Load guest XCR0.
   *
   * The processor doesn't support saving/loading this atomically during VM
   * entry/exit, so we have to load this in host mode before VM entry. That
   * means there's a small window of opportunity (between now and VM entry)
   * wherein it will govern host execution, so we need to be careful that
   * this won't let the system software do something that wouldn't otherwise
   * be allowed.
   *
   * In this case, I think it's safe to load any value into XCR0, because
   * we're not using any XSAVE-related instructions between here and VM entry
   * (except for loading/saving the guest's FPU state). The worst that could
   * happen is we get a #GP exception if one of the reserved bits is
   * set...and if that happens it's the system software's fault. (A crash
   * isn't a security violation because there are a thousand ways the system
   * software is free to crash the system if it so desires.)
   */
#if 0
  DBGPRNT(("Loading guest XCR0 = 0x%lx...\n",
        host_state.active_vm->state.xcr0));
#endif
  xsetbv((uint32_t) host_state.active_vm->state.xcr0);

  /*
   * Load guest XSS MSR.
   *
   * This is the counterpart of XCR0 which controls the subset of extended
   * state components which are accessible only in supervisor mode. At
   * present (2020-10-20), there is only one such feature in the ISA ("Trace
   * Packet Configuration State"), which neither Xen nor SVA cares about
   * using in host (VMX root) mode; but Xen supports the use of XSS features
   * by guests, so we need to context-switch it for guests' benefit.
   *
   * This needs to happen at the same point in the FPU save/restore logic
   * flow as loading of XSAVE, since the combination of the two (XCR0 |
   * XSAVE) controls the selection of state components that are
   * saved/restored by the XSAVES/XRSTORS instructions.
   *
   * We do *not* need to save the host's value of this MSR since we know it
   * should always be 0.
   */
  wrmsr(MSR_XSS, host_state.active_vm->state.msr_xss);

  /*
   * Restore guest FP state. Since the guest's XCR0 is now active, this will
   * restore exactly the set of X-state components which were saved on the
   * last VM exit.
   *
   * FIXME: we should really be saving/restoring guest state in a way that
   * includes *all* live X-state components, even the ones that the guest may
   * not currently have enabled in XCR0. This is necessary to ensure
   * continuity of FPU state for the guest as guaranteed by the ISA, which
   * specifies that state corresponding to features disabled in XCR0 remain
   * untouched unless and until they are re-enabled. Currently, we are only
   * saving the state components *currently* enabled by the guest, which
   * means any disabled ones could get clobbered by the host or other guests.
   *
   * More importantly, this could be a **SECURITY ISSUE** since it could
   * result in X-state data leaking from the host or one guest to another. If
   * the guest doesn't have a feature enabled on VM entry, whatever state was
   * in place for that feature from the host or another guest remains
   * untouched. The guest could read that data by enabling that feature. (It
   * shouldn't be possible for any guest to *corrupt* the host's or another
   * guest's X-state, though, except of course if that feature is currently
   * disabled by the host or other VM, which we already covered above in the
   * discussion of the "clobbering" issue.)
   *
   * Probably the correct behavior here is to just unconditionally
   * save/restore *all* X-state components supported by the processor on
   * every entry and exit. This could be achieved by temporarily loading a
   * "maxed-out" XCR0|XSS value. (Doing so would probably require
   * enumeration of the processor's supported features to avoid triggering a
   * fault by setting too many bits. Or we might just hardcode it to match
   * what our development hardware supports...)
   */
  xrestore(&host_state.active_vm->state.fp.inner);

#if 0
  DBGPRNT(("VM ENTRY: Entering guest mode!\n"));
#endif
  uint64_t vmexit_rflags = asm_run_vm(&host_state, use_vmresume);

  /*
   * Save guest FPU state. This must be done while the guest's XCR0 is still
   * active to ensure we are saving the correct set of X-state components.
   *
   * FIXME: as detailed above where we're loading this prior to entry, we are
   * not correctly handling state components corresponding to X-features that
   * the guest currently has *disabled* (which, per the ISA, should remain
   * intact until the guest might again re-enable them).
   *
   * NB: FPU was re-enabled by our seting of `VMCS_HOST_CR0`.
   */
  /* Save guest FPU state. */
  xsave(&host_state.active_vm->state.fp.inner);

  /* Save guest XCR0 and XSS values. */
  host_state.active_vm->state.xcr0 = xgetbv();
  host_state.active_vm->state.msr_xss = rdmsr(MSR_XSS);

  /* Restore host value of XCR0, and clear XSS to 0. */
  xsetbv(host_state.xcr0);
  wrmsr(MSR_XSS, 0);

  /* Restore host FPU state. */
  xrestore(&host_state.fp.inner);

#ifdef MPX
  /*
   * Save guest MPX bounds registers. Note, as above when we restored them
   * before entry, that we must do this while the *host's* XCR0 is active
   * since we need to save/restore these whether or not the guest has MPX
   * enabled, and the BNDMOV instruction will cause a #UD if XCR0.MPX is not
   * enabled.
   */
  asm __volatile__ (
      "bndmov %%bnd0, %[guest_bnd0]\n"
      "bndmov %%bnd1, %[guest_bnd1]\n"
      "bndmov %%bnd2, %[guest_bnd2]\n"
      "bndmov %%bnd3, %[guest_bnd3]\n"
      : [guest_bnd0] "=m" (host_state.active_vm->state.bnd0),
        [guest_bnd1] "=m" (host_state.active_vm->state.bnd1),
        [guest_bnd2] "=m" (host_state.active_vm->state.bnd2),
        [guest_bnd3] "=m" (host_state.active_vm->state.bnd3)
      );

  /*
   * Save guest's MPX supervisor-mode configuration register (the MSR
   * IA32_BNDCFGS).
   *
   * This piece of state is unusual in that it is VMCS-resident but only
   * partially managed automatically by the processor on VM entry/exit.  It
   * is loaded from the VMCS on VM entry (if the hypervisor chooses to enable
   * the "Load IA32_BNDCFGS" VM-entry control), and can be cleared on VM exit
   * for the host's benefit (if the hypervisor chooses to enable the "Clear
   * IA32_BNDCFGS" VM-exit control), but there is no corresponding way to
   * *save* the guest's value on exit. Basically, a "Save IA32_BNDCFGS"
   * VM-exit control is conspicuously absent.
   *
   * Thus, we need to save the value ourselves on VM exit, although we don't
   * need to load it on VM entry. We store it to the VMCS instead of to our
   * own guest state structure.
   *
   * Note: SVA does not require the hypervisor to use (or not use) either the
   * "Load IA32_BNDCFGS" VM-entry control or the "Clear IA32_BNDCFGS" VM-exit
   * control. If the former is unused, the host's value of BNDCFGS will be
   * retained by the guest, which is fine from a security perspective because
   * it contains no sensitive information (only the BNDENABLE and BNDPRESERVE
   * bits are set). The latter doesn't matter because SVA always reloads its
   * own value into BNDCFGS after VM exit (see below), so it doesn't matter
   * whether the hypervisor leaves the guest's value there or clears it on VM
   * exit.
   */
  uint64_t guest_bndcfgs = rdmsr(MSR_IA32_BNDCFGS);
  /*
   * Unchecked write is OK since we know this value was just in use by the
   * guest.
   */
  writevmcs_unchecked(VMCS_GUEST_IA32_BNDCFGS, guest_bndcfgs);

  /*
   * Restore MPX supervisor-mode configuration and bounds register 0 to the
   * values used by SVA to implement its SFI.
   *
   * We don't need to clear/change the other bounds registers since SVA
   * doesn't use them.
   */
  wrmsr(MSR_IA32_BNDCFGS, BNDCFG_BNDENABLE | BNDCFG_BNDPRESERVE);

  mpx_bnd_init();
#endif /* end #ifdef MPX */

  /* Save guest SYSCALL-handling MSRs. */
  host_state.active_vm->state.msr_fmask = rdmsr(MSR_FMASK);
  host_state.active_vm->state.msr_star = rdmsr(MSR_STAR);
  host_state.active_vm->state.msr_lstar = rdmsr(MSR_LSTAR);

  /*
   * Restore host SYSCALL-handling MSRs.
   *
   * TODO: save the guest values somewhere and restore them before entry.
   * Will need to extend interfaces to allow hypervisor to initialize/get/set
   * these values. Long-term we want to create a general interface for VMX's
   * MSR save/load feature, which can handle these and (most) any other MSRs
   * SVA or Xen might care about; but we may be able to move more quickly by
   * initially handling these MSRs ad-hoc as additions to the guest's
   * SVA-managed "register" state.
   *
   * (If we end up using the MSR save/load feature for these, we shouldn't
   * need to call register_syscall_handler() any more since that'll just
   * automatically save/restore the correct values.)
   *
   * register_syscall_handler() sets the following MSRs to the values
   * required for SVA to mediate syscall handling:
   *  * MSR_FMASK = IF | IOPL(3) | AC | DF | NT | VM | TF | RF
   *  * MSR_STAR = GSEL(GCODE_SEL, 0) for SYSCALL; SVA_USER_CS_32 for SYSRET
   *  * MSR_LSTAR = &SVAsyscall
   *  * MSR_CSTAR = NULL (we don't handle SYSCALL from 32-bit code; this is
   *                     actually superfluous on Intel hardware as 32-bit
   *                     SYSCALL support was only ever provided by AMD, but
   *                     we set this anyway in register_syscall_handler()
   *                     since that part of SVA, unlike the VMX stuff here,
   *                     is at least in theory Intel/AMD-agnostic)
   * SVA does not support the SYSENTER mechanism, so we set its MSRs to 0:
   *  * MSR_IA32_SYSENTER_CS = 0
   *  * MSR_IA32_SYSENTER_EIP = 0
   *  * MSR_IA32_SYSENTER_ESP = 0
   *
   * FIXME: restoring the SYSENTER MSRs here like this is redundant, since
   * they are actually restored atomically by the CPU as part of VM exit. (We
   * saved them to the VMCS above before VM entry for this reason.) If we
   * want to optimize things and avoid doing three superfluous WRMSRs on the
   * VM-exit critical performance path, we could either copy the four
   * SYSCALL-specific lines here from register_syscall_handler(), or, if we
   * want to avoid duplicating code with "magic values" like this (that being
   * bad software engineering practice), we could factor them out into an
   * inline function called both here and in register_syscall_handler(). We
   * can also safely skip resetting CSTAR when restoring (as opposed to
   * initializing on boot) these MSRs.
   */
  register_syscall_handler();

  /*
   * Save the guest's shadow `%gs.base`.
   */
  host_state.active_vm->state.gs_shadow = rdgsshadow();

  /* Confirm that the operation succeeded. */
  enum vmx_statuscode_t result = query_vmx_result(vmexit_rflags);
  if (result == VM_SUCCEED) {
#if 0
    DBGPRNT(("VM EXIT: returned to host mode.\n"));
#endif

#if 0
    DBGPRNT(("--------------------\n"));
    DBGPRNT(("Host GPR values restored:\n"));
    DBGPRNT(("RBP: 0x%16lx\tRSI: 0x%16lx\tRDI: 0x%16lx\n",
          host_state.rbp, host_state.rsi, host_state.rdi));
    DBGPRNT(("R8:  0x%16lx\tR9:  0x%16lx\tR10: 0x%16lx\tR11: 0x%16lx\n",
          host_state.r8, host_state.r9, host_state.r10, host_state.r11));
    DBGPRNT(("R12: 0x%16lx\tR13: 0x%16lx\tR14: 0x%16lx\tR15: 0x%16lx\n",
          host_state.r12, host_state.r13, host_state.r14, host_state.r15));
    DBGPRNT(("RFLAGS restored: 0x%lx\n", hostrestored_rflags));
    DBGPRNT(("--------------------\n"));
#endif

    /*
     * Check if the exit needs special handling.
     */
    if (vmexit_handler()) {
      /*
       * SVA was able to handle the exit by itself.
       */
      use_vmresume = true;

      /*
       * I wish C had proper tail calls.
       */
      goto entry;
    } else {
      /* Return success. */
      return 0;
    }
  } else if (result == VM_FAIL_VALID) {
    DBGPRNT(("Error: VM entry failed! See VM-instruction error field in "
          "VMCS for more details.\n"));

    /* Return failure. */
    return -1;
  } else if (result == VM_FAIL_INVALID) {
    /* This should not happen. VM_FAIL_INVALID means we tried to execute
     * "vmlaunch" or "vmresume" without a valid VMCS loaded on the processor.
     * Since we checked that there was an active VM above, this indicates a
     * flaw in the implementation of our intrinsics.
     */
    panic("Fatal error: SVA thought a VM was loaded on the processor, but "
        "the 'vmlaunch'/'vmresume' instruction returned the VM_FAIL_INVALID "
        "status, which means there is not a valid VM loaded. Something has "
        "gone terribly wrong.\n");

    return -1; /* Will never execute, but the compiler will warn without it. */
  } else {
    /* This should be another impossible case. It means that the value of
     * RFLAGS after executing "vmlaunch" doesn't correspond to any of the VMX
     * result codes listed in the Intel manual.
     */
    panic("Fatal error: the 'vmlaunch'/'vmresume' instruction left RFLAGS "
        "in a configuration that doesn't match any of the VMX result codes "
        "documented by Intel. Something has gone terribly wrong.\n");

    return -1; /* Will never execute, but the compiler will warn without it. */
  }
}

/*
 * Function: readvmcs_checked()
 *
 * Description:
 *  A local helper function which centralizes checks/vetting for VMCS field
 *  reads.
 *
 *  Ensures that the read does not leak sensitive information to untrusted
 *  system software. Unsafe reads are either rejected outright (with a kernel
 *  panic or by returning an error code), or sanitized.
 *
 * Arguments:
 *  Same as sva_readvmcs().
 *
 * Return value:
 *  Same as sva_readvmcs().
 *
 * Preconditions:
 *  - There must be a VMCS loaded on the processor.
 */
static inline int
readvmcs_checked(enum sva_vmcs_field field, uint64_t *data) {
  /*
   * If the field does not contain sensitive information, pass it directly
   * through to the caller.
   *
   * Otherwise, sanitize the read value or reject the read.
   */
  bool is_safe = true;
  switch (field) {
    /*
     * These VMCS controls are safe to read unconditionally.
     *
     * (This is not an exhaustive list of safe fields. We've only added the
     * ones that we've actually needed thusfar for our toy hypervisor.)
     */
    case VMCS_VM_ENTRY_CTRLS:
    case VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD:
    case VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE:
    case VMCS_EXCEPTION_BITMAP:
    case VMCS_PAGE_FAULT_ERROR_CODE_MASK:
    case VMCS_PAGE_FAULT_ERROR_CODE_MATCH:
    case VMCS_GUEST_RIP:
    case VMCS_GUEST_RSP:
    case VMCS_GUEST_RFLAGS:
    case VMCS_GUEST_CR0:
    case VMCS_GUEST_CR4:
    case VMCS_CR0_GUESTHOST_MASK:
    case VMCS_CR4_GUESTHOST_MASK:
    case VMCS_CR0_READ_SHADOW:
    case VMCS_CR4_READ_SHADOW:
    case VMCS_GUEST_DR7:
    case VMCS_GUEST_IA32_DEBUGCTL:
    case VMCS_GUEST_CR3:
    case VMCS_GUEST_PDPTE0:
    case VMCS_GUEST_PDPTE1:
    case VMCS_GUEST_PDPTE2:
    case VMCS_GUEST_PDPTE3:
    case VMCS_GUEST_IA32_PAT:
    case VMCS_GUEST_IA32_EFER:
    case VMCS_GUEST_IA32_SYSENTER_CS:
    case VMCS_GUEST_IA32_SYSENTER_ESP:
    case VMCS_GUEST_IA32_SYSENTER_EIP:
#ifdef MPX
    case VMCS_GUEST_IA32_BNDCFGS:
#endif
    case VMCS_GUEST_CS_SEL:
    case VMCS_GUEST_CS_BASE:
    case VMCS_GUEST_CS_LIMIT:
    case VMCS_GUEST_CS_ACCESS_RIGHTS:
    case VMCS_GUEST_SS_SEL:
    case VMCS_GUEST_SS_BASE:
    case VMCS_GUEST_SS_LIMIT:
    case VMCS_GUEST_SS_ACCESS_RIGHTS:
    case VMCS_GUEST_DS_SEL:
    case VMCS_GUEST_DS_BASE:
    case VMCS_GUEST_DS_LIMIT:
    case VMCS_GUEST_DS_ACCESS_RIGHTS:
    case VMCS_GUEST_ES_SEL:
    case VMCS_GUEST_ES_BASE:
    case VMCS_GUEST_ES_LIMIT:
    case VMCS_GUEST_ES_ACCESS_RIGHTS:
    case VMCS_GUEST_FS_SEL:
    case VMCS_GUEST_FS_BASE:
    case VMCS_GUEST_FS_LIMIT:
    case VMCS_GUEST_FS_ACCESS_RIGHTS:
    case VMCS_GUEST_GS_SEL:
    case VMCS_GUEST_GS_BASE:
    case VMCS_GUEST_GS_LIMIT:
    case VMCS_GUEST_GS_ACCESS_RIGHTS:
    case VMCS_GUEST_TR_SEL:
    case VMCS_GUEST_TR_BASE:
    case VMCS_GUEST_TR_LIMIT:
    case VMCS_GUEST_TR_ACCESS_RIGHTS:
    case VMCS_GUEST_GDTR_BASE:
    case VMCS_GUEST_GDTR_LIMIT:
    case VMCS_GUEST_IDTR_BASE:
    case VMCS_GUEST_IDTR_LIMIT:
    case VMCS_GUEST_LDTR_SEL:
    case VMCS_GUEST_LDTR_BASE:
    case VMCS_GUEST_LDTR_LIMIT:
    case VMCS_GUEST_LDTR_ACCESS_RIGHTS:
    case VMCS_GUEST_ACTIVITY_STATE:
    case VMCS_GUEST_INTERRUPTIBILITY_STATE:
    case VMCS_GUEST_PENDING_DBG_EXCEPTIONS:
    case VMCS_VM_EXIT_REASON:
    case VMCS_EXIT_QUAL:
    case VMCS_GUEST_LINEAR_ADDR:
    case VMCS_GUEST_PHYS_ADDR:
    case VMCS_VM_EXIT_INTERRUPTION_INFO:
    case VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE:
    case VMCS_IDT_VECTORING_INFO_FIELD:
    case VMCS_IDT_VECTORING_ERROR_CODE:
    case VMCS_VM_EXIT_INSTR_LENGTH:
    case VMCS_VM_EXIT_INSTR_INFO:
    case VMCS_VM_INSTR_ERROR:
    case VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:
    case VMCS_PLE_GAP:
    case VMCS_PLE_WINDOW:
    case VMCS_TSC_OFFSET:
    case VMCS_TSC_MULTIPLIER:
    case VMCS_GUEST_INTERRUPT_STATUS:
    case VMCS_EOI_EXIT_BITMAP_0:
    case VMCS_EOI_EXIT_BITMAP_1:
    case VMCS_EOI_EXIT_BITMAP_2:
    case VMCS_EOI_EXIT_BITMAP_3:
    case VMCS_TPR_THRESHOLD:
    case VMCS_XSS_EXITING_BITMAP:
      is_safe = true;
      break;

    default:
      is_safe = false;
      printf("SVA: Disallowed read to VMCS field not on read whitelist: 0x%x (", field);
      print_vmcs_field_name(field, true);
      printf(").\n");
      break;
  }

#ifdef XEN
#if 0
  /*
   * DEBUG CODE: Log this VMCS read so that we can determine which VMCS
   * fields Xen needs us to support.
   */
  extern void log_vmcs_read(enum sva_vmcs_field, bool passed_checks);
  log_vmcs_read(field, is_safe);
#endif
#endif /* end #ifdef XEN */

  if (is_safe)
    return readvmcs_unchecked(field, data);
  else {
    /* Note: field and value already printed above, since currently we
     * don't need to perform any checking/filtering of VMCS reads besides
     * checking whether the field is on the whitelist. */
    panic("SVA: VMCS checks in hard-fail mode; shutting down system.\n");
  }
}

/*
 * Function: readvmcs_unchecked()
 *
 * Description:
 *  A local helper that directly performs a VMCS field read on the hardware.
 *  No checks are performed.
 *
 *  To be used internally by SVA (e.g., by readvmcs_checked() after it has
 *  vetted the read).
 *
 * Preconditions:
 *  Same as readvmcs_checked(), plus:
 *
 *  - The read must not leak sensitive information to the system software.
 */
static inline int
readvmcs_unchecked(enum sva_vmcs_field field, uint64_t *data) {
  uint64_t rflags;
  asm __volatile__ (
      "vmread %%rax, %%rbx\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags), "=b" (*data)
      : "a" (field)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  enum vmx_statuscode_t result = query_vmx_result(rflags);
  if (result == VM_SUCCEED) {
    /* Return success. */
    return 0;
  } else if (result == VM_FAIL_INVALID) {
    /*
     * Indicates that the VMREAD failed due to no VMCS being currently loaded
     * on the processor. Shouldn't happen if the caller is sva_readvmcs(),
     * since it is supposed to ensure that a VMCS is loaded before calling
     * this. (Can happen if SVA is doing a read internally, though.)
     */
    DBGPRNT(("SVA: Error: readvmcs_unchecked() failed due to no VMCS "
             "being loaded. (ISA condition VMfailInvalid)\n"));
    return -1;
  } else if (result == VM_FAIL_VALID) {
    /*
     * Indicates that the VMREAD failed due to the specified VMCS field being
     * invalid (nonexistent). Shouldn't happen if the caller is
     * sva_readvmcs(), unless we accidentally allowed a nonexistent field
     * onto the read whitelist.
     */
    DBGPRNT(("SVA: Error: readvmcs_unchecked() failed due to invalid VMCS "
             "field being specified. (ISA condition VMfailValid)\n"));
    return -2;
  } else {
    panic("SVA: Error: Got nonsensical result (%d) from "
          "query_vmx_result()!\n", (int)result);
  }
}

/*
 * Function: writevmcs_checked()
 *
 * Description:
 *  A local helper function which centralizes checks/vetting for VMCS field
 *  writes.
 *
 *  Verifies that the write can be permitted without compromising the
 *  integrity of SVA's guarantees; if so, performs the VMCS write. Otherwise,
 *  the write is rejected or (if feasible) modified to bring it into line
 *  with security policies.
 *
 *  Rejected writes will either result in a kernel panic or cause a failure
 *  (negative) error code to be returned.
 *
 * Arguments:
 *  Same as sva_writevmcs().
 *
 * Return value:
 *  Same as sva_writevmcs().
 *
 * Preconditions:
 *  - There must be a VMCS loaded and active on the processor.
 */
static inline int
writevmcs_checked(enum sva_vmcs_field field, uint64_t data) {
  /*
   * If the field is harmless, write it directly.
   *
   * Otherwise, modify the write to render it harmless (if we can), or reject
   * it.
   */
  bool is_safe = false;
  switch (field) {
    case VMCS_PINBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_pinbased_vm_exec_ctrls ctrls;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = (uint32_t) data;

        /* Override bits controlled by Shade intrinsics */
        ctrls.process_posted_ints =
          getCPUState()->active_vm->vlapic.posted_interrupts_enabled;

        /* Apply overrides to data that will be written */
        data = (uint64_t) *ctrls_u32;

        /* Check remaining bit settings */
        is_safe =
          /*
           * SVA needs first crack at all interrupts.
           *
           * TODO: Some interrupts are probably safe to pass through, and
           * should be for reasonable guest performance (e.g. the timer
           * interrupt). If we encounter performance issues we should look
           * into the interrupt-virtualization features provided by VMX.
           */
          ctrls.ext_int_exiting &&

          /* Likewise for NMIs. */
          ctrls.nmi_exiting &&

          /*
           * VMX preemption timer must be enabled to prevent the guest from
           * tying up system resources indefinitely.
           */
#if 0 /* our toy hypervisor doesn't know how to use the preemption timer yet */
          ctrls.activate_vmx_preempt_timer &&
#endif

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           */
          (ctrls.reserved1_2 == 0x3) &&
          ctrls.reserved4 &&
          (ctrls.reserved8_31 == 0x0);

        break;
      }
    case VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_primary_procbased_vm_exec_ctrls ctrls;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = (uint32_t) data;

        /* Override bits controlled by Shade intrinsics */
        ctrls.cr8_load_exiting =
          getCPUState()->active_vm->vlapic.mode == VLAPIC_OFF;
        ctrls.cr8_store_exiting =
          getCPUState()->active_vm->vlapic.mode == VLAPIC_OFF;
        ctrls.use_tpr_shadow =
          getCPUState()->active_vm->vlapic.mode != VLAPIC_OFF;

        /* Apply overrides to data that will be written */
        data = (uint64_t) *ctrls_u32;

        /* Check remaining bit settings */
        is_safe =
          /*
           * N.B.: We do not, at present, need to restrict the settings of
           * the "unconditional I/O exiting" or "use I/O bitmaps" controls.
           *
           * This is because:
           *  a) Unconditional I/O exiting is always safe from SVA's
           *     perspective;
           *  b) SVA owns the I/O bitmap pages, and sets them up safely when
           *     creating a new VM in sva_allocvm(); and
           *  c) We don't, at present, actually restrict any particular I/O
           *     ports' intercepts from being cleared (see
           *     sva_vmx_io_intercept_clear()). Thus the hypervisor could, in
           *     principle, clear *all* of the intercepts, which is
           *     functionally equivalent to disabling both unconditional I/O
           *     exiting and I/O bitmaps.
           *
           * Note that this will no longer be true if, in the future, we
           * decide to start restricting the clearing of I/O intercepts on a
           * per-port basis (as we do with the MSR bitmaps). If we do that,
           * then we will need to add a check here to require that *either*
           * unconditional I/O exiting *or* I/O bitmaps be enabled. (If
           * bitmaps are enabled, the processor will ignore the
           * unconditional-exiting control bit.)
           */

          /*
           * N.B.: As with I/O exiting (see above), we do not need to
           * restrict the setting of the "use MSR bitmaps" control - but for
           * a slightly different reason. Unlike with I/O exiting, there is
           * no control for disabling RD/WRMSR exiting except by using the
           * bitmaps to do so on a per-MSR basis. Therefore, even though we
           * do restrict the clearing of certain MSR intercepts in
           * sva_vmx_msr_intercept_clear(), it is safe to permit the
           * hypervisor to enable or disable MSR bitmaps as it chooses -
           * because the result will be safe either way. If bitmaps are
           * disabled, all guest RD/WRMSR instances will cause exits, which
           * is always safe. If bitmaps are enabled, the hypervisor will have
           * to go through our intrinsics to configure the bitmaps (since we
           * own the bitmap page), so we can prevent it from clearing
           * intercepts for sensitive MSRs.
           */

          /*
           * We must activate the secondary controls because SVA requires
           * some of the features they control (e.g., EPT).
           */
          ctrls.activate_secondary_ctrls &&

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           */
          (ctrls.reserved0_1 == 0x2) &&
          (ctrls.reserved4_6 == 0x7) &&
          ctrls.reserved8 &&
          (ctrls.reserved13_14 == 0x3) &&
          (ctrls.reserved17_18 == 0x0) &&
          ctrls.reserved26;

        break;
      }
    case VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_secondary_procbased_vm_exec_ctrls ctrls;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = (uint32_t) data;

        /* Override bits controlled by Shade intrinsics */
        ctrls.virtualize_apic_accesses =
          getCPUState()->active_vm->vlapic.mode == VLAPIC_APIC;
        ctrls.virtualize_x2apic_mode =
          getCPUState()->active_vm->vlapic.mode == VLAPIC_X2APIC;
        ctrls.apic_register_virtualization =
          getCPUState()->active_vm->vlapic.mode != VLAPIC_OFF;
        ctrls.virtual_int_delivery =
          getCPUState()->active_vm->vlapic.posted_interrupts_enabled;

        /* Apply overrides to data that will be written */
        data = (uint64_t) *ctrls_u32;

        /* Check remaining bit settings */
        is_safe =
          /*
           * SVA requires the use of extended page tables (EPT) for guest
           * memory management.
           *
           * While it might be theoretically possible for SVA to support
           * non-EPT scenarios, guest memory management without EPT is a
           * royal hack and would be a lot of work to support. It's largely
           * irrelevant today because VMX-capable hardware has supported EPT
           * for almost a decade.
           *
           * In particular, BHyVe makes the same choice we do to require EPT
           * as a design decision.
           */
          ctrls.enable_ept &&

          /*
           * SVA requires the use of VPIDs (Virtual Processor IDs) to manage
           * TLB entries for both guest-virtual and EPT mappings.
           *
           * Non-VPID scenarios wouldn't be hard to support but it simplifies
           * our prototype to just assume it's enabled. VPID is a significant
           * performance improvement (as it avoids the need to do a global
           * TLB flush on VM entry and exit) so there's no reason that we
           * wouldn't want to use it on a processor that supports it.
           *
           * SVA manages the VPID feature itself (SVA's vmid is used as the
           * VPID) since it would be security-sensitive if they got mixed up
           * (because that could allow cached translations from guest
           * environments to be used by host code).
           */
          ctrls.enable_vpid &&

          /* VM functions not currently supported by SVA */
          !ctrls.enable_vmfunc &&

          /* VMCS shadowing not currently supported by SVA */
          !ctrls.vmcs_shadowing &&

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           *
           * All reserved bits are reserved to 0 in this field.
           */
          !ctrls.reserved21 &&
          (ctrls.reserved23_24 == 0x0) &&
          (ctrls.reserved26_31 == 0x0);

        break;
      }
    case VMCS_VM_EXIT_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_vm_exit_ctrls ctrls;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = (uint32_t) data;

        /* Check bit settings */
        is_safe =
          /*
           * SVA/FreeBSD operates in 64-bit mode, so we must always return to
           * that on VM exit.
           */
          ctrls.host_addr_space_size &&

          /*
           * We rely on these controls to re-load the host's PAT and EFER
           * values on VM exit.
           *
           * The hypervisor is free to set or not set the corresponding
           * "save" controls depending on whether it cares to save the
           * guest's values on exit.
           */
          ctrls.load_ia32_pat &&
          ctrls.load_ia32_efer &&

          /*
           * Note: it is safe to allow the hypervisor to have discretion over
           * the clear_ia32_bndcfgs control.
           *
           * If SVA is using MPX for its SFI, it will restore BNDCFGS to the
           * value desired by SVA on every VM exit. Our VM entry/exit
           * assembly code in run_vm() doesn't perform any MPX bounds checks
           * between VM exit and restoring SVA's value of BNDCFGS, so there
           * is no need to have the CPU explicitly clear it on VM exit.
           */

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           */
          (ctrls.reserved0_1 == 0x3) &&
          (ctrls.reserved3_8 == 0x3f) &&
          (ctrls.reserved10_11 == 0x3) &&
          (ctrls.reserved13_14 == 0x3) &&
          (ctrls.reserved16_17 == 0x3) &&
          (ctrls.reserved25_31 == 0x0);

        break;
      }
    case VMCS_VM_ENTRY_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_vm_entry_ctrls ctrls;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = (uint32_t) data;

        /* Check bit settings */
        is_safe =
          /*
           * We do not support SMM (either on the host or in VMs).
           *
           * Intel requires that both of these controls be set to 0 for any
           * VM entry from outside SMM.
           */
          !ctrls.entry_to_smm &&
          !ctrls.deact_dual_mon_treatment &&

          /*
           * Note: it is safe to allow the hypervisor to have discretion over
           * the load_ia32_bndcfgs control, regardless of whether SVA is
           * compiled with MPX support.
           *
           * If SVA is using MPX for its SFI, BNDCFGS contains the base
           * address and size of the kernel. Although the kernel might
           * consider its base address security-sensitive (due to ASLR) and
           * not want to disclose it to a VM, that is the kernel's problem,
           * not SVA's, and it is free to set the load_ia32_bndcfgs control
           * to 1 to provide that protection.
           *
           * If SVA is not using MPX, then SVA is storing no sensitive
           * information in BNDCFGS, so we don't really care what the
           * hypervisor does with it. It's worth noting that when SVA isn't
           * compiled with MPX support, it doesn't attempt to save/load MPX
           * bounds registers on VM entry/exit; since SVA doesn't provide
           * intrinsics that would allow a hypervisor to do so on its own, it
           * would be impossible for a hypervisor to maintain a consistent
           * MPX state between different guests. (OK, maybe not completely
           * impossible - the hypervisor could create its own VM and use that
           * to do the saving/restoring without intrinsic support - but that
           * would be crazy. :-)) Long story short, if the hypervisor wants
           * to use MPX, you should just compile SVA with MPX support. It'll
           * make SVA faster anyway. :-)
           */

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           */
          (ctrls.reserved0_1 == 0x3) &&
          (ctrls.reserved3_8 == 0x3f) &&
          ctrls.reserved12 &&
          (ctrls.reserved18_31 == 0x0);

        break;
      }

    /*
     * These VMCS controls are safe to write unconditionally.
     *
     * (This is not an exhaustive list of safe fields. We've only added the
     * ones that we've actually needed thusfar for our toy hypervisor.)
     */
    case VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD:
    case VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE:
    case VMCS_EXCEPTION_BITMAP:
    case VMCS_PAGE_FAULT_ERROR_CODE_MASK:
    case VMCS_PAGE_FAULT_ERROR_CODE_MATCH:
    case VMCS_GUEST_RIP:
    case VMCS_GUEST_RSP:
    case VMCS_GUEST_RFLAGS:
    case VMCS_GUEST_CR0:
    case VMCS_GUEST_CR4:
    case VMCS_CR0_GUESTHOST_MASK:
    case VMCS_CR4_GUESTHOST_MASK:
    case VMCS_CR0_READ_SHADOW:
    case VMCS_CR4_READ_SHADOW:
    case VMCS_GUEST_DR7:
    case VMCS_GUEST_IA32_DEBUGCTL:
    case VMCS_GUEST_CR3:
    case VMCS_GUEST_PDPTE0:
    case VMCS_GUEST_PDPTE1:
    case VMCS_GUEST_PDPTE2:
    case VMCS_GUEST_PDPTE3:
    case VMCS_GUEST_IA32_PAT:
    case VMCS_GUEST_IA32_EFER:
    case VMCS_GUEST_IA32_SYSENTER_CS:
    case VMCS_GUEST_IA32_SYSENTER_ESP:
    case VMCS_GUEST_IA32_SYSENTER_EIP:
#ifdef MPX
    case VMCS_GUEST_IA32_BNDCFGS:
#endif
    case VMCS_GUEST_CS_SEL:
    case VMCS_GUEST_CS_BASE:
    case VMCS_GUEST_CS_LIMIT:
    case VMCS_GUEST_CS_ACCESS_RIGHTS:
    case VMCS_GUEST_SS_SEL:
    case VMCS_GUEST_SS_BASE:
    case VMCS_GUEST_SS_LIMIT:
    case VMCS_GUEST_SS_ACCESS_RIGHTS:
    case VMCS_GUEST_DS_SEL:
    case VMCS_GUEST_DS_BASE:
    case VMCS_GUEST_DS_LIMIT:
    case VMCS_GUEST_DS_ACCESS_RIGHTS:
    case VMCS_GUEST_ES_SEL:
    case VMCS_GUEST_ES_BASE:
    case VMCS_GUEST_ES_LIMIT:
    case VMCS_GUEST_ES_ACCESS_RIGHTS:
    case VMCS_GUEST_FS_SEL:
    case VMCS_GUEST_FS_BASE:
    case VMCS_GUEST_FS_LIMIT:
    case VMCS_GUEST_FS_ACCESS_RIGHTS:
    case VMCS_GUEST_GS_SEL:
    case VMCS_GUEST_GS_BASE:
    case VMCS_GUEST_GS_LIMIT:
    case VMCS_GUEST_GS_ACCESS_RIGHTS:
    case VMCS_GUEST_TR_SEL:
    case VMCS_GUEST_TR_BASE:
    case VMCS_GUEST_TR_LIMIT:
    case VMCS_GUEST_TR_ACCESS_RIGHTS:
    case VMCS_GUEST_GDTR_BASE:
    case VMCS_GUEST_GDTR_LIMIT:
    case VMCS_GUEST_IDTR_BASE:
    case VMCS_GUEST_IDTR_LIMIT:
    case VMCS_GUEST_LDTR_SEL:
    case VMCS_GUEST_LDTR_BASE:
    case VMCS_GUEST_LDTR_LIMIT:
    case VMCS_GUEST_LDTR_ACCESS_RIGHTS:
    case VMCS_GUEST_ACTIVITY_STATE:
    case VMCS_GUEST_INTERRUPTIBILITY_STATE:
    case VMCS_GUEST_PENDING_DBG_EXCEPTIONS:
    case VMCS_PLE_GAP:
    case VMCS_PLE_WINDOW:
    case VMCS_TSC_OFFSET:
    case VMCS_TSC_MULTIPLIER:
    case VMCS_GUEST_INTERRUPT_STATUS:
    case VMCS_EOI_EXIT_BITMAP_0:
    case VMCS_EOI_EXIT_BITMAP_1:
    case VMCS_EOI_EXIT_BITMAP_2:
    case VMCS_EOI_EXIT_BITMAP_3:
    case VMCS_TPR_THRESHOLD:
    case VMCS_XSS_EXITING_BITMAP:
      is_safe = true;
      break;

    default:
      is_safe = false;
      printf("SVA: Disallowed write to VMCS field not on write whitelist: 0x%x (", field);
      print_vmcs_field_name(field, true);
      printf("); value = 0x%lx\n", data);
      break;
  }

#ifdef XEN
#if 0
  /*
   * DEBUG CODE: Log this VMCS write so that we can determine which VMCS
   * fields Xen needs us to support.
   */
  extern void log_vmcs_write(enum sva_vmcs_field, uint64_t data, bool passed_checks);
  log_vmcs_write(field, data, is_safe);
#endif
#endif /* end #ifdef XEN */

  if (is_safe)
    return writevmcs_unchecked(field, data);
  else {
    printf("SVA: Disallowed write to VMCS field: 0x%x (", field);
    print_vmcs_field_name(field, true);
    printf("); value = 0x%lx\n", data);
    panic("SVA: VMCS checks in hard-fail mode; shutting down system.\n");
  }
}

/*
 * Function: writevmcs_unchecked()
 *
 * Description:
 *  A local helper that directly performs a VMCS field write on the hardware.
 *  No checks are performed.
 *
 *  To be used internally by SVA when it is known that a write is safe (e.g.,
 *  by writevmcs_checked() after it has vetted the write).
 *
 * Preconditions:
 *  Same as writevmcs_checked(), plus:
 *
 *  - The write must not compromise SVA's security guarantees.
 */
static inline int
writevmcs_unchecked(enum sva_vmcs_field field, uint64_t data) {
  uint64_t rflags;
  asm __volatile__ (
      "vmwrite %%rax, %%rbx\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags)
      : "a" (data), "b" (field)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  enum vmx_statuscode_t result = query_vmx_result(rflags);
  if (result == VM_SUCCEED) {
    /* Return success. */
    return 0;
  } else if (result == VM_FAIL_INVALID) {
    /*
     * Indicates that the VMWRITE failed due to no VMCS being currently
     * loaded on the processor. Shouldn't happen if the caller is
     * sva_writevmcs(), since it is supposed to ensure that a VMCS is loaded
     * before calling this. (Can happen if SVA is doing a write internally,
     * though.)
     */
    DBGPRNT(("SVA: Error: writevmcs_unchecked() failed due to no VMCS "
             "being loaded. (ISA condition VMfailValid)\n"));
    return -1;
  } else if (result == VM_FAIL_VALID) {
    /*
     * Indicates that the VMWRITE failed due to the specified VMCS field being
     * invalid (nonexistent or read-only). Shouldn't happen if the caller is
     * sva_writevmcs(), unless we accidentally allowed an invalid field onto
     * the write whitelist.
     */
    DBGPRNT(("SVA: Error: writevmcs_unchecked() failed due to invalid VMCS "
             "field being specified. (ISA condition VMfailValid)\n"));
    return -2;
  } else {
    panic("SVA: Error: Got nonsensical result (%d) from "
          "query_vmx_result()!\n", (int)result);
  }
}

#define DEFINE_CTRLS_ACCESSORS(name, ty, field)                               \
int vmcs_##name##_get(ty* out) {                                              \
  union {                                                                     \
    ty ctrls;                                                                 \
    uint64_t buf;                                                             \
  } get;                                                                      \
                                                                              \
  int res = readvmcs_unchecked((field), &get.buf);                            \
  if (res == 0) {                                                             \
    *out = get.ctrls;                                                         \
  }                                                                           \
                                                                              \
  return res;                                                                 \
}                                                                             \
                                                                              \
int vmcs_##name##_set(ty ctrls) {                                             \
  union {                                                                     \
    ty ctrls;                                                                 \
    uint64_t buf;                                                             \
  } set = { }; /* Avoid reading uninitialized bytes */                        \
  set.ctrls = ctrls;                                                          \
                                                                              \
  return writevmcs_unchecked((field), set.buf);                               \
}

DEFINE_CTRLS_ACCESSORS(
  pinctrls,
  struct vmcs_pinbased_vm_exec_ctrls,
  VMCS_PINBASED_VM_EXEC_CTRLS)
DEFINE_CTRLS_ACCESSORS(
  proc1ctrls,
  struct vmcs_primary_procbased_vm_exec_ctrls,
  VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS)
DEFINE_CTRLS_ACCESSORS(
  proc2ctrls,
  struct vmcs_secondary_procbased_vm_exec_ctrls,
  VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS)
DEFINE_CTRLS_ACCESSORS(
  entryctrls,
  struct vmcs_vm_entry_ctrls,
  VMCS_VM_ENTRY_CTRLS)
DEFINE_CTRLS_ACCESSORS(
  exitctrls,
  struct vmcs_vm_exit_ctrls,
  VMCS_VM_EXIT_CTRLS)

#undef DEFINE_CTRLS_ACCESSORS

/*
 * Intrinsic: sva_getfp()
 *
 * Description:
 *  Gets the current FPU state of guest virtual machine.
 *
 * Parameters:
 *  - vmid: the numeric handle of the virtual machine whose FPU state we are
 *          to read.
 *  - fp_state: a pointer to a buffer where the FPU state will be written
 *
 * Return value:
 *  True if fetching the guest FPU state succeeded.
 *  False otherwise
 *
 * FIXME: remove this intrinsic as it has been superseded by sva_getvmfpu()
 */
unsigned char
sva_getfp(int vmid, unsigned char *fp_state) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_getfp(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_getfp(): failed to acquire VM descriptor lock!\n");

  const size_t fp_state_size = sizeof(struct xsave_legacy);

  if ( usevmx ) {
    /* Check if it's safe to write to the region pointed to */
    sva_check_memory_write( fp_state, fp_state_size ); /* Assumes FPU state size of 512B */
  }

  /* Do the copy from the guest VM structure to the (pointed to) output buffer */
  memcpy(fp_state, &vm_descs[vmid].state.fp.inner.legacy, fp_state_size);

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return 1;
}


/*
 * Intrinsic: sva_getvmreg()
 *
 * Description:
 *  Gets the current value of a guest register in a virtual machine.
 *
 * Parameters:
 *  - vmid: the numeric handle of the virtual machine whose register we are
 *          to read.
 *
 *  - reg:  the register to be read.
 *
 * Return value:
 *  The 64-bit value of the register that is read. If the register is smaller
 *  than 64 bits, it is zero-extended to an unsigned 64-bit value.
 */
uint64_t
sva_getvmreg(int vmid, enum sva_vm_reg reg) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  
  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_getvmreg(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Note: we don't need to check whether vmid corresponds to a VM that is
   * actually allocated. If it isn't, it is safe to return the "meaningless"
   * data in the unused descriptor's register fields because the VM
   * descriptor array is zero-initialized during sva_initvmx(), ensuring that
   * no sensitive uninitialized data is retained within. Following that
   * initialization, these register fields will only ever be used to store
   * guest data, so in the event the hypervisor specifies a bad vmid and
   * reads from an unallocated VM descriptor, it will read either a zero or
   * some dead value from a previous VM which, in principle, the hypervisor
   * already had access to - so this is not security-sensitive.
   *
   * (This assumption may no longer be true if and when we implement
   * "Virtual Ghost for VMs".)
   */

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_getvmreg(): failed to acquire VM descriptor lock!\n");

  /*
   * Get the respective register from the specified VM's descriptor.
   */
  uint64_t retval;
  switch (reg) {
    case VM_REG_RAX:
      retval = vm_descs[vmid].state.rax;
      break;
    case VM_REG_RBX:
      retval = vm_descs[vmid].state.rbx;
      break;
    case VM_REG_RCX:
      retval = vm_descs[vmid].state.rcx;
      break;
    case VM_REG_RDX:
      retval = vm_descs[vmid].state.rdx;
      break;
    case VM_REG_RBP:
      retval = vm_descs[vmid].state.rbp;
      break;
    case VM_REG_RSI:
      retval = vm_descs[vmid].state.rsi;
      break;
    case VM_REG_RDI:
      retval = vm_descs[vmid].state.rdi;
      break;
    case VM_REG_R8:
      retval = vm_descs[vmid].state.r8;
      break;
    case VM_REG_R9:
      retval = vm_descs[vmid].state.r9;
      break;
    case VM_REG_R10:
      retval = vm_descs[vmid].state.r10;
      break;
    case VM_REG_R11:
      retval = vm_descs[vmid].state.r11;
      break;
    case VM_REG_R12:
      retval = vm_descs[vmid].state.r12;
      break;
    case VM_REG_R13:
      retval = vm_descs[vmid].state.r13;
      break;
    case VM_REG_R14:
      retval = vm_descs[vmid].state.r14;
      break;
    case VM_REG_R15:
      retval = vm_descs[vmid].state.r15;
      break;

    case VM_REG_CR2:
      retval = vm_descs[vmid].state.cr2;
      break;

    case VM_REG_XCR0:
      retval = vm_descs[vmid].state.xcr0;
      break;
    case VM_REG_MSR_XSS:
      retval = vm_descs[vmid].state.msr_xss;
      break;

    case VM_REG_MSR_FMASK:
      retval = vm_descs[vmid].state.msr_fmask;
      break;
    case VM_REG_MSR_STAR:
      retval = vm_descs[vmid].state.msr_star;
      break;
    case VM_REG_MSR_LSTAR:
      retval = vm_descs[vmid].state.msr_lstar;
      break;

    case VM_REG_GS_SHADOW:
      retval = vm_descs[vmid].state.gs_shadow;
      break;

#ifdef MPX
    case VM_REG_BND0_LOWER:
      retval = vm_descs[vmid].state.bnd0[0];
      break;
    case VM_REG_BND0_UPPER:
      retval = vm_descs[vmid].state.bnd0[1];
      break;
    case VM_REG_BND1_LOWER:
      retval = vm_descs[vmid].state.bnd1[0];
      break;
    case VM_REG_BND1_UPPER:
      retval = vm_descs[vmid].state.bnd1[1];
      break;
    case VM_REG_BND2_LOWER:
      retval = vm_descs[vmid].state.bnd2[0];
      break;
    case VM_REG_BND2_UPPER:
      retval = vm_descs[vmid].state.bnd2[1];
      break;
    case VM_REG_BND3_LOWER:
      retval = vm_descs[vmid].state.bnd3[0];
      break;
    case VM_REG_BND3_UPPER:
      retval = vm_descs[vmid].state.bnd3[1];
      break;
#endif /* end #ifdef MPX */

    default:
      panic("sva_getvmreg(): Invalid register specified: %d\n", (int) reg);
      break;
  }

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);

  return retval;
}

/*
 * Intrinsic: sva_setvmreg()
 *
 * Description:
 *  Sets the value of a guest register in a virtual machine.
 *
 * Parameters:
 *  - vmid: the numeric handle of the virtual machine whose register we are
 *          to set.
 *
 *  - reg:  the register to be set.
 *
 *  - data: the 64-bit value to which the register should be set. If the
 *          register is smaller than 64 bits, the higher bits are ignored.
 */
void
sva_setvmreg(int vmid, enum sva_vm_reg reg, uint64_t data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_setvmreg(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Note: we don't need to check whether vmid corresponds to a VM that is
   * actually allocated. If it isn't, the register field we are setting will
   * be overwritten when a new VM is allocated in its slot, because
   * sva_allocvm() doesn't let you leave any registers uninitialized.
   */

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_setvmreg(): failed to acquire VM descriptor lock!\n");

  /*
   * Write to the respective register field in the specified VM's descriptor.
   *
   * We do not need to vet or control the data being written in any way since
   * these fields only influence the guest system's state and have no impact
   * on host security.
   */
  switch (reg) {
    case VM_REG_RAX:
      vm_descs[vmid].state.rax = data;
      break;
    case VM_REG_RBX:
      vm_descs[vmid].state.rbx = data;
      break;
    case VM_REG_RCX:
      vm_descs[vmid].state.rcx = data;
      break;
    case VM_REG_RDX:
      vm_descs[vmid].state.rdx = data;
      break;
    case VM_REG_RBP:
      vm_descs[vmid].state.rbp = data;
      break;
    case VM_REG_RSI:
      vm_descs[vmid].state.rsi = data;
      break;
    case VM_REG_RDI:
      vm_descs[vmid].state.rdi = data;
      break;
    case VM_REG_R8:
      vm_descs[vmid].state.r8 = data;
      break;
    case VM_REG_R9:
      vm_descs[vmid].state.r9 = data;
      break;
    case VM_REG_R10:
      vm_descs[vmid].state.r10 = data;
      break;
    case VM_REG_R11:
      vm_descs[vmid].state.r11 = data;
      break;
    case VM_REG_R12:
      vm_descs[vmid].state.r12 = data;
      break;
    case VM_REG_R13:
      vm_descs[vmid].state.r13 = data;
      break;
    case VM_REG_R14:
      vm_descs[vmid].state.r14 = data;
      break;
    case VM_REG_R15:
      vm_descs[vmid].state.r15 = data;
      break;

    case VM_REG_CR2:
      vm_descs[vmid].state.cr2 = data;
      break;
    case VM_REG_MSR_XSS:
      vm_descs[vmid].state.msr_xss = data;
      break;

    case VM_REG_XCR0:
      vm_descs[vmid].state.xcr0 = data;
      break;

    case VM_REG_MSR_FMASK:
      vm_descs[vmid].state.msr_fmask = data;
      break;
    case VM_REG_MSR_STAR:
      vm_descs[vmid].state.msr_star = data;
      break;
    case VM_REG_MSR_LSTAR:
      vm_descs[vmid].state.msr_lstar = data;
      break;

    case VM_REG_GS_SHADOW:
      vm_descs[vmid].state.gs_shadow = data;
      break;

#ifdef MPX
    case VM_REG_BND0_LOWER:
      vm_descs[vmid].state.bnd0[0] = data;
      break;
    case VM_REG_BND0_UPPER:
      vm_descs[vmid].state.bnd0[1] = data;
      break;
    case VM_REG_BND1_LOWER:
      vm_descs[vmid].state.bnd1[0] = data;
      break;
    case VM_REG_BND1_UPPER:
      vm_descs[vmid].state.bnd1[1] = data;
      break;
    case VM_REG_BND2_LOWER:
      vm_descs[vmid].state.bnd2[0] = data;
      break;
    case VM_REG_BND2_UPPER:
      vm_descs[vmid].state.bnd2[1] = data;
      break;
    case VM_REG_BND3_LOWER:
      vm_descs[vmid].state.bnd3[0] = data;
      break;
    case VM_REG_BND3_UPPER:
      vm_descs[vmid].state.bnd3[1] = data;
      break;
#endif /* end #ifdef MPX */

    default:
      panic("sva_setvmreg(): Invalid register specified: %d. "
          "Value that would have been written: 0x%lx\n", (int) reg, data);
      break;
  }

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
}

/*
 * Intrinsic: sva_getvmfpu()
 *
 * Description:
 *  Gets the current contents of a guest VM's saved FPU (XSAVE) state.
 *
 * Parameters:
 *  - vmid: the numeric handle of the virtual machine whose FPU state is to
 *          be read.
 *
 *  - out_data [OUT-PARAMETER]: a pointer to a caller-owned object of type
 *          "union xsave_area_max", into which this intrinsic will write the
 *          FPU state being read.
 *      NOTE: this pointer cannot be trusted by SVA and must be checked to
 *      ensure it doesn't point into a protected memory region before SVA
 *      dereferences it.
 */
void
sva_getvmfpu(int vmid, union xsave_area_max __kern* out_data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_getvmfpu(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Note: we don't need to check whether vmid corresponds to a VM that is
   * actually allocated. See comment in sva_getvmreg() for explanation why.
   */

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_getvmfpu(): failed to acquire VM descriptor lock!\n");

  /* Sanity check (should be statically optimized away) */
  SVA_ASSERT(__builtin_types_compatible_p(typeof(out_data),
                                          typeof(&vm_descs[vmid].state.fp)),
      "Type mismatch between sva_getvmfpu() parameter and VM descriptor "
      "FPU state object");

  /*
   * Copy the specified VM's FPU data from its descriptor to the buffer
   * pointed to by out_data.
   */
  union xsave_area_max* fp = &vm_descs[vmid].state.fp;
  SVA_ASSERT(sva_copy_to_kernel(out_data, fp, sizeof(*fp)) == 0,
      "Fault copying data to kernel");

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
}

/*
 * Intrinsic: sva_setvmfpu()
 *
 * Description:
 *  Sets a virtual machine's saved FPU (XSAVE) state to a new value.
 *
 * Parameters:
 *  - vmid: the numeric handle of the virtual machine whose FPU state is to
 *          be updated.
 *
 *  - in_data: a pointer to a caller-owned object of type "union
 *          xsave_area_max", from which this intrinsic will read the new FPU
 *          state being set.
 *      NOTE: this pointer cannot be trusted by SVA and must be checked to
 *      ensure it doesn't point into a protected memory region before SVA
 *      dereferences it.
 */
void
sva_setvmfpu(int vmid, union xsave_area_max __kern* in_data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  SVA_ASSERT(getCPUState()->vmx_initialized,
      "sva_setvmfpu(): Shade not yet initialized on this processor!\n");

  /*
   * Bounds check on vmid.
   *
   * vmid must be positive and less than MAX_VMS.
   */
  if (usevmx) {
    if (vmid >= MAX_VMS || vmid <= 0) {
      panic("Fatal error: specified out-of-bounds VM ID (%d)!\n", vmid);
    }
  }

  /*
   * Note: we don't need to check whether vmid corresponds to a VM that is
   * actually allocated. See comment in sva_setvmreg() for explanation why.
   */

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_ASSERT(acquired_lock, "sva_setvmfpu(): failed to acquire VM descriptor lock!\n");

  /* Sanity check (should be statically optimized away) */
  SVA_ASSERT(__builtin_types_compatible_p(typeof(in_data),
                                          typeof(&vm_descs[vmid].state.fp)),
      "Type mismatch between sva_setvmfpu() parameter and VM descriptor "
      "FPU state object");

  /*
   * Copy the new FPU data from the buffer pointed to by in_data to the
   * specified VM's descriptor.
   */
  union xsave_area_max* fp = &vm_descs[vmid].state.fp;
  SVA_ASSERT(sva_copy_from_kernel(fp, in_data, sizeof(*fp)) == 0,
      "Fault copying data from kernel");

  /* Release the VM descriptor lock if we took it earlier. */
  if (acquired_lock == 2 /* 2 == lock newly taken by ensure_lock call above */)
    vm_desc_unlock(&vm_descs[vmid]);

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
}

/**
 * Disable posted interrupt processing.
 *
 * Outlined because we need it when disabling the vlAPIC.
 *
 * Requires that an active VM currently exists.
 */
static void posted_interrupts_disable(void) {
  struct vm_desc_t *const active_vm = getCPUState()->active_vm;

  if (active_vm->vlapic.posted_interrupts_enabled) {
    struct vmcs_pinbased_vm_exec_ctrls pinbased;
    BUG_ON(vmcs_pinctrls_get(&pinbased));
    struct vmcs_secondary_procbased_vm_exec_ctrls secondary;
    BUG_ON(vmcs_proc2ctrls_get(&secondary));

    pinbased.process_posted_ints = false;
    secondary.virtual_int_delivery = false;

    BUG_ON(vmcs_pinctrls_set(pinbased));
    BUG_ON(vmcs_proc2ctrls_set(secondary));

    frame_desc_t* pi_desc_frame_desc =
      get_frame_desc(active_vm->vlapic.posted_interrupt_descriptor);
    frame_drop(pi_desc_frame_desc, PGT_DATA);
  }

  active_vm->vlapic.posted_interrupts_enabled = false;
}

static void vlapic_set_msr_intercepts(vm_desc_t* vm) {
  for (uint32_t msr = MSR_X2APIC_REG_BASE;
       msr < MSR_X2APIC_REG_BASE + 0x40; ++msr)
  {
    msr_bitmaps_set_intercept(vm, msr, VMX_EXIT_BITMAP_RW);
  }
}

int sva_vlapic_disable(void) {
  /* TODO: enter interrupt critical section */

  int __sva_intrinsic_result = 0;

  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  struct vm_desc_t *const active_vm = getCPUState()->active_vm;
  SVA_CHECK(active_vm != NULL, ESRCH);

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  DBGPRNT(("SVA: vlAPIC is in %d mode. Switching to OFF\n",
           active_vm->vlapic.mode));

  posted_interrupts_disable();
  vlapic_set_msr_intercepts(active_vm);

  switch (active_vm->vlapic.mode) {
  case VLAPIC_OFF:
    /* Nothing to do */
    break;
  case VLAPIC_APIC:
  case VLAPIC_X2APIC: {
    struct vmcs_primary_procbased_vm_exec_ctrls primary;
    BUG_ON(vmcs_proc1ctrls_get(&primary));
    struct vmcs_secondary_procbased_vm_exec_ctrls secondary;
    BUG_ON(vmcs_proc2ctrls_get(&secondary));

    primary.use_tpr_shadow = false;
    primary.cr8_load_exiting = true;
    primary.cr8_store_exiting = true;
    secondary.virtualize_apic_accesses = false;
    secondary.virtualize_x2apic_mode = false;
    secondary.apic_register_virtualization = false;

    BUG_ON(vmcs_proc1ctrls_set(primary));
    BUG_ON(vmcs_proc2ctrls_set(secondary));

    frame_drop(get_frame_desc(active_vm->vlapic.virtual_apic_frame), PGT_DATA);
    if (active_vm->vlapic.mode == VLAPIC_APIC) {
      frame_drop(get_frame_desc(active_vm->vlapic.apic_access_frame), PGT_DATA);
    }

    break;
  }
  }

  active_vm->vlapic.mode = VLAPIC_OFF;

__sva_fail:
  usersva_to_kernel_pcid();
  return __sva_intrinsic_result;
}

int sva_vlapic_enable(paddr_t virtual_apic_frame, paddr_t apic_access_frame) {
  /* TODO: enter interrupt critical section */

  int __sva_intrinsic_result = 0;

  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  struct vm_desc_t *const active_vm = getCPUState()->active_vm;
  SVA_CHECK(active_vm != NULL, ESRCH);

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  DBGPRNT(("SVA: vlAPIC is in %d mode. Switching to APIC\n",
           active_vm->vlapic.mode));

  vlapic_set_msr_intercepts(active_vm);

  /* Take frame references. */
  SVA_CHECK(is_aligned_pow2(virtual_apic_frame, PG_L1_SHIFT), EINVAL);
  frame_desc_t* va_frame_desc = get_frame_desc(virtual_apic_frame);
  SVA_CHECK(va_frame_desc != NULL, EINVAL);
  SVA_CHECK(is_aligned_pow2(apic_access_frame, PG_L1_SHIFT), EINVAL);
  frame_desc_t* aa_frame_desc = get_frame_desc(apic_access_frame);
  SVA_CHECK(aa_frame_desc != NULL, EINVAL);

  if (active_vm->vlapic.mode == VLAPIC_OFF ||
      virtual_apic_frame != active_vm->vlapic.virtual_apic_frame) {
    frame_take(va_frame_desc, PGT_DATA);
    BUG_ON(writevmcs_unchecked(VMCS_VIRTUAL_APIC_ADDR, virtual_apic_frame));
    if (active_vm->vlapic.mode != VLAPIC_OFF) {
      frame_desc_t* old_va_frame_desc =
        get_frame_desc(active_vm->vlapic.virtual_apic_frame);
      frame_drop(old_va_frame_desc, PGT_DATA);
    }
    active_vm->vlapic.virtual_apic_frame = virtual_apic_frame;
  }
  if (active_vm->vlapic.mode != VLAPIC_APIC ||
      apic_access_frame != active_vm->vlapic.apic_access_frame) {
    frame_take(aa_frame_desc, PGT_DATA);
    BUG_ON(writevmcs_unchecked(VMCS_APIC_ACCESS_ADDR, apic_access_frame));
    if (active_vm->vlapic.mode == VLAPIC_APIC) {
      frame_drop(get_frame_desc(active_vm->vlapic.apic_access_frame), PGT_DATA);
    }
    active_vm->vlapic.apic_access_frame = apic_access_frame;
  }

  switch (active_vm->vlapic.mode) {
  case VLAPIC_APIC: {
    /* Already in APIC mode: nothing else to do */

    break;
  }
  case VLAPIC_OFF:
  case VLAPIC_X2APIC: {
    // TODO: Check for CPU support of these features

    /* Enable vlAPIC execution controls. */
    struct vmcs_primary_procbased_vm_exec_ctrls primary;
    BUG_ON(vmcs_proc1ctrls_get(&primary));
    struct vmcs_secondary_procbased_vm_exec_ctrls secondary;
    BUG_ON(vmcs_proc2ctrls_get(&secondary));

    primary.use_tpr_shadow = true;
    primary.cr8_load_exiting = false;
    primary.cr8_store_exiting = false;
    secondary.virtualize_apic_accesses = true;
    secondary.virtualize_x2apic_mode = false;
    secondary.apic_register_virtualization = true;

    BUG_ON(vmcs_proc1ctrls_set(primary));
    BUG_ON(vmcs_proc2ctrls_set(secondary));

    break;
  }
  }

  active_vm->vlapic.mode = VLAPIC_APIC;

__sva_fail:
  usersva_to_kernel_pcid();
  return __sva_intrinsic_result;
}

int sva_vlapic_enable_x2apic(paddr_t virtual_apic_frame) {
  /* TODO: enter interrupt critical section */

  int __sva_intrinsic_result = 0;

  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  struct vm_desc_t *const active_vm = getCPUState()->active_vm;
  SVA_CHECK(active_vm != NULL, ESRCH);

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  DBGPRNT(("SVA: vlAPIC is in %d mode. Switching to x2APIC\n",
           active_vm->vlapic.mode));

  SVA_CHECK(is_aligned_pow2(virtual_apic_frame, PG_L1_SHIFT), EINVAL);
  frame_desc_t* va_frame_desc = get_frame_desc(virtual_apic_frame);
  SVA_CHECK(va_frame_desc != NULL, EINVAL);

  if (active_vm->vlapic.mode == VLAPIC_OFF ||
      virtual_apic_frame != active_vm->vlapic.virtual_apic_frame) {
    frame_take(va_frame_desc, PGT_DATA);
    BUG_ON(writevmcs_unchecked(VMCS_VIRTUAL_APIC_ADDR, virtual_apic_frame));
    if (active_vm->vlapic.mode != VLAPIC_OFF) {
      frame_desc_t* old_va_frame_desc =
        get_frame_desc(active_vm->vlapic.virtual_apic_frame);
      frame_drop(old_va_frame_desc, PGT_DATA);
    }
    active_vm->vlapic.virtual_apic_frame = virtual_apic_frame;
  }
  if (active_vm->vlapic.mode == VLAPIC_APIC) {
    frame_drop(get_frame_desc(active_vm->vlapic.apic_access_frame), PGT_DATA);
  }

  switch (active_vm->vlapic.mode) {
  case VLAPIC_OFF:
  case VLAPIC_APIC: {
    // TODO: Check for CPU support of these features

    /* Enable vlAPIC execution controls. */
    struct vmcs_primary_procbased_vm_exec_ctrls primary;
    BUG_ON(vmcs_proc1ctrls_get(&primary));
    struct vmcs_secondary_procbased_vm_exec_ctrls secondary;
    BUG_ON(vmcs_proc2ctrls_get(&secondary));

    primary.use_tpr_shadow = true;
    primary.cr8_load_exiting = false;
    primary.cr8_store_exiting = false;
    secondary.virtualize_apic_accesses = false;
    secondary.virtualize_x2apic_mode = true;
    secondary.apic_register_virtualization = true;

    BUG_ON(vmcs_proc1ctrls_set(primary));
    BUG_ON(vmcs_proc2ctrls_set(secondary));

    break;
  }
  case VLAPIC_X2APIC: {
    /* Already in x2APIC mode: nothing to do. */

    break;
  }
  }

  active_vm->vlapic.mode = VLAPIC_X2APIC;

__sva_fail:
  usersva_to_kernel_pcid();
  return __sva_intrinsic_result;
}

int sva_posted_interrupts_disable(void) {
  /* TODO: enter interrupt critical section */

  int __sva_intrinsic_result = 0;

  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  struct vm_desc_t *const active_vm = getCPUState()->active_vm;
  SVA_CHECK(active_vm != NULL, ESRCH);

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  DBGPRNT(("SVA: disabling posted interrupt processing\n"));

  posted_interrupts_disable();

__sva_fail:
  usersva_to_kernel_pcid();
  return __sva_intrinsic_result;
}

int sva_posted_interrupts_enable(uint8_t vector, paddr_t descriptor) {
  /* TODO: enter interrupt critical section */

  int __sva_intrinsic_result = 0;

  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  struct vm_desc_t *const active_vm = getCPUState()->active_vm;
  SVA_CHECK(active_vm != NULL, ESRCH);

  /*
   * Note: now that we have confirmed there is a VM active on this processor,
   * it is safe for us to freely access its VMCS and VM descriptor fields,
   * since we know this processor currently holds the descriptor lock.
   */

  SVA_CHECK(active_vm->vlapic.mode != VLAPIC_OFF, ENOENT);

  DBGPRNT(("SVA: enabling posted interrupt processing\n"));

  SVA_CHECK(vector >= 32, EINVAL);
  if (!active_vm->vlapic.posted_interrupts_enabled ||
      vector != active_vm->vlapic.posted_interrupt_vector) {
    BUG_ON(writevmcs_unchecked(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR,
                               vector));
    active_vm->vlapic.posted_interrupt_vector = vector;
  }

  SVA_CHECK(is_aligned_pow2(descriptor, 6), EINVAL);
  frame_desc_t* descriptor_frame_desc = get_frame_desc(descriptor);
  SVA_CHECK(descriptor_frame_desc != NULL, EINVAL);
  if (!active_vm->vlapic.posted_interrupts_enabled ||
      descriptor != active_vm->vlapic.posted_interrupt_descriptor) {
    frame_take(descriptor_frame_desc, PGT_DATA);
    BUG_ON(writevmcs_unchecked(VMCS_POSTED_INTERRUPT_DESC_ADDR, descriptor));
    if (active_vm->vlapic.posted_interrupts_enabled) {
      frame_desc_t* old_descriptor_frame_desc =
        get_frame_desc(active_vm->vlapic.posted_interrupt_descriptor);
      frame_drop(old_descriptor_frame_desc, PGT_DATA);
    }
    active_vm->vlapic.posted_interrupt_descriptor = descriptor;
  }

  if (!active_vm->vlapic.posted_interrupts_enabled) {
    struct vmcs_pinbased_vm_exec_ctrls pinbased;
    BUG_ON(vmcs_pinctrls_get(&pinbased));
    struct vmcs_secondary_procbased_vm_exec_ctrls secondary;
    BUG_ON(vmcs_proc2ctrls_get(&secondary));

    pinbased.process_posted_ints = true;
    secondary.virtual_int_delivery = true;

    BUG_ON(vmcs_pinctrls_set(pinbased));
    BUG_ON(vmcs_proc2ctrls_set(secondary));
  }

  active_vm->vlapic.posted_interrupts_enabled = true;

__sva_fail:
  usersva_to_kernel_pcid();
  return __sva_intrinsic_result;
}

/*
 * Helper function: init_vmcs_ctrls()
 *
 * Initializes the active VM's VMCS control fields to safe defaults.
 *
 * Note that this initialization is *NOT* sufficient to actually run a guest
 * and have it perform meaningful computation. The hypervisor is expected to
 * use the sva_writevmcs() intrinsic to specify meaningful initial values to
 * these fields (to the extent required based on the features it intends to
 * use) before running the guest for the first time. The initial values set
 * by this function are intended merely to ensure that SVA's safety needs are
 * met if the hypervisor attempts to run the guest without explicitly
 * initializing these values.
 *
 * This function is designed to be called by sva_loadvm() the first time a
 * particular VMCS is loaded onto the processor, and at no other time.
 *
 * PRECONDITION:
 *    A VMCS must be active on the processor. If this is not the case, the
 *    calls to writevmcs_unchecked() will fail since the VMWRITE instruction
 *    is only valid with an active VMCS.
 */
static inline void
init_vmcs_ctrls(void) {
  SVA_ASSERT(getCPUState()->active_vm,
      "init_vmcs_ctrls(): A VM must be active on the processor.");

  /*******
   * These VMCS fields are not on the writevmcs_checked() whitelist, i.e.,
   * the hypervisor is not allowed to change them using sva_writevmcs(). We
   * initialize them here to the values that SVA wants and do not allow them
   * to be changed throughout the life of the VM.
   */

  /*
   * Set the VPID (Virtual Processor ID) field to be equal to the VM ID
   * assigned to this VM by SVA.
   *
   * The VPID distinguishes TLB entries belonging to the VM from those
   * belonging to the host and to other VMs.
   *
   * It must NOT be set to 0; that is used for the host. (We ensure this by
   * skipping slot #0 in the VM descriptor array when assigning a slot in
   * sva_allocvm().)
   *
   * Note that the hardware VPID field is limited to 16 bits (i.e. uint16_t),
   * but SVA VMIDs are int32_t's; the constant MAX_VMS (defined in vmx.h)
   * should be defined to a value less than UINT16_MAX to prevent overflow.
   * (In practice, it would probably be undesirable to set MAX_VMS that large
   * anyway, because it determines the size of the statically-allocated VM
   * descriptor array.)
   */
  int active_vmid = getCPUState()->active_vm - vm_descs;
  writevmcs_unchecked(VMCS_VPID, active_vmid);

  /*
   * Set the "CR3-target count" VM execution control to 0. The value doesn't
   * actually matter because we are using EPT (and thus there are no
   * restrictions on what the guest can load into CR3); but if we leave the
   * value uninitialized, the processor may throw an error on VM entry if the
   * value is greater than 4.
   */
  writevmcs_unchecked(VMCS_CR3_TARGET_COUNT, 0);

  /*
   * Set VMCS link pointer to indicate that we are not using VMCS shadowing.
   *
   * (SVA currently does not support VMCS shadowing.)
   */
  uint64_t vmcs_link_ptr = 0xffffffffffffffff;
  writevmcs_unchecked(VMCS_VMCS_LINK_PTR, vmcs_link_ptr);

  /*
   * Set VM-entry/exit MSR load/store counts to 0 to indicate that we will
   * not use the general-purpose MSR save/load feature.
   *
   * Some MSRs are individually saved/loaded on entry/exit as part of SVA's
   * guest state management.
   */
  writevmcs_unchecked(VMCS_VM_ENTRY_MSR_LOAD_COUNT, 0);
  writevmcs_unchecked(VMCS_VM_EXIT_MSR_LOAD_COUNT, 0);
  writevmcs_unchecked(VMCS_VM_EXIT_MSR_STORE_COUNT, 0);

  writevmcs_unchecked(VMCS_MSR_BITMAPS_ADDR,
    getCPUState()->active_vm->msr_exiting_bitmaps);
  writevmcs_unchecked(VMCS_IOBITMAP_A_ADDR,
    getCPUState()->active_vm->io_exiting_bitmaps[0]);
  writevmcs_unchecked(VMCS_IOBITMAP_B_ADDR,
    getCPUState()->active_vm->io_exiting_bitmaps[1]);

  /*******
   * SVA permits the hypervisor to modify the following fields with
   * sva_writevmcs(), but subject to bitwise restrictions enforced by
   * writevmcs_checked().
   *
   * We initialize all control bits to 0 unless they are reserved to 1 by the
   * ISA or our runtime checks in writevmcs_checked() would require them to
   * be so.
   */

  /* Field: VMCS_PINBASED_VM_EXEC_CTRLS */
  union {
    struct vmcs_pinbased_vm_exec_ctrls fields;
    uint64_t buf;
  } pinbased;
  pinbased.buf = 0;

  pinbased.fields.ext_int_exiting = 1;
  pinbased.fields.nmi_exiting = 1;
  pinbased.fields.reserved1_2 = 0x3;
  pinbased.fields.reserved4 = 1;

  /*
   * N.B.: We use writevmcs_checked() here and below, rather than
   * writevmcs_unchecked(), even though this is a trusted write from inside
   * SVA, because writevmcs_checked() will automatically override
   * intrinsic-controlled bits (e.g. vlAPIC) to the correct values based on
   * current settings. writevmcs_unchecked() wouldn't do that and would
   * require us to duplicate the code here that determines their correct
   * settings.
   *
   * No significant performance impact is expected from this, because a) this
   * code only runs the first time a VMCS is loaded; and b) we split out
   * writevmcs_checked() and writevmcs_unchecked() not really for performance
   * reasons (the runtime checks are super fast), but because SVA often needs
   * to make changes to VMCS fields that the checks are designed to prevent
   * the hypervisor from making on its own. As the whole point of this code
   * here is to write safe defaults that the hypervisor *could* have written
   * on its own, that is not an issue.
   */
  writevmcs_checked(VMCS_PINBASED_VM_EXEC_CTRLS, pinbased.buf);

  /* Field: VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS */
  union {
    struct vmcs_primary_procbased_vm_exec_ctrls fields;
    uint64_t buf;
  } primary;
  primary.buf = 0;

  primary.fields.activate_secondary_ctrls = 1;
  primary.fields.reserved0_1 = 0x2;
  primary.fields.reserved4_6 = 0x7;
  primary.fields.reserved8 = 1;
  primary.fields.reserved13_14 = 0x3;
  primary.fields.reserved26 = 1;

  writevmcs_checked(VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS, primary.buf);

  /* Field: VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS */
  union {
    struct vmcs_secondary_procbased_vm_exec_ctrls fields;
    uint64_t buf;
  } secondary;
  secondary.buf = 0;

  secondary.fields.enable_ept = 1;
  secondary.fields.enable_vpid = 1;

  writevmcs_checked(VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS, secondary.buf);

  /* Field: VMCS_VM_EXIT_CTRLS */
  union {
    struct vmcs_vm_exit_ctrls fields;
    uint64_t buf;
  } exit;
  exit.buf = 0;

  exit.fields.host_addr_space_size = 1;
  exit.fields.load_ia32_pat = 1;
  exit.fields.load_ia32_efer = 1;
  exit.fields.reserved0_1 = 0x3;
  exit.fields.reserved3_8 = 0x3f;
  exit.fields.reserved10_11 = 0x3;
  exit.fields.reserved13_14 = 0x3;
  exit.fields.reserved16_17 = 0x3;

  writevmcs_checked(VMCS_VM_EXIT_CTRLS, exit.buf);

  /* Field: VMCS_VM_ENTRY_CTRLS */
  union {
    struct vmcs_vm_entry_ctrls fields;
    uint64_t buf;
  } entry;
  entry.buf = 0;

  entry.fields.reserved0_1 = 0x3;
  entry.fields.reserved3_8 = 0x3f;
  entry.fields.reserved12 = 1;

  writevmcs_checked(VMCS_VM_ENTRY_CTRLS, entry.buf);

  vmcs_init_host_cr();
  vmcs_init_host_segments();
  vmcs_init_host_sysenter();
}

static paddr_t exiting_bitmap_create(void) {
  paddr_t frame = alloc_frame();
  frame_morph(get_frame_desc(frame), PGT_SVA);
  frame_take(get_frame_desc(frame), PGT_SVA);
  memset(__va(frame), ~0, FRAME_SIZE);
  return frame;
}

static void exiting_bitmap_free(paddr_t frame) {
  frame_drop(get_frame_desc(frame), PGT_SVA);
  frame_morph(get_frame_desc(frame), PGT_FREE);
  free_frame(frame);
}

static int msr_bitmaps_init(vm_desc_t* vm) {
  vm->msr_exiting_bitmaps = exiting_bitmap_create();
  return 0;
}

static int msr_bitmaps_free(vm_desc_t* vm) {
  exiting_bitmap_free(vm->msr_exiting_bitmaps);
  return 0;
}

#define MSR_BITMAP_COUNT 0x2000UL
#define MSR_BITMAP_HIGH_BASE 0xc0000000U

struct msr_bitmaps {
  unsigned char read_low[MSR_BITMAP_COUNT / CHAR_BIT];
  unsigned char read_high[MSR_BITMAP_COUNT / CHAR_BIT];
  unsigned char write_low[MSR_BITMAP_COUNT / CHAR_BIT];
  unsigned char write_high[MSR_BITMAP_COUNT / CHAR_BIT];
};

static inline int msr_bitmaps_op_intercept(
    void (*op)(unsigned char*, size_t, bool*),
    enum vmx_exit_bitmap_rw* out,
    vm_desc_t* vm,
    uint32_t msr,
    enum vmx_exit_bitmap_rw rw)
{
  struct msr_bitmaps* bitmaps = __va(vm->msr_exiting_bitmaps);

  unsigned char (*read_map)[MSR_BITMAP_COUNT / CHAR_BIT];
  unsigned char (*write_map)[MSR_BITMAP_COUNT / CHAR_BIT];

  size_t idx;
  if (msr < MSR_BITMAP_COUNT) {
    read_map = &bitmaps->read_low;
    write_map = &bitmaps->write_low;
    idx = msr;
  } else if (MSR_BITMAP_HIGH_BASE <= msr &&
             msr < MSR_BITMAP_HIGH_BASE + MSR_BITMAP_COUNT)
  {
    read_map = &bitmaps->read_high;
    write_map = &bitmaps->write_high;
    idx = msr - MSR_BITMAP_HIGH_BASE;
  } else {
    return -ESRCH;
  }

  bool read, write;
  if (rw & VMX_EXIT_BITMAP_R) {
    op(*read_map, idx, &read);
  }
  if (rw & VMX_EXIT_BITMAP_W) {
    op(*write_map, idx, &write);
  }
  if (out != NULL) {
    *out = (read ? VMX_EXIT_BITMAP_R : VMX_EXIT_BITMAP_NONE) |
           (write ? VMX_EXIT_BITMAP_W : VMX_EXIT_BITMAP_NONE);
  }

  return 0;
}

static inline void get_bit(unsigned char* in, size_t off, bool* out) {
  *out = !!(in[off / CHAR_BIT] & (1 << off % CHAR_BIT));
}

int msr_bitmaps_get_intercept(vm_desc_t* vm, uint32_t msr, enum vmx_exit_bitmap_rw* out) {
  *out = VMX_EXIT_BITMAP_NONE;
  return msr_bitmaps_op_intercept(get_bit, out, vm, msr, VMX_EXIT_BITMAP_RW);
}

static inline void clear_bit(unsigned char* in, size_t off, bool* _unused) {
  (void)_unused;
  in[off / CHAR_BIT] &= ~(1 << off % CHAR_BIT);
}

int msr_bitmaps_clear_intercept(vm_desc_t* vm, uint32_t msr, enum vmx_exit_bitmap_rw rw) {
  return msr_bitmaps_op_intercept(clear_bit, NULL, vm, msr, rw);
}

static inline void set_bit(unsigned char* in, size_t off, bool* _unused) {
  (void)_unused;
  in[off / CHAR_BIT] |= 1 << off % CHAR_BIT;
}

int msr_bitmaps_set_intercept(vm_desc_t* vm, uint32_t msr, enum vmx_exit_bitmap_rw rw) {
  return msr_bitmaps_op_intercept(set_bit, NULL, vm, msr, rw);
}

int sva_vmx_msr_intercept_get(int vmid, uint32_t msr) {
  int __sva_intrinsic_result;
  unsigned long rflags = sva_enter_critical();
  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  SVA_CHECK(vmid >= 0 && vmid <= MAX_VMS, ESRCH);
  vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_CHECK(acquired_lock, EBUSY);

  enum vmx_exit_bitmap_rw out;
  int res;
  if ((res = msr_bitmaps_get_intercept(vm, msr, &out)) == 0) {
    __sva_intrinsic_result = (int)out;
  } else {
    __sva_intrinsic_result = res;
  }

  if (acquired_lock == 2) {
    vm_desc_unlock(vm);
  }

__sva_fail:
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
  return __sva_intrinsic_result;
}

int sva_vmx_msr_intercept_clear(int vmid, uint32_t msr, enum vmx_exit_bitmap_rw rw) {
  int __sva_intrinsic_result;
  int acquired_lock = 0;
  unsigned long rflags = sva_enter_critical();
  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  SVA_CHECK(vmid >= 0 && vmid <= MAX_VMS, ESRCH);
  vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Take the lock for this VM if we don't already have it.
   */
  acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_CHECK(acquired_lock, EBUSY);

  switch(msr) {
  /*
   * Read/Write allowed.
   */
  case MSR_IA32_SYSENTER_CS:
  case MSR_IA32_SYSENTER_EIP:
  case MSR_IA32_SYSENTER_ESP:
  case MSR_SPEC_CTRL:
  case MSR_FS_BASE:
  case MSR_GS_BASE:
  case MSR_SHADOW_GS_BASE:
  case MSR_IA32_PAT:
  case MSR_IA32_BNDCFGS:
    break;

  /*
   * Read-only allowed.
   */
  case MSR_EFER:
    SVA_CHECK(!(rw & VMX_EXIT_BITMAP_W), EPERM);
    break;

  /*
   * Write-only allowed.
   */
  case MSR_FLUSH_CMD:
  case MSR_PRED_CMD:
    SVA_CHECK(!(rw & VMX_EXIT_BITMAP_R), EPERM);
    break;

  /*
   * Access to x2APIC MSRs is allowed as long as the vlAPIC is in x2APIC mode.
   */
  case MSR_X2APIC_TPR:
    goto x2apic_msr;

  case MSR_X2APIC_ID:
  case MSR_X2APIC_VERSION:
  case MSR_X2APIC_PPR:
  case MSR_X2APIC_LDR:
  case MSR_X2APIC_SIVR:
  case MSR_X2APIC_ISR(0) ... MSR_X2APIC_ISR(7):
  case MSR_X2APIC_TMR(0) ... MSR_X2APIC_TMR(7):
  case MSR_X2APIC_IRR(0) ... MSR_X2APIC_IRR(7):
  case MSR_X2APIC_ESR:
  case MSR_X2APIC_LVT_CMCI:
  case MSR_X2APIC_ICR:
  case MSR_X2APIC_LVT_TIMER:
  case MSR_X2APIC_LVT_THERMAL:
  case MSR_X2APIC_LVT_PMI:
  case MSR_X2APIC_LVT_LINT0:
  case MSR_X2APIC_LVT_LINT1:
  case MSR_X2APIC_LVT_ERROR:
  case MSR_X2APIC_INIT_COUNT:
  case MSR_X2APIC_CUR_COUNT:
  case MSR_X2APIC_DIV_CONF:
    SVA_CHECK(!(rw & VMX_EXIT_BITMAP_W), EPERM);
    goto x2apic_msr;

  case MSR_X2APIC_EOI:
  case MSR_X2APIC_SELF_IPI:
    SVA_CHECK(!(rw & VMX_EXIT_BITMAP_R), EPERM);
    goto x2apic_msr;

  x2apic_msr:
    SVA_CHECK(vm->vlapic.mode == VLAPIC_X2APIC, EPERM);
    break;

  default:
    SVA_CHECK(false, EPERM);
  }
  __sva_intrinsic_result = msr_bitmaps_clear_intercept(vm, msr, rw);

__sva_fail:
  if (acquired_lock == 2) {
    vm_desc_unlock(vm);
  }

  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
  return __sva_intrinsic_result;
}

int sva_vmx_msr_intercept_set(int vmid, uint32_t msr, enum vmx_exit_bitmap_rw rw) {
  int __sva_intrinsic_result;
  unsigned long rflags = sva_enter_critical();
  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  SVA_CHECK(vmid >= 0 && vmid <= MAX_VMS, ESRCH);
  vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_CHECK(acquired_lock, EBUSY);

  __sva_intrinsic_result = msr_bitmaps_set_intercept(vm, msr, rw);

  if (acquired_lock == 2) {
    vm_desc_unlock(vm);
  }

__sva_fail:
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
  return __sva_intrinsic_result;
}

static int io_bitmaps_init(vm_desc_t* vm) {
  vm->io_exiting_bitmaps[0] = exiting_bitmap_create();
  vm->io_exiting_bitmaps[1] = exiting_bitmap_create();
  return 0;
}

static int io_bitmaps_free(vm_desc_t* vm) {
  exiting_bitmap_free(vm->io_exiting_bitmaps[0]);
  exiting_bitmap_free(vm->io_exiting_bitmaps[1]);
  return 0;
}

static inline int io_bitmaps_op_intercept(
    void (*op)(unsigned char*, size_t, bool*),
    bool* out,
    vm_desc_t* vm,
    uint16_t port)
{
  unsigned char* io_bitmap = __va(vm->io_exiting_bitmaps[port < 0x8000 ? 0 : 1]);

  bool result;
  op(io_bitmap, port & 0x7fff, &result);
  if (out != NULL) {
    *out = result;
  }

  return 0;
}

int io_bitmaps_get_intercept(vm_desc_t* vm, uint16_t port, bool* out) {
  *out = false;
  return io_bitmaps_op_intercept(get_bit, out, vm, port);
}

int io_bitmaps_clear_intercept(vm_desc_t* vm, uint16_t port) {
  return io_bitmaps_op_intercept(clear_bit, NULL, vm, port);
}

int io_bitmaps_set_intercept(vm_desc_t* vm, uint16_t port) {
  return io_bitmaps_op_intercept(set_bit, NULL, vm, port);
}

int sva_vmx_io_intercept_get(int vmid, uint16_t port) {
  int __sva_intrinsic_result;
  unsigned long rflags = sva_enter_critical();
  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  SVA_CHECK(vmid >= 0 && vmid <= MAX_VMS, ESRCH);
  vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_CHECK(acquired_lock, EBUSY);

  bool out;
  int res;
  if ((res = io_bitmaps_get_intercept(vm, port, &out)) == 0) {
    __sva_intrinsic_result = (int)out;
  } else {
    __sva_intrinsic_result = res;
  }

  if (acquired_lock == 2) {
    vm_desc_unlock(vm);
  }

__sva_fail:
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
  return __sva_intrinsic_result;
}

int sva_vmx_io_intercept_clear(int vmid, uint16_t port) {
  int __sva_intrinsic_result;
  unsigned long rflags = sva_enter_critical();
  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  SVA_CHECK(vmid >= 0 && vmid <= MAX_VMS, ESRCH);
  vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_CHECK(acquired_lock, EBUSY);

  __sva_intrinsic_result = io_bitmaps_clear_intercept(vm, port);

  if (acquired_lock == 2) {
    vm_desc_unlock(vm);
  }

__sva_fail:
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
  return __sva_intrinsic_result;
}

int sva_vmx_io_intercept_set(int vmid, uint16_t port) {
  int __sva_intrinsic_result;
  unsigned long rflags = sva_enter_critical();
  kernel_to_usersva_pcid();

  SVA_CHECK(getCPUState()->vmx_initialized, ENODEV);

  SVA_CHECK(vmid >= 0 && vmid <= MAX_VMS, ESRCH);
  vm_desc_t* vm = &vm_descs[vmid];

  /*
   * Take the lock for this VM if we don't already have it.
   */
  int acquired_lock = vm_desc_ensure_lock(&vm_descs[vmid]);
  SVA_CHECK(acquired_lock, EBUSY);

  __sva_intrinsic_result = io_bitmaps_set_intercept(vm, port);

  if (acquired_lock == 2) {
    vm_desc_unlock(vm);
  }

__sva_fail:
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
  return __sva_intrinsic_result;
}
