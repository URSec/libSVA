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
#include <sva/mmu.h>
#include <sva/config.h>

#include <string.h>
#include <stddef.h> // for offsetof()

/**********
 * Global variables
 *
 * (Some of these are really global; others are static, i.e. local to this
 * file but not local to a function.)
 *
 * (Eventually, some of these may need to be handled in a more complex way to
 * support SMP. For instance, we might want to store some of them on a
 * per-CPU basis in some structure already used for that purpose.)
**********/
/* Indicates whether sva_initvmx() has yet been called by the OS. No SVA-VMX
 * intrinsics may be called until this has been done.
 */
unsigned char __attribute__((section("svamem"))) sva_vmx_initialized = 0;

/* Physical address of the VMXON region. This is a special region of memory
 * that the active logical processor uses to "support VMX operation" (see
 * section 24.11.5 in the Intel reference manual, Oct. 2017).
 *
 * All we need to do is allocate it, initialize one of its fields, and pass
 * its physical address as an argument to the VMXON instruction, which enters
 * VMX operation on the active logical processor. From that point, this
 * region belongs entirely to the processor and we're not supposed to touch
 * it (unless and until we switch VMX support back off using the VMXOFF
 * instruction).
 *
 * The VMXON region has (by definition) the same size and alignment
 * requirements as a VMCS. However, unlike the VMCS, there is only one VMXON
 * region per logical processor, not per virtual machine. It also does not
 * have any of the memory type (cacheability properties) restrictions that a
 * VMCS has.
 */
static uintptr_t __attribute__((section("svamem"))) VMXON_paddr = 0;

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
 * This array is zero-initialized in sva_initvmx(), which effectively marks
 * all entries as unused (and the corresponding VM IDs as free to be
 * assigned).
 */
struct vm_desc_t __attribute__((section("svamem"))) vm_descs[MAX_VMS];

/*
 * A structure describing host state for each CPU.
 * 
 * TODO: this should be an array so we're multiprocessor-ready.
 *
 * Includes:
 *  - A pointer to the VM descriptor (vm_desc_t) for the VM currently loaded
 *    on the processor, or null if no VM is loaded.
 *  - Places for the host GPRs to be saved/restored across VM entries/exits.
 *
 * An alternative would be to do this in sva_initvmx(), but this is cleaner
 * and safer (doesn't rely on the assumption that specific code is being run
 * at a specific time).
 *
 */
static vmx_host_state_t __attribute__((section("svamem"))) host_state = {
  /* We use an explicit initializer here to ensure that the active_vm field
   * is initialized to a null pointer before any code can run. It's important
   * this be done before any SVA intrinsics can be called, because their
   * checks use this pointer to determine if a VM is active.
   */
  .active_vm = 0

  /* The other fields don't need to be explicitly initialized. */
};

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

  uint32_t cpuid_ecx = 0xdeadbeef;
  DBGPRNT(("Executing CPUID with 1 in EAX...\n"));
  asm __volatile__ (
      "cpuid"
      : "=c" (cpuid_ecx)
      : "a" (1)
      : "eax", "ebx", "ecx", "edx"
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
 * Function: cpu_supports_smx()
 *
 * Description:
 *  Checks whether the processor supports SMX using the CPUID instruction.
 *
 * Return value:
 *  True if the processor supports SMX, false otherwise.
 */
static inline unsigned char
cpu_supports_smx(void) {
  uint32_t cpuid_ecx = cpuid_1_ecx();
  uint32_t supports_smx = cpuid_ecx & CPUID_01H_ECX_SMX_BIT;

  return (supports_smx ? 1 : 0);
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

  unsigned char supports_smx = cpu_supports_smx();

  DBGPRNT(("Reading IA32_FEATURE_CONTROL MSR...\n"));
  uint64_t feature_control_data = rdmsr(FEATURE_CONTROL_MSR);
  DBGPRNT(("IA32_FEATURE_CONTROL MSR = 0x%lx\n", feature_control_data));

  uint64_t feature_control_locked =
    feature_control_data & FEATURE_CONTROL_LOCK_BIT;
  uint64_t feature_control_vmxallowed_outside_smx =
    feature_control_data & FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX_BIT;
  uint64_t feature_control_vmxallowed_within_smx =
    feature_control_data & FEATURE_CONTROL_ENABLE_VMXON_WITHIN_SMX_BIT;

  /* If the MSR is locked and in the "disallow VMX" setting, then there is
   * nothing we can do; we cannot use VMX.
   *
   * (If this is the case, it is probably due to a BIOS setting prohibiting
   * VMX.)
   *
   * If the CPU supports SMX, we will return failure if *either* of the bits
   * for disabling VMX in or out of SMX mode are unset and locked. This way,
   * we don't have to worry about whether the CPU is actually in SMX mode.
   */
  if (supports_smx) {
    if (feature_control_locked && !feature_control_vmxallowed_within_smx) {
      DBGPRNT(("CPU locked to disallow VMX in SMX mode "
          "(and CPU supports SMX)!\n"));
      return 0;
    }
  }
  if (feature_control_locked && !feature_control_vmxallowed_outside_smx) {
    DBGPRNT(("CPU locked to disallow VMX outside of SMX mode!\n"));
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
   *
   * We can ONLY set the "allow VMX in SMX mode" bit if the processor
   * actually supports SMX; otherwise we will cause a general-protection
   * fault.
   */
  feature_control_data |= FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX_BIT;
  if (supports_smx) {
    feature_control_data |= FEATURE_CONTROL_ENABLE_VMXON_WITHIN_SMX_BIT;
  }
  feature_control_data |= FEATURE_CONTROL_LOCK_BIT;

  DBGPRNT(("Writing new value of IA32_FEATURE_CONTROL MSR to permit VMX: "
      "0x%lx\n", feature_control_data));
  wrmsr(FEATURE_CONTROL_MSR, feature_control_data);

  /* Read back the MSR to confirm this worked. */
  if (rdmsr(FEATURE_CONTROL_MSR) != feature_control_data) {
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
  uint64_t cr0_value = _rcr0();
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
  uint64_t cr4_value = _rcr4();
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
 *  Prepares the SVA Execution Engine to support VMX operations.  (This may
 *  include, for instance, initializing internal data structures and issuing
 *  instructions which enable hardware VMX support.)
 *
 *  **Must be called before using any other SVA-VMX intrinsic!**
 *
 * Return value:
 *  True if VMX initialization was successful (or initialization was not
 *  performed because it was already done earlier), false otherwise.
 *
 * TODO:
 *  Figure out where I'm actually supposed to put libsva initialization
 *  code! (This function should probably be called by said initialization
 *  code automatically during boot, rather than called by the OS as an
 *  intrinsic.)
 *  (If we do decide to keep this as an intrinsic, all the other SVA_VMX
 *  intrinsics will need to check if sva_vmx_initialized is true before doing
 *  anything.)
 */
unsigned char
sva_initvmx(void) {
  if ( usevmx ) {
    if (sva_vmx_initialized) {
      DBGPRNT(("Kernel called sva_initvmx(), but it was already initialized.\n"));
      return 1;
    }
  }

  /* Zero-initialize the array of virtual machine descriptors.
   *
   * This has the effect of marking all VM IDs as free to be assigned.
   */
  for (size_t i = 0; i < MAX_VMS; i++) {
    memset(&vm_descs[i], 0, sizeof(vm_desc_t));
  }

  /* Check to see if VMX is supported by the CPU, and if so, set the
   * IA32_FEATURE_CONTROL MSR to permit VMX operation. If this does not
   * succeed (e.g. because the BIOS or other kernel code has blocked the
   * feature), return failure.
   */
  if (!cpu_permit_vmx()) {
    DBGPRNT(("CPU does not support VMX (or the feature is blocked); "
        "cannot initialize SVA VMX support.\n"));
    return 0;
  }

  /* Sanity check: VMCS_ALLOC_SIZE should be exactly one frame (4 kB). If we
   * ever set VMCS_ALLOC_SIZE to something different, this code will need to
   * be restructured.
   */
  if ( usevmx ) {
	  SVA_ASSERT(VMCS_ALLOC_SIZE == X86_PAGE_SIZE,
				 "SVA: error: VMCS_ALLOC_SIZE is not the same as X86_PAGE_SIZE!\n");
  }

  /* Set the "enable VMX" bit in CR4. This enables VMX operation, allowing us
   * to enter VMX operation by executing the VMXON instruction. Once we have
   * done so, we cannot unset the "enable VMX" bit in CR4 unless we have
   * first exited VMX operation by executing the VMXOFF instruction.
   */
  uint64_t orig_cr4_value = _rcr4();
  DBGPRNT(("Original value of CR4: 0x%lx\n", orig_cr4_value));
  uint64_t new_cr4_value = orig_cr4_value | CR4_ENABLE_VMX_BIT;
  DBGPRNT(("Setting new value of CR4 to enable VMX: 0x%lx\n", new_cr4_value));
  load_cr4(new_cr4_value);
  DBGPRNT(("Confirming new CR4 value: 0x%lx\n", _rcr4()));

  /* Confirm that the values of CR0 and CR4 are allowed for entry into VMX
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
    load_cr4(orig_cr4_value);
    DBGPRNT(("Confirming CR4 restoration: 0x%lx\n", _rcr4()));

    return 0;
  }

  /* Allocate a frame of physical memory to use for the VMXON region.
   * This should only be accessible to SVA (and the hardware), so we will NOT
   * map it into any kernel- or user-space page tables.
   */
  VMXON_paddr = alloc_frame();

  /* Initialize the VMXON region.
   *
   * The Intel manual only specifies that we should write the VMCS revision
   * identifier to bits 30:0 of the first 4 bytes of the VMXON region, and
   * that bit 31 should be cleared to 0. It says that we "need not initialize
   * the VMXON region in any other way." For good measure, though, we'll
   * zero-fill the rest of it.
   */
  unsigned char * VMXON_vaddr = getVirtualSVADMAP(VMXON_paddr);

  DBGPRNT(("Zero-filling VMXON frame...\n"));
  memset(VMXON_vaddr, 0, VMCS_ALLOC_SIZE);

  DBGPRNT(("Reading IA32_VMX_BASIC MSR...\n"));
  uint64_t vmx_basic_data = rdmsr(MSR_VMX_BASIC);
  DBGPRNT(("IA32_VMX_BASIC MSR = %lx\n", vmx_basic_data));

  /* Write the VMCS revision identifier to bits 30:0 of the first 4 bytes of
   * the VMXON region, and clear bit 31 to 0. The VMCS revision identifier is
   * (conveniently) given in bits 30:0 of the IA32_VMX_BASIC MSR, and bit 31
   * of that MSR is guaranteed to always be 0, so we can just copy those
   * lower 4 bytes to the beginning of the VMXON region.
   */
  uint32_t VMCS_rev_id = (uint32_t) vmx_basic_data;
  DBGPRNT(("VMCS revision identifier: %x\n", VMCS_rev_id));
  uint32_t * VMXON_id_field = (uint32_t *) VMXON_vaddr;
  *VMXON_id_field = VMCS_rev_id;
  DBGPRNT(("VMCS revision identifier written to VMXON region.\n"));

  DBGPRNT(("Physical address of VMXON: 0x%lx\n", VMXON_paddr));
  DBGPRNT(("Virtual address of VMXON pointer: 0x%lx\n", &VMXON_paddr));
  /* Enter VMX operation. This is done by executing the VMXON instruction,
   * passing the physical address of the VMXON region as a memory operand.
   */
  DBGPRNT(("Entering VMX operation...\n"));
  uint64_t rflags;
  asm __volatile__ (
      "vmxon (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags)
      : "r" (&VMXON_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags) == VM_SUCCEED) {
    DBGPRNT(("SVA VMX support successfully initialized.\n"));

    if ( usevmx ) {
      sva_vmx_initialized = 1;
    }
    return 1;
  } else {
    DBGPRNT(("Could not enter VMX host mode. "
          "SVA VMX support not initialized.\n"));

    /* Restore CR4 to its original value. */
    DBGPRNT(("Restoring CR4 to its original value: 0x%lx\n", orig_cr4_value));
    load_cr4(orig_cr4_value);
    DBGPRNT(("Confirming CR4 restoration: 0x%lx\n", _rcr4()));

    /* Free the frame of SVA secure memory we allocated for the VMXON region.
     */
    DBGPRNT(("Returning VMXON frame to SVA.\n"));
    free_frame(VMXON_paddr);

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
 * Arguments:
 *  - initial_ctrls: the initial control settings that will define the
 *    parameters under which this VM will operate.
 *  - initial_state: the initial state of the guest system virtualized by
 *    this VM.
 *  - initial_eptable: a (host-virtual) pointer to the initial top-level
 *    extended page table (EPML4) that will map this VM's guest-physical
 *    memory space to host-physical frames.
 *
 * Return value:
 *  A positive integer which will be used to identify this virtual
 *  machine in future invocations of VMX intrinsics. If the return value is
 *  negative, an error occurred and nothing was allocated.
 *
 *  FIXME: You're returning negative error codes, but the return type is
 *  size_t, an unsigned type...
 */
size_t
sva_allocvm(sva_vmx_vm_ctrls initial_ctrls,
    sva_vmx_guest_state initial_state,
    pml4e_t *initial_eptable) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_allocvm() intrinsic called.\n"));

  if ( usevmx ) {
      if (!sva_vmx_initialized) {
          /* sva_initvmx() is responsible for zero-initializing the vm_descs array
           * and thus marking its slots as free for use. */
          panic("Fatal error: must call sva_initvmx() before any other "
                "SVA-VMX intrinsic.\n");
      }
  }

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
  size_t vmid = -1;
  for (size_t i = 1; i < MAX_VMS; i++) {
    if (vm_descs[i].vmcs_paddr == 0) {
      DBGPRNT(("First free VM ID found: %lu\n", i));

      vmid = i;
      break;
    }
  }

  /* If there were no free slots, return failure. */
  if (vmid == -1) {
    DBGPRNT(("Error: all %lu VM IDs are in use; cannot create a new VM.\n",
          MAX_VMS));

    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

  /*
   * Initialize VMCS controls.
   */
  vm_descs[vmid].ctrls = initial_ctrls;
  /*
   * Initialize the guest system state (registers, program counter, etc.).
   */
  vm_descs[vmid].state = initial_state;
  /*
   * Initialize the Extended Page Table Pointer (EPTP).
   *
   * We directly call the helper function that implements the main
   * functionality of sva_load_eptable(), because we know vmid is valid (but
   * still need to vet the extended page table pointer).
   */
  load_eptable_internal(vmid, initial_eptable, 1 /* is initial setting */);

  /*
   * Allocate a physical frame of SVA secure memory from the frame cache to
   * serve as this VM's Virtual Machine Control Structure.
   *
   * This frame is not mapped anywhere except in SVA's DMAP, ensuring that
   * the OS cannot touch it without going through an SVA intrinsic.
   */
  vm_descs[vmid].vmcs_paddr = alloc_frame();

  /* Zero-fill the VMCS frame, for good measure. */
  unsigned char * vmcs_vaddr = getVirtualSVADMAP(vm_descs[vmid].vmcs_paddr);
  memset(vmcs_vaddr, 0, VMCS_ALLOC_SIZE);

  /*
   * Write the processor's VMCS revision identifier to the first 31 bits of
   * the VMCS frame, and clear the 32nd bit.
   *
   * This value is given in the lower 31 bits of the IA32_VMX_BASIC MSR.
   * Conveniently, the 32nd bit of that MSR is always guaranteed to be 0, so
   * we can just copy the lower 4 bytes.
   */
  uint64_t vmx_basic_data = rdmsr(MSR_VMX_BASIC);
  uint32_t vmcs_rev_id = (uint32_t) vmx_basic_data;
  *((uint32_t*)vmcs_vaddr) = vmcs_rev_id;

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
        vm_descs[vmid].vmcs_paddr));
  uint64_t rflags_vmclear;
  asm __volatile__ (
      "vmclear (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmclear)
      : "r" (&vm_descs[vmid].vmcs_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmclear) == VM_SUCCEED) {
    DBGPRNT(("Successfully initialized VMCS.\n"));
  } else {
    DBGPRNT(("Error: failed to initialize VMCS with VMCLEAR.\n"));

    /* Return the VMCS frame to the frame cache. */
    DBGPRNT(("Returning VMCS frame 0x%lx to SVA.\n", vm_descs[vmid].vmcs_paddr));
    free_frame(vm_descs[vmid].vmcs_paddr);

    /* Restore the VM descriptor to a clear state so that it is interpreted
     * as a free slot.
     */
    memset(&vm_descs[vmid], 0, sizeof(vm_desc_t));

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

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
 *  The VMCS frame will be returned to the frame cache, and the VM's
 *  descriptor structure will be zero-filled. This marks its numeric ID and
 *  slot in the vm_descs array as unused so they can be recycled.
 *
 * Arguments:
 *  - vmid: the numeric handle of the virtual machine to be deallocated.
 */
void
sva_freevm(size_t vmid) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_freevm() intrinsic called for VM ID: %lu\n", vmid));

  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /* Bounds check on vmid.
   *
   * (vmid is unsigned, so this also checks for negative values.)
   */
  if ( usevmx ) {
      if (vmid >= MAX_VMS) {
          panic("Fatal error: specified out-of-bounds VM ID!\n");
      }
  }
  /* If this VM's VMCS pointer is already null, this is a double free (or
   * freeing a VM ID which was never allocated).
   */
  if ( usevmx ) {
      if (!vm_descs[vmid].vmcs_paddr) {
          panic("Fatal error: tried to free a VM which was already unallocated!\n");
      }
  }

  /* Don't free a VM which is still active on the processor. */
  if ( usevmx ) {
    if (host_state.active_vm == &vm_descs[vmid]) {
      panic("Fatal error: tried to free a VM which is active on the "
            "processor!\n");
    }
  }

  if ( usevmx ) {
    /*
     * Decrement the refcount for the VM's top-level extended-page-table page
     * to reflect the fact that this VM is no longer using it.
     */
    page_desc_t *ptpDesc = getPageDescPtr(vm_descs[vmid].eptp);
    /*
     * Check that the refcount isn't already zero (in which case we'd
     * underflow). If so, our frame metadata has become inconsistent (as a
     * reference clearly exists).
     */
    SVA_ASSERT(pgRefCount(ptpDesc) > 0,
               "SVA: MMU: frame metadata inconsistency detected "
               "(attempted to decrement refcount below zero)");
    ptpDesc->count--;
  }

  /* Return the VMCS frame to the frame cache. */
  DBGPRNT(("Returning VMCS frame 0x%lx to SVA.\n", vm_descs[vmid].vmcs_paddr));
  free_frame(vm_descs[vmid].vmcs_paddr);

  /* Zero-fill this slot in the vm_descs struct to mark it as unused. */
  memset(&vm_descs[vmid], 0, sizeof(vm_desc_t));

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
 *  Fails if another VM is already active on the processor. If that is the
 *  case, you should call sva_unloadvm() first to make it inactive.
 *
 * Arguments:
 *  - vmid: the numeric handle of the virtual machine to be made active.
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
 */
int
sva_loadvm(size_t vmid) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_loadvm() intrinsic called for VM ID: %lu\n", vmid));
  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /* Bounds check on vmid.
   *
   * (vmid is unsigned, so this also checks for negative values.)
   */
  if ( usevmx ) {
      if (vmid >= MAX_VMS) {
          panic("Fatal error: specified out-of-bounds VM ID!\n");
      }
  }
  /* If this VM descriptor indicated by this ID has a null VMCS pointer, it
   * is not a valid descriptor. (i.e., it is an empty slot not assigned to
   * any VM)
   */
  if ( usevmx ) {
      if (!vm_descs[vmid].vmcs_paddr) {
          panic("Fatal error: tried to load an unallocated VM!\n");
      }
  }
  /* If there is currently a VM active on the processor, it must be unloaded
   * before we can load a new one. Return an error.
   *
   * A non-null active_vm pointer indicates there is an active VM.
   */
  if ( usevmx ) {
    if (host_state.active_vm) {
      DBGPRNT(("Error: there is already a VM active on the processor. "
               "Cannot load a different VM until it is unloaded.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /* Set the indicated VM as the active one. */
  host_state.active_vm = &vm_descs[vmid];

  /* Use the VMPTRLD instruction to make the indicated VM's VMCS active on
   * the processor.
   */
  DBGPRNT(("Using VMPTRLD to make active the VMCS at paddr 0x%lx...\n",
        host_state.active_vm->vmcs_paddr));
  uint64_t rflags_vmptrld;
  asm __volatile__ (
      "vmptrld (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmptrld)
      : "r" (&(host_state.active_vm->vmcs_paddr))
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmptrld) == VM_SUCCEED) {
    DBGPRNT(("Successfully loaded VMCS onto the processor.\n"));
  } else {
    DBGPRNT(("Error: failed to load VMCS onto the processor.\n"));

    /* Unset the active_vm pointer. */
    host_state.active_vm = 0;

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

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
 *  Unload the current virtual machine from the processor.
 *
 *  Fails if no VM is currently active on the processor.
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
 */
int
sva_unloadvm(void) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  DBGPRNT(("sva_unloadvm() intrinsic called.\n"));

  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if ( usevmx ) {
    if (!host_state.active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor to unload.\n"));
      
      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /* Use the VMCLEAR instruction to unload the current VM from the processor.
   */
  DBGPRNT(("Using VMCLEAR to unload VMCS with address 0x%lx from the "
        "processor...\n", host_state.active_vm->vmcs_paddr));
  uint64_t rflags_vmclear;
  asm __volatile__ (
      "vmclear (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags_vmclear)
      : "r" (&(host_state.active_vm->vmcs_paddr))
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags_vmclear) == VM_SUCCEED) {
    DBGPRNT(("Successfully unloaded VMCS from the processor.\n"));

    /* Mark the VM as "not launched". If we load it back onto the processor
     * in the future, we will need to use sva_launchvm() instead of
     * sva_resumevm() to resume its guest-mode operation.
     */
    host_state.active_vm->is_launched = 0;

    /* Set the active_vm pointer to indicate no VM is active. */
    host_state.active_vm = 0;
  } else {
    DBGPRNT(("Error: failed to unload VMCS from the processor.\n"));

    /* Return failure. */
    usersva_to_kernel_pcid();
    sva_exit_critical(rflags);
    return -1;
  }

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
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
 */
int
sva_readvmcs(enum sva_vmcs_field field, uint64_t *data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

#if 0
  DBGPRNT(("sva_readvmcs() intrinsic called with field="));
  print_vmcs_field_name(field);
  DBGPRNT((" (0x%lx), data=%p\n", field, data));
#endif
  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /*
   * If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if ( usevmx ) {
    if (!host_state.active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot read from VMCS.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Perform the read if it won't leak sensitive information to the system
   * software (or if it can be sanitized).
   */
  int retval;
  if ( usevmx ) {
    retval = readvmcs_checked(field, data);
  } else { 
    retval = readvmcs_unchecked(field, data);
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
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
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
  print_vmcs_field_name(field);
  DBGPRNT((" (0x%lx), data=0x%lx\n", field, data));
#endif

  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /*
   * If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if ( usevmx ) {
    if (!host_state.active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot write to VMCS.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /*
   * Vet the value to be written to ensure that it will not compromise system
   * security, and perform the write.
   */
  int retval; 
  if ( usevmx ) { 
    retval = writevmcs_checked(field, data);
  } else { 
    retval = writevmcs_unchecked(field, data);
  }

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

  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if ( usevmx ) {
    if (!host_state.active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot launch VM.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /* If the VM has been launched before since being loaded onto the
   * processor, the sva_resumevm() intrinsic must be used instead of this
   * one.
   */
  if ( usevmx ) {
    if (host_state.active_vm->is_launched) {
      DBGPRNT(("Error: Must use sva_resumevm() to enter a VM which "
               "was previously run since being loaded on the processor.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /* Mark the VM as launched. Until this VM is unloaded from the processor,
   * future entries to it must be performed using the sva_resumevm()
   * intrinsic.
   */
  host_state.active_vm->is_launched = 1;

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

  DBGPRNT(("sva_resumevm() intrinsic called.\n"));
  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if ( usevmx ) {
    if (!host_state.active_vm) {
      DBGPRNT(("Error: there is no VM active on the processor. "
               "Cannot resume VM.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /* If the VM has not previously been launched at least once since being
   * loaded onto the processor, the sva_launchvm() intrinsic must be used
   * instead of this one.
   */
  if ( usevmx ) {
    if (!host_state.active_vm->is_launched) {
      DBGPRNT(("Error: Must use sva_launchvm() to enter a VM which hasn't "
               "previously been run since being loaded on the processor.\n"));

      usersva_to_kernel_pcid();
      sva_exit_critical(rflags);
      return -1;
    }
  }

  /* Enter guest-mode execution (which will ultimately exit back into host
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
 *  - Updating any VMCS controls that have become stale, either because the
 *    VM is being run for the first time or because the hypervisor has edited
 *    them since the last time it was run.
 *
 *  - Updating any guest-state fields in the VMCS that have become stale,
 *    either because the VM is being run for the first time or because the
 *    hypervisor has edited them (using the sva_setvmstate() intrinsic) since
 *    the last time it was run.
 *
 *  - Loading the extended page table pointer (EPTP) for the VM.
 *
 *  - Setting various VMCS fields containing host state to be restored on VM
 *    exit. These include the control registers, segment registers, the
 *    kernel program counter and stack pointer, and the MSRs that control
 *    fast system calls.
 *
 *  - Saving additional host state that will not automatically be restored by
 *    the processor on VM exit. This includes all the general purpose
 *    registers (TODO: and probably the floating point and other specialized
 *    computation registers).
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
  /*
   * If this is the first time this VM has ever been run, set any VMCS fields
   * that have known values and will never need to be changed as long as the
   * VM exists.
   */
  if (!host_state.active_vm->has_run) {
    DBGPRNT(("run_vm: Setting fixed VMCS controls for first run of VM...\n"));

    /*
     * Set the VPID (Virtual Processor ID) field to be equal to the VM ID
     * assigned to this VM by SVA.
     *
     * The VPID distinguishes TLB entries belonging to the VM from those
     * belonging to the host and to other VMs.
     *
     * It must NOT be set to 0; that is used for the host.
     */
    /* TODO: SVA should really be using 16-bit integers for VM ID's, since
     * VPIDs are limited to 16 bits. This is a processor-imposed hard limit on
     * the number of VMs we can run concurrently if we want to take advantage
     * of the VPID feature.
     *
     * Note also that we will need to avoid assigning 0 as a VM ID, since VPID
     * = 0 is used to designate the host (and VM entry will fail if we attempt
     * to use it for a VM).
     *
     * Also note: when we (in the future) want to support multi-CPU guests,
     * each virtual CPU will require its own VMCS and VPID. Think about how we
     * want to handle this: should the hypervisor be responsible for creating
     * an independent "VM" (as far as SVA is concerned) for each VCPU and
     * coordinating between them? Or is there a compelling reason for SVA to
     * track them together? If so, we will need to devise a new scheme for
     * allocating VPIDs, independent of SVA's VM IDs.
     */

    /*
     * Determine the numeric ID of this VM. This is equal to its descriptor's
     * index within the vm_descs array. We only have the active_vm pointer
     * directly to the descriptor, so we need to do some pointer arithmetic
     * to get the index.
     *
     * TODO: this will no longer be necessary when you change
     * sva_launch/resumevm() to take a VMID as a parameter.
     */
    size_t vmid = host_state.active_vm - vm_descs;

    writevmcs_unchecked(VMCS_VPID, vmid);

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
     * guest stsate management.
     */
    writevmcs_unchecked(VMCS_VM_ENTRY_MSR_LOAD_COUNT, 0);
    writevmcs_unchecked(VMCS_VM_EXIT_MSR_LOAD_COUNT, 0);
    writevmcs_unchecked(VMCS_VM_EXIT_MSR_STORE_COUNT, 0);

    /*
     * Load the initial values of VMCS controls that were passed to
     * sva_allocvm() when this VM was created.
     */
    DBGPRNT(("run_vm: Initializing non-fixed VMCS controls for "
          "first run...\n"));
    update_vmcs_ctrls();

    /*
     * Load the initial values of VMCS-resident guest state fields that were
     * passed to sva_allocvm() when this VM was created.
     */
    DBGPRNT(("run_vm: Initializing VMCS-resident guest state fields for "
          "first run...\n"));
    save_restore_guest_state(0 /* this is a "restore" operation */);

    /*
     * Record the fact that we have set these one-time fields so we don't
     * need to do it again on future runs.
     */
    host_state.active_vm->has_run = 1;
  }

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
   * Set the host-state-object fields to recognizable nonsense values so that
   * we can spot them easily in the debugger if we mess up and fail to
   * restore state correctly.
   *
   * (We can remove this code when we're confident this is working well.)
   */
  host_state.rbp = 0xf00f00f0f00f00f0;
  host_state.rsi = 0xf00f00f0f00f00f0;
  host_state.rdi = 0xf00f00f0f00f00f0;
  host_state.r8  = 0xf00f00f0f00f00f0;
  host_state.r9  = 0xf00f00f0f00f00f0;
  host_state.r10 = 0xf00f00f0f00f00f0;
  host_state.r11 = 0xf00f00f0f00f00f0;
  host_state.r12 = 0xf00f00f0f00f00f0;
  host_state.r13 = 0xf00f00f0f00f00f0;
  host_state.r14 = 0xf00f00f0f00f00f0;
  host_state.r15 = 0xf00f00f0f00f00f0;

  /*
   * Save host state in the VMCS that will be restored automatically by the
   * processor on VM exit.
   */
  DBGPRNT(("run_vm: Saving host state...\n"));
  /* Control registers */
  uint64_t host_cr0 = _rcr0();
  writevmcs_unchecked(VMCS_HOST_CR0, host_cr0);
  uint64_t host_cr3 = _rcr3();
  writevmcs_unchecked(VMCS_HOST_CR3, host_cr3);
  uint64_t host_cr4 = _rcr4();
  writevmcs_unchecked(VMCS_HOST_CR4, host_cr4);
  DBGPRNT(("run_vm: Saved host control registers.\n"));

  /* Segment selectors */
  uint16_t es_sel, cs_sel, ss_sel, ds_sel, fs_sel, gs_sel, tr_sel;
  asm __volatile__ (
      "mov %%es, %0\n"
      "mov %%cs, %1\n"
      "mov %%ss, %2\n"
      "mov %%ds, %3\n"
      "mov %%fs, %4\n"
      "mov %%gs, %5\n"
      "str %6\n"
      : "=rm" (es_sel), "=rm" (cs_sel), "=rm" (ss_sel), "=rm" (ds_sel),
        "=rm" (fs_sel), "=rm" (gs_sel), "=rm" (tr_sel)
      );
  /* The saved host selectors must have RPL = 0 and TI = 0 on VM entry.
   * (Intel manual, section 26.2.3.)
   *
   * FreeBSD/SVA normally has the RPLs for DS, ES, and FS set to 3 in kernel
   * mode; those will get changed to 0 on VM exit.
   *
   *  TODO: Do we need to undo this after VM exit to ensure safety?
   *
   *        The fact that the OS leaves these RPLs at 3 in kernel mode makes
   *        me suspicious that it's doing so to avoid having to reload the
   *        selectors before SYSRET. If so, then what we're doing here will
   *        catch the OS "unawares" and leave the data segment RPLs at 0 on
   *        return to user mode.
   *
   *        Note also that VM exit directly sets the in-processor DPLs to 0
   *        for all usable segments, regardless of what's in the in-memory
   *        descriptors (and regardless of what's set in these
   *        saved-host-selector fields that are restored on VM exit). This
   *        too could open a security hole if the OS is counting on itself
   *        not having reloaded any segment selectors (i.e., it might not
   *        bother loading them before SYSRET).
   *
   *        This could lead to returning to user mode with CPL=3,
   *        (in-processor) DPL=0, and RPL=0. As I understand it, this would
   *        leave user-mode code able to access any memory with privilege
   *        level 0, since the in-processor DPL is (if I'm interpreting the
   *        Intel manual correctly) the one actually used to check
   *        instantaneous memory accesses to the segment.
   *
   *        I'm not sure how this would interact with paging - depending on
   *        how the processor enforces user/supervisor page ownership, this
   *        may or may not be a moot point, since the OS is actually using
   *        that to enforce security isolation, not segmentation per se. It
   *        really depends on whether the processor decides that a memory
   *        access is from the user or supervisor by looking at the CPL (i.e.
   *        the CS in-processor DPL) or the in-processor DPL of the code
   *        segment being used to perform the access. Under "normal"
   *        operation, both methods would be equivalent, because the
   *        processor checks CPL before permitting a data segment's DPL to be
   *        loaded; but this assumption breaks down when using fast
   *        syscall/return, since only the CPL and CS/SS DPLs are changed on
   *        a SYSRET. (It's up to the OS to explicitly change the other
   *        segments if it wants to - and here, if it "knows" it never
   *        changed them since SYSCALL, it has no need to change them back.
   *        It doesn't know that we ran some VMX code that changed it...)
   *
   *        This is easy to fix if we need to: just save the original segment
   *        selectors before VM entry, and re-load them on VM exit. But if we
   *        don't need to, it'll just slow things down.
   */
  writevmcs_unchecked(VMCS_HOST_ES_SEL, es_sel & ~0x7);
  writevmcs_unchecked(VMCS_HOST_CS_SEL, cs_sel & ~0x7);
  writevmcs_unchecked(VMCS_HOST_SS_SEL, ss_sel & ~0x7);
  writevmcs_unchecked(VMCS_HOST_DS_SEL, ds_sel & ~0x7);
  writevmcs_unchecked(VMCS_HOST_FS_SEL, fs_sel & ~0x7);
  writevmcs_unchecked(VMCS_HOST_GS_SEL, gs_sel & ~0x7);
  writevmcs_unchecked(VMCS_HOST_TR_SEL, tr_sel & ~0x7);
  DBGPRNT(("run_vm: Saved host segment selectors.\n"));

  /*
   * Segment and descriptor table base-address registers
   */

  uint64_t fs_base = rdmsr(MSR_FS_BASE);
  writevmcs_unchecked(VMCS_HOST_FS_BASE, fs_base);
  uint64_t gs_base = rdmsr(MSR_GS_BASE);
  writevmcs_unchecked(VMCS_HOST_GS_BASE, gs_base);

  unsigned char gdtr[10], idtr[10];
  /* The sgdt/sidt instructions store a 10-byte "pseudo-descriptor" into
   * memory. The first 2 bytes are the limit field adn the last 8 bytes are
   * the base-address field.
   */
  asm __volatile__ (
      "sgdt (%0)\n"
      "sidt (%1)\n"
      : : "r" (gdtr), "r" (idtr)
      );
  uint64_t gdt_base = *(uint64_t*)(gdtr + 2);
  uint64_t idt_base = *(uint64_t*)(idtr + 2);
  writevmcs_unchecked(VMCS_HOST_GDTR_BASE, gdt_base);
  writevmcs_unchecked(VMCS_HOST_IDTR_BASE, idt_base);
  
  DBGPRNT(("run_vm: Saved host FS, GS, GDTR, and IDTR bases.\n"));

  /* Get the TR base address from the GDT */
  uint16_t tr_gdt_index = (tr_sel >> 3);
#if 0
  DBGPRNT(("TR selector: 0x%hx; index in GDT: 0x%hx\n", tr_sel, tr_gdt_index));
#endif
  uint32_t * gdt = (uint32_t*) gdt_base;
#if 0
  DBGPRNT(("GDT base address: 0x%lx\n", (uint64_t)gdt));
#endif
  uint32_t * tr_gdt_entry = gdt + (tr_gdt_index * 2);

#if 0
  DBGPRNT(("TR entry address: 0x%lx\n", (uint64_t)tr_gdt_entry));
  DBGPRNT(("TR entry low 32 bits: 0x%x\n", tr_gdt_entry[0]));
  DBGPRNT(("TR entry high 32 bits: 0x%x\n", tr_gdt_entry[1]));
#endif

  static const uint32_t SEGDESC_BASEADDR_31_24_MASK = 0xff000000;
  static const uint32_t SEGDESC_BASEADDR_23_16_MASK = 0xff;

  /* This marvelous bit-shifting exposition brought to you by Intel's
   * steadfast commitment to backwards compatibility in the x86 architecture!
   *
   * (At least, I'm guessing that's why this otherwise perfectly normal
   * 64-bit address is split up into four noncontiguous chunks placed at the
   * most inconvenient offsets possible within a 16-byte descriptor...)
   */
  uint32_t tr_baseaddr_15_0 = (tr_gdt_entry[0] >> 16);
  uint32_t tr_baseaddr_23_16 =
    ((tr_gdt_entry[1] & SEGDESC_BASEADDR_23_16_MASK) << 16);
  uint32_t tr_baseaddr_31_24 = tr_gdt_entry[1] & SEGDESC_BASEADDR_31_24_MASK;
  uint32_t tr_baseaddr_31_16 = tr_baseaddr_31_24 | tr_baseaddr_23_16;
  uint32_t tr_baseaddr_31_0 = tr_baseaddr_31_16 | tr_baseaddr_15_0;
  uint64_t tr_baseaddr_63_32 = ((uint64_t)tr_gdt_entry[2] << 32);
  uint64_t tr_baseaddr = tr_baseaddr_63_32 | ((uint64_t)tr_baseaddr_31_0);
#if 0
  DBGPRNT(("Reconstructed TR base address: 0x%lx\n", tr_baseaddr));
#endif
  /* Write our hard-earned TR base address to the VMCS... */
  writevmcs_unchecked(VMCS_HOST_TR_BASE, tr_baseaddr);

  DBGPRNT(("run_vm: Saved host TR base.\n"));

  /* Various MSRs */
  uint64_t ia32_sysenter_cs = rdmsr(MSR_SYSENTER_CS);
  writevmcs_unchecked(VMCS_HOST_IA32_SYSENTER_CS, ia32_sysenter_cs);
  uint64_t ia32_sysenter_esp = rdmsr(MSR_SYSENTER_ESP);
  writevmcs_unchecked(VMCS_HOST_IA32_SYSENTER_ESP, ia32_sysenter_esp);
  uint64_t ia32_sysenter_eip = rdmsr(MSR_SYSENTER_EIP);
  writevmcs_unchecked(VMCS_HOST_IA32_SYSENTER_EIP, ia32_sysenter_eip);
  DBGPRNT(("Saved various host MSRs.\n"));

  /*
   * This is where the magic happens.
   *
   * In this assembly section, we:
   *  - Save the host's general purpose registers to the host_state structure.
   *
   *  - Use the VMWRITE instruction to set the RIP and RSP values that will
   *    be loaded by the processor on the next VM exit.
   *
   *  - Restore the guest's general purpose registers from the active VM's
   *    descriptor (vm_desc_t structure).
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
   *  - Save the guest's general purpose registers.
   *
   *  - Restore the host's general purpose registers.
   */
  DBGPRNT(("VM ENTRY: Entering guest mode!\n"));
  uint64_t vmexit_rflags, hostrestored_rflags;
  asm __volatile__ (
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
      "movq $vmexit_landing_pad, %%rbp\n"
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
       * Fortunately, we only need to use MOVs to restore the guest GPRs, and
       * none of those mess with the zero flag (or any of the flags).
       *
       * (If this ever becomes a limitation, there is a way around this: we
       * could store the boolean use_vmresume in memory, and use the
       * "immediate + memory" form of ADD, which would have the same desired
       * effect on ZF. However, we would need to locate use_vmresume in a
       * statically addressible location, since we'd still have no free
       * registers to use for a pointer. This is clumsy and it'd be (perhaps
       * not meaningfully) slower, so let's not do it if we don't have to.)
       */

      /*** Restore guest GPRs ***
       * First, load a pointer to the active VM descriptor (which is stored
       * in the host_state structure). This is where the guest GPR
       * save/restore slots are located.
       *
       * We will restore RAX last, so that we can use it to store this
       * pointer (the instruction that restores RAX will both use this
       * pointer and overwrite it).
       */
      "movq %c[active_vm](%%rax), %%rax\n" // RAX <-- active_vm pointer
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

      : "=d" (vmexit_rflags), "=b" (hostrestored_rflags)
      : "a" (&host_state), "b" (VMCS_HOST_RSP), "c" (VMCS_HOST_RIP),
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
         [guest_r15] "i" (offsetof(vm_desc_t, state.r15))
      : "memory", "cc"
      );

  /* Confirm that the operation succeeded. */
  enum vmx_statuscode_t result = query_vmx_result(vmexit_rflags);
  if (result == VM_SUCCEED) {
    DBGPRNT(("VM EXIT: returned to host mode.\n"));

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

    /* Return success. */
    return 0;
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
 * Function: update_vmcs_ctrls()
 *
 * Description:
 *  A local helper function that updates control fields in the VMCS to match
 *  newer values in the active VM descriptor.
 *
 * Preconditions:
 *  - There must be a VMCS loaded on the processor.
 *
 *  - The host_state.active_vm pointer should point to the VM descriptor
 *    corresponding to the VMCS loaded on the processor.
 *
 *  This function is meant to be used internally by SVA code that has already
 *  ensured these conditions hold. Particularly, this is true in run_vm()
 *  (which inherits these preconditions from its own broader precondition,
 *  namely, that it is only called at the end of sva_launch/resumevm() after
 *  all checks have been performed to ensure it is safe to enter a VM).
 */
static inline void
update_vmcs_ctrls() {
  /* VM execution controls */
  writevmcs_checked(VMCS_PINBASED_VM_EXEC_CTRLS,
      host_state.active_vm->ctrls.pinbased_exec_ctrls);
  writevmcs_checked(VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS,
      host_state.active_vm->ctrls.procbased_exec_ctrls1);
  writevmcs_checked(VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS,
      host_state.active_vm->ctrls.procbased_exec_ctrls2);
  writevmcs_checked(VMCS_VM_ENTRY_CTRLS,
      host_state.active_vm->ctrls.entry_ctrls);
  writevmcs_checked(VMCS_VM_EXIT_CTRLS,
      host_state.active_vm->ctrls.exit_ctrls);

  /* Event injection and exception controls */
  writevmcs_checked(VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD,
      host_state.active_vm->ctrls.entry_interrupt_info);
  writevmcs_checked(VMCS_EXCEPTION_BITMAP,
      host_state.active_vm->ctrls.exception_exiting_bitmap);

  /* Control register guest/host masks */
  writevmcs_checked(VMCS_CR0_GUESTHOST_MASK,
      host_state.active_vm->ctrls.cr0_guesthost_mask);
  writevmcs_checked(VMCS_CR4_GUESTHOST_MASK,
      host_state.active_vm->ctrls.cr4_guesthost_mask);
}

/*
 * Function: save_restore_guest_state()
 *
 * Description:
 *  A local helper function which abstracts around whether we are saving or
 *  restoring guest state from an sva_vmx_guest_state structure.
 *
 *  Saving and restoring are "mirror" operations performed on a long list of
 *  state fields. It's better software engineering practice to do both
 *  operations with the same code, both to make the code more concise and to
 *  prevent inconsistencies between the two operations. The more fields we
 *  add to the state structure, the more important this will be.
 *
 *  This function *always* operates on the active VMCS and its corresponding
 *  VM descriptor (pointed to by host_state.active_vm). The preconditions
 *  below assure that this is safe to do.
 *
 * Arguments:
 *  - saverestore: A boolean value. If true, we are saving (copying from the
 *    active VMCS to the state structure). If false, we are restoring
 *    (copying from the state structure to the active VMCS).
 *
 * Preconditions:
 *  - There must be a VMCS loaded on the processor.
 *
 *  - The host_state.active_vm pointer should point to the VM descriptor
 *    corresponding to the VMCS loaded on the processor.
 *
 *  This function is meant to be used internally by SVA code that has already
 *  ensured these conditions hold. Particularly, this is true in
 *  sva_getvmstate() (which checks those conditions before saving guest
 *  state) and run_vm() (which inherits these preconditions from its own
 *  broader precondition, namely, that it is only called at the end of
 *  sva_launch/resumevm() after all checks have been performed to ensure it
 *  is safe to enter a VM).
 */
static inline void
save_restore_guest_state(unsigned char saverestore) {
  // FIXME; debug code
  if (saverestore /* saving state i.e. reading from VMCS */)
    panic("save_restore_guest_state() called in 'save' mode\n");

  /*
   * If saverestore == true, we are saving state (copying from the active
   * VMCS to the state structure), i.e. *reading* from the VMCS, so the
   * "write" argument passed to read_write_vmcs_field() is false.
   *
   * If saverestore == false, we are restoring state (copying from the state
   * structure to the active VMCS, i.e. *writing* to the VMCS, so the "write"
   * argument passed to read_write_vmcs_field() is true.
   *
   * In other words, !saverestore == write.
   */

  /* RIP and RSP */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_RIP,
      &host_state.active_vm->state.rip);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_RSP,
      &host_state.active_vm->state.rsp);
  /* Flags */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_RFLAGS,
      &host_state.active_vm->state.rflags);

  /* Control registers (except paging-related ones) */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CR0,
      &host_state.active_vm->state.cr0);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CR4,
      &host_state.active_vm->state.cr4);
  /* Control register read shadows */
  read_write_vmcs_field(!saverestore, VMCS_CR0_READ_SHADOW,
      &host_state.active_vm->state.cr0_read_shadow);
  read_write_vmcs_field(!saverestore, VMCS_CR4_READ_SHADOW,
      &host_state.active_vm->state.cr4_read_shadow);

  /* Debug registers/MSRs saved/restored by processor */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_DR7,
      &host_state.active_vm->state.dr7);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_IA32_DEBUGCTL,
      &host_state.active_vm->state.msr_debugctl);

  /* Paging-related registers saved/restored by processor */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CR3,
      &host_state.active_vm->state.cr3);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_PDPTE0,
      &host_state.active_vm->state.pdpte0);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_PDPTE1,
      &host_state.active_vm->state.pdpte1);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_PDPTE2,
      &host_state.active_vm->state.pdpte2);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_PDPTE3,
      &host_state.active_vm->state.pdpte3);

  /* SYSENTER-related MSRs */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_IA32_SYSENTER_CS,
      &host_state.active_vm->state.msr_sysenter_cs);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_IA32_SYSENTER_ESP,
      &host_state.active_vm->state.msr_sysenter_esp);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_IA32_SYSENTER_EIP,
      &host_state.active_vm->state.msr_sysenter_eip);

  /* Segment registers (including hidden portions) */
  /* CS */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CS_BASE,
      &host_state.active_vm->state.cs_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CS_LIMIT,
      &host_state.active_vm->state.cs_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CS_ACCESS_RIGHTS,
      &host_state.active_vm->state.cs_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_CS_SEL,
      &host_state.active_vm->state.cs_sel);
  /* SS */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_SS_BASE,
      &host_state.active_vm->state.ss_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_SS_LIMIT,
      &host_state.active_vm->state.ss_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_SS_ACCESS_RIGHTS,
      &host_state.active_vm->state.ss_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_SS_SEL,
      &host_state.active_vm->state.ss_sel);
  /* DS */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_DS_BASE,
      &host_state.active_vm->state.ds_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_DS_LIMIT,
      &host_state.active_vm->state.ds_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_DS_ACCESS_RIGHTS,
      &host_state.active_vm->state.ds_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_DS_SEL,
      &host_state.active_vm->state.ds_sel);
  /* ES */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_ES_BASE,
      &host_state.active_vm->state.es_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_ES_LIMIT,
      &host_state.active_vm->state.es_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_ES_ACCESS_RIGHTS,
      &host_state.active_vm->state.es_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_ES_SEL,
      &host_state.active_vm->state.es_sel);
  /* FS */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_FS_BASE,
      &host_state.active_vm->state.fs_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_FS_LIMIT,
      &host_state.active_vm->state.fs_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_FS_ACCESS_RIGHTS,
      &host_state.active_vm->state.fs_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_FS_SEL,
      &host_state.active_vm->state.fs_sel);
  /* GS */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_GS_BASE,
      &host_state.active_vm->state.gs_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_GS_LIMIT,
      &host_state.active_vm->state.gs_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_GS_ACCESS_RIGHTS,
      &host_state.active_vm->state.gs_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_GS_SEL,
      &host_state.active_vm->state.gs_sel);
  /* TR */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_TR_BASE,
      &host_state.active_vm->state.tr_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_TR_LIMIT,
      &host_state.active_vm->state.tr_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_TR_ACCESS_RIGHTS,
      &host_state.active_vm->state.tr_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_TR_SEL,
      &host_state.active_vm->state.tr_sel);

  /* Descriptor table registers */
  /* GDTR */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_GDTR_BASE,
      &host_state.active_vm->state.gdtr_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_GDTR_LIMIT,
      &host_state.active_vm->state.gdtr_limit);
  /* IDTR */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_IDTR_BASE,
      &host_state.active_vm->state.idtr_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_IDTR_LIMIT,
      &host_state.active_vm->state.idtr_limit);
  /* LDTR */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_LDTR_BASE,
      &host_state.active_vm->state.ldtr_base);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_LDTR_LIMIT,
      &host_state.active_vm->state.ldtr_limit);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_LDTR_ACCESS_RIGHTS,
      &host_state.active_vm->state.ldtr_access_rights);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_LDTR_SEL,
      &host_state.active_vm->state.ldtr_sel);

  /* Various other guest system state */
  read_write_vmcs_field(!saverestore, VMCS_GUEST_ACTIVITY_STATE,
      &host_state.active_vm->state.activity_state);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_INTERRUPTIBILITY_STATE,
      &host_state.active_vm->state.interruptibility_state);
  read_write_vmcs_field(!saverestore, VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
      &host_state.active_vm->state.pending_debug_exceptions);
}

/*
 * Function: read_write_vmcs_field()
 *
 * Description:
 *  A local helper function which abstracts around whether we are reading or
 *  writing a VMCS field.
 *
 *  Calls writevmcs_checked() if "rw" is true, otherwise calls
 *  readvmcs_checked().  The "data" parameter is appropriately dereferenced
 *  if we're calling writevmcs_checked() (which takes a uint64_t, not a
 *  uint64_t*).
 *
 *  This is useful so that we don't have to repeat ourselves when writing
 *  code that saves/restores long sequences of VMCS fields. These usually
 *  come in pairs (save and restore) which are otherwise identical; using the
 *  same code for both is better software engineering practice (makes the
 *  code more concise and eliminates the risk of inconsistency between the
 *  two implementations).
 *
 * Arguments:
 *  - write: A boolean value. If true, we write the VMCS field; if false, we
 *    read it.
 *
 *  - field: Specifies the VMCS field. Passed through to
 *    read/writevmcs_checked().
 *
 *  - data: Pointer to the location containing the data to be written, or to
 *    which the data to be read should be stored. For writes, this is
 *    dereferenced and the value in it is passed on to writevmcs_checked() be
 *    written. For reads, the address is passed directly to
 *    readvmcs_checked() and the read value is stored there.
 *
 * Return value:
 *  The error code returned by read/writevmcs_checked(), respectively, is
 *  passed through.
 *
 * Preconditions:
 *  - There must be a VMCS loaded on the processor.
 */
static inline int
read_write_vmcs_field(unsigned char write,
    enum sva_vmcs_field field, uint64_t *data) {
  if (write) {
    /* We are writing to the VMCS field. */
    return writevmcs_checked(field, *data);
  } else {
    /* We are reading from the VMCS field. */
    return readvmcs_checked(field, data);
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
  if ( ! usevmx ) {
    return readvmcs_unchecked(field, data);
  }
  switch (field) {
    /* TODO: implement checks. For now we treat all fields as safe. */
    default:
      return readvmcs_unchecked(field, data);
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
  if (query_vmx_result(rflags) == VM_SUCCEED) {

    /* The specified field has been successfully read into the location
     * pointed to by "data". Return success.
     */
    return 0;
  } else {
    DBGPRNT(("Error: failed to read VMCS field.\n"));

    /* Return failure. */
    return -1;
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
 *  - There must be a VMCS loaded on the processor.
 */
static inline int
writevmcs_checked(enum sva_vmcs_field field, uint64_t data) {
  /*
   * If the field is harmless, write it directly.
   *
   * Otherwise, modify the write to render it harmless (if we can), or reject
   * it.
   */
  if ( ! usevmx ) {
    return writevmcs_unchecked( field, data );
  }
  switch (field) {
    case VMCS_PINBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_pinbased_vm_exec_ctrls ctrls;
        uint32_t data_lower32 = (uint32_t) data;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = data_lower32;

        /* Check bit settings */
        unsigned char is_safe =
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

          /* NMI virtualization not currently supported by SVA */
          !ctrls.virtual_nmis &&

          /*
           * VMX preemption timer must be enabled to prevent the guest from
           * tying up system resources indefinitely.
           */
#if 0 /* our toy hypervisor doesn't know how to use the preemption timer yet */
          ctrls.activate_vmx_preempt_timer &&
#endif

          /* APIC virtualization not currently supported by SVA */
          !ctrls.process_posted_ints &&

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           */
          (ctrls.reserved1_2 == 0x3) &&
          ctrls.reserved4 &&
          (ctrls.reserved8_31 == 0x0);

        if (!is_safe)
          panic("SVA: Disallowed VMCS pin-based VM-exec controls setting.\n");

        return writevmcs_unchecked(field, data);
      }
    case VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_primary_procbased_vm_exec_ctrls ctrls;
        uint32_t data_lower32 = (uint32_t) data;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = data_lower32;

        /* Check bit settings */
        unsigned char is_safe =
          /*
           * We must unconditionally exit for I/O instructions since SVA
           * mediates all access to hardware.
           */
          ctrls.uncond_io_exiting &&

          /*
           * I/O bitmaps are irrelevant since we are unconditionally exiting
           * for I/O instructions. This bit must be 0 because it would
           * otherwise override the "unconditional I/O exiting" setting which
           * we enforce above.
           */
          !ctrls.use_io_bitmaps &&

          /*
           * SVA will mitigate all access to MSRs, so we will not use MSR
           * bitmaps (i.e., we will exit unconditionally for RDMSR/WRMSR).
           *
           * If necessary for performance, we can potentially relax this
           * constraint by allowing guests to read/write certain MSRs
           * directly that are deemed safe.
           */
          !ctrls.use_msr_bitmaps &&

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

        if (!is_safe)
          panic("SVA: Disallowed VMCS primary processor-based VM-exec "
              "controls setting.\n");

        return writevmcs_unchecked(field, data);
      }
    case VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_secondary_procbased_vm_exec_ctrls ctrls;
        uint32_t data_lower32 = (uint32_t) data;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = data_lower32;

        /* Check bit settings */
        unsigned char is_safe =
          /* APIC virtualization not currently supported by SVA */
          !ctrls.virtualize_apic_accesses &&

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

          /* APIC virtualization not currently supported by SVA */
          !ctrls.virtualize_x2apic_mode &&

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

          /* APIC virtualization not currently supported by SVA */
          !ctrls.apic_register_virtualization &&

          /* APIC virtualization not currently supported by SVA */
          !ctrls.virtual_int_delivery &&

          /* VM functions not currently supported by SVA */
          !ctrls.enable_vmfunc &&

          /* VMCS shadowing not currently supported by SVA */
          !ctrls.vmcs_shadowing &&

          /*
           * Don't allow the guest to use XSAVES/XRSTORS.
           *
           * We don't currently support using these instructions to manage FP
           * state in the host, so we couldn't maintain correctness if we
           * allowed guests to use them.
           */
          !ctrls.enable_xsaves_xrstors &&

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           *
           * All reserved bits are reserved to 0 in this field.
           */
          !ctrls.reserved21 &&
          (ctrls.reserved23_24 == 0x0) &&
          (ctrls.reserved26_31 == 0x0);

        if (!is_safe)
          panic("SVA: Disallowed VMCS secondary processor-based VM-exec "
              "controls setting.\n");

        return writevmcs_unchecked(field, data);
      }

    case VMCS_VM_EXIT_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_vm_exit_ctrls ctrls;
        uint32_t data_lower32 = (uint32_t) data;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = data_lower32;

        /* Check bit settings */
        unsigned char is_safe =
          /*
           * SVA/FreeBSD operates in 64-bit mode, so we must always return to
           * that on VM exit.
           */
          ctrls.host_addr_space_size &&

          /*
           * Since we currently don't allow guests to change MSRs (or have
           * their values changed for them by the hypervisor), we do not save
           * or load any MSRs on VM exit; we know their values are exactly as
           * we left them on VM entry.
           */
          !ctrls.save_ia32_pat &&
          !ctrls.load_ia32_pat &&
          !ctrls.save_ia32_efer &&
          !ctrls.load_ia32_efer &&
          !ctrls.clear_ia32_bndcfgs &&

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

        if (!is_safe)
          panic("SVA: Disallowed VMCS secondary processor-based VM-exec "
              "controls setting.\n");

        return writevmcs_unchecked(field, data);
      }
    case VMCS_VM_ENTRY_CTRLS:
      {
        /* Cast data field to bitfield struct */
        struct vmcs_vm_entry_ctrls ctrls;
        uint32_t data_lower32 = (uint32_t) data;
        uint32_t *ctrls_u32 = (uint32_t *) &ctrls;
        *ctrls_u32 = data_lower32;

        /* Check bit settings */
        unsigned char is_safe =
          /*
           * We do not support SMM (either on the host or in VMs).
           *
           * Intel requires that both of these controls be set to 0 for any
           * VM entry from outside SMM.
           */
          !ctrls.entry_to_smm &&
          !ctrls.deact_dual_mon_treatment &&

          /*
           * We currently don't allow guests to change any MSRs (or have
           * their values changed for them by the hypervisor) from whatever
           * they are set to on the host.
           *
           * (Note: the FS_BASE and GS_BASE MSRs are an exception to this
           * because segment bases are handled through separate VMCS fields.)
           *
           * We will probably need to add support for saving/loading MSRs on
           * VM entry/exit when we port BHyVe to SVA, but for now we don't
           * have any need for it.
           *
           * Note in particular that support for loading IA32_EFER on VM
           * entry will be necessary to support guests running in anything
           * other than 64-bit mode.
           */
          !ctrls.load_ia32_perf_global_ctrl &&
          !ctrls.load_ia32_pat &&
          !ctrls.load_ia32_efer &&
          !ctrls.load_ia32_bndcfgs &&

          /*
           * Enforce reserved bits to ensure safe defaults on future
           * processors with features SVA doesn't support.
           */
          (ctrls.reserved0_1 == 0x3) &&
          (ctrls.reserved3_8 == 0x3f) &&
          ctrls.reserved12 &&
          (ctrls.reserved18_31 == 0x0);

        if (!is_safe)
          panic("SVA: Disallowed VMCS secondary processor-based VM-exec "
              "controls setting.\n");

        return writevmcs_unchecked(field, data);
      }

    /*
     * These VMCS controls are safe to write unconditionally.
     */
    case VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD:
    case VMCS_EXCEPTION_BITMAP:
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
    case VMCS_GUEST_IA32_SYSENTER_CS:
    case VMCS_GUEST_IA32_SYSENTER_ESP:
    case VMCS_GUEST_IA32_SYSENTER_EIP:
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
      return writevmcs_unchecked(field, data);

    default:
      printf("SVA: Attempted write to VMCS field: 0x%lx (",
          field);
      print_vmcs_field_name(field);
      printf("); value = 0x%lx\n", data);
      panic("SVA: Disallowed write to unrecognized VMCS field.\n");

      /* Unreachable code to silence compiler warning */
      return -1;
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
  if (query_vmx_result(rflags) == VM_SUCCEED) {
    /* Return success. */
    return 0;
  } else {
    DBGPRNT(("Error: failed to write VMCS field.\n"));

    /* Return failure. */
    return -1;
  }
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
sva_getvmreg(size_t vmid, enum sva_vm_reg reg) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();
  
  if ( usevmx ) {
    if (!sva_vmx_initialized) {
      panic("Fatal error: must call sva_initvmx() before any other "
            "SVA-VMX intrinsic.\n");
    }
  }

  /*
   * Bounds check on vmid.
   *
   * (vmid is unsigned, so this also checks for negative values.)
   */
  if ( usevmx ) {
    if (vmid >= MAX_VMS) {
      panic("Fatal error: specified out-of-bounds VM ID!\n");
    }
  }

  /*
   * Note: we don't need to check whether vmid corresponds to a VM that is
   * actually allocated. If it isn't, it is safe to return the "meaningless"
   * data in the unused descriptor's register fields because the VM
   * descriptor array is zero-initialized during SVA-VMX init, ensuring that
   * no sensitive uninitialized data is contained within.
   *
   * VM descriptors are cleared by sva_freevm(), so it's also not possible to
   * read latent register state from a previously freed VM this way (although
   * this will only be important for security when we implement "Virtual
   * Ghost for VMs" in the future).
   *
   * The only case in which calling this intrinsic with a not-in-use vmid
   * would result in a non-zero value being returned is if the system
   * software had previously used sva_setvmreg() to *write* to that register
   * field in the not-in-use VM descriptor. The data is still "meaningless"
   * since it will be overwritten when a new VM is allocated in the slot
   * (sva_allocvm() doesn't let you leave any registers uninitialized).
   */

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

    default:
      panic("sva_getvmreg(): Invalid register specified: %d\n", (int) reg);
      break;
  }

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
sva_setvmreg(size_t vmid, enum sva_vm_reg reg, uint64_t data) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();
  /*
   * Switch to the user/SVA page tables so that we can access SVA memory
   * regions.
   */
  kernel_to_usersva_pcid();

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /*
   * Bounds check on vmid.
   *
   * (vmid is unsigned, so this also checks for negative values.)
   */
  if ( usevmx ) {
    if (vmid >= MAX_VMS) {
      panic("Fatal error: specified out-of-bounds VM ID!\n");
    }
  }

  /*
   * Note: we don't need to check whether vmid corresponds to a VM that is
   * actually allocated. If it isn't, the register field we are setting will
   * be overwritten when a new VM is allocated in its slot, because
   * sva_allocvm() doesn't let you leave any registers uninitialized.
   */

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

    default:
      panic("sva_setvmreg(): Invalid register specified: %d. "
          "Value that would have been written: 0x%lx\n", (int) reg, data);
      break;
  }

  /* Restore interrupts and return to the kernel page tables. */
  usersva_to_kernel_pcid();
  sva_exit_critical(rflags);
}
