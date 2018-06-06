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

/**********
 * "Global" static variables (local to this file)
 *
 * (Eventually, some of these may need to be handled in a more complex way to
 * support SMP. For instance, we might want to store some of them on a
 * per-CPU basis in some structure already used for that purpose.)
**********/
/* Indicates whether sva_initvmx() has yet been called by the OS. No SVA-VMX
 * intrinsics may be called until this has been done.
 */
static unsigned char __attribute__((section("svamem"))) sva_vmx_initialized = 0;

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
static const size_t MAX_VMS = 128;
static struct vm_desc_t __attribute__((section("svamem"))) vm_descs[MAX_VMS];

/*
 * Pointer to the virtual machine descriptor structure for the VM currently
 * loaded on the processor.
 *
 * If no VM is loaded on the processor, this pointer is null.
 *
 * TODO: make this a per-CPU array so it's multiprocessor-ready.
 */
static vm_desc_t * __attribute__((section("svamem"))) active_vm = 0;

/*
 * The object we will use to store saved host state (registers, stack
 * pointer, etc.) before a VM entry so we can restore it after VM exit.
 *
 * TODO: make this a per-CPU array so it's multiprocessor-ready.
 */
static vmx_host_state_t __attribute__((section("svamem"))) host_state;

/*
 * Function: my_getVirtual()
 *
 * Description:
 *  A local helper function to abstract around whether SVA_DMAP is defined
 *  (which determines which function should be called to convert a physical
 *  address to a virtual one using the direct map). This function will always
 *  call the correct one.
 */
static inline unsigned char *
my_getVirtual(uintptr_t physical) {
#if 0
  DBGPRNT(("Called my_getVirtual() with physical address 0x%lx...\n", physical));
#ifdef SVA_DMAP
  DBGPRNT(("Using SVA's DMAP.\n"));
#else
  DBGPRNT(("Using FreeBSD's DMAP.\n"));
#endif
#endif

  unsigned char * r;
#ifdef SVA_DMAP
  r = getVirtualSVADMAP(physical);
#else
  r = getVirtual(physical);
#endif

  DBGPRNT(("my_getVirtual() returning 0x%lx...\n", r));
  return r;
}

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
 * Function: query_vmx_result()
 *
 * Description:
 *  Examines an RFLAGS value to determine the success or failure of a
 *  previously issued VMX instruction.
 *
 *  The various status codes that can be set by a VMX instruction are
 *  described in section 30.2 of the Intel SDM. Here, we represent them with
 *  the enumerated type vmx_statuscode_t.
 *
 * Arguments:
 *  - rflags: an RFLAGS value to be interpreted. Inline assembly issuing VMX
 *    instructions should save the contents of RFLAGS immediately after doing
 *    so, so that they can be passed to this function later.
 *
 * Return value:
 *  A member of the enumerated type vmx_statuscode_t corresponding to the
 *  condition indicated by the processor.
 *
 *  If the bits in RFLAGS do not correspond to a valid VMX status condition
 *  described in the Intel SDM, we return the value VM_UNKNOWN.
 */
static inline enum vmx_statuscode_t
query_vmx_result(uint64_t rflags) {
#if 0
  DBGPRNT(("\tRFLAGS value passed to query_vmx_result(): 0x%lx\n", rflags));
#endif

  /* Test for VMsucceed. */
  if ((rflags & RFLAGS_VM_SUCCEED) == rflags) {
#if 0
    DBGPRNT(("\tRFLAGS matches VMsucceed condition.\n"));
#endif
    return VM_SUCCEED;
  }

  /* Test for VMfailInvalid. */
  if (((rflags & RFLAGS_VM_FAIL_INVALID_0) == rflags)
      && (rflags & RFLAGS_VM_FAIL_INVALID_1)) {
    DBGPRNT(("RFLAGS matches VMfailInvalid condition.\n"));
    return VM_FAIL_INVALID;
  }

  /* Test for VMfailValid. */
  if (((rflags & RFLAGS_VM_FAIL_VALID_0) == rflags)
      && (rflags & RFLAGS_VM_FAIL_VALID_1)) {
    DBGPRNT(("RFLAGS matches VMfailValid condition.\n"));
    return VM_FAIL_VALID;
  }

  /* If none of these conditions matched, return an unknown value. */
  return VM_UNKNOWN;
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
  if (sva_vmx_initialized) {
    DBGPRNT(("Kernel called sva_initvmx(), but it was already initialized.\n"));
    return 1;
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
  /* FIXME: use a proper assertion */
  if (VMCS_ALLOC_SIZE != X86_PAGE_SIZE)
    panic("VMCS_ALLOC_SIZE is not the same as X86_PAGE_SIZE!\n");

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
  unsigned char * VMXON_vaddr = my_getVirtual(VMXON_paddr);

  /***** TEMPORARY CODE */
  // This works because physical addresses have the frame address in the same
  // bit location as a page table entry pointing to them. (This is surely
  // intentional on Intel's part to enable tricks exactly like this...)
  page_desc_t * vmxon_pg = getPageDescPtr(VMXON_paddr);
  printf("VMXON page type (enum page_type_t): %d\n", vmxon_pg->type);
  printf("VMXON page vaddr: 0x%lx\n", vmxon_pg->pgVaddr);
  printf("VMXON page is active: %u\n", vmxon_pg->active);
  printf("VMXON page reference count: %u\n", vmxon_pg->count);
  printf("VMXON page other_pgPaddr: 0x%lx\n", vmxon_pg->other_pgPaddr);
  /***** END TEMPORARY CODE */

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

    sva_vmx_initialized = 1;
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
 * Return value:
 *  A positive integer which will be used to identify this virtual
 *  machine in future invocations of VMX intrinsics. If the return value is
 *  negative, an error occurred and nothing was allocated.
 *
 *  FIXME: You're returning negative error codes, but the return type is
 *  size_t, an unsigned type...
 */
size_t
sva_allocvm(void) {
  DBGPRNT(("sva_allocvm() intrinsic called.\n"));

  if (!sva_vmx_initialized) {
    /* sva_initvmx() is responsible for zero-initializing the vm_descs array
     * and thus marking its slots as free for use. */
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* Scan the vm_descs array for the first free slot, i.e., the first entry
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
   *
   * FIXME: SVA should be setting the VPID field in the VMCS itself, to
   * uphold this invariant (and to ensure that the hypervisor can't
   * mis-configure the TLB tagging to break security barriers between VMs or
   * between a VM and the host). For now, we are leaving it up to the OS to
   * set the VPID field with the sva_writevmcs() intrinsic. (Right now we
   * don't have any field checks in sva_writevmcs() anyway...)
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
    return -1;
  }

  /* Allocate a physical frame of SVA secure memory from the frame cache to
   * serve as this VM's Virtual Machine Control Structure.
   *
   * This frame is not mapped anywhere except in SVA's DMAP, ensuring that
   * the OS cannot touch it without going through an SVA intrinsic.
   */
  vm_descs[vmid].vmcs_paddr = alloc_frame();

  /* Zero-fill the VMCS frame, for good measure. */
  unsigned char * vmcs_vaddr = my_getVirtual(vm_descs[vmid].vmcs_paddr);
  memset(vmcs_vaddr, 0, VMCS_ALLOC_SIZE);

  /* Write the processor's VMCS revision identifier to the first 31 bits of
   * the VMCS frame, and clear the 32nd bit.
   *
   * This value is given in the lower 31 bits of the IA32_VMX_BASIC MSR.
   * Conveniently, the 32nd bit of that MSR is always guaranteed to be 0, so
   * we can just copy the lower 4 bytes.
   */
  uint64_t vmx_basic_data = rdmsr(MSR_VMX_BASIC);
  uint32_t vmcs_rev_id = (uint32_t) vmx_basic_data;
  *((uint32_t*)vmcs_vaddr) = vmcs_rev_id;

  /* Use the VMCLEAR instruction to initialize any processor
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
  uint64_t rflags;
  asm __volatile__ (
      "vmclear (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags)
      : "r" (&vm_descs[vmid].vmcs_paddr)
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags) == VM_SUCCEED) {
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
    return -1;
  }

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
  DBGPRNT(("sva_freevm() intrinsic called for VM ID: %lu\n", vmid));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* Bounds check on vmid.
   *
   * (vmid is unsigned, so this also checks for negative values.)
   */
  if (vmid >= MAX_VMS) {
    panic("Fatal error: specified out-of-bounds VM ID!\n");
  }

  /* If this VM's VMCS pointer is already null, this is a double free (or
   * freeing a VM ID which was never allocated).
   */
  if (!vm_descs[vmid].vmcs_paddr) {
    panic("Fatal error: tried to free a VM which was already unallocated!\n");
  }

  /* Don't free a VM which is still active on the processor. */
  if (active_vm == &vm_descs[vmid]) {
    panic("Fatal error: tried to free a VM which is active on the "
        "processor!\n");
  }

  /* Return the VMCS frame to the frame cache. */
  DBGPRNT(("Returning VMCS frame 0x%lx to SVA.\n", vm_descs[vmid].vmcs_paddr));
  free_frame(vm_descs[vmid].vmcs_paddr);

  /* Zero-fill this slot in the vm_descs struct to mark it as unused. */
  memset(&vm_descs[vmid], 0, sizeof(vm_desc_t));
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
  DBGPRNT(("sva_loadvm() intrinsic called for VM ID: %lu\n", vmid));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* Bounds check on vmid.
   *
   * (vmid is unsigned, so this also checks for negative values.)
   */
  if (vmid >= MAX_VMS) {
    panic("Fatal error: specified out-of-bounds VM ID!\n");
  }

  /* If this VM descriptor indicated by this ID has a null VMCS pointer, it
   * is not a valid descriptor. (i.e., it is an empty slot not assigned to
   * any VM)
   */
  if (!vm_descs[vmid].vmcs_paddr) {
    panic("Fatal error: tried to load an unallocated VM!\n");
  }

  /* If there is currently a VM active on the processor, it must be unloaded
   * before we can load a new one. Return an error.
   *
   * A non-null active_vm pointer indicates there is an active VM.
   */
  if (active_vm) {
    DBGPRNT(("Error: there is already a VM active on the processor. "
          "Cannot load a different VM until it is unloaded.\n"));
    return -1;
  }

  /* Set the indicated VM as the active one. */
  active_vm = &vm_descs[vmid];

  /* Use the VMPTRLD instruction to make the indicated VM's VMCS active on
   * the processor.
   */
  DBGPRNT(("Using VMPTRLD to make active the VMCS at paddr 0x%lx...\n",
        active_vm->vmcs_paddr));
  uint64_t rflags;
  asm __volatile__ (
      "vmptrld (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags)
      : "r" (&(active_vm->vmcs_paddr))
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags) == VM_SUCCEED) {
    DBGPRNT(("Successfully loaded VMCS onto the processor.\n"));
  } else {
    DBGPRNT(("Error: failed to load VMCS onto the processor.\n"));

    /* Unset the active_vm pointer. */
    active_vm = 0;

    /* Return failure. */
    return -1;
  }

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
  DBGPRNT(("sva_unloadvm() intrinsic called.\n"));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (!active_vm) {
    DBGPRNT(("Error: there is no VM active on the processor to unload.\n"));
    return -1;
  }

  /* Use the VMCLEAR instruction to unload the current VM from the processor.
   */
  DBGPRNT(("Using VMCLEAR to unload VMCS with address 0x%lx from the "
        "processor...\n", active_vm->vmcs_paddr));
  uint64_t rflags;
  asm __volatile__ (
      "vmclear (%1)\n"
      "pushfq\n"
      "popq %0\n"
      : "=r" (rflags)
      : "r" (&(active_vm->vmcs_paddr))
      : "cc"
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result(rflags) == VM_SUCCEED) {
    DBGPRNT(("Successfully unloaded VMCS from the processor.\n"));

    /* Mark the VM as "not launched". If we load it back onto the processor
     * in the future, we will need to use sva_launchvm() instead of
     * sva_resumevm() to resume its guest-mode operation.
     */
    active_vm->is_launched = 0;

    /* Set the active_vm pointer to indicate no VM is active. */
    active_vm = 0;
  } else {
    DBGPRNT(("Error: failed to unload VMCS from the processor.\n"));

    /* Return failure. */
    return -1;
  }

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
  DBGPRNT(("sva_readvmcs() intrinsic called with field="));
  print_vmcs_field_name(field);
  DBGPRNT((" (0x%lx), data=%p\n", field, data));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (!active_vm) {
    DBGPRNT(("Error: there is no VM active on the processor. "
          "Cannot read from VMCS.\n"));
    return -1;
  }

#if 0
  DBGPRNT(("Executing VMREAD instruction...\n"));
#endif
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
#if 0
    DBGPRNT(("Successfully read VMCS field.\n"));
#endif

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
  DBGPRNT(("sva_writevmcs() intrinsic called with field="));
  print_vmcs_field_name(field);
  DBGPRNT((" (0x%lx), data=0x%lx\n", field, data));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (!active_vm) {
    DBGPRNT(("Error: there is no VM active on the processor. "
          "Cannot write to VMCS.\n"));
    return -1;
  }

#if 0
  DBGPRNT(("\tExecuting VMWRITE instruction...\n"));
#endif
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
#if 0
    DBGPRNT(("\tSuccessfully wrote VMCS field.\n"));
#endif

    /* Return success. */
    return 0;
  } else {
    DBGPRNT(("Error: failed to write VMCS field.\n"));

    /* Return failure. */
    return -1;
  }
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
  DBGPRNT(("sva_launchvm() intrinsic called.\n"));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (!active_vm) {
    DBGPRNT(("Error: there is no VM active on the processor. "
          "Cannot launch VM.\n"));
    return -1;
  }

  /* If the VM has been launched before since being loaded onto the
   * processor, the sva_resumevm() intrinsic must be used instead of this
   * one.
   */
  if (active_vm->is_launched) {
    DBGPRNT(("Error: Must use sva_resumevm() to enter a VM which "
          "was previously run since being loaded on the processor.\n"));
    return -1;
  }

  /* Mark the VM as launched. Until this VM is unloaded from the processor,
   * future entries to it must be performed using the sva_resumevm()
   * intrinsic.
   */
  active_vm->is_launched = 1;

  /* Enter guest-mode execution (which will ultimately exit back into host
   * mode and return us here).
   *
   * This involves a lot of detailed assembly code to save/restore host
   * state, and all of it is the same as for sva_resumevm() (except that we
   * use the VMRESUME instruction instead of VMLAUNCH), so we perform this in
   * a common helper function.
   */
  return run_vm(0 /* use_vmresume */);
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
  DBGPRNT(("sva_resumevm() intrinsic called.\n"));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_initvmx() before any other "
          "SVA-VMX intrinsic.\n");
  }

  /* If there is no VM currently active on the processor, return failure.
   *
   * A null active_vm pointer indicates there is no active VM.
   */
  if (!active_vm) {
    DBGPRNT(("Error: there is no VM active on the processor. "
          "Cannot resume VM.\n"));
    return -1;
  }

  /* If the VM has not previously been launched at least once since being
   * loaded onto the processor, the sva_launchvm() intrinsic must be used
   * instead of this one.
   */
  if (!active_vm->is_launched) {
    DBGPRNT(("Error: Must use sva_launchvm() to enter a VM which hasn't "
          "previously been run since being loaded on the processor.\n"));
    return -1;
  }

  /* Enter guest-mode execution (which will ultimately exit back into host
   * mode and return us here).
   *
   * This involves a lot of detailed assembly code to save/restore host
   * state, and all of it is the same as for sva_launchvm() (except that we
   * use the VMLAUNCH instruction instead of VMRESUME), so we perform this in
   * a common helper function.
   */
  return run_vm(1 /* use_vmresume */);
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
 *  - Entering guest execution by executing the VMLAUNCH or VMRESUME
 *    instruction, as appropriate.
 *
 *  - Noting the state of RFLAGS after we come back from VMLAUNCH/VMRESUME so
 *    we can pass it to query_vmx_result().
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
   *
   * NOTE: we call our own sva_writevmcs() intrinsic for this.
   */
  DBGPRNT(("run_vm: Saving host state...\n"));
  /* Control registers */
  uint64_t host_cr0 = _rcr0();
  sva_writevmcs(VMCS_HOST_CR0, host_cr0);
  uint64_t host_cr3 = _rcr3();
  sva_writevmcs(VMCS_HOST_CR3, host_cr3);
  uint64_t host_cr4 = _rcr4();
  sva_writevmcs(VMCS_HOST_CR4, host_cr4);
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
      : "=m" (es_sel), "=m" (cs_sel), "=m" (ss_sel), "=m" (ds_sel),
        "=m" (fs_sel), "=m" (gs_sel), "=m" (tr_sel)
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
  sva_writevmcs(VMCS_HOST_ES_SEL, es_sel & ~0x7);
  sva_writevmcs(VMCS_HOST_CS_SEL, cs_sel & ~0x7);
  sva_writevmcs(VMCS_HOST_SS_SEL, ss_sel & ~0x7);
  sva_writevmcs(VMCS_HOST_DS_SEL, ds_sel & ~0x7);
  sva_writevmcs(VMCS_HOST_FS_SEL, fs_sel & ~0x7);
  sva_writevmcs(VMCS_HOST_GS_SEL, gs_sel & ~0x7);
  sva_writevmcs(VMCS_HOST_TR_SEL, tr_sel & ~0x7);
  DBGPRNT(("run_vm: Saved host segment selectors.\n"));

  /*
   * Segment and descriptor table base-address registers
   */

  uint64_t fs_base = rdmsr(MSR_FS_BASE);
  sva_writevmcs(VMCS_HOST_FS_BASE, fs_base);
  uint64_t gs_base = rdmsr(MSR_GS_BASE);
  sva_writevmcs(VMCS_HOST_GS_BASE, gs_base);

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
  sva_writevmcs(VMCS_HOST_GDTR_BASE, gdt_base);
  sva_writevmcs(VMCS_HOST_IDTR_BASE, idt_base);
  
  DBGPRNT(("run_vm: Saved host FS, GS, GDTR, and IDTR bases.\n"));

  /* Get the TR base address from the GDT */
  uint16_t tr_gdt_index = (tr_sel >> 3);
  DBGPRNT(("TR selector: 0x%hx; index in GDT: 0x%hx\n", tr_sel, tr_gdt_index));
  uint32_t * gdt = (uint32_t*) gdt_base;
  DBGPRNT(("GDT base address: 0x%lx\n", (uint64_t)gdt));
  uint32_t * tr_gdt_entry = gdt + (tr_gdt_index * 2);

  DBGPRNT(("TR entry address: 0x%lx\n", (uint64_t)tr_gdt_entry));
  DBGPRNT(("TR entry low 32 bits: 0x%x\n", tr_gdt_entry[0]));
  DBGPRNT(("TR entry high 32 bits: 0x%x\n", tr_gdt_entry[1]));

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
  DBGPRNT(("Reconstructed TR base address: 0x%lx\n", tr_baseaddr));
  /* Write our hard-earned TR base address to the VMCS... */
  sva_writevmcs(VMCS_HOST_TR_BASE, tr_baseaddr);

  DBGPRNT(("run_vm: Saved host TR base.\n"));

  /* Various MSRs */
  uint64_t ia32_sysenter_cs = rdmsr(MSR_SYSENTER_CS);
  sva_writevmcs(VMCS_HOST_IA32_SYSENTER_CS, ia32_sysenter_cs);
  uint64_t ia32_sysenter_esp = rdmsr(MSR_SYSENTER_ESP);
  sva_writevmcs(VMCS_HOST_IA32_SYSENTER_ESP, ia32_sysenter_esp);
  uint64_t ia32_sysenter_eip = rdmsr(MSR_SYSENTER_EIP);
  sva_writevmcs(VMCS_HOST_IA32_SYSENTER_EIP, ia32_sysenter_eip);
  DBGPRNT(("Saved various host MSRs.\n"));

  /*
   * This is where the magic happens.
   *
   * In this assembly section, we:
   *  - Save the general purpose registers to the host_state structure.
   *
   *  - Use the VMWRITE instruction to set the RIP and RSP values that will
   *    be loaded by the processor on the next VM exit.
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
   *  - Restore the general purpose registers.
   */
  DBGPRNT(("VM ENTRY: Entering guest mode!\n"));
  uint64_t rflags;
  asm __volatile__ (
      "# RAX contains a pointer to the host_state structure.\n"
      "# Push it so that we can get it back after VM exit.\n"
      "pushq %%rax\n"

      "### Save GPRs\n"
      "# We don't need to save RAX, RBX, RCX, or RDX because we've used them\n"
      "# as input/output registers for this inline assembly block.\n"
      "movq %%rbp,  (%%rax)\n"
      "movq %%rsi,  8(%%rax)\n"
      "movq %%rdi,  16(%%rax)\n"
      "movq %%r8,   24(%%rax)\n"
      "movq %%r9,   32(%%rax)\n"
      "movq %%r10,  40(%%rax)\n"
      "movq %%r11,  48(%%rax)\n"
      "movq %%r12,  56(%%rax)\n"
      "movq %%r13,  64(%%rax)\n"
      "movq %%r14,  72(%%rax)\n"
      "movq %%r15,  80(%%rax)\n"

      "# (Now all the GPRs are free for our own use in this code.)\n"

      "### Use VMWRITE to set RIP and RSP to be loaded on VM exit\n"
      "vmwrite %%rsp, %%rbx # Write RSP to VMCS_HOST_RSP\n"
      "movq $vmexit_landing_pad, %%rbp\n"
      "vmwrite %%rbp, %%rcx # Write vmexit_landing_pad to VMCS_HOST_RIP\n"

      "### Execute the appropriate VM entry instruction based on the value\n"
      "### of use_vmresume.\n"
      "# Note that we need to place an explicit jump to vmexit_landing_pad\n"
      "# after the launch/resume instructions to ensure correct behavior if\n"
      "# the VM entry fails (and thus execution falls through to the next\n"
      "# instruction).\n"
      "addb $0, %%dl\n"
      "jnz do_vmresume\n"
      "vmlaunch\n"
      "jmp vmexit_landing_pad\n"

      "do_vmresume:\n"
      "vmresume\n"
      "# Here the fall-through is OK since vmexit_landing_pad is next.\n"

      "### VM exits return here!!!\n"
      "vmexit_landing_pad:\n"

      "### Save RFLAGS to RDX (output register for asm block)\n"
      "pushfq\n"
      "popq %%rdx\n"

      "### Get pointer to host_state structure which we saved on the stack\n"
      "### prior to VM entry\n"
      "popq %%rax\n"

      "### Restore GPRs\n"
      "movq (%%rax),   %%rbp\n"
      "movq 8(%%rax),  %%rsi\n"
      "movq 16(%%rax), %%rdi\n"
      "movq 24(%%rax), %%r8\n"
      "movq 32(%%rax), %%r9\n"
      "movq 40(%%rax), %%r10\n"
      "movq 48(%%rax), %%r11\n"
      "movq 56(%%rax), %%r12\n"
      "movq 64(%%rax), %%r13\n"
      "movq 72(%%rax), %%r14\n"
      "movq 80(%%rax), %%r15\n"

      : "=d" (rflags)
      : "a" (&host_state), "b" (VMCS_HOST_RSP), "c" (VMCS_HOST_RIP),
        "d" (use_vmresume)
      : "memory", "cc"
      );

  /* Confirm that the operation succeeded. */
  enum vmx_statuscode_t result = query_vmx_result(rflags);
  if (result == VM_SUCCEED) {
    DBGPRNT(("VM EXIT: returned to host mode.\n"));

    /* For debugging: print out the host GPR values that were restored
     * (and some others that weren't because they didn't contain live values,
     * so we can see the whole picture of the guest's GPR state on VM entry).
     */
    DBGPRNT(("Host GPR values restored:\n"));
    DBGPRNT(("RBP: 0x%16lx\tRSI: 0x%16lx\tRDI: 0x%16lx\n",
          host_state.rbp, host_state.rsi, host_state.rdi));
    DBGPRNT(("R8:  0x%16lx\tR9:  0x%16lx\tR10: 0x%16lx\tR11: 0x%16lx\n",
          host_state.r8, host_state.r9, host_state.r10, host_state.r11));
    DBGPRNT(("R12: 0x%16lx\tR13: 0x%16lx\tR14: 0x%16lx\tR15: 0x%16lx\n",
          host_state.r12, host_state.r13, host_state.r14, host_state.r15));
    DBGPRNT(("Other host GPRs (not restored) had these values on VM entry:\n"));
    DBGPRNT(("RAX: 0x%16lx\tRBX: 0x%16lx\tRCX: 0x%16lx\tRDX: 0x%16lx\n",
          (uint64_t)(&host_state), VMCS_HOST_RSP, VMCS_HOST_RIP,
          (uint64_t)(use_vmresume)));

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
 * Intrinsic: sva_set_up_ept()
 *
 * Description:
 *  Set up a simple EPT page table hierarchy for a "hello world" VM.
 *
 *  This is for use during early development. It is not part of the designed
 *  SVA-VMX interface and will be removed.
 *
 * Return value:
 *  A structure describing the created EPT hierarchy.
 */
sva_vmx_ept_hier
sva_set_up_ept(void) {
  sva_vmx_ept_hier hier;

  /*
   * We will map 16 contiguous frames into the guest-physical address space:
   *  0x 0000 0000 BEEF 0000 through
   *  0x 0000 0000 BEEF FFFF
   *
   * 0xBEEF0000 indexes into the four table levels as follows:
   *  - Bits 47-39: offset 0x0 into the EPT PML4 table
   *  - Bits 38-30: offset 0x2 into the EPT PDPT
   *  - Bits 29-21: offset 0x1F7 into the EPT PD
   *  - Bits 20-12: offset 0xF0 into the EPT PT
   * The remaining 15 frames correspond to offsets 0xF1-FF into the EPT PT;
   * their indices into the other tables are the same.
   */
  for (int i = 0; i < 16; i++) {
    hier.guestpage_guest_paddrs[i] = 0xbeef0000 + (i * 0x1000);
  }

  /* Get frames from the frame cache to serve as page-table pages for each of
   * the four levels of the EPT table hierarchy.
   */
  hier.epml4t_paddr = alloc_frame();
  DBGPRNT(("EPML4T paddr: 0x%lx\n", hier.epml4t_paddr));
  uint64_t * epml4t_vaddr = (uint64_t*)my_getVirtual(hier.epml4t_paddr);
  hier.epdpt_paddr = alloc_frame();
  DBGPRNT(("EPDPT paddr: 0x%lx\n", hier.epdpt_paddr));
  uint64_t * epdpt_vaddr = (uint64_t*)my_getVirtual(hier.epdpt_paddr);
  hier.epd_paddr = alloc_frame();
  DBGPRNT(("EPD paddr: 0x%lx\n", hier.epd_paddr));
  uint64_t * epd_vaddr = (uint64_t*)my_getVirtual(hier.epd_paddr);
  hier.ept_paddr = alloc_frame();
  DBGPRNT(("EPT paddr: 0x%lx\n", hier.ept_paddr));
  uint64_t * ept_vaddr = (uint64_t*)my_getVirtual(hier.ept_paddr);

  /* Zero the page-table pages to set all entries (initially) to "not
   * present".
   */
  memset(epml4t_vaddr, 0, X86_PAGE_SIZE);
  memset(epdpt_vaddr, 0, X86_PAGE_SIZE);
  memset(epd_vaddr, 0, X86_PAGE_SIZE);
  memset(ept_vaddr, 0, X86_PAGE_SIZE);

  /* Set the 0x0'th entry in the EPT PML4 table to point to the EPT PDPT.
   * Mapping has RWX permissions.
   */
  epml4t_vaddr[0x0] = (0x7 | hier.epdpt_paddr);

  /* Set the 0x2'nd entry in the EPT PDPT to point to the EPT PD.
   * Mapping has RWX permissions.
   */
  epdpt_vaddr[0x2] = (0x7 | hier.epd_paddr);

  /* Set the 0x1F7'th entry in the EPT PD to point to the EPT PT.
   * Mapping has RWX permissions.
   */
  epd_vaddr[0x1f7] = (0x7 | hier.ept_paddr);

  /* Set the 0xF0'th through 0xFF'th entries in the EPT PT to point to 16
   * actual physical frames taken from the frame cache.
   *
   * The mappings have RWX permissions and 6 (WB) memory type (PAT not
   * ignored).
   */
  unsigned char * guestpage_vaddrs[16];
  for (int i = 0; i < 16; i++) {
    hier.guestpage_host_paddrs[i] = alloc_frame();
    DBGPRNT(("Guest-visible page #%d host-paddr: 0x%lx, guest-paddr: 0x%lx\n",
          i+1, hier.guestpage_host_paddrs[i], hier.guestpage_guest_paddrs[i]));

    ept_vaddr[0xf0 + i] = (0x37 | hier.guestpage_host_paddrs[i]);

    guestpage_vaddrs[i] =
      my_getVirtual(hier.guestpage_host_paddrs[i]);

    /* Zero the frames that will be mapped into the guest. */
    memset(guestpage_vaddrs[i], 0, X86_PAGE_SIZE);
  }

  /*
   * Create a guest-side page table hierarchy mapping a single 1 GB large
   * page into the guest-virtual address space.
   *
   * Note that only a 16 x 4 kB (64 kB) slice of this range has been
   * EPT-mapped into the guest-physical address space. Accesses to
   * guest-virtual addresses corresponding to these unmapped guest-physical
   * addresses will result in an EPT fault (VM exit). This will not occur in
   * our test code, which will only access one of the 4 kB pages that are
   * mapped in both dimensions. Mapping an entire 1 GB large page in the
   * guest makes things simpler because we only need to create two levels of
   * guest page tables.
   *
   * Our mapping will be as follows:
   *  0x FFFF DEAD 8000 0000 - 0x FFFF DEAD BFFF FFFF (guest-virtual)
   *    maps to
   *  0x 0000 0000 8000 0000 - 0x 0000 0000 BFFF FFFF (guest-physical)
   *
   * Note that the only guest-virtual range which will actually correspond to
   * EPT-mapped guest-physical space is:
   *  0x FFFF DEAD BEEF 0000 - 0x FFFF DEAD BEEF FFFF (guest-virtual)
   *    at
   *  0x 0000 0000 BEEF 0000 - 0x 0000 0000 BEEF FFFF (guest-physical)
   * i.e., this range points to the 16 successive (contiguous in the guest,
   * but not in the host) pages we allocated for the guest from the SVA frame
   * cache.
   *
   * We will put our guest test code and the guest's stack in the first such
   * frame, i.e. 0x FFFF DEAD BEEF 0000 - 0x FFFF DEAD BEEF 0FFF.
   * (The code will be at the beginning and the stack at the end.)
   *
   * 0xFFFFDEADBEEF0000 indexes into the four table levels as follows:
   *  - Bits 47-39: offset 0x1BD into the PML4 table
   *  - Bits 38-30: offset 0xB6 into the PDPT
   *  - Bits 29-21: offset 0x1F7 into the PD
   *  - Bits 20-12: offset oxF0 into the PT
   * Since we are mapping in the entire 1 GB guest-virtual range as a large
   * page, we will only need these first two levels.
   */
  for (int i = 0; i < 16; i++) {
    hier.guestpage_guest_vaddrs[i] = 0xffffdeadbeef0000 + (i * 0x1000);
  }

  /* We will locate the guest's page-table pages as follows within the
   * guest-physical address space:
   *  * The PML4 table will be at guest-physical address 0xbeef8000,
   *    i.e., the 9th (index-8'th) page we've EPT-mapped into the guest.
   *  * The PDPT will be at guest-physical address 0xbeef9000, i.e., the
   *    10th (index-9'th) page we've EPT-mapped into the guest.
   *
   * Set the 0x1BD'th entry in the PML4 table to point to the PDPT.
   * Mapping has RWX permissions and is designated as "supervisor", with
   * accessed = 0, PWT = 0, and PCD = 0.
   */
  uint64_t * guest_pml4t_vaddr = (uint64_t*) guestpage_vaddrs[8];
  guest_pml4t_vaddr[0x1bd] = (0x3 | hier.guestpage_guest_paddrs[9]);

  /* Set the 0xB6'th entry in the PDPT to be a 1 GB large page pointing to
   * the 1 GB-aligned guest-physical range containing the 16 pages we've
   * EPT-mapped in, namely, the range 0x80000000 - 0xbfffffff.
   *
   * Mapping has RWX permissions and is designated as "supervisor", with
   * accessed = 0, dirty = 1, indicating PAT entry 0, and with a protection
   * key of 0.
   */
  uint64_t * guest_pdpt_vaddr = (uint64_t*) guestpage_vaddrs[9];
  guest_pdpt_vaddr[0xb6] =
    (0xc3 | (hier.guestpage_guest_paddrs[0] & 0xffffffffc0000000));

  /*
   * Write the following program to guest-mapped page #0:
   *    8b 44 24 04           movl 0x4(%rsp), %eax
   *    8b 1c 24              movl (%rsp), %ebx
   *    09 c3                 orl %eax, %ebx
   *    53                    pushq %rbx
   *    f4                    hlt
   *    48 31 c0              xorq %rax, %rax
   *    48 31 f6              xorq %rsi, %rsi
   *    48 83 c0 06           addq $6, %rax
   *    48 83 c6 07           addq $7, %rsi
   *    48 f7 e6              mulq %rsi
   *    50                    pushq %rax
   *    0f a2                 cpuid
   * This will perform a computation on two values which we'll pre-load onto
   * the guest stack before VM entry, push the result onto the stack, and
   * then issue HLT to force a VM exit. We can confirm that the guest code
   * actually ran by examining the guest's stack after the exit.
   *
   * Following this, we will adjust the guest's RIP to skip over the HLT,
   * then do another VM entry using VMRESUME. The guest will then multiply 6
   * and 7 together and push the result, 42, to the stack. It will then issue
   * CPUID to force a VM exit (for a different reason than the last time).
   */
  /* This will also write a trailing null byte, which doesn't change
   * anything since we already zeroed the page. */
  strcpy((char*)guestpage_vaddrs[0],
      "\x8b\x44\x24\x04"  // movl 0x4(%rsp), %eax
      "\x8b\x1c\x24"      // movl (%rsp), %ebx
      "\x09\xc3"          // orl %eax, %ebx
      "\x53"              // pushq %rbx
      "\xf4"              // hlt
      "\x48\x31\xc0"      // xorq %rax, %rax
      "\x48\x31\xf6"      // xorq %rsi, %rsi
      "\x48\x83\xc0\x06"  // addq $6, %rax
      "\x48\x83\xc6\x07"  // addq $7, %rsi
      "\x48\xf7\xe6"      // mulq %rsi
      "\x50"              // pushq %rax
      "\x0f\xa2"          // cpuid
      );

  /*
   * Write the values 0xd0a0b0e0 and 0x0e0d0e0f to the last two doublewords
   * in guest-mapped page #0. This will be the guest's initial stack. If all
   * goes well, it will OR the two together to form 0xdeadbeef and write it
   * to address 0xdeadbeef0ff0 with the PUSHQ, providing evidence for us that
   * the guest code actually ran.
   */
  uint32_t * guestpage_as_dwords = (uint32_t *)guestpage_vaddrs[0];
  guestpage_as_dwords[1023] = 0xd0a0b0e0;
  guestpage_as_dwords[1022] = 0x0e0d0e0f;

  /*
   * Lastly, create a simple Global Descriptor Table (GDT) in guest-mapped
   * page #16. This will be located at guest-virtual address 0xffffdeadbeeff000.
   *
   * This GDT has three entries:
   *  1. A null-selector entry (as required)
   *
   *  2. A code-segment descriptor:
   *      base = limit = 0x0
   *      G = 0, D/B = 0, L = 1, AVL = 0
   *      P = 1, DPL = 00b, S = 1 (code or data)
   *      type = 1000b (0x8 - execute-only nonconforming code segment,
   *        not accessed)
   *
   *  3. A data-segment descriptor:
   *      base = limit = 0x0
   *      G = 0, D/B = 0, L = 0, AVL = 0
   *      P = 1, DPL = 00b, S = 1 (code or data)
   *      type = 0000b (0x0 - read-only expand-up data segment, not accessed)
   *
   * These settings imitate the way BHyVe sets up its GDT.
   */
  uint64_t * guest_gdt_as_qwords = (uint64_t *)guestpage_vaddrs[15];
  guest_gdt_as_qwords[0] = 0x0; // null selector
  guest_gdt_as_qwords[1] = 0x0020980000000000;
  guest_gdt_as_qwords[2] = 0x0000900000000000;

  return hier;
}

/*
 * Intrinsic: sva_print_guest_stack()
 *
 * Description:
 *  Print out the contents of the stack for a guest created using the
 *  sva_set_up_ept() intrinsic.
 *
 *  This needs to be done by an SVA intrinsic since the guest-mapped page is
 *  located in SVA protected memory.
 *
 *  This is for use during early development. It is not part of the designed
 *  SVA-VMX interface and will be removed.
 *
 *  WARNING: this function is unsafe since it takes on faith a pointer
 *  (within the "hier" structure parameter) given to it by the kernel, and
 *  then proceeds to read from it. This is OK for debugging but, as noted
 *  above, it is not part of the "real" interface and should not, under any
 *  circumstances, be shipped in a production system.
 *
 *  (Really, this whole method of setting up and using the EPT is super
 *  insecure and hacky. It's just for use in early development. :-))
 *
 * Arguments:
 *  - hier: an sva_vmx_ept_hier structure specifying an EPT hierarchy created
 *    by sva_set_up_ept().
 */
void
sva_print_guest_stack(sva_vmx_ept_hier hier) {
  printf("--------------------\n");

  /* Read the guest RSP value from the VMCS. */
  uint64_t guest_rsp;
  sva_readvmcs(VMCS_GUEST_RSP, &guest_rsp);
  printf("Guest RSP: 0x%lx\n", guest_rsp);

  /* Mask off all but the lowest 12 bits of the guest RSP to get its relative
   * offset within the guest-mapped page.
   */
  uint64_t guest_stack_offset = guest_rsp & 0xfff;

  /* Use this offset to construct a virtual address by which we can read from
   * the guest's stack.
   */
  unsigned char * guestpage_vaddr =
    my_getVirtual(hier.guestpage_host_paddrs[0]);
  uint64_t * guest_stack_vaddr =
    (uint64_t*)((uint64_t)guestpage_vaddr + guest_stack_offset);

  /* A pointer to (one byte past) the end of the guest-mapped page. */
  uint64_t * guestpage_end_vaddr = (uint64_t*)(guestpage_vaddr + 0x1000);

  /* Print out the stack contents, 8 bytes at a time, from the RSP offset to
   * the end of the guest-mapped page (the top of its stack).
   */
  for (uint64_t * qword = guest_stack_vaddr;
       qword < guestpage_end_vaddr;
       ++qword) {
    /* Compute the address of this qword from the guest's perspective so we
     * can print out the address that corresponds to this value.
     */
    uint64_t qword_offset = (uint64_t)qword & 0xfff;
    uint64_t qword_guest_addr =
      qword_offset + hier.guestpage_guest_paddrs[0];

    printf("0x%lx:\t0x%lx\n", qword_guest_addr, *qword);
  }

  printf("--------------------\n");
}
