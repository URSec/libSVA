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
#include <sva/mmu.h>
#include <sva/config.h>

#include <string.h>

/* Set this to 1/0 respectively to turn verbose printf's on or off. */
#define SVAVMX_DEBUG 1

/* Debug print macro to allow verbose printf's to be turned on/off with
 * SVAVMX_DEBUG.
 * 
 * Use DBGPRNT((...)) in place of printf(...).
 *
 * Note that the double parentheses are necessary due to the fact that we
 * aren't using C99 (and thus can't use variadic macros) in the FreeBSD 9.0
 * kernel.
 *
 * For more information see:
 *  https://stackoverflow.com/questions/1644868/
 *    c-define-macro-for-debug-printing#1644898
 */
#define DBGPRNT(args) \
  do { if (SVAVMX_DEBUG) printf args; } while (0)

/**********
 * Constants
**********/
static const u_int VMX_BASIC_MSR = 0x480;
static const u_int FEATURE_CONTROL_MSR = 0x3A;
static const u_int VMX_CR0_FIXED0_MSR = 0x486;
static const u_int VMX_CR0_FIXED1_MSR = 0x487;
static const u_int VMX_CR4_FIXED0_MSR = 0x488;
static const u_int VMX_CR4_FIXED1_MSR = 0x489;

static const uint64_t CR4_ENABLE_VMX_BIT = 0x2000;
static const uint64_t FEATURE_CONTROL_LOCK_BIT = 0x1; // bit 0
static const uint64_t FEATURE_CONTROL_ENABLE_VMXON_WITHIN_SMX_BIT = 0x2; // bit 1
static const uint64_t FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX_BIT = 0x4; // bit 2
static const uint32_t CPUID_01H_ECX_VMX_BIT = 0x20; // bit 5
static const uint32_t CPUID_01H_ECX_SMX_BIT = 0x40; // bit 6

/* Each virtual machine in active operation requires a Virtual Machine
 * Control Structure (VMCS). Each VMCS requires a processor-dependent amount
 * of space up to 4 kB, aligned to a 4 kB boundary.
 *
 * (We could query an MSR to determine the exact size, but the obvious thing
 * to do here is to just allocate an entire 4 kB frame.)
 */
static const size_t VMCS_ALLOC_SIZE = 4096;

/**********
 * Forward declarations of helper functions local to this file (not
 * declared in header).
**********/
static inline unsigned char * my_getVirtual(uintptr_t physical);
static inline uint32_t cpuid_1_ecx(void);
static inline unsigned char cpu_supports_vmx(void);
static inline unsigned char cpu_supports_smx(void);
static inline unsigned char cpu_permit_vmx(void);
static inline unsigned char check_cr0_fixed_bits(void);
static inline unsigned char check_cr4_fixed_bits(void);

/**********
 * "Global" static variables (local to this file)
 * 
 * (Eventually, we will need to ensure these are stored in SVA protected
 * memory. Some of them may need to be handled in a more complex way once we
 * add SMP support. For instance, we might want to store some of them on a
 * per-CPU basis in some structure already used for that purpose.)
**********/
/* Indicates whether sva_init_vmx() has yet been called by the OS. No SVA-VMX
 * intrinsics may be called until this has been done.
 */
static unsigned char sva_vmx_initialized = 0;

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
static uintptr_t VMXON_paddr = 0;

/*
 * Function: my_getVirtual
 *
 * Description:
 *  A local helper function to abstract around whether SVA_DMAP is defined
 *  (which determines which function should be called to convert a physical
 *  address to a virtual one using the direct map). This function will always
 *  call the correct one.
 */
static inline unsigned char *
my_getVirtual(uintptr_t physical) {
  DBGPRNT(("Called my_getVirtual() with physical address 0x%lx...\n", physical));
#ifdef SVA_DMAP
  DBGPRNT(("Using SVA's DMAP.\n"));
#else
  DBGPRNT(("Using FreeBSD's DMAP.\n"));
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
 * Function: cpuid_1_ecx
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
 * Function: cpu_supports_vmx
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
 * Function: cpu_supports_smx
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
 * Function: cpu_permit_vmx
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
 * Function: check_cr0_fixed_bits
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

  uint64_t fixed0_msr = rdmsr(VMX_CR0_FIXED0_MSR);
  uint64_t fixed1_msr = rdmsr(VMX_CR0_FIXED1_MSR);
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
 * Function: check_cr4_fixed_bits
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

  uint64_t fixed0_msr = rdmsr(VMX_CR4_FIXED0_MSR);
  uint64_t fixed1_msr = rdmsr(VMX_CR4_FIXED1_MSR);
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
 * Intrinsic: sva_init_vmx
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
 *  anything...and we will need to make sure that variable is stored in
 *  protected memory.)
 */
unsigned char
sva_init_vmx(void) {
  if (sva_vmx_initialized) {
    DBGPRNT(("Kernel called sva_init_vmx(), but it was already initialized.\n"));
    return 1;
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

  DBGPRNT(("Zero-filling VMXON frame...\n"));
  memset(VMXON_vaddr, 0, VMCS_ALLOC_SIZE);

  DBGPRNT(("Reading IA32_VMX_BASIC MSR...\n"));
  uint64_t vmx_basic_data = rdmsr(VMX_BASIC_MSR);
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
  asm __volatile__ (
      "vmxon (%%rax)\n"
      : : "a" (&VMXON_paddr)
      );
  /* Read the RFLAGS register to confirm that VMXON succeeded. If it was
   * successful, then CF, PF, AF, ZF, SF, and OF will all have been set to 0.
   */
  uint64_t rflags;
  asm __volatile__ (
      "pushfq\n"
      "popq %%rax\n"
      : "=a" (rflags)
      );
  DBGPRNT(("RFLAGS after executing VMXON: 0x%lx\n", rflags));

  sva_vmx_initialized = 1;

  return 1;
}


/*
 * Intrinsic: allocvm
 *
 * Description:
 *  Allocates a Virtual Machine Control Structure in SVA protected memory for
 *  a virtual machine.
 *
 * Return value:
 *  A non-negative integer which will be used to identify this virtual
 *  machine in future invocations of VMX intrinsics. If the return value is
 *  negative, an error occurred and the VMCS was not allocated.
 */
size_t
allocvm(void) {
    return -1;
}
