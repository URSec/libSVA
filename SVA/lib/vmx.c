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

/* Bit mask indicating the zero settings of CF (carry flag), PF (parity
 * flag), AF (auxiliary carry flag), ZF (zero flag), SF (sign flag), and OF
 * (overflow flag) in the RFLAGS register.
 *
 * If all of these are zero after executing a VMX instruction, the VMsucceed
 * condition is indicated by the processor (corresponding to our enum value
 * VM_SUCCEED).
 *
 * To check if RFLAGS == VMsucceed, test that:
 *  (RFLAGS & RFLAGS_VM_SUCCEED) == RFLAGS
 */
static const uint64_t RFLAGS_VM_SUCCEED = 0xFFFFFFFFFFFFF73A;
/* The condition VMfailInvalid is indicated by CF = 1, and all other flags
 * the same as in VMsucceed.
 *
 * Test with:
 *  (RFLAGS & RFLAGS_VM_FAIL_INVALID_0) == RFLAGS, and
 *  (RFLAGS & RFLAGS_VM_FAIL_INVALID_1).
 */
static const uint64_t RFLAGS_VM_FAIL_INVALID_0 = 0xFFFFFFFFFFFFF73B;
static const uint64_t RFLAGS_VM_FAIL_INVALID_1 = 0x1;
/* The condition VMfailValid is indicated by ZF = 1, and all other flags the
 * same as in VMsucceed.
 *
 * Test with:
 *  (RFLAGS & RFLAGS_VM_FAIL_VALID_0) == RFLSGS, and
 *  (RFLAGS & RFLAGS_VM_FAIL_VALID_1).
 */
static const uint64_t RFLAGS_VM_FAIL_VALID_0 = 0xFFFFFFFFFFFFF77A;
static const uint64_t RFLAGS_VM_FAIL_VALID_1 = 0x40;

/* Each virtual machine in active operation requires a Virtual Machine
 * Control Structure (VMCS). Each VMCS requires a processor-dependent amount
 * of space up to 4 kB, aligned to a 4 kB boundary.
 *
 * (We could query an MSR to determine the exact size, but the obvious thing
 * to do here is to just allocate an entire 4 kB frame.)
 */
static const size_t VMCS_ALLOC_SIZE = 4096;

/*
 * Enumeration of status codes indicating the success or failure of VMX
 * instructions.
 *
 * These are indicated by the processor by setting/clearing particular
 * combinations of bits in RFLAGS. To query this status, use the helper
 * function query_vmx_result() (defined in this file).
 *
 * See section 30.2 of the Intel SDM for a description of these status codes.
 */
enum vmx_statuscode_t {
  /* VM_UNKNOWN is a default value which does not correspond to a real status
   * code returned by the processor. It is used to represent the situation
   * where the combination of bits set in RFLAGS does not decode to any valid
   * VMX status code. */
  VM_UNKNOWN = 0,
  VM_SUCCEED,
  VM_FAIL_INVALID,
  VM_FAIL_VALID
};

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
static inline enum vmx_statuscode_t query_vmx_result(void);

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
 *
 * TODO: ensure this global variable is in an SVA protected region
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
 *
 * TODO: ensure this global pointer is in an SVA protected region
 */
static uintptr_t VMXON_paddr = 0;

/*
 * Structure: vm_desc_t
 *
 * Description:
 *  A descriptor for a virtual machine.
 *
 *  Summarizes the state of the VM (e.g., is it active on a processor) and
 *  contains pointers to its Virtual Machine Control Structure (VMCS) frame
 *  and related structures.
 *
 *  This structure can be safely zero-initialized. When all its fields are
 *  zero, it is interpreted as not being assigned to any virtual machine.
 */
typedef struct vm_desc_t {
  /* Physical-address pointer to the VM's Virtual Machine Control Structure
   * (VMCS) frame.
   *
   * The VMCS contains numerous fields for controlling various aspects of the
   * processor's VMX features and saving host/guest state across transitions
   * in and out of guest operation for this VM.
   *
   * The layout and format of these fields is implementation-dependent to the
   * processor, and when the VM is active on the processor, it may freely
   * cache them in internal registers. Therefore, these fields *must not*,
   * under any circumstances, be read or written using normal memory loads
   * and stores, or undefined behavior may result. Instead, the processor
   * provides the VMREAD/VMWRITE instructions to read/write these fields
   * indirectly by "name" (i.e., by a logical numeric index which refers to
   * the field abstractly).
   *
   * Because of the potential for undefined behavior if the VMCS is used
   * incorrectly, and because many of its fields are sensitive to system
   * security, the VMCS must be allocated in SVA protected memory, forcing
   * the OS to use SVA intrinsics to access it. A suitable frame will be
   * obtained from the frame cache by the allocvm() intrinsic.
   */
  uintptr_t vmcs_paddr;

  /* Has the VMCS been initialized with the VMCLEAR instruction? (true/false)
   *
   * (This must be done *before* reading/writing any fields with
   * VMREAD/VMWRITE.)
   */
  unsigned char vmcs_initialized;

  /* Has the VM been launched since it was last made active (loaded) onto the
   * processor? (true/false)
   *
   * (If and only if so, we should use the VMRESUME instruction for VM entry
   * instead of VMLAUNCH.)
   */
  unsigned char is_launched;
} vm_desc_t;

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
 * is returned by the allocvm() intrinsic and used to refer to the VM in
 * future intrinsic calls.
 *
 * This array is zero-initialized in sva_init_vmx(), which effectively marks
 * all entries as unused (and the corresponding VM IDs as free to be
 * assigned).
 *
 * TODO: ensure this is located in an SVA protected region
 */
static const size_t MAX_VMS = 128;
static struct vm_desc_t vm_descs[MAX_VMS];

/*
 * Pointer to the virtual machine descriptor structure for the VM currently
 * loaded on the processor.
 *
 * If no VM is loaded on the processor, this pointer is null.
 */
static vm_desc_t * active_vm = 0;

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
 * Function: query_vmx_result()
 *
 * Description:
 *  Examines the value of RFLAGS to determine the success or failure of a
 *  previously issued VMX instruction.
 *
 *  The various status codes that can be set by a VMX instruction are
 *  described in section 30.2 of the Intel SDM. Here, we represent them with
 *  the enumerated type vmx_statuscode_t.
 *
 * Return value:
 *  A member of the enumerated type vmx_statuscode_t corresponding to the
 *  condition indicated by the processor.
 *
 *  If the bits in RFLAGS do not correspond to a valid VMX status condition
 *  described in the Intel SDM, we return the value VM_UNKNOWN.
 */
static inline enum vmx_statuscode_t
query_vmx_result(void) {
  /* Read the RFLAGS register. */
  uint64_t rflags;
  asm __volatile__ (
      "pushfq\n"
      "popq %%rax\n"
      : "=a" (rflags)
      );
  DBGPRNT(("Contents of RFLAGS: 0x%lx\n", rflags));

  /* Test for VMsucceed. */
  if ((rflags & RFLAGS_VM_SUCCEED) == rflags) {
    DBGPRNT(("RFLAGS matches VMsucceed condition.\n"));
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
 * Intrinsic: sva_init_vmx()
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
  /* Confirm that the operation succeeded. */
  if (query_vmx_result() == VM_SUCCEED) {
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
 * Intrinsic: allocvm()
 *
 * Description:
 *  Allocates a virtual machine descriptor and numeric ID for a new virtual
 *  machine. Creates and initializes any auxiliary structures (such as the
 *  Virtual Machine Control Structure) necessary to load this VM onto the
 *  processor.
 *
 * Return value:
 *  A non-negative integer which will be used to identify this virtual
 *  machine in future invocations of VMX intrinsics. If the return value is
 *  negative, an error occurred and nothing was allocated.
 *
 *  FIXME: You're returning negative error codes, but the return type is
 *  size_t, an unsigned type...
 */
size_t
allocvm(void) {
  DBGPRNT(("allocvm() intrinsic called.\n"));

  if (!sva_vmx_initialized) {
    /* sva_init_vmx() is responsible for zero-initializing the vm_descs array
     * and thus marking its slots as free for use. */
    panic("Fatal error: must call sva_init_vmx() before any other "
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
   */
  size_t vmid = -1;
  for (size_t i = 0; i < MAX_VMS; i++) {
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
  uint64_t vmx_basic_data = rdmsr(VMX_BASIC_MSR);
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
  asm __volatile__ (
      "vmclear (%%rax)\n"
      : : "a" (&vm_descs[vmid].vmcs_paddr)
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result() == VM_SUCCEED) {
    DBGPRNT(("Successfully initialized VMCS.\n"));

    vm_descs[vmid].vmcs_initialized = 1;
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
 * Intrinsic: freevm()
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
freevm(size_t vmid) {
  DBGPRNT(("freevm() intrinsic called for VM ID: %lu\n", vmid));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_init_vmx() before any other "
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
 * Intrinsic: loadvm()
 *
 * Description:
 *  Makes the specified virtual machine active on the processor.
 *
 *  Fails if another VM is already active on the processor. If that is the
 *  case, you should call unloadvm() first to make it inactive.
 *
 * Arguments:
 *  - vmid: the numeric handle of the virtual machine to be made active.
 *
 * Return value:
 *  An error code indicating the result of this operation. 0 indicates
 *  success, and a negative value indicates failure.
 */
int
loadvm(size_t vmid) {
  DBGPRNT(("loadvm() intrinsic called for VM ID: %lu\n", vmid));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_init_vmx() before any other "
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
  asm __volatile__ (
      "vmptrld (%%rax)\n"
      : : "a" (&(active_vm->vmcs_paddr))
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result() == VM_SUCCEED) {
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
 * Intrinsic: unloadvm()
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
unloadvm(void) {
  DBGPRNT(("unloadvm() intrinsic called.\n"));

  if (!sva_vmx_initialized) {
    panic("Fatal error: must call sva_init_vmx() before any other "
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
  asm __volatile__ (
      "vmclear (%%rax)\n"
      : : "a" (&(active_vm->vmcs_paddr))
      );
  /* Confirm that the operation succeeded. */
  if (query_vmx_result() == VM_SUCCEED) {
    DBGPRNT(("SUccessfully unloaded VMCS from the processor.\n"));

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
