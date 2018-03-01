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

#include <sys/libkern.h> // For memset()

#define SVAVMX_DEBUG

#define VMX_BASIC_MSR 0x480
#define FEATURE_CONTROL_MSR 0x3A
#define VMX_CR0_FIXED0_MSR 0x486
#define VMX_CR0_FIXED1_MSR 0x487
#define VMX_CR4_FIXED0_MSR 0x488
#define VMX_CR4_FIXED1_MSR 0x489

#define CR4_ENABLE_VMX_BIT 0x2000
#define FEATURE_CONTROL_LOCK_BIT 0x1 // bit 0
#define FEATURE_CONTROL_ENABLE_VMXON_WITHIN_SMX_BIT 0x2 // bit 1
#define FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX_BIT 0x4 // bit 2
#define CPUID_01H_ECX_VMX_BIT 0x20 // bit 5
#define CPUID_01H_ECX_SMX_BIT 0x40 // bit 6

/* Each virtual machine in active operation requires a Virtual Machine
 * Control Structure (VMCS). Each VMCS requires a processor-dependent amount
 * of space up to 4 kB, aligned to a 4 kB boundary.
 *
 * (We could query an MSR to determine the exact size, but the obvious thing
 * to do here is to just allocate an entire 4 kB frame.) */
const size_t VMCS_ALLOC_SIZE = 4096;

/* Indicates whether sva_init_vmx() has yet been called by the OS. No SVA-VMX
 * intrinsics may be called until this has been done. */
unsigned char sva_vmx_initialized = 0;

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
 * VMCS has. */
uintptr_t VMXON_paddr = 0;

/* Helper function to write MSR's. Copied from mmu.c. */
static __inline void
wrmsr(u_int msr, uint64_t newval)
{
  uint32_t low, high;
  low = newval;
  high = newval >> 32;
  __asm __volatile("wrmsr" : : "a" (low), "d" (high), "c" (msr));
}

/* Helper function to avoid having to clutter up all the code in this file
 * with #ifdef SVA_DMAP's. */
static inline unsigned char *
my_vtophys(uintptr_t physical) {
#ifdef SVAVMX_DEBUG
  printf("Called my_vtophys() with physical address 0x%lx...\n", physical);
#ifdef SVA_DMAP
  printf("Using SVA's DMAP.\n");
#else
  printf("Using FreeBSD's DMAP.\n");
#endif
#endif

  unsigned char * r;
#ifdef SVA_DMAP
  r = getVirtualSVADMAP(physical);
#else
  r = getVirtual(physical);
#endif

#ifdef SVAVMX_DEBUG
  printf("my_vtophys() returning 0x%lx...\n", r);
#endif
  return r;
}

/* Helper function to query CPUID:1.ECX (Feature Information) */
static inline uint32_t
cpuid_1_ecx(void) {
  uint32_t cpuid_ecx = 0xdeadbeef;
#ifdef SVAVMX_DEBUG
  printf("Executing CPUID with 1 in EAX...\n");
#endif
  asm __volatile__ (
      "cpuid"
      : "=c" (cpuid_ecx)
      : "a" (1)
      : "eax", "ebx", "ecx", "edx"
      );
#ifdef SVAVMX_DEBUG
  printf("Value of ECX after CPUID:1 = 0x%x\n", cpuid_ecx);
#endif

  return cpuid_ecx;
}

/* Helper function to check whether the processor supports VMX using the
 * CPUID instruction.
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

/* Helper function to check whether the processor supports SMX using the
 * CPUID instruction.
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

/* Function: cpu_permit_vmx
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

#ifdef SVAVMX_DEBUG
  printf("Reading IA32_FEATURE_CONTROL MSR...\n");
#endif
  uint64_t feature_control_data = rdmsr(FEATURE_CONTROL_MSR);
#ifdef SVAVMX_DEBUG
  printf("IA32_FEATURE_CONTROL MSR = 0x%lx\n", feature_control_data);
#endif

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
#ifdef SVAVMX_DEBUG
      printf("CPU locked to disallow VMX in SMX mode "
          "(and CPU supports SMX)!\n");
#endif
      return 0;
    }
  }
  if (feature_control_locked && !feature_control_vmxallowed_outside_smx) {
#ifdef SVAVMX_DEBUG
    printf("CPU locked to disallow VMX outside of SMX mode!\n");
#endif
    return 0;
  }

  /* If the lock bit is already set, but VMX is allowed, return success. */
  if (feature_control_locked) {
#ifdef SVAVMX_DEBUG
    printf("IA32_FEATURE_CONTROL was already locked, but allows VMX.\n");
#endif
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

#ifdef SVAVMX_DEBUG
  printf("Writing new value of IA32_FEATURE_CONTROL MSR to permit VMX: "
      "0x%lx\n", feature_control_data);
#endif
  wrmsr(FEATURE_CONTROL_MSR, feature_control_data);

  /* Read back the MSR to confirm this worked. */
  if (rdmsr(FEATURE_CONTROL_MSR) != feature_control_data) {
#ifdef SVAVMX_DEBUG
    printf("Wrote new value to IA32_FEATURE_CONTROL MSR, but it didn't take.\n");
#endif
    return 0;
  }

  /* We've succcessfully set this CPU to allow VMX. */
  return 1;
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
#ifdef SVAVMX_DEBUG
    printf("Kernel called sva_init_vmx(), but it was already initialized.\n");
#endif
    return 1;
  }

  /* Check to see if VMX is supported by the CPU, and if so, set the
   * IA32_FEATURE_CONTROL MSR to permit VMX operation. If this does not
   * succeed (e.g. because the BIOS or other kernel code has blocked the
   * feature), return failure. */
  if (!cpu_permit_vmx()) {
#ifdef SVAVMX_DEBUG
    printf("CPU does not support VMX (or the feature is blocked); "
        "cannot initialize SVA VMX support.\n");
#endif
    return 0;
  }

  /* Sanity check: VMCS_ALLOC_SIZE should be exactly one frame (4 kB). If we
   * ever set VMCS_ALLOC_SIZE to something different, this code will need to
   * be restructured. */
  // FIXME: use a proper assertion
  if (VMCS_ALLOC_SIZE != X86_PAGE_SIZE)
    panic("VMCS_ALLOC_SIZE is not the same as X86_PAGE_SIZE!\n");

  /* Allocate a frame of physical memory to use for the VMXON region.
   * This should only be accessible to SVA (and the hardware), so we will NOT
   * map it into any kernel- or user-space page tables. */
  VMXON_paddr = alloc_frame();

  /* Initialize the VMXON region.
   *
   * The Intel manual only specifies that we should write the VMCS revision
   * identifier to bits 30:0 of the first 4 bytes of the VMXON region, and
   * that bit 31 should be cleared to 0. It says that we "need not initialize
   * the VMXON region in any other way." For good measure, though, we'll
   * zero-fill the rest of it. */
  unsigned char * VMXON_vaddr = my_vtophys(VMXON_paddr);

  printf("Zero-filling VMXON frame...\n");
  memset(VMXON_vaddr, 0, VMCS_ALLOC_SIZE);
  //for (int i = 0; i < VMCS_ALLOC_SIZE; i++) {
  //  VMXON_vaddr[i] = 0;
  //}

  printf("Reading IA32_VMX_BASIC MSR...\n");
  uint64_t vmx_basic_data = rdmsr(VMX_BASIC_MSR);
  printf("IA32_VMX_BASIC MSR = %lx\n", vmx_basic_data);

  // Write the VMCS revision identifier to bits 30:0 of the first 4 bytes of
  // the VMXON region, and clear bit 31 to 0. The VMCS revision identifier is
  // (conveniently) given in bits 30:0 of the IA32_VMX_BASIC MSR, and bit 31
  // of that MSR is guaranteed to always be 0, so we can just copy those
  // lower 4 bytes to the beginning of the VMXON region.
  uint32_t VMCS_rev_id = (uint32_t) vmx_basic_data;
  printf("VMCS revision identifier: %x\n", VMCS_rev_id);
  uint32_t * VMXON_id_field = (uint32_t *) VMXON_vaddr;
  *VMXON_id_field = VMCS_rev_id;
  printf("VMCS revision identifier written to VMXON region.\n");

  /* Set the "enable VMX" bit in CR4. This enables VMX operation, allowing us
   * to enter VMX operation by executing the VMXON instruction. Once we have
   * done so, we cannot unset the "enable VMX" bit in CR4 unless we have
   * first exited VMX operation by executing the VMXOFF instruction. */
  uint64_t orig_cr4_value = _rcr4();
  printf("Original value of CR4: 0x%lx\n", orig_cr4_value);
  uint64_t new_cr4_value = orig_cr4_value | CR4_ENABLE_VMX_BIT;
  printf("Setting new value of CR4 to enable VMX: 0x%lx\n", new_cr4_value);
  load_cr4(new_cr4_value);
  printf("Confirming new CR4 value: 0x%lx\n", _rcr4());
  uint64_t fixed0_cr4 = rdmsr(VMX_CR4_FIXED0_MSR);
  uint64_t fixed1_cr4 = rdmsr(VMX_CR4_FIXED1_MSR);
  printf("Fixed-0 bits: 0x%lx\n", fixed0_cr4);
  printf("Fixed-1 bits: 0x%lx\n", fixed1_cr4);

  uint64_t fixed0 = rdmsr(VMX_CR0_FIXED0_MSR);
  uint64_t fixed1 = rdmsr(VMX_CR0_FIXED1_MSR);
  printf("CR0 value: 0x%lx\n", _rcr0());
  printf("Fixed-0 bits: 0x%lx\n", fixed0);
  printf("Fixed-1 bits: 0x%lx\n", fixed1);

  printf("Physical address of VMXON: 0x%lx\n", VMXON_paddr);
  printf("Virtual address of VMXON pointer: 0x%lx\n", &VMXON_paddr);
  // Enter VMX operation. This is done by executing the VMXON instruction,
  // passing the physical address of the VMXON region as a memory operand.
  printf("Entering VMX operation...\n");
  asm __volatile__ (
      "vmxon (%%rax)\n"
      : : "a" (&VMXON_paddr)
      );
  // Read the RFLAGS register to confirm that VMXON succeeded. If it was
  // successful, then CF, PF, AF, ZF, SF, and OF will all have been set to 0.
  uint64_t rflags;
  asm __volatile__ (
      "pushfq\n"
      "popq %%rax\n"
      : "=a" (rflags)
      );
  printf("RFLAGS after executing VMXON: 0x%lx\n", rflags);

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