/*===- vmx.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the SVA research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file defines functions and macros used by the SVA Execution
 * Engine for supporting hardware-accelerated virtualization.
 *
 * NOTE: this header is for internal constants, declarations, etc. related to
 * SVA's VMX support. It is NOT considered part of the public interface.
 * Instead, see vmx_intrinsics.h for the public interface.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_VMX_H
#define _SVA_VMX_H

#include <sys/types.h>

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
/* MSRs (non-VMX-related) */
static const u_int FEATURE_CONTROL_MSR = 0x3a;
static const u_int MSR_SYSENTER_CS = 0x174;
static const u_int MSR_SYSENTER_ESP = 0x175;
static const u_int MSR_SYSENTER_EIP = 0x176;
static const u_int MSR_DEBUGCTL = 0x1d9;
static const u_int MSR_EFER = 0xc0000080;
static const u_int MSR_FS_BASE = 0xc0000100;
static const u_int MSR_GS_BASE = 0xc0000101;

/* VMX-related MSRs */
/* We are not necessarily using all of these (yet); they're defined here so
 * that we don't have to go hunting in the Intel manual if we turn out to
 * need them later.
 *
 * These *appear* to be all of the VMX-related architectural MSRs listed in
 * the October 2017 version of the Intel manual.
 */
static const u_int MSR_VMX_BASIC = 0x480;
static const u_int MSR_VMX_PINBASED_CTLS = 0x481;
static const u_int MSR_VMX_PROCBASED_CTLS = 0x482;
static const u_int MSR_VMX_EXIT_CTLS = 0x483;
static const u_int MSR_VMX_ENTRY_CTLS = 0x484;
static const u_int MSR_VMX_MISC = 0x485;
static const u_int MSR_VMX_CR0_FIXED0 = 0x486;
static const u_int MSR_VMX_CR0_FIXED1 = 0x487;
static const u_int MSR_VMX_CR4_FIXED0 = 0x488;
static const u_int MSR_VMX_CR4_FIXED1 = 0x489;
static const u_int MSR_VMX_VMCS_ENUM = 0x48a;
static const u_int MSR_VMX_PROCBASED_CTLS2 = 0x48b;
static const u_int MSR_VMX_EPT_VPID_CAP = 0x48c;
static const u_int MSR_VMX_TRUE_PINBASED_CTLS = 0x48d;
static const u_int MSR_VMX_TRUE_PROCBASED_CTLS = 0x48e;
static const u_int MSR_VMX_TRUE_EXIT_CTLS = 0x48f;
static const u_int MSR_VMX_TRUE_ENTRY_CTLS = 0x490;
static const u_int MSR_VMX_VMFUNC = 0x491;

/* VMX-related bitmasks */
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
 * Helper functions
**********/
static inline unsigned char * my_getVirtual(uintptr_t physical);
static inline uint32_t cpuid_1_ecx(void);
static inline unsigned char cpu_supports_vmx(void);
static inline unsigned char cpu_supports_smx(void);
static inline unsigned char cpu_permit_vmx(void);
static inline unsigned char check_cr0_fixed_bits(void);
static inline unsigned char check_cr4_fixed_bits(void);
static inline enum vmx_statuscode_t query_vmx_result(uint64_t rflags);
static int run_vm(unsigned char use_vmresume);

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
   * obtained from the frame cache by the sva_allocvm() intrinsic.
   */
  uintptr_t vmcs_paddr;

  /* Has the VM been launched since it was last made active (loaded) onto the
   * processor? (true/false)
   *
   * (If and only if so, we should use the VMRESUME instruction for VM entry
   * instead of VMLAUNCH.)
   */
  unsigned char is_launched;

  /* Guest GPRs saved on VM exit and restored on (next) VM entry */
  uint64_t rax, rbx, rcx, rdx;
  uint64_t rbp, rsi, rdi;
  uint64_t r8,  r9,  r10, r11;
  uint64_t r12, r13, r14, r15;
} vm_desc_t;

/*
 * Structure: vmx_host_state_t
 *
 * Description:
 *  A per-CPU structure storing various aspects of the host system's state.
 *
 *  These include:
 *    - A pointer to the VM descriptor (vm_desc_t) for the VM currently
 *      loaded on the processor, or null if no VM is loaded.
 *    - Places for the host GPRs to be saved/restored across VM
 *      entries/exits.
 */
typedef struct vmx_host_state_t {
  /* Pointer to the descriptor for the VM currently loaded on this processor.
   * If no VM is loaded, this should be set to null.
   *
   * NOTE: any code that allocates a vmx_host_state_t is responsible for
   * ensuring that this field is initialized to null. SVA's intrinsics use
   * this field to determine whether a VM is currently loaded; if a bad value
   * is stored here, they will assume there is an active VM and look for its
   * descriptor at that address.
   */
  vm_desc_t * active_vm;

  /* Host GPRs that need to be saved/restored across VM entries/exits
   *
   * Note: we do not need to save/restore RAX, RBX, RCX, and RDX since we use
   * them as inputs and outputs for the inline assembly block that handles
   * the saving/restoring (and the VM entry/exit itself). Thus, the compiler
   * does not expect any values to be preserved in them.
   */
  uint64_t rbp, rsi, rdi;
  uint64_t r8, r9, r10, r11;
  uint64_t r12, r13, r14, r15;
} vmx_host_state_t;

#endif /* _SVA_VMX_H */
