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

#include <sva/callbacks.h> // for printf()
#include <sva/vmx_intrinsics.h>

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
 * Constants and Enumerations
**********/
static const size_t MAX_VMS = 128;

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

/*
 * *** Bit-field definitions for VMCS fields **
 */

/* 32-bit control field: VMCS_PINBASED_VM_EXEC_CTRLS */
struct vmcs_pinbased_vm_exec_ctrls {
  unsigned ext_int_exiting : 1;           /* bit 0 */

  unsigned reserved1_2 : 2;               /* bits 1-2 */

  unsigned nmi_exiting : 1;               /* bit 3 */

  unsigned reserved4 : 1;                 /* bit 4 */

  unsigned virtual_nmis : 1;              /* bit 5 */
  unsigned activate_vmx_preempt_timer : 1; /* bit 6 */
  unsigned process_posted_ints : 1;       /* bit 7 */

  unsigned reserved8_31 : 24;             /* bits 8-31 */
} __attribute__((packed));

/* 32-bit control field: VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS */
struct vmcs_primary_procbased_vm_exec_ctrls {
  unsigned reserved0_1 : 2;                 /* bits 0-1 */

  unsigned int_window_exiting : 1;        /* bit 2 */
  unsigned use_tsc_offsetting : 1;        /* bit 3 */

  unsigned reserved4_6 : 3;               /* bits 4-6 */

  unsigned hlt_exiting : 1;               /* bit 7 */

  unsigned reserved8 : 1;                 /* bit 8 */

  unsigned invlpg_exiting : 1;            /* bit 9 */
  unsigned mwait_exiting : 1;             /* bit 10 */
  unsigned rdpmc_exiting : 1;             /* bit 11 */
  unsigned rdtsc_exiting : 1;             /* bit 12 */

  unsigned reserved13_14 : 2;             /* bits 13-14 */

  unsigned cr3_load_exiting : 1;          /* bit 15 */
  unsigned cr3_store_exiting : 1;         /* bit 16 */

  unsigned reserved17_18 : 2;             /* bits 17-18 */

  unsigned cr8_load_exiting : 1;          /* bit 19 */
  unsigned cr8_store_exiting : 1;         /* bit 20 */
  unsigned use_tpr_shadow : 1;            /* bit 21 */
  unsigned nmi_window_exiting : 1;        /* bit 22 */
  unsigned mov_dr_exiting : 1;            /* bit 23 */
  unsigned uncond_io_exiting : 1;         /* bit 24 */
  unsigned use_io_bitmaps : 1;            /* bit 25 */

  unsigned reserved26 : 1;                /* bit 26 */

  unsigned monitor_trap_flag : 1;         /* bit 27 */
  unsigned use_msr_bitmaps : 1;           /* bit 28 */
  unsigned monitor_exiting : 1;           /* bit 29 */
  unsigned pause_exiting : 1;             /* bit 30 */
  unsigned activate_secondary_ctrls : 1;  /* bit 31 */
} __attribute__((packed));

/* 32-bit control field: VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS */
struct vmcs_secondary_procbased_vm_exec_ctrls {
  unsigned virtualize_apic_accesses : 1;  /* bit 0 */
  unsigned enable_ept : 1;                /* bit 1 */
  unsigned descriptor_table_exiting : 1;  /* bit 2 */
  unsigned enable_rdtscp : 1;             /* bit 3 */
  unsigned virtualize_x2apic_mode : 1;    /* bit 4 */
  unsigned enable_vpid : 1;               /* bit 5 */
  unsigned wbinvd_exiting : 1;            /* bit 6 */
  unsigned unrestricted_guest : 1;        /* bit 7 */
  unsigned apic_register_virtualization : 1; /* bit 8 */
  unsigned virtual_int_delivery : 1;      /* bit 9 */
  unsigned pause_loop_exiting : 1;        /* bit 10 */
  unsigned rdrand_exiting : 1;            /* bit 11 */
  unsigned enable_invpcid : 1;            /* bit 12 */
  unsigned enable_vmfunc : 1;             /* bit 13 */
  unsigned vmcs_shadowing : 1;            /* bit 14 */
  unsigned enable_encls_exiting : 1;      /* bit 15 */
  unsigned rdseed_exiting : 1;            /* bit 16 */
  unsigned enable_pml : 1;                /* bit 17 */
  unsigned ept_violation_ve : 1;          /* bit 18 */
  unsigned conceal_nonroot_from_pt : 1;   /* bit 19 */
  unsigned enable_xsaves_xrstors : 1;     /* bit 20 */

  unsigned reserved21 : 1;                /* bit 21 */

  unsigned mode_based_exec_ctrl_ept : 1;  /* bit 22 */

  unsigned reserved23_24 : 2;             /* bits 23-24 */

  unsigned use_tsc_scaling : 1;           /* bit 25 */

  unsigned reserved26_31 : 6;             /* bits 26-31 */
} __attribute__((packed));

/* 32-bit control field: VMCS_VM_EXIT_CTRLS */
struct vmcs_vm_exit_ctrls {
  unsigned reserved0_1 : 2;               /* bits 0-1 */

  unsigned save_debug_ctrls : 1;          /* bit 2 */

  unsigned reserved3_8 : 6;               /* bits 3-8 */

  unsigned host_addr_space_size : 1;      /* bit 9 */

  unsigned reserved10_11 : 2;             /* bits 10-11 */

  unsigned load_ia32_perf_global_ctrl : 1; /* bit 12 */

  unsigned reserved13_14 : 2;             /* bits 13-14 */

  unsigned ack_int_on_exit : 1;           /* bit 15 */

  unsigned reserved16_17 : 2;             /* bits 16-17 */

  unsigned save_ia32_pat : 1;             /* bit 18 */
  unsigned load_ia32_pat : 1;             /* bit 19 */
  unsigned save_ia32_efer : 1;            /* bit 20 */
  unsigned load_ia32_efer : 1;            /* bit 21 */
  unsigned save_vmx_preempt_timer : 1;    /* bit 22 */
  unsigned clear_ia32_bndcfgs : 1;        /* bit 23 */
  unsigned conceal_vmexit_from_pt : 1;    /* bit 24 */

  unsigned reserved25_31 : 7;             /* bits 25-31 */
} __attribute__((packed));

/* 32-bit control field: VMCS_VM_ENTRY_CTRLS */
struct vmcs_vm_entry_ctrls {
  unsigned reserved0_1 : 2;               /* bits 0-1 */

  unsigned load_debug_ctrls : 1;          /* bit 2 */

  unsigned reserved3_8 : 6;               /* bits 3-8 */

  unsigned ia32e_mode_guest : 1;          /* bit 9 */
  unsigned entry_to_smm : 1;              /* bit 10 */
  unsigned deact_dual_mon_treatment : 1;  /* bit 11 */

  unsigned reserved12 : 1;                /* bit 12 */

  unsigned load_ia32_perf_global_ctrl : 1; /* bit 13 */
  unsigned load_ia32_pat : 1;             /* bit 14 */
  unsigned load_ia32_efer : 1;            /* bit 15 */
  unsigned load_ia32_bndcfgs : 1;         /* bit 16 */
  unsigned conceal_vmentry_from_pt : 1;   /* bit 17 */

  unsigned reserved18_31 : 14;            /* bits 18-31 */
} __attribute__((packed));

/* 32-bit control field: VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD */
struct vmcs_vm_entry_interrupt_info_field {
  unsigned vector : 8;                    /* bits 0-7 */
  unsigned int_type : 3;                  /* bits 8-10 */
  unsigned deliver_error_code : 1;        /* bit 11 */

  unsigned reserved12_30 : 19;            /* bits 12-30 */

  unsigned valid : 1;                     /* bit 31 */
} __attribute__((packed));

/**********
 * Structures
**********/
/*
 * Structure: vm_desc_t
 *
 * Description:
 *  A descriptor for a virtual machine.
 *
 *  Summarizes the status of the VM (e.g., is it active on a processor) and
 *  contains pointers to its Virtual Machine Control Structure (VMCS) frame
 *  and related structures. Also contains a sub-structure of type
 *  sva_vmx_guest_state which describes the state of the guest machine
 *  virtualized by the VM.
 *
 *  This structure can be safely zero-initialized. When all its fields are
 *  zero, it is interpreted as not being assigned to any virtual machine.
 *  (Client code may suffice to check just the vmcs_paddr field; if it is
 *  null, the descriptor can be assumed to not be assigned to a VM.)
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

  /* Has this VM ever been run?
   *
   * There are a few VMCS fields which SVA needs to set to known values
   * before the first run of a VM, but which will never need to be changed
   * after that. This flag tells us if we need to do so on VM entry.
   */
  unsigned char has_run;

  /* Current values of all VMCS controls for this VM. */
  sva_vmx_vm_ctrls ctrls;

  /* State of the guest system virtualized by this VM.
   *
   * GPRs are saved here on VM exit and restored on next VM entry.
   *
   * RIP and RSP are also stored here, and these values are used to
   * initialize RIP and RSP before the first VM launch.
   *
   * NOTE: For now, the RIP and RSP fields here are not updated on VM exit or
   * re-loaded on VM entry. (The processor takes care of saving/restoring
   * them through fields in the VMCS.) We only save or load these here
   * on-demand when the hypervisor wants to see or edit the guest's state.
   */
  sva_vmx_guest_state state;

  /* Extended page-table pointer (EPT) for this VM.
   *
   * Set on VM creation by the sva_allocvm() intrinsic, and accessed
   * thereafter by the sva_load_eptable() and sva_save_eptable() intrinsics.
   *
   * This is extended paging's equivalent of the CR3 register. It points to
   * the top-level (level 4) table in an extended page table hierarchy. This
   * hierarchy will map guest-physical addresses to host-physical frames.
   *
   * This value is loaded by SVA into the VMCS on every VM entry.
   *   (Note: we might change this behavior to avoid reloading it when it
   *   hasn't changed if this ends up slowing things down. I don't think
   *   it will, because loading the EPTP doesn't seem to invalidate any TLB
   *   entries, but if so, we can use a "stale/not-stale" flag to
   *   hide this optimization from the SVA-OS API user.)
   */
  eptp_t eptp;
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

/**********
 * Global variables
**********/
extern unsigned char sva_vmx_initialized; /* defined in vmx.c */
extern struct vm_desc_t vm_descs[MAX_VMS]; /* defined in vmx.c */

/**********
 * Helper functions
**********/
static inline uint32_t cpuid_1_ecx(void);
static inline unsigned char cpu_supports_vmx(void);
static inline unsigned char cpu_supports_smx(void);
static inline unsigned char cpu_permit_vmx(void);
static inline unsigned char check_cr0_fixed_bits(void);
static inline unsigned char check_cr4_fixed_bits(void);
static int run_vm(unsigned char use_vmresume);
static inline void update_vmcs_ctrls();
static inline void save_restore_guest_state(unsigned char saverestore);
static inline int read_write_vmcs_field(
    unsigned char write,
    enum sva_vmcs_field field, uint64_t *data);
static inline int readvmcs_checked(enum sva_vmcs_field field, uint64_t *data);
static inline int readvmcs_unchecked(enum sva_vmcs_field field, uint64_t *data);
static inline int writevmcs_checked(enum sva_vmcs_field field, uint64_t data);
static inline int writevmcs_unchecked(enum sva_vmcs_field field, uint64_t data);
void load_eptable_internal(
    size_t vmid, pml4e_t *epml4t, unsigned char is_initial_setting);

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
  /* Test for VMsucceed. */
  if ((rflags & RFLAGS_VM_SUCCEED) == rflags) {
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

#endif /* _SVA_VMX_H */
