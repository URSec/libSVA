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
#include <sva/state.h>

/* Set this to 1/0 respectively to turn verbose printf's on or off. */
#define SVAVMX_DEBUG 0

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
  do { if (SVAVMX_DEBUG) { printf("(SVA VMX debug) "); printf args; } } while (0)

/**********
 * Constants and Enumerations
**********/
/*
 * NOTE: MAX_VMS must be less than 2^16-1 (16-bit UINT_MAX) because SVA's VM
 * identifiers do double-duty as VPIDs to tag TLB entries belonging to the
 * VM. Intel's specification limits these to 16-bit positive integers.
 *
 * Note also that SVA statically allocates an array of VM descriptors
 * (vm_descs) based on this value, so actually setting this limit to 2^16-1
 * would use memory rather excessively. We do not expect to need to run
 * anywhere near that many VMs at once on real hardware. (Real hypervisors
 * likely have their own limits as well that are lower than that.)
 */
static const int MAX_VMS = 128;

enum sva_vm_exit_reason {
  VM_EXIT_EXCEPTION_NMI = 0,
  VM_EXIT_EXTERNAL_INTERRUPT = 1,
  VM_EXIT_TRIPLE_FAULT = 2,
  VM_EXIT_INIT = 3,
  VM_EXIT_SIPI = 4,
  VM_EXIT_IO_SMI = 5,
  VM_EXIT_OTHER_SMI = 6,
  VM_EXIT_INTERRUPT_WINDOW = 7,
  VM_EXIT_NMI_WINDOW = 8,
  VM_EXIT_TASK_SWITCH = 9,
  VM_EXIT_CPUID = 10,
  VM_EXIT_GETSEC = 11,
  VM_EXIT_HLT = 12,
  VM_EXIT_INVD = 13,
  VM_EXIT_INVLPG = 14,
  VM_EXIT_RDPMC = 15,
  VM_EXIT_RDTSC = 16,
  VM_EXIT_RSM = 17,
  VM_EXIT_VMCALL = 18,
  VM_EXIT_VMCLEAR = 19,
  VM_EXIT_VMLAUNCH = 20,
  VM_EXIT_VMPTRLD = 21,
  VM_EXIT_VMPTRST = 22,
  VM_EXIT_VMREAD = 23,
  VM_EXIT_VMRESUME = 24,
  VM_EXIT_VMWRITE = 25,
  VM_EXIT_VMXOFF = 26,
  VM_EXIT_VMXON = 27,
  VM_EXIT_CR_ACCESS = 28,
  VM_EXIT_DR_ACCESS = 29,
  VM_EXIT_IO = 30,
  VM_EXIT_RDMSR = 31,
  VM_EXIT_WRMSR = 32,
  VM_EXIT_INVALID_GUEST_STATE = 33,
  VM_EXIT_MSR_LOAD_FAILURE = 34,
  VM_EXIT_MWAIT = 36,
  VM_EXIT_MONITOR_TRAP_FLAG = 37,
  VM_EXIT_MONITOR = 39,
  VM_EXIT_PAUSE = 40,
  VM_EXIT_MCE_DURING_ENTRY = 41,
  VM_EXIT_TPR_BELOW_THRESHOLD = 43,
  VM_EXIT_APIC_ACCESS = 44,
  VM_EXIT_VIRTUALIZED_EOI = 45,
  VM_EXIT_GDTR_IDTR_ACCESS = 46,
  VM_EXIT_LDTR_TR_ACCESS = 47,
  VM_EXIT_EPT_VIOLATION = 48,
  VM_EXIT_EPT_MISCONFIGURATION = 49,
  VM_EXIT_INVEPT = 50,
  VM_EXIT_RDTSCP = 51,
  VM_EXIT_VMX_PREEMPT_TIMER = 52,
  VM_EXIT_INVVPID = 53,
  VM_EXIT_WBINVD = 54,
  VM_EXIT_XSETBV = 55,
  VM_EXIT_APIC_WRITE = 56,
  VM_EXIT_RDRAND = 57,
  VM_EXIT_INVPCID = 58,
  VM_EXIT_VMFUNC = 59,
  VM_EXIT_ENCLS = 60,
  VM_EXIT_RDSEED = 61,
  VM_EXIT_PML_FULL = 62,
  VM_EXIT_XSAVES = 63,
  VM_EXIT_XRESTORS = 64,
  VM_EXIT_SPP = 66,
  VM_EXIT_UMWAIT = 67,
  VM_EXIT_TPAUSE = 68,
};

/* MSRs (non-VMX-related) */
static const u_int MSR_FEATURE_CONTROL = 0x3a;
static const u_int MSR_SYSENTER_CS = 0x174;
static const u_int MSR_SYSENTER_ESP = 0x175;
static const u_int MSR_SYSENTER_EIP = 0x176;
static const u_int MSR_DEBUGCTL = 0x1d9;
static const u_int MSR_FS_BASE = 0xc0000100;
static const u_int MSR_GS_BASE = 0xc0000101;
static const u_int CR0_TS_OFFSET = 0x0000008;
static const u_int MSR_XSS = 0xda0;

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
static const uint64_t CR4_ENABLE_VMX_BIT = 0x2000; // bit 13
static const uint64_t CR4_ENABLE_SMX_BIT = 0x4000; // bit 14
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
 *  (RFLAGS & RFLAGS_VM_FAIL_VALID_0) == RFLAGS, and
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

/**
 * State of the guest's APIC virtualization.
 */
struct vlapic {
  /**
   * The current mode of this vlAPIC.
   *
   * If this is `VLAPIC_OFF`, the following fields need not be defined.
   */
  enum vlapic_mode {
    VLAPIC_OFF,
    VLAPIC_APIC,
    VLAPIC_X2APIC,
  } mode;

  /**
   * The host-physical address of the virtual APIC frame.
   *
   * Some guest reads and writes to APIC registers are redirected to this frame.
   */
  paddr_t virtual_apic_frame;

  /**
   * The host-physical address of the APIC access frame.
   *
   * Guest-mode accesses to this frame will cause a VM exit or emulation by
   * hardware.
   */
  paddr_t apic_access_frame;

  /**
   * Whether this guest has posted interrupts enabled.
   *
   * If this is `false`, the following two fields need not be defined.
   */
  bool posted_interrupts_enabled;

  /**
   * The IPI vector for notifying a CPU in guest mode about posted interrupts.
   */
  int posted_interrupt_vector;

  /**
   * The host-physical address of the structure used to send posted interrupts.
   */
  paddr_t posted_interrupt_descriptor;
};

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
  /*
   * Lock field indicating that this VM descriptor is currently "owned" by a
   * particular logical processor. SVA code should always take this lock
   * by calling vm_desc_lock() before attempting to read or write
   * any field in this structure, or attempting to load (VMPTRLD) or clear
   * (VMCLEAR) its associated VMCS; and likewise release the lock by calling
   * vm_desc_unlock() when it is done.
   *
   * This is necessary to avoid race conditions on the vm_desc_t fields
   * themselves, as well as to prevent attempting to load a VMCS on two
   * different logical processors simultaneously, which (per the Intel
   * manual) would be very bad and result in corruption of the VMCS and
   * undefined behavior.
   *
   * Values:
   *  0 (false): not in use
   *  n>0 (true): in use by processor with ID n-1
   * Note: we shift the processor ID up by one to allow 0 to be used as the
   * "not in use" value, even though the actual processor IDs begin at 0.
   */
  size_t in_use;

  /*
   * Physical-address pointer to the VM's Virtual Machine Control Structure
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

  /*
   * Has the VM been launched since it was last made active (loaded) onto the
   * processor? (true/false)
   *
   * (If and only if so, we should use the VMRESUME instruction for VM entry
   * instead of VMLAUNCH.)
   */
  unsigned char is_launched;

  /*
   * Initial values of all VMCS controls for this VM.
   *
   * This stores the initial settings provided to sva_allocvm() when creating
   * a VM so that they can be written to the VMCS the first time it is loaded
   * onto the processor. This is necessary because Intel's hardware interface
   * only allows us to write to VMCS fields when the VMCS is active on the
   * processor.
   *
   * This structure is not used any more after the first load of the VMCS.
   * Once it's been loaded, the system software can use sva_writevmcs() to
   * update individual VMCS fields.
   */
  sva_vmx_vm_ctrls initial_ctrls;

  /*
   * State of the guest system virtualized by this VM.
   *
   * This structure includes two groups of fields:
   *
   * 1. Non-VMCS-resident state fields that must be saved and loaded by the
   *    host on VM entry and exit. These are managed by SVA and "live" in
   *    this structure when a VM is not running. The system software can read
   *    and write these using the sva_getvmreg() and sva_setvmreg()
   *    intrinsics.
   *
   * 2. VMCS-resident state fields that are automatically saved and loaded by
   *    the processor on VM entry and exit. These are *only* stored in this
   *    structure during the window of time between a new VM being created by
   *    sva_allocvm() and when that VM is first loaded with sva_loadvmcs()
   *    (our first opportunity to write to the VMCS). Thereafter, they are
   *    managed by the processor and the values stored here are "dead". The
   *    system software should read and write these using sva_readvmcs() and
   *    sva_writevmcs().
   */
  sva_vmx_guest_state state;

  /*
   * Have VMCS fields been loaded with their initial values provided to
   * sva_allocvm()?
   *
   * These initial values are stored in "initial_ctrls" and "state" above (as
   * appropriate) and are written to the VMCS at the first opportunity,
   * namely, the first time the VMCS is loaded. sva_loadvm() will set this
   * flag after initializing the values to ensure that we don't attempt to
   * reinstall the initial values on subsequent loads of the VMCS.
   */
  unsigned char vmcs_fields_initialized;

  /*
   * Extended page-table pointer (EPT) for this VM.
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

  /**
   * The VM's vlAPIC (virtual local APIC).
   */
  struct vlapic vlapic;
} vm_desc_t;

/*
 * Structure: vmx_host_state_t
 *
 * Description:
 *  A structure storing various aspects of the host system's state that must
 *  be saved before VM entry and restored after VM exit.
 *
 *  This structure is intended for use as a stack allocation local to
 *  run_vm(), and exists to provide convenient access to all of these fields
 *  within the VM entry/exit assembly block (rather than having to keep track
 *  of each of these fields' positions on the stack individually).
 */
typedef struct vmx_host_state_t {
  /*
   * Copy of the pointer to the active VM's VM descriptor structure (which is
   * normally kept in per-CPU storage, i.e. getCPUState()->active_vm) for
   * more convenient access within the VM entry/exit assembly block of
   * run_vm(), where we have no GPRs available immediately following VM exit
   * and must restore everything from the stack.
   */
  vm_desc_t *active_vm;

  /*
   * Host GPRs that need to be saved/restored across VM entries/exits
   *
   * Note: we do not need to save/restore RAX, RBX, RCX, and RDX since we use
   * them as inputs and outputs for the inline assembly block that handles
   * the saving/restoring (and the VM entry/exit itself). Thus, the compiler
   * does not expect any values to be preserved in them.
   */
  uint64_t rbp, rsi, rdi;
  uint64_t r8, r9, r10, r11;
  uint64_t r12, r13, r14, r15;

  /* Host FP State that needs to be saved/restored across VM entries/exits */
  union xsave_area_max fp;

  /*
   * Extended Control Register 0 (XCR0)
   *
   * This governs the use of processor feature sets controlled by the XSAVE
   * instruction set. (This includes the FPU instruction sets and MPX.)
   */
  uint64_t xcr0;

  /*
   * GS Shadow register
   *
   * In a classic example of ISA-minimalism lawyering on Intel's part, they
   * decided to leave the GS Shadow register - by itself - to be manually
   * switched between host and guest values by the hypervisor on VM entry and
   * exit, despite the fact that *every other part* of the segment registers
   * (including the non-shadow GS Base) corresponds to a field in the VMCS
   * and is switched automatically by the processor as part of VM entry/exit.
   *
   * Thus, we take care of switching GS Shadow in sva_runvm() along with the
   * GPRs and other non-VMCS-resident control registers/MSRs stored here.
   */
  uint64_t gs_shadow;
} vmx_host_state_t;

/**********
 * Global variables
**********/
extern struct vm_desc_t vm_descs[MAX_VMS]; /* defined in vmx.c */

/**********
 * Helper functions
**********/
static inline uint32_t cpuid_1_ecx(void);
static inline unsigned char cpu_supports_vmx(void);
static inline unsigned char cpu_permit_vmx(void);
static inline unsigned char check_cr0_fixed_bits(void);
static inline unsigned char check_cr4_fixed_bits(void);
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
    int vmid, pml4e_t __kern* epml4t, unsigned char is_initial_setting);

/**
 * Get the pin-based execution controls.
 */
int vmcs_pinctrls_get(struct vmcs_pinbased_vm_exec_ctrls* out);

/**
 * Set the pin-based execution controls.
 */
int vmcs_pinctrls_set(struct vmcs_pinbased_vm_exec_ctrls ctrls);

/**
 * Get the primary processor-based execution controls.
 */
int vmcs_proc1ctrls_get(struct vmcs_primary_procbased_vm_exec_ctrls* out);

/**
 * Set the primary processor-based execution controls.
 */
int vmcs_proc1ctrls_set(struct vmcs_primary_procbased_vm_exec_ctrls ctrls);

/**
 * Get the secondary processor-based execution controls.
 */
int vmcs_proc2ctrls_get(struct vmcs_secondary_procbased_vm_exec_ctrls* out);

/**
 * Set the secondary processor-based execution controls.
 */
int vmcs_proc2ctrls_set(struct vmcs_secondary_procbased_vm_exec_ctrls ctrls);

/**
 * Get the entry controls.
 */
int vmcs_entryctrls_get(struct vmcs_vm_entry_ctrls* out);

/**
 * Set the entry controls.
 */
int vmcs_entryctrls_set(struct vmcs_vm_entry_ctrls ctrls);

/**
 * Get the exit controls.
 */
int vmcs_exitctrls_get(struct vmcs_vm_exit_ctrls* out);

/**
 * Set the exit controls.
 */
int vmcs_exitctrls_set(struct vmcs_vm_exit_ctrls ctrls);

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

/*
 * Function: vm_desc_lock()
 *
 * Description:
 *  Atomically acquires the "in_use" lock for a struct vm_desc_t.
 *
 * Arguments:
 *  - vm: a pointer to the vm_desc_t structure to be locked.
 *
 * Return value:
 *  True (non-zero) if the lock has been successfully acquired; false (zero)
 *  if it was already locked and thus not acquired.
 */
static inline int
vm_desc_lock(struct vm_desc_t *vm) {
  /*
   * If the lock value is currently 0 (free), the compare-and-swap will
   * succeed and claim the lock for us by changing the lock value to
   * getProcessorID() + 1.
   *
   * We shift the processor ID up by 1 to allow 0 to be used as the "lock is
   * free" value even though processor IDs are 0-based.
   */
  size_t expected = 0;
  return __atomic_compare_exchange_n(&vm->in_use,
      &expected, getProcessorID() + 1,
      false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
}

/*
 * Function: vm_desc_ensure_lock()
 *
 * Description:
 *  Checks to see if the current processor already owns the "in_use" lock
 *  for a struct vm_desc_t, and tries to acquire it if it doesn't.
 *
 * Arguments:
 *  - vm: a pointer to the vm_desc_t structure to be locked.
 *
 * Return value:
 *  - True (non-zero) if the lock was already held or has been successfully
 *    acquired. More precisely:
 *      * 1 if the lock was already held
 *      * 2 if we took it just now
 *  - False (zero) if it was found to be locked by a different processor
 *    and thus not acquired.
 */
static inline int
vm_desc_ensure_lock(struct vm_desc_t *vm) {
  /*
   * Check if we already hold the lock.
   *
   * Note: the processor ID in the lock field is shifted up by 1 since the IDs
   * are 0-based and we need to reserve a value for "not in use".
   */
  if (vm->in_use == getProcessorID() + 1)
    return 1;

  /* We don't already hold the lock, so attempt to acquire it. */
  if (vm_desc_lock(vm))
    return 2;
  else
    return 0;
}

/*
 * Function: vm_desc_unlock()
 *
 * Description:
 *  Release the "in_use" lock for a struct vm_desc_t.
 *
 * Arguments:
 *  - vm: a pointer to the vm_desc_t structure to be unlocked.
 */
static inline void
vm_desc_unlock(struct vm_desc_t *vm) {
  __atomic_clear(&vm->in_use, __ATOMIC_RELEASE);
}

#endif /* _SVA_VMX_H */
