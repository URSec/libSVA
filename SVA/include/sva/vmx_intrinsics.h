/*===- vmx_intrinsics.h - SVA Execution Engine  =--------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the SVA research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file exports the SVA intrinsics available for utilizing
 * hardware-assisted virtualization. It is separate from vmx.h because the
 * vmx.h code is primarily internal SVA functionality supporting VMX and
 * should not be exported.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_VMX_INTRINSICS_H
#define _SVA_VMX_INTRINSICS_H

#include <sva/asmconfig.h>
#include <sva/fpu_types.h>
#include <sva/mmu_types.h>
#include <sva/icontext.h>

/*
 * Enumeration: sva_vmcs_field
 *
 * Identifies a Virtual Machine Control Structure field to be read or
 * written by the readvmcs()/writevmcs() intrinsics.
 *
 * The values of the enum entries are explicitly chosen so that they are
 * exactly the same as their corresponding 16-bit field encodings specified
 * in the Intel manual. This allows us to directly pass an enum value to the
 * VMREAD/VMWRITE instructions.
 *
 * NOTE: Some of the fields listed in this enumeration are not (yet)
 * recognized or used by SVA. They are listed here for consistency with the
 * Intel manual (currently, the October 2017 revision). Note especially that
 * some of these fields may not even *exist* on the particular Intel hardware
 * we are using for development; some of them correspond to features added in
 * newer hardware.
 *
 * (This is not to say all of the fields listed in the Intel manual are here.
 * I tried to get all of them, but I might have missed some we don't care
 * about yet.)
 *
 */
enum sva_vmcs_field {
  /*
   * GUEST_STATE FIELDS
   */
  /* 16-bit guest-state fields */
  VMCS_GUEST_ES_SEL = 0x800,
  VMCS_GUEST_CS_SEL = 0x802,
  VMCS_GUEST_SS_SEL = 0X804,
  VMCS_GUEST_DS_SEL = 0x806,
  VMCS_GUEST_FS_SEL = 0x808,
  VMCS_GUEST_GS_SEL = 0x80a,
  VMCS_GUEST_LDTR_SEL = 0x80c,
  VMCS_GUEST_TR_SEL = 0x80e,
  VMCS_GUEST_INTERRUPT_STATUS = 0x810,
  VMCS_GUEST_PML_INDEX = 0x812,

  /* 64-bit guest-state fields */
  /* Not a typo, the field is called "VMCS link pointer". */
  VMCS_VMCS_LINK_PTR = 0x2800,
  VMCS_GUEST_IA32_DEBUGCTL = 0x2802,
  VMCS_GUEST_IA32_PAT = 0x2804,
  VMCS_GUEST_IA32_EFER = 0x2806,
  VMCS_GUEST_IA32_PERF_GLOBAL_CTRL = 0x2808,
  VMCS_GUEST_PDPTE0 = 0x280a,
  VMCS_GUEST_PDPTE1 = 0x280c,
  VMCS_GUEST_PDPTE2 = 0x280e,
  VMCS_GUEST_PDPTE3 = 0x2810,
  VMCS_GUEST_IA32_BNDCFGS = 0x2812,

  /* 32-bit guest-state fields */
  VMCS_GUEST_ES_LIMIT = 0x4800,
  VMCS_GUEST_CS_LIMIT = 0x4802,
  VMCS_GUEST_SS_LIMIT = 0x4804,
  VMCS_GUEST_DS_LIMIT = 0x4806,
  VMCS_GUEST_FS_LIMIT = 0x4808,
  VMCS_GUEST_GS_LIMIT = 0x480a,
  VMCS_GUEST_LDTR_LIMIT = 0x480c,
  VMCS_GUEST_TR_LIMIT = 0x480e,
  VMCS_GUEST_GDTR_LIMIT = 0x4810,
  VMCS_GUEST_IDTR_LIMIT = 0x4812,
  VMCS_GUEST_ES_ACCESS_RIGHTS = 0x4814,
  VMCS_GUEST_CS_ACCESS_RIGHTS = 0x4816,
  VMCS_GUEST_SS_ACCESS_RIGHTS = 0x4818,
  VMCS_GUEST_DS_ACCESS_RIGHTS = 0x481a,
  VMCS_GUEST_FS_ACCESS_RIGHTS = 0x481c,
  VMCS_GUEST_GS_ACCESS_RIGHTS = 0x481e,
  VMCS_GUEST_LDTR_ACCESS_RIGHTS = 0x4820,
  VMCS_GUEST_TR_ACCESS_RIGHTS = 0x4822,
  VMCS_GUEST_INTERRUPTIBILITY_STATE = 0x4824,
  VMCS_GUEST_ACTIVITY_STATE = 0x4826,
  VMCS_GUEST_SMBASE = 0x4828,
  VMCS_GUEST_IA32_SYSENTER_CS = 0x482a,
  VMCS_VMX_PREEMPT_TIMER_VAL = 0x482e,

  /* Natural-width guest-state fields */
  VMCS_GUEST_CR0 = 0x6800,
  VMCS_GUEST_CR3 = 0x6802,
  VMCS_GUEST_CR4 = 0x6804,
  VMCS_GUEST_ES_BASE = 0x6806,
  VMCS_GUEST_CS_BASE = 0x6808,
  VMCS_GUEST_SS_BASE = 0x680a,
  VMCS_GUEST_DS_BASE = 0x680c,
  VMCS_GUEST_FS_BASE = 0x680e,
  VMCS_GUEST_GS_BASE = 0x6810,
  VMCS_GUEST_LDTR_BASE = 0x6812,
  VMCS_GUEST_TR_BASE = 0x6814,
  VMCS_GUEST_GDTR_BASE = 0x6816,
  VMCS_GUEST_IDTR_BASE = 0x6818,
  VMCS_GUEST_DR7 = 0x681a,
  VMCS_GUEST_RSP = 0x681c,
  VMCS_GUEST_RIP = 0x681e,
  VMCS_GUEST_RFLAGS = 0x6820,
  VMCS_GUEST_PENDING_DBG_EXCEPTIONS = 0x6822,
  VMCS_GUEST_IA32_SYSENTER_ESP = 0x6824,
  VMCS_GUEST_IA32_SYSENTER_EIP = 0x6826,

  /*
   * HOST-STATE FIELDS
   */
  /* 16-bit host-state fields */
  VMCS_HOST_ES_SEL = 0xc00,
  VMCS_HOST_CS_SEL = 0xc02,
  VMCS_HOST_SS_SEL = 0xc04,
  VMCS_HOST_DS_SEL = 0xc06,
  VMCS_HOST_FS_SEL = 0xc08,
  VMCS_HOST_GS_SEL = 0xc0a,
  VMCS_HOST_TR_SEL = 0xc0c,

  /* 64-bit host-state fields */
  VMCS_HOST_IA32_PAT = 0x2c00,
  VMCS_HOST_IA32_EFER = 0x2c02,
  VMCS_HOST_IA32_PERF_GLOBAL_CTRL = 0x2c04,

  /* 32-bit host-state field (there's only one) */
  VMCS_HOST_IA32_SYSENTER_CS = 0x4c00,

  /* Natural-width host-state fields */
  VMCS_HOST_CR0 = 0x6c00,
  VMCS_HOST_CR3 = 0x6c02,
  VMCS_HOST_CR4 = 0x6c04,
  VMCS_HOST_FS_BASE = 0x6c06,
  VMCS_HOST_GS_BASE = 0x6c08,
  VMCS_HOST_TR_BASE = 0x6c0a,
  VMCS_HOST_GDTR_BASE = 0x6c0c,
  VMCS_HOST_IDTR_BASE = 0x6c0e,
  VMCS_HOST_IA32_SYSENTER_ESP = 0x6c10,
  VMCS_HOST_IA32_SYSENTER_EIP = 0x6c12,
  VMCS_HOST_RSP = 0x6c14,
  VMCS_HOST_RIP = 0x6c16,

  /*
   * CONTROL FIELDS
   */
  /* 16-bit control fields */
  VMCS_VPID = 0x0,
  VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR = 0x2,
  VMCS_EPTP_INDEX = 0x4,

  /* 64-bit control fields */
  VMCS_IOBITMAP_A_ADDR = 0x2000,
  VMCS_IOBITMAP_B_ADDR = 0x2002,
  VMCS_MSR_BITMAPS_ADDR = 0x2004,
  VMCS_VMEXIT_MSR_STORE_ADDR = 0x2006,
  VMCS_VMEXIT_MSR_LOAD_ADDR = 0x2008,
  VMCS_VMENTRY_MSR_LOAD_ADDR = 0x200a,
  VMCS_EXECUTIVE_VMCS_PTR = 0x200c,
  VMCS_PML_ADDR = 0x200e,
  VMCS_TSC_OFFSET = 0x2010,
  VMCS_VIRTUAL_APIC_ADDR = 0x2012,
  VMCS_APIC_ACCESS_ADDR = 0x2014,
  VMCS_POSTED_INTERRUPT_DESC_ADDR = 0x2016,
  VMCS_VM_FUNC_CTRLS = 0x2018,
  VMCS_EPT_PTR = 0x201a,
  VMCS_EOI_EXIT_BITMAP_0 = 0x201c,
  VMCS_EOI_EXIT_BITMAP_1 = 0x201e,
  VMCS_EOI_EXIT_BITMAP_2 = 0x2020,
  VMCS_EOI_EXIT_BITMAP_3 = 0x2022,
  VMCS_EPTP_LIST_ADDR = 0x2024,
  VMCS_VMREAD_BITMAP_ADDR = 0x2026,
  VMCS_VMWRITE_BITMAP_ADDR = 0x2028,
  VMCS_VIRT_EXCEPTION_INFO_ADDR = 0x202a,
  VMCS_XSS_EXITING_BITMAP = 0x202c,
  VMCS_ENCLS_EXITING_BITMAP = 0x202e,
  /* No, this isn't a mistake - the Intel manual doesn't list anything for
   * 0x2030, it goes straight from 0x202e to 0x2032. I don't know why. Maybe
   * a feature they haven't announced yet? */
  VMCS_TSC_MULTIPLIER = 0x2032,

  /* 32-bit control fields */
  VMCS_PINBASED_VM_EXEC_CTRLS = 0x4000,
  VMCS_PRIMARY_PROCBASED_VM_EXEC_CTRLS = 0x4002,
  VMCS_EXCEPTION_BITMAP = 0x4004,
  VMCS_PAGE_FAULT_ERROR_CODE_MASK = 0x4006,
  VMCS_PAGE_FAULT_ERROR_CODE_MATCH = 0x4008,
  VMCS_CR3_TARGET_COUNT = 0x400a,
  VMCS_VM_EXIT_CTRLS = 0x400c,
  VMCS_VM_EXIT_MSR_STORE_COUNT = 0x400e,
  VMCS_VM_EXIT_MSR_LOAD_COUNT = 0x4010,
  VMCS_VM_ENTRY_CTRLS = 0x4012,
  VMCS_VM_ENTRY_MSR_LOAD_COUNT = 0x4014,
  VMCS_VM_ENTRY_INTERRUPT_INFO_FIELD = 0x4016,
  VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE = 0x4018,
  VMCS_VM_ENTRY_INSTR_LENGTH = 0x401a,
  VMCS_TPR_THRESHOLD = 0x401c,
  VMCS_SECONDARY_PROCBASED_VM_EXEC_CTRLS = 0x401e,
  VMCS_PLE_GAP = 0x4020,
  VMCS_PLE_WINDOW = 0x4022,

  /* Natural-width control fields */
  VMCS_CR0_GUESTHOST_MASK = 0x6000,
  VMCS_CR4_GUESTHOST_MASK = 0x6002,
  VMCS_CR0_READ_SHADOW = 0x6004,
  VMCS_CR4_READ_SHADOW = 0x6006,
  VMCS_CR3_TARGET_VAL0 = 0x6008,
  VMCS_CR3_TARGET_VAL1 = 0x600a,
  VMCS_CR3_TARGET_VAL2 = 0x600c,
  VMCS_CR3_TARGET_VAL3 = 0x600e,

  /*
   * READ-ONLY DATA FIELDS
   */
  /* There are no 16-bit read-only data fields. */

  /* 64-bit read-only data field (there's only one) */
  VMCS_GUEST_PHYS_ADDR = 0x2400,

  /* 32-bit read-only data fields */
  VMCS_VM_INSTR_ERROR = 0x4400,
  VMCS_VM_EXIT_REASON = 0x4402,
  VMCS_VM_EXIT_INTERRUPTION_INFO = 0x4404,
  VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE = 0x4406,
  VMCS_IDT_VECTORING_INFO_FIELD = 0x4408,
  VMCS_IDT_VECTORING_ERROR_CODE = 0x440a,
  VMCS_VM_EXIT_INSTR_LENGTH = 0x440c,
  VMCS_VM_EXIT_INSTR_INFO = 0x440e,

  /* Natural-width read-only data fields */
  VMCS_EXIT_QUAL = 0x6400,
  VMCS_IO_RCX = 0x6402,
  VMCS_IO_RSI = 0x6404,
  VMCS_IO_RDI = 0x6406,
  VMCS_IO_RIP = 0x6408,
  VMCS_GUEST_LINEAR_ADDR = 0x640a
  /* THE END */
};

/*
 * Enumeration: sva_vm_reg
 *
 * Identifies a register in a virtualized system.
 *
 * Note that not all x86 registers virtualized in a VM are included in this
 * enumeration - only the ones that SVA needs to load/save on VM entry and
 * exit.
 *
 * Other registers (e.g. some key control registers, most segment registers,
 * etc.) are automatically loaded/saved by the processor on VM entry/exit
 * from VMCS fields. Those registers' values therefore "live" in their
 * respective VMCS fields and do not need to be tracked separately by SVA.
 * The respective fields are identified in the sva_vmcs_field enumeration
 * above and can be accessed using the sva_read/writevmcs() intrinsics.
 */
enum sva_vm_reg {
  VM_REG_RAX, VM_REG_RBX, VM_REG_RCX, VM_REG_RDX,
  VM_REG_RBP, VM_REG_RSI, VM_REG_RDI,
  VM_REG_R8,  VM_REG_R9,  VM_REG_R10, VM_REG_R11,
  VM_REG_R12, VM_REG_R13, VM_REG_R14, VM_REG_R15,

  VM_REG_CR2,

  VM_REG_XCR0, VM_REG_MSR_XSS,

  VM_REG_MSR_FMASK, VM_REG_MSR_STAR, VM_REG_MSR_LSTAR,

  /*
   * In a classic example of ISA-minimalism lawyering on Intel's part, they
   * decided to leave the GS Shadow register - by itself - to be manually
   * switched between host and guest values by the hypervisor on VM entry and
   * exit, despite the fact that *every other part* of the segment registers
   * (including the non-shadow GS Base) corresponds to a field in the VMCS
   * and is switched automatically by the processor as part of VM entry/exit.
   *
   * Thus, we take care of switching GS Shadow in sva_runvm() along with the
   * GPRs and other non-VMCS-resident control registers/MSRs enumerated here.
   */
  VM_REG_GS_SHADOW,

#ifdef MPX
  VM_REG_BND0_LOWER, VM_REG_BND0_UPPER,
  VM_REG_BND1_LOWER, VM_REG_BND1_UPPER,
  VM_REG_BND2_LOWER, VM_REG_BND2_UPPER,
  VM_REG_BND3_LOWER, VM_REG_BND3_UPPER
#endif
};

/*
 *****************************************************************************
 * Prototypes for VMX intrinsics implemented in the library
 *  (vmx.c and vmx_ept.c)
 *****************************************************************************
 */
unsigned char sva_initvmx(void);

/**
 * Allocate a virtual machine descriptor ID for a new virtual machine.
 *
 * Creates and initializes any auxiliary structures (such as the Virtual
 * Machine Control Structure) necessary to load this VM onto the processor.
 *
 * This function takes a handle to a thread that must be the currently running
 * thread before SVA will allow the VM to be launched.
 *
 * Note that zero is not used as a VMID because we use the VMID as the VPID to
 * tag TLB entries belonging to the VM; Intel reserves VPID=0 to tag the host's
 * TLB entires (and asking the processor to launch a VM with VPID=0 will result
 * in an error). This intrinsic should *never* return zero.
 *
 * @param thread  An SVA thread handle to associate the VM with
 * @return        The ID of the new VM or a negative error code
 */
int sva_allocvm(sva_thread_handle_t thread);

void sva_freevm(int vmid);
int sva_loadvm(int vmid);
int sva_unloadvm(int vmid);
int sva_readvmcs(enum sva_vmcs_field field, uint64_t __kern* data);
int sva_writevmcs(enum sva_vmcs_field field, uint64_t data);
int sva_launchvm(void);
int sva_resumevm(void);
uint64_t sva_getvmreg(int vmid, enum sva_vm_reg reg);
void sva_setvmreg(int vmid, enum sva_vm_reg reg, uint64_t data);
void sva_getvmfpu(int vmid, union xsave_area_max __kern* out_data);
void sva_setvmfpu(int vmid, union xsave_area_max __kern* in_data);

/*
 * VMX-specific MMU intrinsics for managing Extended Page Tables
 * (impl. in vmx_ept.c)
 *
 * In addition to the intrinsics declared here, the following
 * non-EPT-specific MMU intrinsics (see mmu_intrinsics.h) support extended
 * page tables as well as regular ones:
 *    * sva_remove_mapping() (used to clear a page table entry)
 *    * sva_remove_page() (used to undeclare a page table page)
 */
void sva_declare_l1_eptpage(uintptr_t frameAddr);
void sva_declare_l2_eptpage(uintptr_t frameAddr);
void sva_declare_l3_eptpage(uintptr_t frameAddr);
void sva_declare_l4_eptpage(uintptr_t frameAddr);
void sva_update_ept_mapping(page_entry_t __kern* eptePtr, page_entry_t val);
void sva_load_eptable(int vmid, uintptr_t eptp);
uintptr_t sva_save_eptable(int vmid);

/* EPT/VPID TLB flush intrinsics (impl. in vmx_ept.c) */
void sva_flush_ept_all(void);
void sva_flush_ept_single(paddr_t ept_root_ptp);
void sva_flush_vpid_all(void);
void sva_flush_vpid_single(int vmid, bool retain_global);
void sva_flush_vpid_addr(int vmid, uintptr_t guest_linear_addr);

/*******************************************************************************
 *                       APIC virtualization interface
 ******************************************************************************/

/**
 * Disable the active VM's vlAPIC.
 *
 * @return  0 if successful or an error code
 *
 * Errors:
 *  ENODEV: VMX is not initialized
 *  ESRCH:  No active VM
 */
int sva_vlapic_disable(void);

/**
 * Set the active VM's vlAPIC to (legacy) APIC mode.
 *
 * If the active VM's vlAPIC is already in APIC mode, this intrinsic can be used
 * to change the virtual APIC frame and/or APIC access frame.
 *
 * @param virtual_apic_frame  The host-physical address of the virtual APIC page
 * @param apic_access_frame   The host-physical address of the APIC access page
 * @return                    0 if successful or an error code
 *
 * Errors:
 *  EINVAL: A physical address is not page-aligned or is not a valid frame
 *  ENODEV: VMX is not initialized
 *  ESRCH:  No active VM
 */
int sva_vlapic_enable(paddr_t virtual_apic_frame, paddr_t apic_access_frame);

/**
 * Set the active VM's vlAPIC to x2APIC mode.
 *
 * If the active VM's vlAPIC is already in x2APIc mode, this intrinsic can be
 * used to change the virtual APIC frame.
 *
 * @param virtual_apic_frame  The host-physical address of the virtual APIC page
 * @return                    0 if successful or an error code
 *
 * Errors:
 *  EINVAL: A physical address is not page-aligned or is not a valid frame
 *  ENODEV: VMX is not initialized
 *  ESRCH:  No active VM
 */
int sva_vlapic_enable_x2apic(paddr_t virtual_apic_frame);

/**
 * Disable posted interrupt processing for the active VM.
 *
 * @return            0 if successful or an error code
 *
 * Errors:
 *  ENODEV: VMX is not initialized
 *  ESRCH:  No active VM
 */
int sva_posted_interrupts_disable(void);

/**
 * Enable posted interrupt processing for the active VM.
 *
 * If poster interrupt processing is already enabled on the active VM, this
 * intrinsic can be used to change the posted interrupt notification vector or
 * the address of the posted interrupt descriptor.
 *
 * Requires that the guest's vlAPIC be enabled first.
 *
 * @param vector      The posted interrupt notification vector
 * @param descriptor  The host-physical address of the posted interrupt
 *                    descriptor
 * @return            0 if successful or an error code
 *
 * Errors:
 *  EINVAL: The vector is less than 32
 *          The descriptor address is not 64-byte aligned or is not a valid
 *          physical address
 *  ENODEV: VMX is not initialized
 *  ENOENT: The active VM's vlAPIC is not enabled
 *  ESRCH:  No active VM
 */
int sva_posted_interrupts_enable(uint8_t vector, paddr_t descriptor);

/*
 * These intrinsics are for use during development.
 * They will be removed "soon" and are not part of the designed SVA-VMX
 * interface.
 */
/* "Cheater's code" to support gradual porting of Xen */
#if 0
uintptr_t sva_get_vmcs_paddr(int vmid); /* defined in debug.c */
int sva_get_vmid_from_vmcs(uintptr_t vmcs_paddr); /* defined in debug.c */
#endif
/* Functions for printing debug information to screen (defined in debug.c) */
void sva_print_vmx_msrs(void);
void print_vmcs_field_name(enum sva_vmcs_field field, bool enable);
void print_vmcs_field(enum sva_vmcs_field field, uint64_t value);
void sva_print_vmcs_allowed_settings(void);

enum vmx_exit_bitmap_rw {
  VMX_EXIT_BITMAP_NONE = 0,
  VMX_EXIT_BITMAP_R = 0x1,
  VMX_EXIT_BITMAP_W = 0x2,
  VMX_EXIT_BITMAP_RW = 0x3,
};

/**
 * Query whether reads or writes to the given MSR are configured to cause an
 * exit.
 *
 * @param vmid  The VM ID for the VM to query
 * @param msr   The MSR for which to determine guest accessibility
 * @return      A value in the range of `enum vmx_exit_bitmap_rw` on success or
 *              an error code (<0)
 *
 * Errors:
 *  ENODEV  VMX is not initialized
 *  ESRCH   No VM with the given ID found
 *  EBUSY   The VM is in use by another CPU
 *  ESRCH   The MSR is outside the range which the exiting bitmaps cover
 */
extern int sva_vmx_msr_intercept_get(int vmid, uint32_t msr);

/**
 * Allow guest access to the given MSR.
 *
 * @param vmid  The VM to which to grant access
 * @param msr   The MSR for which to grant access
 * @return      0 on success or an error code
 *
 * Errors:
 *  ENODEV  VMX is not initialized
 *  ESRCH   No VM with the given ID found
 *  EBUSY   The VM is in use by another CPU
 *  ESRCH   The MSR is outside the range which the exiting bitmaps cover
 */
extern int sva_vmx_msr_intercept_clear(int vmid, uint32_t msr,
                                       enum vmx_exit_bitmap_rw rw);

/**
 * Deny guest access to the given MSR.
 *
 * @param vmid  The VM to which to deny access
 * @param msr   The MSR for which to deny access
 * @return      0 on success or an error code
 *
 * Errors:
 *  ENODEV  VMX is not initialized
 *  ESRCH   No VM with the given ID found
 *  EBUSY   The VM is in use by another CPU
 *  ESRCH   The MSR is outside the range which the exiting bitmaps cover
 */
extern int sva_vmx_msr_intercept_set(int vmid, uint32_t msr,
                                     enum vmx_exit_bitmap_rw rw);

/**
 * Query whether reads or writes to the given IO port are configured to cause
 * an exit.
 *
 * @param vmid  The VM ID for the VM to query
 * @param port  The IO port for which to determine guest accessibility
 * @return      0 (intercept clear) or 1 (intercept set) on success or
 *              an error code (<0)
 *
 * Errors:
 *  ENODEV  VMX is not initialized
 *  ESRCH   No VM with the given ID found
 *  EBUSY   The VM is in use by another CPU
 */
extern int sva_vmx_io_intercept_get(int vmid, uint16_t port);

/**
 * Allow guest access to the given IO port.
 *
 * @param vmid  The VM to which to grant access
 * @param port  The IO port for which to grant access
 * @return      0 on success or an error code
 *
 * Errors:
 *  ENODEV  VMX is not initialized
 *  ESRCH   No VM with the given ID found
 *  EBUSY   The VM is in use by another CPU
 */
extern int sva_vmx_io_intercept_clear(int vmid, uint16_t port);

/**
 * Deny guest access to the given IO port.
 *
 * @param vmid  The VM to which to deny access
 * @param port  The IO port for which to deny access
 * @return      0 on success or an error code
 *
 * Errors:
 *  ENODEV  VMX is not initialized
 *  ESRCH   No VM with the given ID found
 *  EBUSY   The VM is in use by another CPU
 */
extern int sva_vmx_io_intercept_set(int vmid, uint16_t port);

#endif /* _SVA_VMX_INTRINSICS_H */
