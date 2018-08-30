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

#include <sva/mmu_types.h>

#include <sys/types.h>

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
 * *** Structure definitions used by VMX intrinsics ***
 */

/*
 * Structure: sva_vmx_vm_ctrls
 *
 * Description:
 *  A structure describing the various VMX controls that govern execution of
 *  a VM.
 */
typedef struct sva_vmx_vm_ctrls {
  /** VM execution controls **/
  uint64_t pinbased_exec_ctrls;
  /* Primary and secondary processor-based execution controls */
  uint64_t procbased_exec_ctrls1, procbased_exec_ctrls2;
  uint64_t entry_ctrls, exit_ctrls;

  /** VM entry/exit MSR load/store controls **/
  uint64_t entry_msr_load_count;
  uint64_t exit_msr_load_count;
  uint64_t exit_msr_store_count;

  /** Event injection and exception controls **/
  uint64_t entry_interrupt_info;
  uint64_t exception_exiting_bitmap;

  /** Control register guest/host masks **/
  uint64_t cr0_guesthost_mask, cr4_guesthost_mask;
} sva_vmx_vm_ctrls;

/*
 * Structure: sva_vmx_guest_state
 *
 * Description:
 *  A structure describing the state of a guest system virtualized by a VM.
 */
typedef struct sva_vmx_guest_state {
  /*
   * This field is only used when an object of this type is returned from the
   * sva_getvmstate() intrinsic. It contains an error code for the intrinsic:
   * 0 indicates success, and a negative value indicates failure.
   *
   * It is not used when this structure is instantiated as a substructure
   * within a VM descriptor internal to SVA; however, it is overwritten there
   * by the sva_getvmstate() and sva_setvmstate() intrinsics. Other SVA code
   * should not assume it has any particular value.
   */
  int errorcode;

  /*
   *** STATE NOT SAVED/RESTORED BY PROCESSOR ON VM ENTRY/EXIT ***
   * (i.e. needs to be saved/restored by SVA)
   *
   * These fields always contain the latest values that represent the current
   * state of the guest.
   *
   * (Except when the guest is actually running, in which case the values
   * will be what they were at the time of the last VM entry. This is a moot
   * point on a uniprocessor system since the host and guest cannot both run
   * at the same time; the host can only see these values when they are in
   * fact up-to-date.)
   */

  /* General purpose registers */
  uint64_t rax, rbx, rcx, rdx;
  uint64_t rbp, rsi, rdi;
  uint64_t r8,  r9,  r10, r11;
  uint64_t r12, r13, r14, r15;

  /*
   **** STATE THAT IS SAVED/RESTORED AUTOMATICALLY BY PROCESSOR
   *    ON VM ENTRY/EXIT ***
   *
   * These fields are saved/restored directly to corresponding VMCS fields on
   * VM entry/exit. The copies here are only used when we need to allow
   * client software (the kernel/hypervisor) to read them; they are updated
   * on-demand by the sva_getvmstate() intrinsic, and written by the
   * sva_setvmstate() intrinsic.
   *
   * sva_setvmstate() sets a flag in SVA's internal VM descriptor to indicate
   * that these values should be applied to the VMCS before the next VM
   * entry.
   */

  /* Program counter and stack pointer */
  uint64_t rip, rsp;
  /* Flags register */
  uint64_t rflags;

  /* Control registers (except paging-related ones) */
  uint64_t cr0, cr4;
  /* Control register read shadows */
  uint64_t cr0_read_shadow, cr4_read_shadow;

  /* Debug registers/MSRs saved/restored by processor */
  uint64_t dr7;
  uint64_t msr_debugctl;

  /* Paging-related registers saved/restored by processor */
  uint64_t cr3;
  /* PDPTE registers (use when guest is in PAE paging mode) */
  uint64_t pdpte0, pdpte1, pdpte2, pdpte3;

  /* SYSENTER-related MSRs */
  uint64_t msr_sysenter_cs, msr_sysenter_esp, msr_sysenter_eip;

  /* Segment registers (including hidden portions) */
  uint64_t cs_base, cs_limit, cs_access_rights, cs_sel;
  uint64_t ss_base, ss_limit, ss_access_rights, ss_sel;
  uint64_t ds_base, ds_limit, ds_access_rights, ds_sel;
  uint64_t es_base, es_limit, es_access_rights, es_sel;
  uint64_t fs_base, fs_limit, fs_access_rights, fs_sel;
  uint64_t gs_base, gs_limit, gs_access_rights, gs_sel;
  /* TR (Task Register) */
  uint64_t tr_base, tr_limit, tr_access_rights, tr_sel;

  /* Descriptor table registers */
  uint64_t gdtr_base, gdtr_limit;
  uint64_t idtr_base, idtr_limit;
  uint64_t ldtr_base, ldtr_limit, ldtr_access_rights, ldtr_sel;

  /* Various other guest system state */
  uint64_t activity_state;
  uint64_t interruptibility_state;
  uint64_t pending_debug_exceptions;
} sva_vmx_guest_state;

/*
 * *** Prototypes for VMX intrinsics ***
 */
size_t sva_allocvm(sva_vmx_vm_ctrls initial_ctrls,
    sva_vmx_guest_state initial_state);
void sva_freevm(size_t vmid);
int sva_loadvm(size_t vmid);
int sva_unloadvm(void);
int sva_readvmcs(enum sva_vmcs_field field, uint64_t *data);
int sva_writevmcs(enum sva_vmcs_field field, uint64_t data);
int sva_launchvm(void);
int sva_resumevm(void);
/* TODO: implement these.
 *
 * We don't need them just yet since (at the moment) we only set these
 * controls once when we create the VM and never change them.
 *
 * Note to self:
 *  This will be simpler to implement than the corresponding guest state
 *  intrinsics, since **most** (but not all) of these fields are never
 *  changed by the processor (i.e. we only ever have to copy them one way
 *  since we know they can't have changed).
 *
 *  However, one in particular - the VM-entry interruption-info field - is
 *  changed by the processor, namely, one of its bits is flipped off to
 *  indicate that the processor successfully acted upon its contents.
 *
 *  We might not actually even need to implement sva_getvmctrls(); a single
 *  intrinsic to handle the VM-entry interruption-info field would suffice
 *  and be more efficient.
 */
#if 0
sva_vmx_vm_ctrls sva_getvmctrls(void);
void sva_setvmctrls(size_t vmid, sva_vmx_vm_ctrls newctrls);
#endif
sva_vmx_guest_state sva_getvmstate(void);
void sva_setvmstate(size_t vmid, sva_vmx_guest_state newstate);

/*
 * VMX-specific MMU intrinsics for managing Extended Page Tables.
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
void sva_update_ept_mapping(page_entry_t *eptePtr, page_entry_t val);
int sva_load_eptable(size_t vmid, pml4e_t *epml4t);
uintptr_t sva_save_eptable(size_t vmid);

/* These intrinsics are for use during development.
 * They will be removed "soon" and are not part of the designed SVA-VMX
 * interface.
 */
unsigned char sva_initvmx(void);
/* sva_print_vmx_msrs() is defined in debug.c. */
void sva_print_vmx_msrs(void);

typedef struct sva_vmx_ept_hier {
  /* Physical address of the top (fourth)-level EPT page table page, i.e.,
   * the EPT PML4 table.
   */
  uintptr_t epml4t_paddr;

  /* Physical address of the third-level EPT page table page, i.e., the EPT
   * Page Directory Pointer Table (PDPT).
   */
  uintptr_t epdpt_paddr;

  /* Physical address of the second-level EPT page table page, i.e., the EPT
   * Page Directory (PD).
   */
  uintptr_t epd_paddr;

  /* Physical address of the lowest (first)-level EPT page table page, i.e.,
   * the EPT Page Table (PT).
   */
  uintptr_t ept_paddr;

  /* Host-physical addresses of the 16 pages which are mapped into the
   * guest's physical address space.
   */
  uintptr_t guestpage_host_paddrs[16];

  /* Guest-physical addresses of the 16 pages mapped into the guest's
   * physical address space. (They are mapped contiguously, so these
   * addresses just count up by 0x1000.)
   */
  uintptr_t guestpage_guest_paddrs[16];

  /* Guest-virtual addresses of the 16 pages in the guest-virtual mapping
   * which are backed by the 16 respective guest-physical pages. (These are
   * also mapped contiguously, i.e. the addresses count up by 0x1000.)
   *
   * (The mapped guest-virtual space is larger, but not all of its pages
   * correspond to guest-physical addresses that are present in the EPT map.)
   */
  uintptr_t guestpage_guest_vaddrs[16];
} sva_vmx_ept_hier;
sva_vmx_ept_hier sva_set_up_ept(void);

void sva_print_guest_stack(sva_vmx_ept_hier hier);
/* Defined in debug.c */
void print_vmcs_field_name(enum sva_vmcs_field);

#endif /* _SVA_VMX_INTRINSICS_H */
