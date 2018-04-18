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
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_VMX_H
#define _SVA_VMX_H

#include <sys/types.h>

/*
 * Enumeration: vmcs_field
 *
 * Identifies a Virtual Machine Control Structure field to be read or
 * written by the readvmcs()/writevmcs() intrinsics.
 *
 * The values of the enum entries are explicitly chosen so that they are
 * exactly the same as their corresponding 16-bit field encodings specified
 * in the Intel manual. This allows us to directly pass an enum value to the
 * VMREAD/VMWRITE instructions.
 */
enum sva_vmcs_field {
  VMCS_VM_INST_ERR = 0x4400,
  VMCS_EXIT_REASON = 0x4402,

  VMCS_GUEST_RIP = 0x681e,

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

  REPLACE_ME // placeholder so enum isn't empty
};

/* Prototypes for VMX intrinsics */
size_t sva_allocvm(void);
void sva_freevm(size_t vmid);
int sva_loadvm(size_t vmid);
int sva_unloadvm(void);
int sva_readvmcs(enum sva_vmcs_field field, uint64_t *data);
int sva_writevmcs(enum sva_vmcs_field field, uint64_t data);
int sva_launchvm(void);
int sva_resumevm(void);

/* These intrinsics are for use during development.
 * They will be removed "soon" and are not part of the designed SVA-VMX
 * interface.
 */
unsigned char sva_initvmx(void);
void print_vmx_msrs(void);

#endif /* _SVA_VMX_H */
