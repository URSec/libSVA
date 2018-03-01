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
 */
enum sva_vmcs_field {
  REPLACE_ME // placeholder so enum isn't empty
};

/* Prototypes for VMX intrinsics */
size_t allocvm(void);
int freevm(size_t vmid);
int readvmcs(size_t vmid, enum sva_vmcs_field field, void * data);
int writevmcs(size_t vmid, enum sva_vmcs_field field, void * data);
int launchvm(size_t vmid);
int resumevm(size_t vmid);

unsigned char sva_init_vmx(void);

#endif /* _SVA_VMX_H */
