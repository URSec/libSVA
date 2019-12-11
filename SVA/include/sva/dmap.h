/*===- dmap.h - SVA Execution Engine  =--------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2019.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * Functions that handle direct map virtual addresses.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_DMAP_H
#define SVA_DMAP_H

#include <sva/secmem.h>

/**
 * Determine if a virtual address is part of the kernel's direct map.
 *
 * @param address The virtual address to check
 * @return        Whether or not `address` is part of the kernel's direct map
 */
static inline bool isKernelDirectMap(uintptr_t address) {
  return ((KERNDMAPSTART <= address) && (address < KERNDMAPEND));
}

#ifdef SVA_DMAP
/**
 * Determine if a virtual address is part of SVA's direct map.
 *
 * @param address The virtual address to check
 * @return        Whether or not `address` is part of SVA's direct map
 */
static inline bool isSVADirectMap(uintptr_t address) {
  return ((SVADMAPSTART <= address) && (address < SVADMAPEND));
}
#endif

/**
 * Determine if a virtual address is part of the direct map.
 *
 * This checks SVA's direct map if it is enabled, otherwise it checks the
 * kernel's.
 *
 * @param address The virtual address to check
 * @return        Whether or not `address` is part of the direct map
 */
static inline bool isDirectMap(uintptr_t address) {
#ifdef SVA_DMAP
  return isSVADirectMap(address);
#else
  return isKernelDirectMap(address);
#endif
}

/**
 * Get the SVA direct map virtual address for a physical address.
 *
 * @param paddr A physical address
 * @return      A virtual address in SVA's direct map which maps to `paddr`
 */
static inline unsigned char* getVirtualSVADMAP(uintptr_t physical) {
  return (unsigned char*)(physical | SVADMAPSTART);
}

/**
 * Get the kernel direct map virtual address for a physical address.
 *
 * @param paddr A physical address
 * @return      A virtual address in the kernel's direct map which maps to
 *              `paddr`
 */
static inline unsigned char* getVirtualKernelDMAP(uintptr_t physical) {
  return (unsigned char*)(physical | KERNDMAPSTART);
}

/**
 * Get the direct map virtual address for a physical address.
 *
 * This will use SVA's direct map if it is available and fall back on the
 * kernel's direct map if not.
 *
 * @param paddr A physical address
 * @return      A virtual address in the direct map which maps to `paddr`
 */
static inline unsigned char* getVirtual(uintptr_t physical) {
#ifdef SVA_DMAP
  return getVirtualSVADMAP(physical);
#else
  return getVirtualKernelDMAP(physical);
#endif
}

#endif /* SVA_DMAP_H */
