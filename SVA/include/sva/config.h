/*===- config.h - SVA Utilities --------------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file contains macros that can be used to configure the SVA
 * Execution Engine.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_CONFIG_H
#define _SVA_CONFIG_H

#include <limits.h>
#include <sva/asmconfig.h>
#include <sva/types.h>

/* Determine whether VMX features are enabled */
//#ifdef SVA_VMX
static const unsigned char usevmx = 1;
//#else
//static const unsigned char usevmx = 0;
//#endif

/* Determine whether the virtual ghost features are enabled */
#ifdef VG
static const unsigned char vg = 1;
#else
static const unsigned char vg = 0;
#endif

/* Determine whether the randomized Ghost Memory allocation is enabled */
#ifdef VG_RANDOM
static const unsigned char vg_random = 1;
#else
static const unsigned char vg_random = 0;
#endif

/* Enable or Disable the use of MPX */
#ifdef MPX
static const unsigned char usempx = 1;
#else
static const unsigned char usempx = 0;
#endif

/* Enable or Disable the use of page table side-channel defenses*/
#ifdef SVA_PG_DEF
static const unsigned char pgdef = 1;
#else
static const unsigned char pgdef = 0;
#endif

/* Configure whether to use the hack that keeps page tables writeable */
static unsigned char keepPTWriteableHack = 1;

/* Enable/Disable MMU checks */
#ifdef CHECKMMU
static unsigned char disableMMUChecks = 0;
#else
static unsigned char disableMMUChecks = 1;
#endif

/* Enable/Disable SVA direct map */
#ifdef SVA_DMAP
static const bool sva_dmap = 1;
#else
static const bool sva_dmap = 0;
#endif


/* Enable copying of the Interrupt Context to Trapframe for Debugging */
static unsigned char copyICToTrapFrame = 0;

#endif
