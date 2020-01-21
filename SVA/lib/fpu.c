/*===- fpu.c - SVA x87, SSE, AVX, and XSAVE definitions ---------------------===
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
 * This file contains definitions for SVA's support for the x87, SSE, AVX, and
 * XSAVE extentions.
 *
 *===------------------------------------------------------------------------===
 */

#include <sva/fpu.h>

#include <string.h>

uint32_t __svadata xsave_features;

void xinit(struct xsave_area* xsave_area) {
    /*
     * Header fields (except xcomp_bv) need to be all 0 or we will #GP.
     */
    memset(&xsave_area->header, 0, sizeof(struct xsave_header));
    xsave_area->header.xcomp_bv = XSTATE_XCOMP_COMPRESSED;
}
