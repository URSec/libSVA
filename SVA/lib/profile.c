/*===- profile.c - SVA Execution Engine Assembly ---------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the Rochester Security Group and is distributed
 * under the University of Illinois Open Source License. See LICENSE.TXT for
 * details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file provides functions that profile the time spent in different
 * SVA-OS intrinsics.
 *
 *===----------------------------------------------------------------------===
 */


#include <sva/self_profile.h>

/* Global variables used for profiling */
bool tsc_read_enable = 0;
bool tsc_read_enable_sva = 0;
uint64_t sva_tsc_val[SVA_API_NUM];
uint64_t sva_call_freq[SVA_API_NUM];
uint64_t wp_num;
uint64_t as_num;

void init_sva_counter(void) {
  for (size_t i = 0; i < SVA_API_NUM; i++)
    sva_tsc_val[i] = sva_call_freq[i] = 0;
  wp_num = 0;
  as_num = 0;
}
