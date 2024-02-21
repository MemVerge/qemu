/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2024 MemVerge Inc.
 *
 */

#ifndef CXL_MHSLD_H
#define CXL_MHSLD_H
#include <stdint.h>
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_mailbox.h"
#include "hw/cxl/cxl_device.h"
#include "qemu/units.h"

#define MHSLD_MIN_MEMBLK (128 * MiB)

/*
 * The shared state cannot have 2 variable sized regions
 * so we have to max out the ldmap.
 */
typedef struct MHSLDSharedState {
    uint8_t nr_heads;
    uint8_t nr_lds;
    uint8_t ldmap[65536];
    /* TODO: shared state Mutex */
    /* TODO: Extent information */
} MHSLDSharedState;

struct CXLMHSLDState {
    CXLType3Dev ct3d;
    uint32_t mhd_head;
    uint32_t mhd_shmid;
    MHSLDSharedState *mhd_state;
};

struct CXLMHSLDClass {
    CXLType3Class parent_class;
};

enum {
    MHSLD_MHD = 0x55,
        #define GET_MHD_INFO 0x0
};

/*
 * MHD Get Info Command
 * Returns information the LD's associated with this head
 */
typedef struct MHDGetInfoInput {
    uint8_t start_ld;
    uint8_t ldmap_len;
} QEMU_PACKED MHDGetInfoInput;

typedef struct MHDGetInfoOutput {
    uint8_t nr_lds;
    uint8_t nr_heads;
    uint16_t resv1;
    uint8_t start_ld;
    uint8_t ldmap_len;
    uint16_t resv2;
    uint8_t ldmap[];
} QEMU_PACKED MHDGetInfoOutput;
#endif
