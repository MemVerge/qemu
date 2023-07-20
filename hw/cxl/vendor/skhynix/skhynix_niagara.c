/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2023 MemVerge Inc.
 * Copyright (c) 2023 SK hynix Inc.
 *
 * Reference list:
 * From www.computeexpresslink.org
 * Compute Express Link (CXL) Specification revision 3.0 Version 1.0
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_device.h"
#include "hw/pci/pcie.h"
#include "hw/pci/pcie_port.h"
#include "hw/qdev-properties.h"

#define MIN_MEMBLK_SIZE (1024*1024*128)

/*
 * The shared state cannot have 2 variable sized regions
 * so we have to max out the ldmap.
*/
typedef struct Niagara_Shared_State Niagara_Shared_State;
struct Niagara_Shared_State {
    uint8_t nr_heads;
    uint8_t nr_lds;
    uint8_t ldmap[65536];
    uint32_t total_sections;
    uint32_t free_sections;
    uint32_t section_size;
    uint32_t sections[];
};

#define IMMEDIATE_CONFIG_CHANGE (1 << 1)
#define IMMEDIATE_DATA_CHANGE (1 << 2)
#define IMMEDIATE_POLICY_CHANGE (1 << 3)
#define IMMEDIATE_LOG_CHANGE (1 << 4)
#define SECURITY_STATE_CHANGE (1 << 5)
#define BACKGROUND_OPERATION (1 << 6)

enum {
    NIAGARA = 0xC0
        #define GET_SECTION_STATUS 0x0
        #define SET_SECTION_ALLOC 0x1
        #define SET_SECTION_RELEASE 0x2
        #define SET_SECTION_SIZE 0x3
        #define MOVE_DATA 0x4
        #define GET_SECTION_MAP 0x5
        #define CLEAR_SECTION 0x99
};

static CXLRetCode cmd_niagara_get_section_status(const struct cxl_cmd *cmd,
                                               uint8_t *payload_in,
                                               size_t len_in,
                                               uint8_t *payload_out,
                                               size_t *len_out,
                                               CXLCCI *cci)
{
    CXLType3Dev *ct3d = CXL_TYPE3(cci->d);
    Niagara_Shared_State *niagara_state = (Niagara_Shared_State*)ct3d->mhd_state;
    struct {
        uint32_t total_section_count;
        uint32_t free_section_count;
    } QEMU_PACKED *output = (void *)payload_out;

    if (!ct3d->is_mhd)
        return CXL_MBOX_UNSUPPORTED;

    output->total_section_count = niagara_state->total_sections;
    output->free_section_count = niagara_state->free_sections;

    *len_out = sizeof(*output);

    return CXL_MBOX_SUCCESS;
}

#define MHD_SECTION_ALLOC_POLICY_ALL_OR_NOTHING 0
#define MHD_SECTION_ALLOC_POLICY_BEST_EFFORT 1
#define MHD_SECTION_ALLOC_POLICY_MANUAL 2
static CXLRetCode cmd_niagara_set_section_alloc(const struct cxl_cmd *cmd,
                                              uint8_t *payload_in,
                                              size_t len_in,
                                              uint8_t *payload_out,
                                              size_t *len_out,
                                              CXLCCI *cci)
{
    CXLType3Dev *ct3d = CXL_TYPE3(cci->d);
    Niagara_Shared_State *niagara_state = (Niagara_Shared_State*)ct3d->mhd_state;
    struct {
        uint8_t policy;
        uint8_t reserved1[3];
        uint32_t section_count;
        uint8_t reserved2[4];
        uint32_t extent_count;
        struct {
            uint32_t start_section_id;
            uint32_t section_count;
            uint8_t reserved[8];
        } extents[];
    } QEMU_PACKED *input = (void *)payload_in;
    struct {
        uint32_t section_count;
        uint32_t extent_count;
        struct {
            uint32_t start_section_id;
            uint32_t section_count;
            uint8_t reserved[8];
        } extents[];
    } QEMU_PACKED *output = (void *)payload_out;

    uint8_t policy = input->policy;
    uint32_t count = input->section_count;
    uint32_t i = 0;

    if (count == 0 || count > niagara_state->total_sections) {
        return CXL_MBOX_INVALID_INPUT;
    }

    if (input->policy == MHD_SECTION_ALLOC_POLICY_MANUAL) {
        /* iterate input extents and count total sections for validation */
        uint32_t ttl_sec = 0;
        for (i = 0; i < input->extent_count; i++) {
            uint32_t start = input->extents[i].start_section_id;
            uint32_t end = start + input->extents[i].section_count;
            if ((start >= niagara_state->total_sections) || (end > niagara_state->total_sections))
                return CXL_MBOX_INVALID_INPUT;
            ttl_sec += input->extents[i].section_count;
        }
        if (ttl_sec != input->section_count)
            return CXL_MBOX_INVALID_INPUT;
    }

    uint32_t *section_ids = malloc(count*sizeof(uint32_t));
    uint32_t *sections = &niagara_state->sections[0];
    uint32_t allocated = 0;

    if (input->policy & MHD_SECTION_ALLOC_POLICY_MANUAL) {
        uint32_t cur_extent = 0;
        for (cur_extent = 0; cur_extent < input->extent_count; cur_extent++) {
            uint32_t start_section = input->extents[cur_extent].start_section_id;
            uint32_t count = input->extents[cur_extent].section_count;
            uint32_t cur_section;
            for (cur_section = input->extents[cur_extent].start_section_id;
                 cur_section < (start_section + count);
                 cur_section++) {
                uint32_t *section = &sections[cur_section];
                uint32_t old_value = __sync_fetch_and_or(section, (1 << ct3d->mhd_head));
                /* if the old value wasn't 0, this section was already claimed
                 * if it was owned by use already, just continue and don't count it
                 */
                if (old_value & (1 << ct3d->mhd_head)) {
                    continue;
                } else if (old_value != 0) {
                    __sync_fetch_and_and(section, ~(1 << ct3d->mhd_head));
                    continue;
                }
                __sync_fetch_and_sub(&niagara_state->free_sections, 1);
                section_ids[allocated++] = i;
            }
        }
    } else {
        /* Iterate the the section list and allocate free sections */
        for (i = 0; (i < niagara_state->total_sections) && (allocated != count); i++) {
            uint32_t old_value = __sync_fetch_and_or(&sections[i], (1 << ct3d->mhd_head));
            /* if the old value wasn't 0, this section was already claimed
             * if it was owned by use already, just continue and don't count it
             */
            if (old_value & (1 << ct3d->mhd_head)) {
                continue;
            } else if (old_value != 0) {
                __sync_fetch_and_and(&sections[i], ~(1 << ct3d->mhd_head));
                continue;
            }
            __sync_fetch_and_sub(&niagara_state->free_sections, 1);
            section_ids[allocated++] = i;
        }
    }

    if ((policy & MHD_SECTION_ALLOC_POLICY_ALL_OR_NOTHING) &&
        (allocated != count)) {
        goto all_or_nothing_fail;
    }

    /* Build the output */
    output->section_count = allocated;
    uint32_t extents = 0;
    uint32_t previous = 0;
    for (i=0; i < allocated; i++) {
        if (i == 0) {
            /* start the first extent */
            output->extents[extents].start_section_id = section_ids[i];
            output->extents[extents].section_count = 1;
            extents++;
        }
        else if (section_ids[i] == (previous+1)) {
            /* increment the current extent */
            output->extents[extents-1].section_count++;
        }
        else {
            /* start a new extent */
            output->extents[extents].start_section_id = section_ids[i];
            output->extents[extents].section_count = 1;
            extents++;
        }
        previous = section_ids[i];
    }
    output->extent_count = extents;

    *len_out = (8+(16*extents));

    free(section_ids);
    return CXL_MBOX_SUCCESS;
all_or_nothing_fail:
    /* free any successfully allocated sections */
    for (i = 0; i < allocated; i++) {
        __sync_fetch_and_and(&sections[i], ~(1 << ct3d->mhd_head));
        __sync_fetch_and_add(&niagara_state->free_sections, 1);
    }
    free(section_ids);
    return CXL_MBOX_INTERNAL_ERROR;
}

#define MHD_SECTION_RELEASE_POLICY_NONE 0
#define MHD_SECTION_RELEASE_POLICY_CLEARING 1
#define MHD_SECTION_RELEASE_POLICY_RANDOMIZING 2
static CXLRetCode cmd_niagara_set_section_release(const struct cxl_cmd *cmd,
                                                uint8_t *payload_in,
                                                size_t len_in,
                                                uint8_t *payload_out,
                                                size_t *len_out,
                                                CXLCCI *cci)
{
    CXLType3Dev *ct3d = CXL_TYPE3(cci->d);
    Niagara_Shared_State *niagara_state = (Niagara_Shared_State*)ct3d->mhd_state;
    struct {
        uint32_t extent_count;
        uint8_t policy;
        uint8_t reserved[3];
        struct {
            uint32_t start_section_id;
            uint32_t section_count;
            uint8_t reserved[8];
        } extents[];
    } QEMU_PACKED *input = (void *)payload_in;
    uint32_t i, j;

    uint32_t* sections = &niagara_state->sections[0];
    for (i = 0; i < input->extent_count; i++) {
        uint32_t start = input->extents[i].start_section_id;
        for (j = 0; j < input->extents[i].section_count; j++) {
            uint32_t old_val = __sync_fetch_and_and(&sections[start+j], ~(1 << ct3d->mhd_head));
            if (old_val & (1 << ct3d->mhd_head))
                __sync_fetch_and_add(&niagara_state->free_sections, 1);

            // TODO: Policy
        }
    }

    return CXL_MBOX_SUCCESS;
}

static CXLRetCode cmd_niagara_set_section_size(const struct cxl_cmd *cmd,
                                             uint8_t *payload_in,
                                             size_t len_in,
                                             uint8_t *payload_out,
                                             size_t *len_out,
                                             CXLCCI *cci)
{
    CXLType3Dev *ct3d = CXL_TYPE3(cci->d);
    Niagara_Shared_State *niagara_state = (Niagara_Shared_State*)ct3d->mhd_state;
    struct {
        uint8_t section_unit;
        uint8_t reserved[7];
    } QEMU_PACKED *input = (void *)payload_in;
    struct {
        uint8_t section_unit;
        uint8_t reserved[7];
    } QEMU_PACKED *output = (void *)payload_out;

    if (niagara_state->section_size ==  (1 << (input->section_unit - 1)))
        goto set_section_size_success;

    /* Check that there are no actively alloc'd sections */
    if(niagara_state->free_sections != niagara_state->total_sections)
        return CXL_MBOX_INTERNAL_ERROR;

    uint32_t prev_section_size = niagara_state->section_size;
    uint32_t prev_total_sections = niagara_state->total_sections;

    niagara_state->section_size = (1 << (input->section_unit - 1));
    niagara_state->total_sections = (prev_section_size * prev_total_sections) / niagara_state->section_size;
    niagara_state->free_sections = niagara_state->total_sections;

set_section_size_success:
    output->section_unit = input->section_unit;
    return CXL_MBOX_SUCCESS;
}

#define MHD_MOVE_DATA_POLICY_CLEARING 0
#define MHD_MOVE_DATA_POLICY_NONE 1
static CXLRetCode cmd_niagara_move_data(const struct cxl_cmd *cmd,
                                      uint8_t *payload_in,
                                      size_t len_in,
                                      uint8_t *payload_out,
                                      size_t *len_out,
                                      CXLCCI *cci)
{
    struct {
        uint32_t extent_count;
        uint8_t policy;
        uint8_t reserved[3];
        struct {
            uint32_t source_section_id;
            uint32_t source_data_offset;
            uint32_t destination_section_id;
            uint32_t destination_data_offset;
            uint32_t data_length;
            uint8_t reserved[4];
        } extents;
    } QEMU_PACKED *input = (void *)payload_in;

    struct {
        uint64_t task_id;
        uint32_t bitset[];
    } QEMU_PACKED *output = (void *)payload_out;

    (void)input;
    (void)output;

    return CXL_MBOX_UNSUPPORTED;
}

static CXLRetCode cmd_niagara_clear_section(const struct cxl_cmd *cmd,
                                          uint8_t *payload_in,
                                          size_t len_in,
                                          uint8_t *payload_out,
                                          size_t *len_out,
                                          CXLCCI *cci)
{
    return CXL_MBOX_UNSUPPORTED;
}

#define MHD_GSM_QUERY_FREE 0
#define MHD_GSM_QUERY_ALLOCATED 1
static CXLRetCode cmd_niagara_get_section_map(const struct cxl_cmd *cmd,
                                            uint8_t *payload_in,
                                            size_t len_in,
                                            uint8_t *payload_out,
                                            size_t *len_out,
                                            CXLCCI *cci)
{
    CXLType3Dev *ct3d = CXL_TYPE3(cci->d);
    Niagara_Shared_State *niagara_state = (Niagara_Shared_State*)ct3d->mhd_state;
    struct {
        uint8_t query_type;
        uint8_t reserved[7];
    } QEMU_PACKED *input = (void *)payload_in;
    struct {
        uint32_t ttl_section_count;
        uint32_t qry_section_count;
        uint8_t bitset[];
    } QEMU_PACKED *output = (void *)payload_out;

    uint8_t query_type = input->query_type;
    uint32_t i;

    if ((query_type != MHD_GSM_QUERY_FREE) && (query_type != MHD_GSM_QUERY_ALLOCATED))
        return CXL_MBOX_INVALID_INPUT;

    output->ttl_section_count = niagara_state->total_sections;
    output->qry_section_count = 0;
    uint32_t bytes = (output->ttl_section_count/8);
    if (output->ttl_section_count % 8)
        bytes += 1;
    for (i = 0; i < bytes; i++)
        output->bitset[i] = 0x0;

    /* Iterate the the section list and check the bits */
    uint32_t* sections = &niagara_state->sections[0];
    for (i = 0; (i < niagara_state->total_sections); i++) {
        uint32_t section = sections[i];
        if (((query_type == MHD_GSM_QUERY_FREE) && (!section)) ||
            ((query_type == MHD_GSM_QUERY_ALLOCATED) && (section & (1 << ct3d->mhd_head)))) {
            uint32_t byte = i / 8;
            uint8_t bit = (1 << (i % 8));
            output->bitset[byte] |= bit;
            output->qry_section_count++;
        }
    }

    *len_out = (8+bytes);
    return CXL_MBOX_SUCCESS;
}

static bool mhdsld_access_valid(CXLType3Dev *ct3d, uint64_t dpa_offset, unsigned int size) {
    Niagara_Shared_State *niagara_state = (Niagara_Shared_State*)ct3d->mhd_state;
    if (ct3d->mhd_state) {
        uint32_t section = (dpa_offset / MIN_MEMBLK_SIZE);
        if (!(niagara_state->sections[section] & (1 << ct3d->mhd_head))) {
            return false;
        }
    }
    return true;
}

static const struct cxl_cmd cxl_cmd_set_niagara[256][256] = {
    [NIAGARA][GET_SECTION_STATUS] = { "GET_SECTION_STATUS",
        cmd_niagara_get_section_status, 0, 0 },
    [NIAGARA][SET_SECTION_ALLOC] = { "SET_SECTION_ALLOC",
        cmd_niagara_set_section_alloc, ~0,
        (IMMEDIATE_CONFIG_CHANGE | IMMEDIATE_DATA_CHANGE |
         IMMEDIATE_POLICY_CHANGE | IMMEDIATE_LOG_CHANGE)
    },
    [NIAGARA][SET_SECTION_RELEASE] = { "SET_SECTION_RELEASE",
        cmd_niagara_set_section_release, ~0,
        (IMMEDIATE_CONFIG_CHANGE | IMMEDIATE_DATA_CHANGE |
         IMMEDIATE_POLICY_CHANGE | IMMEDIATE_LOG_CHANGE)
    },
    [NIAGARA][SET_SECTION_SIZE] = { "SET_SECTION_SIZE",
        cmd_niagara_set_section_size, 8,
        (IMMEDIATE_CONFIG_CHANGE | IMMEDIATE_DATA_CHANGE |
         IMMEDIATE_POLICY_CHANGE | IMMEDIATE_LOG_CHANGE)
    },
    [NIAGARA][MOVE_DATA] = { "MOVE_DATA",
        cmd_niagara_move_data, ~0, IMMEDIATE_DATA_CHANGE },
    [NIAGARA][GET_SECTION_MAP] = { "GET_SECTION_MAP",
        cmd_niagara_get_section_map, 8 , IMMEDIATE_DATA_CHANGE },
    [NIAGARA][CLEAR_SECTION] = { "CLEAR_SECTION",
        cmd_niagara_clear_section, 0, IMMEDIATE_DATA_CHANGE },
};

enum cxl_dev_type {
    cxl_type3,
};

struct CXL_Niagara_State {
    CXLType3Dev parent_obj;
    PCIDevice *target;
    enum cxl_dev_type type;
    CXLCCI *cci;
};

struct CXL_NiagaraClass {
    CXLType3Class parent_class;
};


#define TYPE_CXL_Niagara "cxl-skh-niagara"
OBJECT_DECLARE_TYPE(CXL_Niagara_State, CXL_NiagaraClass, CXL_Niagara)

static Property cxl_niagara_props[] = {
    DEFINE_PROP_LINK("target", CXL_Niagara_State,
                     target, TYPE_PCI_DEVICE, PCIDevice *),
    DEFINE_PROP_END_OF_LIST(),
};

static void cxl_niagara_realize(DeviceState *d, Error **errp)
{
    CXL_Niagara_State *s = CXL_Niagara(d);

    if (object_dynamic_cast(OBJECT(s->target), TYPE_CXL_TYPE3)) {
        CXLType3Dev *ct3d = CXL_TYPE3(s->target);

        if (!ct3d->is_mhd) {
            error_setg(errp, "Niagara target must be a cxl-type3 mhd");
            return;
        }

        s->type = cxl_type3;
        s->cci = &ct3d->cci;

        ct3d->mhd_access_valid = mhdsld_access_valid;
        return;
    }

    error_setg(errp, "Unhandled target type for CXL Niagara MHSLD");
}

static void cxl_niagara_reset(DeviceState *d)
{
    CXL_Niagara_State *s = CXL_Niagara(d);

    if (object_dynamic_cast(OBJECT(s->target), TYPE_CXL_TYPE3)) {
        CXLType3Dev *ct3d = CXL_TYPE3(s->target);
        cxl_add_cci_commands(&ct3d->cci, cxl_cmd_set_niagara, 512);
        return;
    }
}

static void cxl_niagara_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = cxl_niagara_realize;
    dc->reset = cxl_niagara_reset;
    device_class_set_props(dc, cxl_niagara_props);
}

static const TypeInfo cxl_niagara_info = {
    .name = TYPE_CXL_Niagara,
    .parent = TYPE_CXL_TYPE3,
    .class_size = sizeof(struct CXL_NiagaraClass),
    .class_init = cxl_niagara_class_init,
    .instance_size = sizeof(CXL_Niagara_State),
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CXL_DEVICE },
        { INTERFACE_PCIE_DEVICE },
        {}
    },
};

static void cxl_niagara_register_types(void)
{
    type_register_static(&cxl_niagara_info);
}

type_init(cxl_niagara_register_types)
