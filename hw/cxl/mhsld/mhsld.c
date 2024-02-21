/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2024 MemVerge Inc.
 *
 */

#include <sys/shm.h>
#include "qemu/osdep.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_mailbox.h"
#include "hw/cxl/cxl_device.h"
#include "hw/pci/pcie.h"
#include "hw/pci/pcie_port.h"
#include "hw/qdev-properties.h"
#include "mhsld.h"

#define TYPE_CXL_MHSLD "cxl-mhsld"
OBJECT_DECLARE_TYPE(CXLMHSLDState, CXLMHSLDClass, CXL_MHSLD)

/*
 * CXL r3.0 section 7.6.7.5.1 - Get Multi-Headed Info (Opcode 5500h)
 *
 * This command retrieves the number of heads, number of supported LDs,
 * and Head-to-LD mapping of a Multi-Headed device.
 */
static CXLRetCode cmd_mhd_get_info(const struct cxl_cmd *cmd,
                                   uint8_t *payload_in,
                                   size_t len_in,
                                   uint8_t *payload_out,
                                   size_t *len_out,
                                   CXLCCI * cci)
{
    CXLMHSLDState *s = CXL_MHSLD(cci->d);
    MHDGetInfoInput *input = (void *)payload_in;
    MHDGetInfoOutput *output = (void *)payload_out;

    uint8_t start_ld = input->start_ld;
    uint8_t ldmap_len = input->ldmap_len;
    uint8_t i;

    if (start_ld >= s->mhd_state->nr_lds) {
        return CXL_MBOX_INVALID_INPUT;
    }

    output->nr_lds = s->mhd_state->nr_lds;
    output->nr_heads = s->mhd_state->nr_heads;
    output->resv1 = 0;
    output->start_ld = start_ld;
    output->resv2 = 0;

    for (i = 0; i < ldmap_len && (start_ld + i) < output->nr_lds; i++) {
        output->ldmap[i] = s->mhd_state->ldmap[start_ld + i];
    }
    output->ldmap_len = i;

    *len_out = sizeof(*output) + output->ldmap_len;
    return CXL_MBOX_SUCCESS;
}

static const struct cxl_cmd cxl_cmd_set_mhsld[256][256] = {
    [MHSLD_MHD][GET_MHD_INFO] = {"GET_MULTI_HEADED_INFO",
        cmd_mhd_get_info, 2, 0},
};

static Property cxl_mhsld_props[] = {
    DEFINE_PROP_UINT32("mhd-head", CXLMHSLDState, mhd_head, ~(0)),
    DEFINE_PROP_UINT32("mhd-shmid", CXLMHSLDState, mhd_shmid, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void cxl_mhsld_realize(PCIDevice *pci_dev, Error **errp)
{
    CXLMHSLDState *s = CXL_MHSLD(pci_dev);

    ct3_realize(pci_dev, errp);

    if (!s->mhd_shmid || s->mhd_head == ~(0)) {
        error_setg(errp, "is_mhd requires mhd_shmid and mhd_head settings");
        return;
    }

    if (s->mhd_head >= 32) {
        error_setg(errp, "MHD Head ID must be between 0-31");
        return;
    }

    s->mhd_state = shmat(s->mhd_shmid, NULL, 0);
    if (s->mhd_state == (void *)-1) {
        s->mhd_state = NULL;
        error_setg(errp, "Unable to attach MHD State. Check ipcs is valid");
        return;
    }

    /* For now, limit the number of LDs to the number of heads (SLD) */
    if (s->mhd_head >= s->mhd_state->nr_heads) {
        error_setg(errp, "Invalid head ID for multiheaded device.");
        return;
    }

    if (s->mhd_state->nr_lds <= s->mhd_head) {
        error_setg(errp, "MHD Shared state does not have sufficient lds.");
        return;
    }

    s->mhd_state->ldmap[s->mhd_head] = s->mhd_head;
    return;
}

static void cxl_mhsld_exit(PCIDevice *pci_dev)
{
    CXLMHSLDState *s = CXL_MHSLD(pci_dev);

    ct3_exit(pci_dev);

    if (s->mhd_state) {
        shmdt(s->mhd_state);
    }
}

static void cxl_mhsld_reset(DeviceState *d)
{
    CXLMHSLDState *s = CXL_MHSLD(d);

    ct3d_reset(d);
    cxl_add_cci_commands(&s->ct3d.cci, cxl_cmd_set_mhsld, 512);
}

/* TODO: Implement shared device hooks
 *
 * Example: DCD-add events need to validate that the requested extent
 *          does not already have a mapping (or, if it does, it is
 *          a shared extent with the right tagging).
 *
 * Since this operates on the shared state, we will need to serialize
 * these callbacks across QEMU instances via a mutex in shared state.
 */

static void cxl_mhsld_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(klass);

    pc->realize = cxl_mhsld_realize;
    pc->exit = cxl_mhsld_exit;
    dc->reset = cxl_mhsld_reset;
    device_class_set_props(dc, cxl_mhsld_props);

    /* TODO: type3 class callbacks for multi-host access validation
     * CXLType3Class *cvc = CXL_TYPE3_CLASS(klass);
     * cvc->mhd_access_valid = mhsld_access_valid;
     * cvc->dcd_extent_action = mhsld_dcd_extent_action;
     */
}

static const TypeInfo cxl_mhsld_info = {
    .name = TYPE_CXL_MHSLD,
    .parent = TYPE_CXL_TYPE3,
    .class_size = sizeof(struct CXLMHSLDClass),
    .class_init = cxl_mhsld_class_init,
    .instance_size = sizeof(CXLMHSLDState),
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CXL_DEVICE },
        { INTERFACE_PCIE_DEVICE },
        {}
    },
};

static void cxl_mhsld_register_types(void)
{
    type_register_static(&cxl_mhsld_info);
}

type_init(cxl_mhsld_register_types)
