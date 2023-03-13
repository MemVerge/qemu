/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Generic Port device implementation
 *
 * Copyright (C) 2023 Intel Corporation
 */
#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qom/object_interfaces.h"
#include "hw/qdev-core.h"

#define TYPE_GENERIC_PORT_DEVICE "genport"

#define GENPORT_NUMA_NODE_PROP "node"
#define GENPORT_DEV_PROP       "genport"

typedef struct GenericPortDevice {
    /* private */
    DeviceState parent_obj;

    /* public */
    uint32_t node;
} GenericPortDevice;

typedef struct GenericPortDeviceClass {
        DeviceClass parent_class;
} GenericPortDeviceClass;

static Property genport_properties[] = {
    DEFINE_PROP_UINT32(GENPORT_NUMA_NODE_PROP, GenericPortDevice, node, 0),
    DEFINE_PROP_END_OF_LIST(),
};

OBJECT_DEFINE_TYPE_WITH_INTERFACES(GenericPortDevice, genport_device,
                                   GENERIC_PORT_DEVICE, DEVICE,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void genport_device_init(Object *obj)
{
}

static void genport_device_finalize(Object *obj)
{
}

static void genport_device_realize(DeviceState *dev, Error **errp)
{
        printf("XXX %s called\n", __func__);
}

static void genport_device_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = genport_device_realize;
    dc->desc = "Generic Port";
    device_class_set_props(dc, genport_properties);
}

