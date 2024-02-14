/*
 * Support for generating APEI tables and recording CPER for Guests
 *
 * Copyright (c) 2020 HUAWEI TECHNOLOGIES CO., LTD.
 *
 * Author: Dongjiu Geng <gengdongjiu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/acpi/ghes.h"
#include "hw/acpi/aml-build.h"
#include "qemu/error-report.h"
#include "hw/acpi/generic_event_device.h"
#include "hw/nvram/fw_cfg.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "qemu/uuid.h"
#include "hw/cxl/cxl_device.h"
#include "hw/cxl/cxl.h"

#define ACPI_GHES_ERRORS_FW_CFG_FILE        "etc/hardware_errors"
#define ACPI_GHES_DATA_ADDR_FW_CFG_FILE     "etc/hardware_errors_addr"

/* The max size in bytes for one error block */
#define ACPI_GHES_MAX_RAW_DATA_LENGTH   (1 * KiB)

/* Support ARMv8 SEA notification type error source and GPIO interrupt. */
#define ACPI_GHES_ERROR_SOURCE_COUNT        2

/* Generic Hardware Error Source version 2 */
#define ACPI_GHES_SOURCE_GENERIC_ERROR_V2   10

/* Address offset in Generic Address Structure(GAS) */
#define GAS_ADDR_OFFSET 4

/*
 * The total size of Generic Error Data Entry
 * ACPI 6.1/6.2: 18.3.2.7.1 Generic Error Data,
 * Table 18-343 Generic Error Data Entry
 */
#define ACPI_GHES_DATA_LENGTH               72

/* The memory section CPER size, UEFI 2.6: N.2.5 Memory Error Section */
#define ACPI_GHES_MEM_CPER_LENGTH           80
#define ACPI_GHES_PCIE_CPER_LENGTH 208

/* Masks for block_status flags */
#define ACPI_GEBS_UNCORRECTABLE         1

/*
 * Total size for Generic Error Status Block except Generic Error Data Entries
 * ACPI 6.2: 18.3.2.7.1 Generic Error Data,
 * Table 18-380 Generic Error Status Block
 */
#define ACPI_GHES_GESB_SIZE                 20

/*
 * Values for error_severity field
 */
enum AcpiGenericErrorSeverity {
    ACPI_CPER_SEV_RECOVERABLE = 0,
    ACPI_CPER_SEV_FATAL = 1,
    ACPI_CPER_SEV_CORRECTED = 2,
    ACPI_CPER_SEV_NONE = 3,
};

/*
 * Hardware Error Notification
 * ACPI 4.0: 17.3.2.7 Hardware Error Notification
 * Composes dummy Hardware Error Notification descriptor of specified type
 */
static void build_ghes_hw_error_notification(GArray *table, const uint8_t type)
{
    /* Type */
    build_append_int_noprefix(table, type, 1);
    /*
     * Length:
     * Total length of the structure in bytes
     */
    build_append_int_noprefix(table, 28, 1);
    /* Configuration Write Enable */
    build_append_int_noprefix(table, 0, 2);
    /* Poll Interval */
    build_append_int_noprefix(table, 0, 4);
    /* Vector */
    build_append_int_noprefix(table, 0, 4);
    /* Switch To Polling Threshold Value */
    build_append_int_noprefix(table, 0, 4);
    /* Switch To Polling Threshold Window */
    build_append_int_noprefix(table, 0, 4);
    /* Error Threshold Value */
    build_append_int_noprefix(table, 0, 4);
    /* Error Threshold Window */
    build_append_int_noprefix(table, 0, 4);
}

/*
 * Generic Error Data Entry
 * ACPI 6.1: 18.3.2.7.1 Generic Error Data
 */
static void acpi_ghes_generic_error_data(GArray *table,
                const uint8_t *section_type, uint32_t error_severity,
                uint8_t validation_bits, uint8_t flags,
                uint32_t error_data_length, QemuUUID fru_id,
                uint64_t time_stamp)
{
    const uint8_t fru_text[20] = {0};

    /* Section Type */
    g_array_append_vals(table, section_type, 16);

    /* Error Severity */
    build_append_int_noprefix(table, error_severity, 4);
    /* Revision */
    build_append_int_noprefix(table, 0x300, 2);
    /* Validation Bits */
    build_append_int_noprefix(table, validation_bits, 1);
    /* Flags */
    build_append_int_noprefix(table, flags, 1);
    /* Error Data Length */
    build_append_int_noprefix(table, error_data_length, 4);

    /* FRU Id */
    g_array_append_vals(table, fru_id.data, ARRAY_SIZE(fru_id.data));

    /* FRU Text */
    g_array_append_vals(table, fru_text, sizeof(fru_text));

    /* Timestamp */
    build_append_int_noprefix(table, time_stamp, 8);
}

/*
 * Generic Error Status Block
 * ACPI 6.1: 18.3.2.7.1 Generic Error Data
 */
static void acpi_ghes_generic_error_status(GArray *table, uint32_t block_status,
                uint32_t raw_data_offset, uint32_t raw_data_length,
                uint32_t data_length, uint32_t error_severity)
{
    /* Block Status */
    build_append_int_noprefix(table, block_status, 4);
    /* Raw Data Offset */
    build_append_int_noprefix(table, raw_data_offset, 4);
    /* Raw Data Length */
    build_append_int_noprefix(table, raw_data_length, 4);
    /* Data Length */
    build_append_int_noprefix(table, data_length, 4);
    /* Error Severity */
    build_append_int_noprefix(table, error_severity, 4);
}

/* UEFI 2.6: N.2.5 Memory Error Section */
static void acpi_ghes_build_append_mem_cper(GArray *table,
                                            uint64_t error_physical_addr)
{
    /*
     * Memory Error Record
     */

    /* Validation Bits */
    build_append_int_noprefix(table,
                              (1ULL << 14) | /* Type Valid */
                              (1ULL << 1) /* Physical Address Valid */,
                              8);
    /* Error Status */
    build_append_int_noprefix(table, 0, 8);
    /* Physical Address */
    build_append_int_noprefix(table, error_physical_addr, 8);
    /* Skip all the detailed information normally found in such a record */
    build_append_int_noprefix(table, 0, 48);
    /* Memory Error Type */
    build_append_int_noprefix(table, 0 /* Unknown error */, 1);
    /* Skip all the detailed information normally found in such a record */
    build_append_int_noprefix(table, 0, 7);
}

static void build_append_aer_cper(PCIDevice *dev, GArray *table)
{
    PCIDeviceClass *pci_class = PCI_DEVICE_GET_CLASS(dev);
    uint16_t pcie_cap_offset = pci_find_capability(dev, 0x10);
    uint16_t sn_cap_offset = pcie_find_capability(dev, 0x3);
    uint16_t aer_cap_offset = pcie_find_capability(dev, 0x1);
    int i;

    build_append_int_noprefix(table,
                               /* Port Type */
                              ((pcie_cap_offset ? 1UL : 0UL) << 0) |
                               /* PCI Express Version */
                              (1UL << 1) |
                              /* Command Status */
                              (1UL << 2) |
                              /* Device ID valid */
                              (1UL << 3) |
                              /* Serial Number */
                              ((sn_cap_offset ? 1UL : 0UL) << 4) |
                              /* Whole PCIe Capability */
                              ((pcie_cap_offset ? 1UL : 0UL) << 6) |
                              /* AER capability */
                              ((aer_cap_offset ? 1UL : 0UL) << 7),
                              8);
    if (pcie_cap_offset) {
        uint16_t cap_reg = pci_get_word(dev->config + pcie_cap_offset
                                        + PCI_EXP_FLAGS);
        uint16_t port_type = (cap_reg & PCI_EXP_FLAGS_TYPE) >>
            PCI_EXP_FLAGS_TYPE_SHIFT;

        build_append_int_noprefix(table, port_type, 4);
    }
    build_append_int_noprefix(table, 1, 1); /* Version PCIE r6.1 */
    build_append_int_noprefix(table, 6, 1);
    build_append_int_noprefix(table, 0, 2); /* Reserved */

    build_append_int_noprefix(table,
                              pci_get_word(dev->config + PCI_COMMAND), 2);
    build_append_int_noprefix(table, pci_get_word(dev->config + PCI_STATUS), 2);
    build_append_int_noprefix(table, 0, 4); /* 20-23 reserved */

    build_append_int_noprefix(table, pci_class->vendor_id, 2);
    build_append_int_noprefix(table, pci_class->device_id, 2);
    build_append_int_noprefix(table, pci_class->class_id, 3);
    build_append_int_noprefix(table, PCI_FUNC(dev->devfn), 1);
    build_append_int_noprefix(table, PCI_SLOT(dev->devfn), 1);
    build_append_int_noprefix(table, 0, 2); /* Segment number */

    /* RP/B primary bus number / device bus number */
    build_append_int_noprefix(table, pci_dev_bus_num(dev), 1);
    build_append_int_noprefix(table, 0, 1);
    /*
     * TODO: Figure out where to get the slot number from.
     * The slot number capability is deprecated so it only really
     * exists via the _DSM which is not easily available from here.
     */
    build_append_int_noprefix(table, 0, 2);
    build_append_int_noprefix(table, 0, 1);  /* reserved */

    /* Serial number */
    if (sn_cap_offset) {
        uint32_t dw = pci_get_long(dev->config + sn_cap_offset + 4);

        build_append_int_noprefix(table, dw, 4);
        dw = pci_get_long(dev->config + sn_cap_offset + 8);
        build_append_int_noprefix(table, dw, 4);
    } else {
        build_append_int_noprefix(table, 0, 8);
    }

    /* Bridge control status */
    build_append_int_noprefix(table, 0, 4);

    if (pcie_cap_offset) {
        uint32_t *pcie_cap = (uint32_t *)(dev->config + pcie_cap_offset);
        for (i = 0; i < 60 / sizeof(uint32_t); i++) {
            build_append_int_noprefix(table, pcie_cap[i], sizeof(uint32_t));
        }
    } else { /* Odd if we don't have one of these! */
        build_append_int_noprefix(table, 0, 60);
    }

    if (aer_cap_offset) {
        uint32_t *aer_cap = (uint32_t *)(dev->config + aer_cap_offset);
        for (i = 0; i < 96 / sizeof(uint32_t); i++) {
            build_append_int_noprefix(table, aer_cap[i], sizeof(uint32_t));
        }
    } else {
        build_append_int_noprefix(table, 0, 96);
    }
}

static void build_append_cxl_event_cper(PCIDevice *dev, CXLEventGenMedia *gen,
                                  GArray *table)
{
    PCIDeviceClass *pci_class = PCI_DEVICE_GET_CLASS(dev);
    uint16_t sn_cap_offset = pcie_find_capability(dev, 0x3);
    int i;

    build_append_int_noprefix(table, 0x90, 4); /* Length */
    build_append_int_noprefix(table,
                              (1UL << 0) | /* Device ID */
                              ((sn_cap_offset ? 1UL : 0UL) << 1) |
                              (1UL << 2), /* Event Log entry */
                              8);
    /* Device id - differnet syntax from protocol error - sigh */
    build_append_int_noprefix(table, pci_class->vendor_id, 2);
    build_append_int_noprefix(table, pci_class->device_id, 2);
    build_append_int_noprefix(table, PCI_FUNC(dev->devfn), 1);
    build_append_int_noprefix(table, PCI_SLOT(dev->devfn), 1);
    build_append_int_noprefix(table, pci_dev_bus_num(dev), 1);
    build_append_int_noprefix(table, 0 /* Seg */, 2);
    /*
     * TODO: figure out how to get the slot number as the slot number
     * capabiltiy is deprecated so it only really exists via _DSM
     */
    build_append_int_noprefix(table, 0, 2);

    /* Reserved */
    build_append_int_noprefix(table, 0, 1);

    if (sn_cap_offset) {
        uint32_t dw = pci_get_long(dev->config + sn_cap_offset + 4);

        build_append_int_noprefix(table, dw, 4);
        dw = pci_get_long(dev->config + sn_cap_offset + 8);
        build_append_int_noprefix(table, dw, 4);
    } else {
        build_append_int_noprefix(table, 0, 8);
    }
    for (i = offsetof(typeof(*gen), hdr.length); i < sizeof(*gen); i++) {
        build_append_int_noprefix(table, ((uint8_t *)gen)[i], 1);
    }
}

static void build_append_cxl_cper(PCIDevice *dev, CXLError *cxl_err,
                                  GArray *table)
{
    PCIDeviceClass *pci_class = PCI_DEVICE_GET_CLASS(dev);
    uint16_t sn_cap_offset = pcie_find_capability(dev, 0x3);
    uint16_t pcie_cap_offset = pci_find_capability(dev, 0x10);
    uint16_t cxl_dvsec_offset;
    uint16_t cxl_dvsec_len = 0;
    uint8_t type = 0xff;
    int i;

    if (object_dynamic_cast(OBJECT(dev), TYPE_CXL_TYPE3)) {
        type = 2;
    } else if (object_dynamic_cast(OBJECT(dev), TYPE_CXL_USP)) {
        type = 7;
    } else if (object_dynamic_cast(OBJECT(dev), TYPE_CXL_DSP)) {
        type = 6;
    } else if (object_dynamic_cast(OBJECT(dev), TYPE_CXL_ROOT_PORT)) {
        type = 5;
    }

    /* Only device or port dvsec should exist */
    cxl_dvsec_offset = pcie_find_dvsec(dev, 0x1e98, 0);
    if (cxl_dvsec_offset == 0) {
        cxl_dvsec_offset = pcie_find_dvsec(dev, 0x1e98, 3);
    }

    if (cxl_dvsec_offset) {
        cxl_dvsec_len = pci_get_long(dev->config + cxl_dvsec_offset + 4) >> 20;
    }

    /* CXL Protocol error record */
    build_append_int_noprefix(table,
                              (type != 0xff ? 1UL << 0 : 0) |
                              (1UL << 1) | /* Agent address valid */
                              (1UL << 2) | /* Device ID */
                              ((sn_cap_offset ? 1UL : 0UL) << 3) |
                              (1UL << 4) | /* Capability structure */
                              ((cxl_dvsec_offset ? 1UL : 0UL) << 5) |
                              (1UL << 6), /* Error Log */
                              8);
    /* Agent Type */
    build_append_int_noprefix(table, type, 1); /* CXL 2.0 device */

    /* Reserved */
    build_append_int_noprefix(table, 0, 7);
    /* Agent Address */
    build_append_int_noprefix(table, PCI_FUNC(dev->devfn), 1);
    build_append_int_noprefix(table, PCI_SLOT(dev->devfn), 1);
    build_append_int_noprefix(table, pci_dev_bus_num(dev), 1);
    build_append_int_noprefix(table, 0 /* Seg */, 2);
    /* Reserved */
    build_append_int_noprefix(table, 0, 3);
    /* Device id */
    build_append_int_noprefix(table, pci_class->vendor_id, 2);
    build_append_int_noprefix(table, pci_class->device_id, 2);
    build_append_int_noprefix(table, pci_class->subsystem_vendor_id, 2);
    build_append_int_noprefix(table, pci_class->subsystem_id, 2);
    build_append_int_noprefix(table, pci_class->class_id, 2);
    /*
     * TODO: figure out how to get the slot number as the slot number
     * capabiltiy is deprecated so it only really exists via _DSM
     */
    build_append_int_noprefix(table, 0, 2);
    /* Reserved */
    build_append_int_noprefix(table, 0, 4);

    if (sn_cap_offset) {
        uint32_t dw = pci_get_long(dev->config + sn_cap_offset + 4);

        build_append_int_noprefix(table, dw, 4);
        dw = pci_get_long(dev->config + sn_cap_offset + 8);
        build_append_int_noprefix(table, dw, 4);
    } else {
        build_append_int_noprefix(table, 0, 8);
    }

    if (pcie_cap_offset) {
        uint32_t *pcie_cap = (uint32_t *)(dev->config + pcie_cap_offset);
        for (i = 0; i < 60 / sizeof(uint32_t); i++) {
            build_append_int_noprefix(table, pcie_cap[i], sizeof(uint32_t));
        }
    } else { /* Odd if we don't have one of these! */
        build_append_int_noprefix(table, 0, 60);
    }

    /* CXL DVSEC Length */
    build_append_int_noprefix(table, cxl_dvsec_len, 2);

    /* Error log length */
    build_append_int_noprefix(table, 0x18, 2); /* No head log as I'm lazy */
    /* Reserved */
    build_append_int_noprefix(table, 0, 4);
    /* DVSEC */
    for (i = 0; i < cxl_dvsec_len; i += sizeof(uint32_t)) {
        uint32_t dw = pci_get_long(dev->config + cxl_dvsec_offset + i);

        build_append_int_noprefix(table, dw, sizeof(dw));
    }

    /* error log */
    if (object_dynamic_cast(OBJECT(dev), TYPE_CXL_TYPE3)) {
        CXLType3Dev *ct3d = CXL_TYPE3(dev);
        uint32_t *rs = ct3d->cxl_cstate.crb.cache_mem_registers;

        /*
         * TODO: Possibly move this to caller to gather up  - or work out
         * generic way to get to it.
         */
        build_append_int_noprefix(table,
                                  ldl_le_p(rs + R_CXL_RAS_UNC_ERR_STATUS), 4);
        build_append_int_noprefix(table,
                                  ldl_le_p(rs + R_CXL_RAS_UNC_ERR_MASK), 4);
        build_append_int_noprefix(table,
                                  ldl_le_p(rs + R_CXL_RAS_UNC_ERR_SEVERITY), 4);
        build_append_int_noprefix(table,
                                  ldl_le_p(rs + R_CXL_RAS_COR_ERR_STATUS), 4);
        build_append_int_noprefix(table,
                                  ldl_le_p(rs + R_CXL_RAS_COR_ERR_MASK), 4);
        build_append_int_noprefix(table,
                                  ldl_le_p(rs + R_CXL_RAS_ERR_CAP_CTRL), 4);
        if (cxl_err) {
            for (i = 0; i < CXL_RAS_ERR_HEADER_NUM; i++) {
                build_append_int_noprefix(table, cxl_err->header[i], 4);
            }
        } else {
            build_append_int_noprefix(table, 0, 4 * CXL_RAS_ERR_HEADER_NUM);
        }
    } else {
        /* TODO: Add support for ports etc */
        build_append_int_noprefix(table, 0, 0x18 + 512);
    }
}

static int acpi_ghes_record_mem_error(uint64_t error_block_address,
                                      uint64_t error_physical_addr)
{
    GArray *block;

    /* Memory Error Section Type */
    const uint8_t uefi_cper_mem_sec[] =
          UUID_LE(0xA5BC1114, 0x6F64, 0x4EDE, 0xB8, 0x63, 0x3E, 0x83, \
                  0xED, 0x7C, 0x83, 0xB1);

    /* invalid fru id: ACPI 4.0: 17.3.2.6.1 Generic Error Data,
     * Table 17-13 Generic Error Data Entry
     */
    QemuUUID fru_id = {};
    uint32_t data_length;

    block = g_array_new(false, true /* clear */, 1);

    /* This is the length if adding a new generic error data entry*/
    data_length = ACPI_GHES_DATA_LENGTH + ACPI_GHES_MEM_CPER_LENGTH;
    /*
     * It should not run out of the preallocated memory if adding a new generic
     * error data entry
     */
    assert((data_length + ACPI_GHES_GESB_SIZE) <=
            ACPI_GHES_MAX_RAW_DATA_LENGTH);

    /* Build the new generic error status block header */
    acpi_ghes_generic_error_status(block, ACPI_GEBS_UNCORRECTABLE,
        0, 0, data_length, ACPI_CPER_SEV_RECOVERABLE);

    /* Build this new generic error data entry header */
    acpi_ghes_generic_error_data(block, uefi_cper_mem_sec,
        ACPI_CPER_SEV_RECOVERABLE, 0, 0,
        ACPI_GHES_MEM_CPER_LENGTH, fru_id, 0);

    /* Build the memory section CPER for above new generic error data entry */
    acpi_ghes_build_append_mem_cper(block, error_physical_addr);

    /* Write the generic error data entry into guest memory */
    cpu_physical_memory_write(error_block_address, block->data, block->len);

    g_array_free(block, true);

    return 0;
}

static int ghes_record_aer_error(PCIDevice *dev, uint64_t error_block_address)
{
    const uint8_t aer_section_id_le[] = {
        0x54, 0xE9, 0x95, 0xD9, 0xC1, 0xBB, 0x0F,
        0x43, 0xAD, 0x91, 0xB4, 0x4D, 0xCB, 0x3C,
        0x6F, 0x35 };
    QemuUUID fru_id = { 0 };
    GArray *block = g_array_new(false, true, 1);
    uint32_t data_length;

    /* Read the current length in bytes of the generic error data */
    cpu_physical_memory_read(error_block_address + 8, &data_length, 4);

    /* Add a new generic error data entry*/
    data_length += ACPI_GHES_DATA_LENGTH;
    data_length += ACPI_GHES_PCIE_CPER_LENGTH;

    /*
     * Check whether it will run out of the preallocated memory if adding a new
     * generic error data entry
     */
    if ((data_length + ACPI_GHES_GESB_SIZE) > ACPI_GHES_MAX_RAW_DATA_LENGTH) {
        error_report("Record CPER out of boundary!!!");
        return false;
    }

    acpi_ghes_generic_error_status(block, ACPI_GEBS_UNCORRECTABLE, 0, 0,
                                   data_length, ACPI_CPER_SEV_RECOVERABLE);
    acpi_ghes_generic_error_data(block, aer_section_id_le,
                                 ACPI_CPER_SEV_RECOVERABLE, 0, 0,
                                 ACPI_GHES_PCIE_CPER_LENGTH, fru_id, 0);

    build_append_aer_cper(dev, block);
    cpu_physical_memory_write(error_block_address, block->data, block->len);
    g_array_free(block, true);

    return true;
}

static int ghes_record_cxl_gen_media(PCIDevice *dev, CXLEventGenMedia *gem,
                                     uint64_t error_block_address)
{
    QemuUUID fru_id = {0};
    GArray *block;
    uint32_t data_length;
    uint32_t event_length = 0x90;
    const uint8_t section_id_le[] = { 0x77, 0x0a, 0xcd, 0xfb,
                                      0x60, 0xc2,
                                      0x7f, 0x41,
                                      0x85, 0xa9,
                                      0x08, 0x8b, 0x16, 0x21, 0xeb, 0xa6 };
    block = g_array_new(false, true, 1);
        /* Read the current length in bytes of the generic error data */
    cpu_physical_memory_read(error_block_address + 8, &data_length, 4);

    /* Add a new generic error data entry*/
    data_length += ACPI_GHES_DATA_LENGTH;
    data_length += event_length;

    /*
     * Check whether it will run out of the preallocated memory if adding a new
     * generic error data entry
     */
    if ((data_length + ACPI_GHES_GESB_SIZE) > ACPI_GHES_MAX_RAW_DATA_LENGTH) {
        error_report("Record CPER out of boundary!!!");
        return false;
    }
    /* Build the new generic error status block header */
    acpi_ghes_generic_error_status(block, ACPI_GEBS_UNCORRECTABLE, 0, 0,
                                   data_length, ACPI_CPER_SEV_RECOVERABLE);

    /* Build the new generic error data entry header */
    acpi_ghes_generic_error_data(block, section_id_le,
                                 ACPI_CPER_SEV_RECOVERABLE, 0, 0,
                                 0x90, fru_id, 0);

    /* Build the CXL CPER */
    build_append_cxl_event_cper(dev, gem, block); /* 0x90 long */
    /* Write back above whole new generic error data entry to guest memory */
    cpu_physical_memory_write(error_block_address, block->data, block->len);
    g_array_free(block, true);

    return 0;
}

static int ghes_record_cxl_error(PCIDevice *dev, CXLError *cxl_err,
                                 uint64_t error_block_address)
{
    GArray *block;
    uint32_t data_length;
    const uint8_t aer_section_id_le[] = {
        0xB4, 0xEF, 0xB9, 0x80,
        0xB5, 0x52,
        0xE3, 0x4D,
        0xA7, 0x77, 0x68, 0x78, 0x4B, 0x77, 0x10, 0x48 };
    QemuUUID fru_id = {0};

    block = g_array_new(false, true /* clear */, 1);
    /* Read the current length in bytes of the generic error data */
    cpu_physical_memory_read(error_block_address + 8,
                             &data_length, 4);

    /* Add a new generic error data entry */
    data_length += ACPI_GHES_DATA_LENGTH;
    /* TO FIX: Error record dependent */
    data_length += ACPI_GHES_PCIE_CPER_LENGTH;

    /*
     * Check whether it will run out of the preallocated memory if adding a new
     * generic error data entry
     */
    if ((data_length + ACPI_GHES_GESB_SIZE) > ACPI_GHES_MAX_RAW_DATA_LENGTH) {
        error_report("Record CPER out of boundary!!!");
        return false;
    }
    /* Build the new generic error status block header */
    acpi_ghes_generic_error_status(block, ACPI_GEBS_UNCORRECTABLE, 0, 0,
                                   data_length, ACPI_CPER_SEV_RECOVERABLE);

    /* Build the new generic error data entry header */
    acpi_ghes_generic_error_data(block, aer_section_id_le,
                                 ACPI_CPER_SEV_RECOVERABLE, 0, 0,
                                 ACPI_GHES_PCIE_CPER_LENGTH, fru_id, 0);
    /* Build the CXL CPER */
    build_append_cxl_cper(dev, cxl_err, block);
    /* Write back above whole new generic error data entry to guest memory */
    cpu_physical_memory_write(error_block_address, block->data, block->len);
    g_array_free(block, true);
    return true;
}

/*
 * Build table for the hardware error fw_cfg blob.
 * Initialize "etc/hardware_errors" and "etc/hardware_errors_addr" fw_cfg blobs.
 * See docs/specs/acpi_hest_ghes.rst for blobs format.
 */
void build_ghes_error_table(GArray *hardware_errors, BIOSLinker *linker)
{
    int i, error_status_block_offset;

    /* Build error_block_address */
    for (i = 0; i < ACPI_GHES_ERROR_SOURCE_COUNT; i++) {
        build_append_int_noprefix(hardware_errors, 0, sizeof(uint64_t));
    }

    /* Build read_ack_register */
    for (i = 0; i < ACPI_GHES_ERROR_SOURCE_COUNT; i++) {
        /*
         * Initialize the value of read_ack_register to 1, so GHES can be
         * writable after (re)boot.
         * ACPI 6.2: 18.3.2.8 Generic Hardware Error Source version 2
         * (GHESv2 - Type 10)
         */
        build_append_int_noprefix(hardware_errors, 1, sizeof(uint64_t));
    }

    /* Generic Error Status Block offset in the hardware error fw_cfg blob */
    error_status_block_offset = hardware_errors->len;

    /* Reserve space for Error Status Data Block */
    acpi_data_push(hardware_errors,
        ACPI_GHES_MAX_RAW_DATA_LENGTH * ACPI_GHES_ERROR_SOURCE_COUNT);

    /* Tell guest firmware to place hardware_errors blob into RAM */
    bios_linker_loader_alloc(linker, ACPI_GHES_ERRORS_FW_CFG_FILE,
                             hardware_errors, sizeof(uint64_t), false);

    for (i = 0; i < ACPI_GHES_ERROR_SOURCE_COUNT; i++) {
        /*
         * Tell firmware to patch error_block_address entries to point to
         * corresponding "Generic Error Status Block"
         */
        bios_linker_loader_add_pointer(linker,
            ACPI_GHES_ERRORS_FW_CFG_FILE, sizeof(uint64_t) * i,
            sizeof(uint64_t), ACPI_GHES_ERRORS_FW_CFG_FILE,
            error_status_block_offset + i * ACPI_GHES_MAX_RAW_DATA_LENGTH);
    }

    /*
     * tell firmware to write hardware_errors GPA into
     * hardware_errors_addr fw_cfg, once the former has been initialized.
     */
    bios_linker_loader_write_pointer(linker, ACPI_GHES_DATA_ADDR_FW_CFG_FILE,
        0, sizeof(uint64_t), ACPI_GHES_ERRORS_FW_CFG_FILE, 0);
}

/* Build Generic Hardware Error Source version 2 (GHESv2) */
static void build_ghes_v2(GArray *table_data, int source_id, BIOSLinker *linker)
{
    uint64_t address_offset;
    /*
     * Type:
     * Generic Hardware Error Source version 2(GHESv2 - Type 10)
     */
    build_append_int_noprefix(table_data, ACPI_GHES_SOURCE_GENERIC_ERROR_V2, 2);
    /* Source Id */
    build_append_int_noprefix(table_data, source_id, 2);
    /* Related Source Id */
    build_append_int_noprefix(table_data, 0xffff, 2);
    /* Flags */
    build_append_int_noprefix(table_data, 0, 1);
    /* Enabled */
    build_append_int_noprefix(table_data, 1, 1);

    /* Number of Records To Pre-allocate */
    build_append_int_noprefix(table_data, 1, 4);
    /* Max Sections Per Record */
    build_append_int_noprefix(table_data, 1, 4);
    /* Max Raw Data Length */
    build_append_int_noprefix(table_data, ACPI_GHES_MAX_RAW_DATA_LENGTH, 4);

    address_offset = table_data->len;
    /* Error Status Address */
    build_append_gas(table_data, AML_AS_SYSTEM_MEMORY, 0x40, 0,
                     4 /* QWord access */, 0);
    bios_linker_loader_add_pointer(linker, ACPI_BUILD_TABLE_FILE,
        address_offset + GAS_ADDR_OFFSET, sizeof(uint64_t),
        ACPI_GHES_ERRORS_FW_CFG_FILE, source_id * sizeof(uint64_t));

    switch (source_id) {
    case ACPI_HEST_SRC_ID_SEA:
        /*
         * Notification Structure
         * Now only enable ARMv8 SEA notification type
         */
        build_ghes_hw_error_notification(table_data, ACPI_GHES_NOTIFY_SEA);
        break;
    case ACPI_HEST_SRC_ID_GPIO:
        build_ghes_hw_error_notification(table_data, ACPI_GHES_NOTIFY_GPIO);
        break;
    default:
        error_report("Not support this error source");
        abort();
    }

    /* Error Status Block Length */
    build_append_int_noprefix(table_data, ACPI_GHES_MAX_RAW_DATA_LENGTH, 4);

    /*
     * Read Ack Register
     * ACPI 6.1: 18.3.2.8 Generic Hardware Error Source
     * version 2 (GHESv2 - Type 10)
     */
    address_offset = table_data->len;
    build_append_gas(table_data, AML_AS_SYSTEM_MEMORY, 0x40, 0,
                     4 /* QWord access */, 0);
    bios_linker_loader_add_pointer(linker, ACPI_BUILD_TABLE_FILE,
        address_offset + GAS_ADDR_OFFSET,
        sizeof(uint64_t), ACPI_GHES_ERRORS_FW_CFG_FILE,
        (ACPI_GHES_ERROR_SOURCE_COUNT + source_id) * sizeof(uint64_t));

    /*
     * Read Ack Preserve field
     * We only provide the first bit in Read Ack Register to OSPM to write
     * while the other bits are preserved.
     */
    build_append_int_noprefix(table_data, ~0x1ULL, 8);
    /* Read Ack Write */
    build_append_int_noprefix(table_data, 0x1, 8);
}

/* Build Hardware Error Source Table */
void acpi_build_hest(GArray *table_data, BIOSLinker *linker,
                     const char *oem_id, const char *oem_table_id)
{
    AcpiTable table = { .sig = "HEST", .rev = 1,
                        .oem_id = oem_id, .oem_table_id = oem_table_id };

    acpi_table_begin(&table, table_data);

    /* Error Source Count */
    build_append_int_noprefix(table_data, ACPI_GHES_ERROR_SOURCE_COUNT, 4);
    build_ghes_v2(table_data, ACPI_HEST_SRC_ID_SEA, linker);
    build_ghes_v2(table_data, ACPI_HEST_SRC_ID_GPIO, linker);

    acpi_table_end(linker, &table);
}

void acpi_ghes_add_fw_cfg(AcpiGhesState *ags, FWCfgState *s,
                          GArray *hardware_error)
{
    /* Create a read-only fw_cfg file for GHES */
    fw_cfg_add_file(s, ACPI_GHES_ERRORS_FW_CFG_FILE, hardware_error->data,
                    hardware_error->len);

    /* Create a read-write fw_cfg file for Address */
    fw_cfg_add_file_callback(s, ACPI_GHES_DATA_ADDR_FW_CFG_FILE, NULL, NULL,
        NULL, &(ags->ghes_addr_le), sizeof(ags->ghes_addr_le), false);

    ags->present = true;
}

static uint64_t ghes_get_state_start_address(void)
{
    AcpiGedState *acpi_ged_state =
        ACPI_GED(object_resolve_path_type("", TYPE_ACPI_GED, NULL));
    AcpiGhesState *ags = &acpi_ged_state->ghes_state;

    return le64_to_cpu(ags->ghes_addr_le);
}

int acpi_ghes_record_errors(uint8_t source_id, uint64_t physical_address)
{
    uint64_t error_block_addr, read_ack_register_addr, read_ack_register = 0;
    uint64_t start_addr = ghes_get_state_start_address();
    bool ret = -1;
    assert(source_id < ACPI_HEST_SRC_ID_RESERVED);

    if (physical_address) {

        if (source_id < ACPI_HEST_SRC_ID_RESERVED) {
            start_addr += source_id * sizeof(uint64_t);
        }

        cpu_physical_memory_read(start_addr, &error_block_addr,
                                 sizeof(error_block_addr));

        error_block_addr = le64_to_cpu(error_block_addr);

        read_ack_register_addr = start_addr +
            ACPI_GHES_ERROR_SOURCE_COUNT * sizeof(uint64_t);

        cpu_physical_memory_read(read_ack_register_addr,
                                 &read_ack_register, sizeof(read_ack_register));

        /* zero means OSPM does not acknowledge the error */
        if (!read_ack_register) {
            error_report("OSPM does not acknowledge previous error,"
                " so can not record CPER for current error anymore");
        } else if (error_block_addr) {
            read_ack_register = cpu_to_le64(0);
            /*
             * Clear the Read Ack Register, OSPM will write it to 1 when
             * it acknowledges this error.
             */
            cpu_physical_memory_write(read_ack_register_addr,
                &read_ack_register, sizeof(uint64_t));

            ret = acpi_ghes_record_mem_error(error_block_addr,
                                             physical_address);
        } else
            error_report("can not find Generic Error Status Block");
    }

    return ret;
}

/*
 * Error register block data layout
 *
 * | +---------------------+ ges.ghes_addr_le
 * | |error_block_address0 |
 * | +---------------------+
 * | |error_block_address1 |
 * | +---------------------+ --+--
 * | |    .............    | GHES_ADDRESS_SIZE
 * | +---------------------+ --+--
 * | |error_block_addressN |
 * | +---------------------+
 * | | read_ack_register0  |
 * | +---------------------+ --+--
 * | | read_ack_register1  | GHES_ADDRESS_SIZE
 * | +---------------------+ --+--
 * | |   .............     |
 * | +---------------------+
 * | | read_ack_registerN  |
 * | +---------------------+ --+--
 * | |      CPER           |   |
 * | |      ....           | GHES_MAX_RAW_DATA_LENGT
 * | |      CPER           |   |
 * | +---------------------+ --+--
 * | |    ..........       |
 * | +---------------------+
 * | |      CPER           |
 * | |      ....           |
 * | |      CPER           |
 * | +---------------------+
 */

/* Map from uint32_t notify to entry offset in GHES */
static const uint8_t error_source_to_index[] = { 0xff, 0xff, 0xff, 0xff,
                                                 0xff, 0xff, 0xff, 1, 0};

static bool ghes_get_addr(uint32_t notify, uint64_t *error_block_addr,
                          uint64_t *read_ack_register_addr)
{
    uint64_t base;

    if (notify >= ACPI_GHES_NOTIFY_RESERVED) {
        return false;
    }

    /* Find and check the source id for this new CPER */
    if (error_source_to_index[notify] == 0xff) {
        return false;
    }

    base = ghes_get_state_start_address();

    *read_ack_register_addr = base +
        ACPI_GHES_ERROR_SOURCE_COUNT * sizeof(uint64_t) +
        error_source_to_index[notify] * sizeof(uint64_t);

    /* Could also be read back from the error_block_address register */
    *error_block_addr = base +
        ACPI_GHES_ERROR_SOURCE_COUNT * sizeof(uint64_t) +
        ACPI_GHES_ERROR_SOURCE_COUNT * sizeof(uint64_t) +
        error_source_to_index[notify] * ACPI_GHES_MAX_RAW_DATA_LENGTH;

    return true;
}

bool ghes_record_aer_errors(PCIDevice *dev, uint32_t notify)
{
    int read_ack_register = 0;
    uint64_t read_ack_register_addr = 0;
    uint64_t error_block_addr = 0;

    if (!ghes_get_addr(notify, &error_block_addr, &read_ack_register_addr)) {
        return false;
    }

    cpu_physical_memory_read(read_ack_register_addr, &read_ack_register,
                             sizeof(uint64_t));
    /* zero means OSPM does not acknowledge the error */
    if (!read_ack_register) {
        error_report("Last time OSPM does not acknowledge the error,"
                     " record CPER failed this time, set the ack value to"
                     " avoid blocking next time CPER record! exit");
        read_ack_register = 1;
        cpu_physical_memory_write(read_ack_register_addr, &read_ack_register,
                                  sizeof(uint64_t));
        return false;
    }

    read_ack_register = cpu_to_le64(0);
    cpu_physical_memory_write(read_ack_register_addr, &read_ack_register,
                              sizeof(uint64_t));

    return ghes_record_aer_error(dev, error_block_addr);
}

bool ghes_record_cxl_event_gm(PCIDevice *dev, CXLEventGenMedia *gem,
                              uint32_t notify)
{
    int read_ack_register = 0;
    uint64_t read_ack_register_addr = 0;
    uint64_t error_block_addr = 0;

    if (!ghes_get_addr(notify, &error_block_addr, &read_ack_register_addr)) {
        return false;
    }

    cpu_physical_memory_read(read_ack_register_addr,
                             &read_ack_register, sizeof(uint64_t));
    /* zero means OSPM does not acknowledge the error */
    if (!read_ack_register) {
        error_report("Last time OSPM does not acknowledge the error,"
                     " record CPER failed this time, set the ack value to"
                     " avoid blocking next time CPER record! exit");
        read_ack_register = 1;
        cpu_physical_memory_write(read_ack_register_addr,
                                  &read_ack_register, sizeof(uint64_t));
        return false;
    }

    read_ack_register = cpu_to_le64(0);
    cpu_physical_memory_write(read_ack_register_addr,
                              &read_ack_register, sizeof(uint64_t));

    return ghes_record_cxl_gen_media(dev, gem, error_block_addr);
}

bool ghes_record_cxl_errors(PCIDevice *dev, PCIEAERErr *aer_err,
                            CXLError *cxl_err, uint32_t notify)
{
    int read_ack_register = 0;
    uint64_t read_ack_register_addr = 0;
    uint64_t error_block_addr = 0;

    if (!ghes_get_addr(notify, &error_block_addr, &read_ack_register_addr)) {
        return false;
    }

    cpu_physical_memory_read(read_ack_register_addr,
                             &read_ack_register, sizeof(uint64_t));
    /* zero means OSPM does not acknowledge the error */
    if (!read_ack_register) {
        error_report("Last time OSPM does not acknowledge the error,"
                     " record CPER failed this time, set the ack value to"
                     " avoid blocking next time CPER record! exit");
        read_ack_register = 1;
        cpu_physical_memory_write(read_ack_register_addr,
                                  &read_ack_register, sizeof(uint64_t));
        return false;
    }

    read_ack_register = cpu_to_le64(0);
    cpu_physical_memory_write(read_ack_register_addr,
                              &read_ack_register, sizeof(uint64_t));
    return ghes_record_cxl_error(dev, cxl_err, error_block_addr);
}

bool acpi_ghes_present(void)
{
    AcpiGedState *acpi_ged_state;
    AcpiGhesState *ags;

    acpi_ged_state = ACPI_GED(object_resolve_path_type("", TYPE_ACPI_GED,
                                                       NULL));

    if (!acpi_ged_state) {
        return false;
    }
    ags = &acpi_ged_state->ghes_state;
    return ags->present;
}

bool acpi_fw_first_pci(void)
{
    if (acpi_ghes_present()) {
        AcpiGhesState *ags =
            &ACPI_GED(object_resolve_path_type("", TYPE_ACPI_GED,
                                               NULL))->ghes_state;
        uint32_t pci_osc;

        cpu_physical_memory_read(le64_to_cpu(ags->pci_osc_addr_le),
                                 &pci_osc, sizeof(pci_osc));
        if (pci_osc == 0) {
            printf("OSC not called yet\n");
            return true; /* OSC not run yet */
        }
        printf("OSC has been called %x\n", pci_osc);
        return !(pci_osc & (1 << 3));
    }
    return false;
}

bool acpi_fw_first_cxl_mem(void)
{
    if (!acpi_fw_first_pci()) {
        return false;
    }
    if (acpi_ghes_present()) {
        AcpiGhesState *ags =
            &ACPI_GED(object_resolve_path_type("", TYPE_ACPI_GED,
                                               NULL))->ghes_state;
        uint32_t cxl_osc;

        cpu_physical_memory_read(le64_to_cpu(ags->pci_osc_addr_le) +
                                 sizeof(uint32_t),
                                 &cxl_osc, sizeof(cxl_osc));
        if (cxl_osc == 0) {
            printf("CXL OSC not called yet or memory error not requested\n");
            return true; /* OSC not run yet */
        }
        printf("OSC has been called %x\n", cxl_osc);
        return !(cxl_osc & (1 << 0));
    }
    return false;
}
