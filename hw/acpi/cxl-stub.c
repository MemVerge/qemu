
/*
 * Stubs for ACPI platforms that don't support CXl
 */
#include "qemu/osdep.h"
#include "hw/acpi/aml-build.h"
#include "hw/acpi/cxl.h"

void build_cxl_osc_method(Aml *dev, bool fw_first)
{
    g_assert_not_reached();
}
