// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <kernel/dt.h>
#include <drivers/dt.h>
#include <kernel/linker.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>

const struct dt_driver *dt_find_compatible_driver(const void *fdt, int offs)
{
	const struct dt_device_match *dm;
	const struct dt_driver *drv;

	for_each_dt_driver(drv) {
		for (dm = drv->match_table; dm; dm++) {
			if (!dm->compatible) {
				break;
			}
			if (!fdt_node_check_compatible(fdt, offs,
						       dm->compatible)) {
				return drv;
			}
		}
	}

	return NULL;
}

// not secloak
bool dt_have_prop(const void *fdt, int offs, const char *propname)
{
	const void *prop;

	prop = fdt_getprop(fdt, offs, propname, NULL);

	return prop;
}

int dt_get_irq(void *fdt, int node)
{
	const uint32_t *int_prop = NULL;
	int len_prop = 0;
	int it_num = DT_INFO_INVALID_INTERRUPT;

	/*
	 * Interrupt property can be defined with at least 2x32 bits word
	 *  - Type of interrupt
	 *  - Interrupt Number
	 */
	int_prop = fdt_getprop(fdt, node, "interrupts", &len_prop);

	if (!int_prop || len_prop < 2)
		return it_num;

	it_num = fdt32_to_cpu(int_prop[1]);

	return it_num;
}

int dt_disable_status(void *fdt, int node)
{
	const char *prop = NULL;
	int len = 0;

	prop = fdt_getprop(fdt, node, "status", &len);
	if (!prop) {
		if (fdt_setprop_string(fdt, node, "status", "disabled"))
			return -1;
	} else {
		/*
		 * Status is there, modify it.
		 * Ask to set "disabled" value to the property. The value
		 * will be automatically truncated with "len" size by the
		 * fdt_setprop_inplace function.
		 * Setting a value different from "ok" or "okay" will disable
		 * the property.
		 * Setting a truncated value of "disabled" with the original
		 * property "len" is preferred to not increase the DT size and
		 * losing time in recalculating the overall DT offsets.
		 * If original length of the status property is larger than
		 * "disabled", the property will start with "disabled" and be
		 * completed with the rest of the original property.
		 */
		if (fdt_setprop_inplace(fdt, node, "status", "disabled", len))
			return -1;
	}

	return 0;
}

int dt_enable_secure_status(void *fdt, int node)
{
	if (dt_disable_status(fdt, node)) {
		EMSG("Unable to disable Normal Status");
		return -1;
	}

	if (fdt_setprop_string(fdt, node, "secure-status", "okay"))
		return -1;

	return 0;
}
// not secloak

int dt_probe_compatible_driver(const void *fdt, struct device *dev)
 {
	const struct dt_driver *driver;

	for_each_dt_driver(driver) {
		for (const struct dt_device_match *match = driver->match_table; match->compatible != NULL; match++) {
			if (!fdt_node_check_compatible(fdt, dev->node, match->compatible)) {
				return driver->probe(fdt, dev, match->data);
			}
		}
 	}
 
 	return 0;
 }

const struct dt_driver *__dt_driver_start(void)
{
	return &__rodata_dtdrv_start;
}

const struct dt_driver *__dt_driver_end(void)
{
	return &__rodata_dtdrv_end;
}

const void* dt_read_property(const void *fdt, int offs, const char *name) {
	const void *prop;
	prop = fdt_getprop(fdt, offs, name, NULL);

	return prop;
}

int dt_read_property_u32(const void *fdt, int offs, const char *name, uint32_t *out) {
	const void *prop;
	int prop_size;

	prop = fdt_getprop(fdt, offs, name, &prop_size);
	if (!prop || (prop_size != sizeof(uint32_t))) {
 		return -1;
	}

	*out = fdt32_to_cpu(*((uint32_t*)prop));
	return 0;
}

// not secloak
/* Read a physical address (n=1 or 2 cells) */
static paddr_t _fdt_read_paddr(const uint32_t *cell, int n)
{
	paddr_t addr;

	if (n < 1 || n > 2)
		goto bad;

	addr = fdt32_to_cpu(*cell);
	cell++;
	if (n == 2) {
#ifdef ARM32
		if (addr) {
			/* High order 32 bits can't be nonzero */
			goto bad;
		}
		addr = fdt32_to_cpu(*cell);
#else
		addr = (addr << 32) | fdt32_to_cpu(*cell);
#endif
	}

	if (!addr)
		goto bad;

	return addr;
bad:
	return DT_INFO_INVALID_REG;

}

paddr_t _fdt_reg_base_address(const void *fdt, int offs)
{
	const void *reg;
	int ncells;
	int len;
	int parent;

	parent = fdt_parent_offset(fdt, offs);
	if (parent < 0)
		return DT_INFO_INVALID_REG;

	reg = fdt_getprop(fdt, offs, "reg", &len);
	if (!reg)
		return DT_INFO_INVALID_REG;

	ncells = fdt_address_cells(fdt, parent);
	if (ncells < 0)
		return DT_INFO_INVALID_REG;

	return _fdt_read_paddr(reg, ncells);
}

ssize_t _fdt_reg_size(const void *fdt, int offs)
{
	const uint32_t *reg;
	uint32_t sz;
	int n;
	int len;
	int parent;

	parent = fdt_parent_offset(fdt, offs);
	if (parent < 0)
		return DT_INFO_INVALID_REG;

	reg = (const uint32_t *)fdt_getprop(fdt, offs, "reg", &len);
	if (!reg)
		return -1;

	n = fdt_address_cells(fdt, parent);
	if (n < 1 || n > 2)
		return -1;

	reg += n;

	n = fdt_size_cells(fdt, parent);
	if (n < 1 || n > 2)
		return -1;

	sz = fdt32_to_cpu(*reg);
	if (n == 2) {
		if (sz)
			return -1;
		reg++;
		sz = fdt32_to_cpu(*reg);
	}

	return sz;
}
//

static bool is_okay(const char *st, int len)
{
	return !strncmp(st, "ok", len) || !strncmp(st, "okay", len);
}

int _fdt_get_status(const void *fdt, int offs)
{
	const char *prop;
	int st = 0;
	int len;

	prop = fdt_getprop(fdt, offs, "status", &len);
	if (!prop || is_okay(prop, len)) {
		st |= DT_STATUS_OK_NSEC | DT_STATUS_OK_SEC;
 	}

	return st;
}

void _fdt_fill_device_info(void *fdt, struct dt_node_info *info, int offs)
{
	struct dt_node_info dinfo = {
		.reg = DT_INFO_INVALID_REG,
		.clock = DT_INFO_INVALID_CLOCK,
		.reset = DT_INFO_INVALID_RESET,
	};
	const fdt32_t *cuint;

	dinfo.reg = _fdt_reg_base_address(fdt, offs);

	cuint = fdt_getprop(fdt, offs, "clocks", NULL);
	if (cuint) {
		cuint++;
		dinfo.clock = (int)fdt32_to_cpu(*cuint);
	}

	cuint = fdt_getprop(fdt, offs, "resets", NULL);
	if (cuint) {
		cuint++;
		dinfo.reset = (int)fdt32_to_cpu(*cuint);
	}

	dinfo.status = _fdt_get_status(fdt, offs);

	*info = dinfo;
}
