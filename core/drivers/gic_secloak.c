// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <errno.h>
#include <drivers/dt.h>
#include <drivers/gic.h>
#include <kernel/dt.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <util.h>
#include <io.h>
#include <trace.h>

//#define BSTGW_GIC_SECLK_DBG

/* Offsets from gic.gicc_base */
#define GICC_CTLR		(0x000)
#define GICC_PMR		(0x004)
#define GICC_IAR		(0x00C)
#define GICC_EOIR		(0x010)

#define GICC_CTLR_ENABLEGRP0	(1 << 0)
#define GICC_CTLR_ENABLEGRP1	(1 << 1)
#define GICD_CTLR_ENABLEGRP1S	(1 << 2)
#define GICC_CTLR_FIQEN		(1 << 3)

/* Offsets from gic.gicd_base */
#define GICD_CTLR		(0x000)
#define GICD_TYPER		(0x004)
#define GICD_IGROUPR(n)		(0x080 + (n) * 4)
#define GICD_ISENABLER(n)	(0x100 + (n) * 4)
#define GICD_ICENABLER(n)	(0x180 + (n) * 4)
#define GICD_ISPENDR(n)		(0x200 + (n) * 4)
#define GICD_ICPENDR(n)		(0x280 + (n) * 4)
#define GICD_IPRIORITYR(n)	(0x400 + (n) * 4)
#define GICD_ITARGETSR(n)	(0x800 + (n) * 4)
#define GICD_IGROUPMODR(n)	(0xd00 + (n) * 4)
#define GICD_SGIR		(0xF00)

#define GICD_CTLR_ENABLEGRP0	(1 << 0)
#define GICD_CTLR_ENABLEGRP1	(1 << 1)

/* Number of Private Peripheral Interrupt */
#define NUM_PPI	32

/* Number of Software Generated Interrupt */
#define NUM_SGI			16

/* Number of Non-secure Software Generated Interrupt */
#define NUM_NS_SGI		8

/* Number of interrupts in one register */
#define NUM_INTS_PER_REG	32

/* Number of targets in one register */
#define NUM_TARGETS_PER_REG	4

/* Accessors to access ITARGETSRn */
#define ITARGETSR_FIELD_BITS	8
#define ITARGETSR_FIELD_MASK	0xff

/* Maximum number of interrups a GIC can support */
#define GIC_MAX_INTS		1020

#define GICC_IAR_IT_ID_MASK	0x3ff
#define GICC_IAR_CPU_ID_MASK	0x7
#define GICC_IAR_CPU_ID_SHIFT	10

struct gic_data g_gic;

static int32_t gic_op_map(struct irq_chip *chip, const fdt32_t *dt_spec, size_t *irq, uint32_t *flags);
static int32_t gic_op_add(struct irq_chip *chip, size_t it, uint32_t flags);
static int32_t gic_op_enable(struct irq_chip *chip, size_t it);
static int32_t gic_op_disable(struct irq_chip *chip, size_t it);
static int32_t gic_op_secure(struct irq_chip *chip, size_t it);
static int32_t gic_op_unsecure(struct irq_chip *chip, size_t it);
static int32_t gic_op_raise(struct irq_chip *chip, size_t it);
static int32_t gic_op_raise_sgi(struct irq_chip *chip, size_t it, uint8_t cpu_mask);
static int32_t gic_op_set_affinity(struct irq_chip *chip, size_t it, uint8_t cpu_mask);

static const struct irq_chip_ops gic_ops = {
	.map = gic_op_map,
	.add = gic_op_add,
	.enable = gic_op_enable,
	.disable = gic_op_disable,
	.secure = gic_op_secure,
	.unsecure = gic_op_unsecure,
	.raise = gic_op_raise,
	.raise_sgi = gic_op_raise_sgi,
	.set_affinity = gic_op_set_affinity,
};
KEEP_PAGER(gic_ops);

static size_t probe_max_it(vaddr_t gicc_base __maybe_unused, vaddr_t gicd_base)
{
	int i;
	uint32_t old_ctlr;
	size_t ret = 0;
	const size_t max_regs = ((GIC_MAX_INTS + NUM_INTS_PER_REG - 1) /
					NUM_INTS_PER_REG) - 1;

	/*
	 * Probe which interrupt number is the largest.
	 */
#if defined(CFG_ARM_GICV3)
	old_ctlr = read_icc_ctlr();
	write_icc_ctlr(0);
#else
	old_ctlr = io_read32(gicc_base + GICC_CTLR);
	io_write32(gicc_base + GICC_CTLR, 0);
#endif
	for (i = max_regs; i >= 0; i--) {
		uint32_t old_reg;
		uint32_t reg;
		int b;

		old_reg = io_read32(gicd_base + GICD_ISENABLER(i));
		io_write32(gicd_base + GICD_ISENABLER(i), 0xffffffff);
		reg = io_read32(gicd_base + GICD_ISENABLER(i));
		io_write32(gicd_base + GICD_ICENABLER(i), ~old_reg);
		for (b = NUM_INTS_PER_REG - 1; b >= 0; b--) {
			if (BIT32(b) & reg) {
				ret = i * NUM_INTS_PER_REG + b;
				goto out;
			}
		}
	}
out:
#if defined(CFG_ARM_GICV3)
	write_icc_ctlr(old_ctlr);
#else
	io_write32(gicc_base + GICC_CTLR, old_ctlr);
#endif
	return ret;
}

void gic_cpu_init(void)
{
#if defined(CFG_ARM_GICV3)
	assert(g_gic.gicd_base);
#else
	assert(g_gic.gicd_base && g_gic.gicc_base);
#endif

	/* per-CPU interrupts config:
	 * ID0-ID7(SGI)   for Non-secure interrupts
	 * ID8-ID15(SGI)  for Secure interrupts.
	 * All PPI config as Non-secure interrupts.
	 */
	io_write32(g_gic.gicd_base + GICD_IGROUPR(0), 0xffff00ff);

	/* Set the priority mask to permit Non-secure interrupts, and to
	 * allow the Non-secure world to adjust the priority mask itself
	 */
#if defined(CFG_ARM_GICV3)
	write_icc_pmr(0x80);
	write_icc_igrpen1(1);
#else
	io_write32(g_gic.gicc_base + GICC_PMR, 0x80);

	/* Enable GIC */
	io_write32(g_gic.gicc_base + GICC_CTLR,
		   GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 |
		   GICC_CTLR_FIQEN);
#endif
}

static void gic_init(struct gic_data *gd)
{
	size_t n;

	for (n = 0; n <= gd->max_it / NUM_INTS_PER_REG; n++) {
		/* Disable interrupts */
		io_write32(gd->gicd_base + GICD_ICENABLER(n), 0xffffffff);

		/* Make interrupts non-pending */
		io_write32(gd->gicd_base + GICD_ICPENDR(n), 0xffffffff);

		/* Mark interrupts non-secure */
		if (n == 0) {
			/* per-CPU inerrupts config:
                         * ID0-ID7(SGI)   for Non-secure interrupts
                         * ID8-ID15(SGI)  for Secure interrupts.
                         * All PPI config as Non-secure interrupts.
			 */
			io_write32(gd->gicd_base + GICD_IGROUPR(n), 0xffff00ff);
		} else {
			io_write32(gd->gicd_base + GICD_IGROUPR(n), 0xffffffff);
		}
	}

	/* Set the priority mask to permit Non-secure interrupts, and to
	 * allow the Non-secure world to adjust the priority mask itself
	 */
#if defined(CFG_ARM_GICV3)
	write_icc_pmr(0x80);
	write_icc_igrpen1(1);
	io_setbits32(gd->gicd_base + GICD_CTLR, GICD_CTLR_ENABLEGRP1S);
#else
	io_write32(gd->gicc_base + GICC_PMR, 0x80);

	/* Enable GIC */
	io_write32(gd->gicc_base + GICC_CTLR, GICC_CTLR_FIQEN |
		   GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1);
	io_setbits32(gd->gicd_base + GICD_CTLR,
		     GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1);
#endif
}

static int gic_probe(const void *fdt __unused, struct device *dev, const void *data)
{
	if (data) { // arm,cortex-a9-gic
		if (dev->num_resources != 2 || dev->resource_type != RESOURCE_MEM) {
			EMSG("Resource is not valid for device %s\n", dev->name);
			return -EINVAL;
		}

		paddr_t dist_paddr = dev->resources[0].address[0];
		size_t dist_size = dev->resources[0].size[0];
		paddr_t cpu_paddr = dev->resources[1].address[0];
		size_t cpu_size = dev->resources[1].size[0];

		g_gic.gicc_base = (vaddr_t)phys_to_virt(cpu_paddr, MEM_AREA_IO_SEC);
		g_gic.gicd_base = (vaddr_t)phys_to_virt(dist_paddr, MEM_AREA_IO_SEC);
		g_gic.max_it = probe_max_it(g_gic.gicc_base, g_gic.gicd_base);
		gic_init(&g_gic);

		irq_construct_chip(&g_gic.chip, dev, &gic_ops, g_gic.max_it, (void *)&g_gic, false);

		IMSG("Registered device %s with memory regions (0x%lX, 0x%X) and (0x%lX, 0x%X)\n", dev->name, cpu_paddr, cpu_size, dist_paddr, dist_size);
	} else {
#ifdef BSTGW_GIC_SECLK_DBG
        DMSG("GIC false construction GPC");
#endif
		irq_construct_chip(&g_gic.chip_gpc, dev, &gic_ops, g_gic.max_it, (void *)&g_gic, false);
	}

	return 0;
}

static const struct dt_device_match gic_match_table[] = {
	{ .compatible = "arm,cortex-a9-gic", .data = (void *)1, },
	{ .compatible = "fsl,imx6q-gpc", .data = NULL, }, // FIXME: Workaround
	{ 0 }
};

const struct dt_driver gic_dt_driver __dt_driver = {
	.name = "gic",
	.match_table = gic_match_table,
	.probe = gic_probe,
};

static void gic_it_add(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Disable the interrupt */
	io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
	/* Make it non-pending */
	io_write32(gd->gicd_base + GICD_ICPENDR(idx), mask);
	/* Assign it to group0 */
	io_clrbits32(gd->gicd_base + GICD_IGROUPR(idx), mask);
#if defined(CFG_ARM_GICV3)
	/* Assign it to group1S */
	io_setbits32(gd->gicd_base + GICD_IGROUPMODR(idx), mask);
#endif
}

static void gic_it_set_cpu_mask(struct gic_data *gd, size_t it,
				uint8_t cpu_mask)
{
	size_t idx __maybe_unused = it / NUM_INTS_PER_REG;
	uint32_t mask __maybe_unused = 1 << (it % NUM_INTS_PER_REG);
	uint32_t target, target_shift;
	vaddr_t itargetsr = gd->gicd_base +
			    GICD_ITARGETSR(it / NUM_TARGETS_PER_REG);

	/* Assigned to group0 */
	assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Route it to selected CPUs */
	target = io_read32(itargetsr);
	target_shift = (it % NUM_TARGETS_PER_REG) * ITARGETSR_FIELD_BITS;
	target &= ~(ITARGETSR_FIELD_MASK << target_shift);
	target |= cpu_mask << target_shift;
#ifdef BSTGW_GIC_SECLK_DBG
	DMSG("cpu_mask: writing 0x%x to 0x%" PRIxVA, target, itargetsr);
#endif
	io_write32(itargetsr, target);
#ifdef BSTGW_GIC_SECLK_DBG
	DMSG("cpu_mask: 0x%x", io_read32(itargetsr));
#endif
}

static void gic_it_set_prio(struct gic_data *gd, size_t it, uint8_t prio)
{
	size_t idx __maybe_unused = it / NUM_INTS_PER_REG;
	uint32_t mask __maybe_unused = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Set prio it to selected CPUs */
#ifdef BSTGW_GIC_SECLK_DBG
	DMSG("prio: previous value of 0x%x", io_read8(gd->gicd_base + GICD_IPRIORITYR(0) + it));
	DMSG("prio: writing 0x%x to 0x%" PRIxVA, prio, gd->gicd_base + GICD_IPRIORITYR(0) + it);
#endif
	io_write8(gd->gicd_base + GICD_IPRIORITYR(0) + it, prio);
}

static void gic_it_enable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	vaddr_t base = gd->gicd_base;

	/* Assigned to group0 */
	assert(!(io_read32(base + GICD_IGROUPR(idx)) & mask));
	if (it >= NUM_SGI) {
		/*
		 * Not enabled yet, except Software Generated Interrupt
		 * which is implementation defined
		 */
		if (io_read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask) {
			return;
		}
	}

	/* Enable the interrupt */
	io_write32(base + GICD_ISENABLER(idx), mask);
}

static void gic_it_disable(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	/* Assigned to group0 */
	//assert(!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask));

	/* Disable the interrupt */
	io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
}

static void gic_it_secure(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	if (!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask)) {
		return;
	}

	bool enabled = io_read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask;
	if (enabled) {
		io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
	}
	io_write32(gd->gicd_base + GICD_IGROUPR(idx), io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & ~mask);
	gic_it_set_prio(gd, it, 0x1);
	if (enabled) {
		io_write32(gd->gicd_base + GICD_ISENABLER(idx), mask);
	}
}

static void gic_it_unsecure(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);

	if (io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask) {
		return;
	}

	bool enabled = io_read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask;
	if (enabled) {
		io_write32(gd->gicd_base + GICD_ICENABLER(idx), mask);
	}
	io_write32(gd->gicd_base + GICD_IGROUPR(idx), io_read32(gd->gicd_base + GICD_IGROUPR(idx)) | mask);
	if (enabled) {
		io_write32(gd->gicd_base + GICD_ISENABLER(idx), mask);
	}
}

static void gic_it_set_pending(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = BIT32(it % NUM_INTS_PER_REG);

	/* Should be Peripheral Interrupt */
	assert(it >= NUM_SGI);

	/* Raise the interrupt */
	io_write32(gd->gicd_base + GICD_ISPENDR(idx), mask);
}

static void gic_it_raise_sgi(struct gic_data *gd, size_t it,
		uint8_t cpu_mask, uint8_t group)
{
	uint32_t mask_id = it & 0xf;
	uint32_t mask_group = group & 0x1;
	uint32_t mask_cpu = cpu_mask & 0xff;
	uint32_t mask = (mask_id | SHIFT_U32(mask_group, 15) |
		SHIFT_U32(mask_cpu, 16));

	/* Should be Software Generated Interrupt */
	assert(it < NUM_SGI);

	/* Raise the interrupt */
	io_write32(gd->gicd_base + GICD_SGIR, mask);
}

static uint32_t gic_read_iar(struct gic_data *gd __maybe_unused)
{
#if defined(CFG_ARM_GICV3)
	return read_icc_iar1();
#else
	return io_read32(gd->gicc_base + GICC_IAR);
#endif
}

static void gic_write_eoir(struct gic_data *gd __maybe_unused, uint32_t eoir)
{
#if defined(CFG_ARM_GICV3)
	write_icc_eoir1(eoir);
#else
	io_write32(gd->gicc_base + GICC_EOIR, eoir);
#endif
}

static bool gic_it_is_enabled(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(io_read32(gd->gicd_base + GICD_ISENABLER(idx)) & mask);
}

static bool __maybe_unused gic_it_get_group(struct gic_data *gd, size_t it)
{
	size_t idx = it / NUM_INTS_PER_REG;
	uint32_t mask = 1 << (it % NUM_INTS_PER_REG);
	return !!(io_read32(gd->gicd_base + GICD_IGROUPR(idx)) & mask);
}

static uint32_t __maybe_unused gic_it_get_target(struct gic_data *gd, size_t it)
{
	size_t reg_idx = it / NUM_TARGETS_PER_REG;
	uint32_t target_shift = (it % NUM_TARGETS_PER_REG) *
				ITARGETSR_FIELD_BITS;
	uint32_t target_mask = ITARGETSR_FIELD_MASK << target_shift;
	uint32_t target = io_read32(gd->gicd_base + GICD_ITARGETSR(reg_idx));

	return (target & target_mask) >> target_shift;
}

void gic_dump_state(void)
{
	int i;

#ifdef BSTGW_GIC_SECLK_DBG
#if defined(CFG_ARM_GICV3)
	DMSG("GICC_CTLR: 0x%x", read_icc_ctlr());
#else
	DMSG("GICC_CTLR: 0x%x", io_read32(g_gic.gicc_base + GICC_CTLR));
#endif
	DMSG("GICD_CTLR: 0x%x", io_read32(g_gic.gicd_base + GICD_CTLR));
#endif

	for (i = 0; i < (int)g_gic.max_it; i++) {
		if (gic_it_is_enabled(&g_gic, i)) {
#ifdef BSTGW_GIC_SECLK_DBG
			DMSG("irq%d: enabled, group:%d, target:%x", i,
			     gic_it_get_group(&g_gic, i), gic_it_get_target(&g_gic, i));
#endif
		}
	}
}

void gic_it_handle(void)
{
#ifdef BSTGW_GIC_SECLK_DBG
    DMSG("gic_it_handle() got called");
#endif

	uint32_t iar;
	uint32_t id;

	iar = gic_read_iar(&g_gic);
	id = iar & GICC_IAR_IT_ID_MASK;

	if (id < g_gic.max_it) {
		if (g_gic.chip_gpc.handlers[id] != NULL) {
			irq_handle(&g_gic.chip_gpc, id);
		} else {
			irq_handle(&g_gic.chip, id);
		}
	}

	gic_write_eoir(&g_gic, iar);
}

static int32_t gic_op_map(struct irq_chip *chip, const fdt32_t *dt_spec, size_t *irq, uint32_t *flags)
{
	struct gic_data *gd = chip->data;

	*irq = ((fdt32_to_cpu(dt_spec[0]) == 0) ? 32 : 16) + fdt32_to_cpu(dt_spec[1]);
	*flags = fdt32_to_cpu(dt_spec[2]);

	return (*irq < gd->max_it) ? 0 : -EINVAL;
}

static int32_t gic_op_add(struct irq_chip *chip, size_t it,
		       uint32_t flags __unused)
{
	struct gic_data *gd = chip->data;
	gic_it_add(gd, it);
	gic_it_set_cpu_mask(gd, it, 0x1); // TODO: consider changing to 0xff to contact all CPUs (might require SMP code changes)
 	gic_it_set_prio(gd, it, 0x1);
	return 0;
}

static int32_t gic_op_enable(struct irq_chip *chip, size_t it)
{
	struct gic_data *gd = chip->data;
 	gic_it_enable(gd, it);
	return 0;
}

static int32_t gic_op_disable(struct irq_chip *chip, size_t it)
{
	struct gic_data *gd = chip->data;
 	gic_it_disable(gd, it);
	return 0;
}

static int32_t gic_op_secure(struct irq_chip *chip, size_t it)
{
	struct gic_data *gd = chip->data;
	gic_it_secure(gd, it);
	return 0;
}

static int32_t gic_op_unsecure(struct irq_chip *chip, size_t it)
{
	struct gic_data *gd = chip->data;
	gic_it_unsecure(gd, it);
	return 0;
}

static int32_t gic_op_raise(struct irq_chip *chip, size_t it)
{
	struct gic_data *gd = chip->data;
	gic_it_set_pending(gd, it);
	return 0;
}

static int32_t gic_op_raise_sgi(struct irq_chip *chip, size_t it,
			uint8_t cpu_mask)
{
	struct gic_data *gd = chip->data;

	if (it < NUM_NS_SGI)
		gic_it_raise_sgi(gd, it, cpu_mask, 1);
	else
		gic_it_raise_sgi(gd, it, cpu_mask, 0);

	return 0;
}

static int32_t gic_op_set_affinity(struct irq_chip *chip, size_t it,
			uint8_t cpu_mask)
{
	struct gic_data *gd = chip->data;
	gic_it_set_cpu_mask(gd, it, cpu_mask);
	return 0;
}
