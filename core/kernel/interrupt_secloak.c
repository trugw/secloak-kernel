// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2019, Linaro Limited
 */

#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <errno.h>
#include <malloc.h>
#include <trace.h>
#include <assert.h>

static SLIST_HEAD(, irq_chip) chips = SLIST_HEAD_INITIALIZER(chips);

int32_t irq_construct_chip(struct irq_chip *chip, struct device *dev, const struct irq_chip_ops *ops, size_t num_irqs, void *data, bool default_handler) {
	chip->dev = dev;
	chip->ops = ops;
	chip->num_irqs = num_irqs;
	chip->data = data;
	chip->default_handler = default_handler;
	chip->handlers = malloc(num_irqs * sizeof(*chip->handlers));
	if (!chip->handlers) {
		return -ENOMEM;
	}

	memset(chip->handlers, 0, num_irqs * sizeof(*chip->handlers));
	SLIST_INSERT_HEAD(&chips, chip, entry);

	return 0;
}

void irq_destruct_chip(struct irq_chip *chip) {
	SLIST_REMOVE(&chips, chip, irq_chip, entry);
	free(chip->handlers);
}

struct irq_chip *irq_find_chip(struct device *dev) {
	struct irq_chip *chip;
	SLIST_FOREACH(chip, &chips, entry) {
		if (chip->dev == dev) {
			break;
		}
	}

	return chip;
}

static bool irq_check_valid(struct irq_chip *chip, size_t irq) {
	if (irq >= chip->num_irqs) {
		DMSG("[IRQ] Invalid IRQ %d", irq);
		panic();
		return false;
	}

	return true;
 }

enum irq_return irq_handle(struct irq_chip *chip, size_t irq)
 {
	if (!irq_check_valid(chip, irq)) {
		return ITRR_NONE;
	}
	struct irq_handler *handler = chip->handlers[irq];
	if (!handler) {
		if (chip->default_handler) {
            DMSG("IRQ unhandled, returning forward to default handler (IRQ: %zu)", irq);
			return ITRR_HANDLED_DEFAULT;
		} else {
			EMSG("[IRQ] Disabling unhandled interrupt %zu", irq);
			chip->ops->disable(chip, irq);
			return ITRR_NONE;
		}
 	}
	enum irq_return ret = handler->handle(handler);
	if (ret == ITRR_NONE) {
		EMSG("[IRQ] Disabling interrupt %zu not handled by handler", irq);
		chip->ops->disable(chip, irq);
 	}

	return ret;
 }

int32_t irq_map(struct irq_chip *chip, const fdt32_t *dt_spec, size_t *irq, uint32_t *flags) {
	return chip->ops->map(chip, dt_spec, irq, flags);
 }

int32_t irq_add(struct irq_desc *desc, uint32_t flags, struct irq_handler *handler) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	chip->handlers[irq] = handler;
	return chip->ops->add(chip, irq, flags);
 }

int32_t irq_remove(struct irq_desc *desc) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	int32_t error = chip->ops->remove(chip, irq);
	if (!error) {
		chip->handlers[irq] = NULL;
	}

	return error;
 }

int32_t irq_enable(struct irq_desc *desc) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	return chip->ops->enable(chip, irq);
 }

int32_t irq_disable(struct irq_desc *desc) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	return chip->ops->disable(chip, irq);
 }

int32_t irq_secure(struct irq_desc *desc) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	return chip->ops->secure(chip, irq);
}

int32_t irq_unsecure(struct irq_desc *desc) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	return chip->ops->unsecure(chip, irq);
}

int32_t irq_raise(struct irq_desc *desc) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	return chip->ops->raise(chip, irq);
}

int32_t irq_raise_sgi(struct irq_desc *desc, uint8_t cpu_mask) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	if (chip->ops->raise_sgi) {
		return -EINVAL;
	}

	return chip->ops->raise_sgi(chip, irq, cpu_mask);
}

int32_t irq_set_affinity(struct irq_desc *desc, uint8_t cpu_mask) {
	struct irq_chip *chip = desc->chip;
	size_t irq = desc->irq;
	if (!irq_check_valid(chip, irq)) {
		return -EINVAL;
	}

	if (chip->ops->set_affinity) {
		return -EINVAL;
	}

	return chip->ops->set_affinity(chip, irq, cpu_mask);
 }

/* none-SeCloak, but required */

/* This function is supposed to be overridden in platform specific code */
void __weak __noreturn itr_core_handler(void)
{
	panic("Secure interrupt handler not defined");
}
