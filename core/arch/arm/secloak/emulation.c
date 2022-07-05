#include <secloak/emulation.h>

#include <arm.h>
#include <compiler.h>
#include <drivers/dt.h>
#include <errno.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <initcall.h>
#include <io.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>

#include <kernel/spinlock.h>

static paddr_t emu_data_pstart;
static vaddr_t emu_data_vstart;
static size_t emu_data_size;
#ifdef CFG_BSTGW_VNIC
static paddr_t virtio_mmio_pstart;
static vaddr_t virtio_mmio_vstart;
static size_t virtio_mmio_size;
#endif
static paddr_t emu_instr_pstart;
static vaddr_t emu_instr_vstart;
static size_t emu_instr_size;


static SLIST_HEAD(, region) regions = SLIST_HEAD_INITIALIZER(regions);

//#define BSTGW_DEBUG

// TODO: lock!
int32_t emu_add_region(paddr_t base, uint32_t size, emu_check_t check, void *user_data) {
	struct region *r = malloc(sizeof(struct region));
	if (!r) {
		return -ENOMEM;
	}

	r->base = base;
	r->size = size;
	r->check = check;
	r->user_data = user_data;
	r->rg_slock = SPINLOCK_UNLOCK;
	SLIST_INSERT_HEAD(&regions, r, entry);

	return 0;
}

void emu_remove_region(paddr_t base, uint32_t size, emu_check_t check, void *user_data) {
	struct region *r;
	SLIST_FOREACH(r, &regions, entry) {
		if (r->base == base && r->size == size && r->check == check && r->user_data == user_data) {
			SLIST_REMOVE(&regions, r, region, entry);
			free(r);
			return;
		}
	}
}

static bool emu_check(paddr_t address, enum emu_state state, uint32_t *value, int size, bool sign) {
	bool allowed = true;

	struct region *r;
	SLIST_FOREACH(r, &regions, entry) {
		if (r->base <= address && (r->base + r->size) >= address) {
			cpu_spin_lock(&r->rg_slock);
			allowed &= r->check(r, address, state, value, size, sign);
			cpu_spin_unlock(&r->rg_slock);
		}
	}

	return allowed;
}

bool emu_allow_all(struct region *region __unused, paddr_t address __unused, enum emu_state state __unused, uint32_t *value __unused, int size __unused, bool sign __unused) {
	return true;
}

bool emu_deny_all(struct region *region __unused, paddr_t address __unused, enum emu_state state __unused, uint32_t *value __unused, int size __unused, bool sign __unused) {
	return false;
}

static inline uint32_t read(vaddr_t addr, int size) {
	switch(size) {
		case 1:
			return io_read8(addr);
		case 2:
			return io_read16(addr);
		case 4:
			return io_read32(addr);
		default:
			return 0; // Note: Will never happen
	}
}

static inline void write(uint32_t value, vaddr_t addr, int size) {
	switch(size) {
		case 1:
			io_write8(addr, value);
			break;
		case 2:
			io_write16(addr, value);
			break;
		case 4:
			io_write32(addr, value);
			break;
		default:
			break; // Note: Will never happen
	}
}

// TODO: either we have to adapt the load to not perform a read in our case, or
// 		 we have to make sure it doesn't cause harm.
// TODO: if we keep it, we prob. have to pass the size into the READ_AFTER handler
// TODO: why is only the paddr passed?
static inline void emu_handle_load(paddr_t data_paddr, vaddr_t data_vaddr, uint32_t *reg, int size, bool sign) {
	if (emu_check(data_paddr, EMU_STATE_READ_BEFORE, NULL, size, sign)) {
		*reg = read(data_vaddr, size);
		if (sign) {
			if (size == 1) {
				if ((*reg) & 0x80) {
					*reg |= 0xFFFFFF00;
				}
			} else if (size == 2) {
				if ((*reg) & 0x8000) {
					*reg |= 0xFFFF0000;
				}
			}
		}
		emu_check(data_paddr, EMU_STATE_READ_AFTER, reg, size, sign);
	} else {
		*reg = 0;
	}
#ifdef BSTGW_DEBUG
    DMSG("load result: 0x%08x", *reg);
#endif
}

// TODO: why is only the paddr passed?
static inline void emu_handle_store(paddr_t data_paddr, vaddr_t data_vaddr, uint32_t *reg, int size) {
	if (emu_check(data_paddr, EMU_STATE_WRITE, reg, size, false)) {
		write(*reg, data_vaddr, size);
#ifdef BSTGW_DEBUG
        DMSG("emu_handle wrote value: 0x%08x", *reg);
#endif
	} else { 
#ifdef BSTGW_DEBUG
		DMSG("no emu value stored");
#endif
	}
}

void emu_handle(struct sm_ctx *ctx, unsigned long status, unsigned long data_paddr, unsigned long instr_paddr) {
#ifdef BSTGW_DEBUG
    DMSG("emu_handle(status = 0x%08lx, data_paddr: 0x%08lx, instr_paddr: 0x%08lx) got called", status, data_paddr, instr_paddr);
#endif

	if ((status & 0x40F) != 0x008) {
		EMSG("[EMU] Ignoring status of 0x%lX", status);
		// -4 with prev. -4 ==> -8, i.e., repeat instr. which faced async. DA (pref. return address)
		ctx->nsec.mon_lr -= 4;
		return;
	}

#define likely(x)      __builtin_expect(!!(x), 1) 
	vaddr_t data_vaddr = 0;
	// most of the time it will be a valid MMIO device access
	if(likely( (data_paddr >= emu_data_pstart) 
		&& (data_paddr < (emu_data_pstart + emu_data_size)) )) {
		data_vaddr = emu_data_vstart + (data_paddr - emu_data_pstart);
#ifdef CFG_BSTGW_VNIC
	// virtio-mmio access
	} else if (likely( (data_paddr >= virtio_mmio_pstart)
			&& (data_paddr < (virtio_mmio_pstart + virtio_mmio_size)) )) {
#ifdef BSTGW_DEBUG
		DMSG("[EMU] Access attempt to secure VirtIO-MMIO region: 0x%08lx (offset: 0x%03lx)", data_paddr, (data_paddr - virtio_mmio_pstart));
#endif
		data_vaddr = virtio_mmio_vstart + (data_paddr - virtio_mmio_pstart);
	// invalid
#endif
	} else {
		EMSG("[EMU] Could not translate PA->VA for data address 0x%lX", data_paddr);
		return;
	}
#undef likely

	if ((instr_paddr < emu_instr_pstart) || (instr_paddr >= (emu_instr_pstart + emu_instr_size))) {
		EMSG("[EMU] Could not translate PA->VA for instruction address 0x%lX", instr_paddr);
		return;
	}
	vaddr_t instr_vaddr = emu_instr_vstart + (instr_paddr - emu_instr_pstart);

#ifdef BSTGW_DEBUG
    DMSG("data_vaddr: 0x%08lx, instr_vaddr: 0x%08lx", data_vaddr, instr_vaddr);
#endif

	uint32_t instr = *((uint32_t *)instr_vaddr);

	uint32_t instr_rt = (instr >> 12) & 0xF;
	uint32_t *reg;
	if (instr_rt <= 7) {
		reg = &ctx->nsec.r0 + instr_rt;
	} else if (instr_rt <= 12) {
			reg = &ctx->nsec.r8 + (instr_rt - 8);
	} else if (instr_rt == 14) {
			reg = &ctx->nsec.ub_regs.svc_lr;
	} else {
		EMSG("[EMU] Unexpected instruction with Rt of %u", instr_rt);
		panic();
		return;
	}

	uint32_t instr_type = (instr >> 25) & 0x7;
	if ((instr_type & 0x6) == 0x2) {
		int size = (instr & (1 << 22)) ? 1 : 4;
		if (instr & (1 << 20)) {
			emu_handle_load(data_paddr, data_vaddr, reg, size, false);
		} else {
			emu_handle_store(data_paddr, data_vaddr, reg, size);
		}
	} else if (instr_type == 0) {
		int size = (instr & (1 << 5)) ? 2 : 1;
		if (instr & (1 << 20)) {
			bool sign = (instr & (1 << 6));
			emu_handle_load(data_paddr, data_vaddr, reg, size, sign);
		} else {
			emu_handle_store(data_paddr, data_vaddr, reg, size);
		}
	} else {
		EMSG("[EMU] Unexpected instruction with type %u", instr_type);
		panic();
	}

#ifdef BSTGW_DEBUG
    DMSG("exiting emu_handle()");
#endif
}

static TEE_Result emulation_init(void) {
    DMSG("emulation_init()");

  const struct tee_mmap_region *map;

	map = core_mmu_find_map_by_type_and_pa(MEM_AREA_IO_SEC, 0x01000000);
	if (map == NULL) {
		EMSG("[EMU] Could not get MEM_AREA_IO_SEC mapping");
		panic();
	}

	emu_data_pstart = map->pa;
	emu_data_vstart = map->va;
	emu_data_size = map->size;

#ifdef CFG_BSTGW_VNIC
	map = core_mmu_find_map_by_type_and_pa(MEM_AREA_IO_SEC, BSTGW_VNIC_START);
	if (map == NULL) {
		EMSG("[EMU] Could not get IO_SEC/BSTGW_VNIC_START mapping");
		panic();
	}

	virtio_mmio_pstart = map->pa;
	virtio_mmio_vstart = map->va;
	virtio_mmio_size = map->size; /* TODO: currently only VNIC region is used */
#endif

	map = core_mmu_find_map_by_type(MEM_AREA_RAM_NSEC);
	if (map == NULL) {
		EMSG("[EMU] Could not get MEM_AREA_RAM_NSEC mapping");
		panic();
	}

	emu_instr_pstart = map->pa;
	emu_instr_vstart = map->va;
	emu_instr_size = map->size;

	return 0;
}
driver_init_late(emulation_init);
