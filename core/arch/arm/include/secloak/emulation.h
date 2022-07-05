#ifndef SECLOAK_EMULATION_H
#define SECLOAK_EMULATION_H

#include <io.h>
#include <sm/sm.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

enum emu_state {
	EMU_STATE_WRITE,
	EMU_STATE_READ_BEFORE,
	EMU_STATE_READ_AFTER
};

struct region;
typedef bool (*emu_check_t)(struct region *, paddr_t, enum emu_state, uint32_t*, int, bool);

struct region {
	paddr_t base;
	uint32_t size;
	emu_check_t check;
	void *user_data;
	unsigned int rg_slock;
	SLIST_ENTRY(region) entry;
};

int32_t emu_add_region(paddr_t base, uint32_t size, emu_check_t check, void *user_data);
void emu_remove_region(paddr_t base, uint32_t size, emu_check_t check, void *user_data);

bool emu_allow_all(struct region *region, paddr_t address, enum emu_state state, uint32_t *value, int size, bool sign);
bool emu_deny_all(struct region *region, paddr_t address, enum emu_state state, uint32_t *value, int size, bool sign);

void emu_handle(struct sm_ctx *ctx, unsigned long status, unsigned long data_paddr, unsigned long instr_paddr);

#endif

