/* SPDX-License-Identifier: GPL-2.0-only */

#ifdef CONFIG_ACPI_PRMT
void init_prmt(void);
extern bool acpi_prmt_off;
#else
static inline void init_prmt(void) { }
#endif
