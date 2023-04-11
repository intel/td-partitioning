/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_RPB_H
#define LINUX_RPB_H

static inline bool is_rpb_device(struct pci_dev *pdev)
{
        return false;
}

static inline bool is_vtc_device(struct pci_dev *pdev)
{
        return false;
}

#endif /* LINUX_RPB_H */
