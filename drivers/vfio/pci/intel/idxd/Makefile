ccflags-y += -I$(srctree)/drivers/dma/idxd -DDEFAULT_SYMBOL_NAMESPACE=IDXD

obj-$(CONFIG_VFIO_DEVICE_IDXD) += idxd_vdev.o
idxd_vdev-y := vfio_device.o vidxd.o vidxd_cmd.o
