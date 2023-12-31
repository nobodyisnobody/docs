#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio.h"
#include "migration/qemu-file-types.h"
#include "qemu/host-utils.h"
#include "qemu/module.h"
#include "sysemu/kvm.h"
#include "sysemu/replay.h"
#include "hw/virtio/virtio-mmio.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"
#include "hw/hw.h"
#include "qemu/bitops.h"

#define TYPE_VIRT_MYDEV          "virt-mydev"
#define VIRT_mydev(obj)          OBJECT_CHECK(VirtmydevState, (obj), TYPE_VIRT_MYDEV)

/* Register map */
#define MYDEV_OFFSET_ID 0x00

typedef struct {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;
} VirtmydevState;

static uint64_t virt_mydev_read(void *opaque, hwaddr offset, unsigned size)
{
    VirtmydevState *s = (VirtmydevState *)opaque;

    switch (offset) {
    case MYDEV_OFFSET_ID:
        return 0xdeadbeef;
    default:
        break;
    }
    return 0;
}

static void virt_mydev_write(void *opaque, hwaddr offset, uint64_t value,                  unsigned size)
{
    VirtmydevState *s = (VirtmydevState *)opaque;

    switch (offset) {
    case MYDEV_OFFSET_ID:
            return -1;
    default:
        break;
    }
}

static const MemoryRegionOps virt_mydev_ops = {
    .read = virt_mydev_read,
    .write = virt_mydev_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void virt_mydev_realize(DeviceState *d, Error **errp)
{
    VirtmydevState *s = VIRT_mydev(d);
    SysBusDevice *sbd = SYS_BUS_DEVICE(d);

    memory_region_init_io(&s->iomem, OBJECT(s), &virt_mydev_ops, s, TYPE_VIRT_MYDEV, 0x200);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void virt_mydev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = virt_mydev_realize;
}

static const TypeInfo virt_mydev_info = {
    .name          = TYPE_VIRT_MYDEV,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VirtmydevState),
    .class_init    = virt_mydev_class_init,
};

static void virt_mydev_register_types(void)
{
    type_register_static(&virt_mydev_info);
}

type_init(virt_mydev_register_types)

