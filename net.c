#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"


/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;

struct net_device *
net_device_alloc(void)
{
    struct net_device *dev = memory_alloc(sizeof(struct net_device));
    if (!dev) {
        errorf("Failed to net_device_alloc");
        return NULL;
    }

    return dev;
}

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{
    if (dev == NULL) {
        errorf("device is null.");
        return -1;
    }
    
    // NOTE: dev->index = index++の実装がよくわからない。indexをずらしていく方法だとdevicesの全部のindexをずらさないとだめで、効率悪くないか?
    static unsigned int index = 0;
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    dev->next = devices;
    devices = dev;
    infof("registerd, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int
net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    
    if (dev->ops->open(dev) == -1) {
        errorf("failure open, dev=%s", dev->name);
        return -1;
    }
    
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("already closed, dev=%s", dev->name);
        return -1;
    }
    
    if (dev->ops->close(dev) == -1) {
        errorf("failure close, dev=%s", dev->name);
        return -1;
    }
    
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("failure transmit, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    
    return 0;
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    // NOTE: With the current implementation, all we need to know is that the data was sent.
    debugf("dev=%s, type=%0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    return 0;   
}

int
net_run(void)
{
    
}

void
net_shutdown(void)
{

}

int
net_init(void)
{
    
}
    