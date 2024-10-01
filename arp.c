#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignmetns/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same values as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];
    uint8_t spa[IP_ADDR_LEN];
    uint8_t tha[ETHER_ADDR_LEN];
    uint8_t tpa[IP_ADDR_LEN];
};

static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    // fprintf(stderr, "       vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "       hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "       pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "       hln: %u\n", message->hdr.hln);
    fprintf(stderr, "       pln: %u\n", message->hdr.pln);
    fprintf(stderr, "        op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "       sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "       spa: %s\n", ip_addr_ntop(message->spa, addr, sizeof(addr)));
    fprintf(stderr, "       tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&spa, message->tpa, sizeof(tpa));
    fprintf(stderr, "       tpa: %s\n", ip_addr_ntop(message->tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif HEXDUMP
    funlock(stderr);
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;
    memcpy(&reply.spa, ((struct ip_iface *)iface)->unicast, sizeof(reply.spa));
    memcpy(&reply.sha, iface->dev->addr, sizeof(reply.sha));
    memcpy(&reply.tpa, tpa, sizeof(reply.tpa));
    memcpy(&reply.tha, tha, sizeof(reply.tha));

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;

    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }

    msg = (struct arp_ether_ip *)data;
    // 対応可能なアドレスペアのメッセージのみ受け入れる
    // (1) ハードウェアアドレスの種別とアドレス長がEthernetと合致しなければ中断
    if (msg->hdr.hrd != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("hardware addrss type or hardware address length does not correspond ether address");
        return;
    }
    // (2) プロトコルアドレスの種別とアドレス長がIPと合致しなければ中断
    if (msg->hdr.pro != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("protocol addrss type or protocol address length does not correspond ip address");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        // ARP要求への応答
        if (msg->hdr.op == ARP_OP_REQUEST) {
            // TODO: dstに対応するものを確認する
            arp_reply(iface, msg->tha, msg->tpa, spa);
        }
    }

}

int arp_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    
    return 0;
}