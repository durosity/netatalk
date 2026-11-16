/*
 * (c) 2026 Durosity. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*!
 * @file
 * @brief LAN mode for Linux: TAP device on a bridge, one Ethernet MAC per
 *        MacIP client
 *
 * Packets from MacIP clients are framed with the client's own MAC and sent
 * to the next hop on the LAN. Frames for a client's MAC are unwrapped and
 * passed to the MacIP side. macipgw answers ARP for active clients itself, so
 * the host kernel never routes MacIP traffic and needs no proxy ARP or NAT.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <netatalk/at.h>
#include <atalk/nbp.h>

#include "common.h"
#include "util.h"
#include "macip.h"
#include "lan.h"

#define ETH_HLEN_       14
#define ETHTYPE_IP      0x0800
#define ETHTYPE_ARP     0x0806
#define MACIP_MTU       586
#define LAN_MAX_CLIENTS 64
#define LAN_HOLD        4       /* packets held per client while identifying */
#define LAN_MAX_NODES   128
#define DDPTYPE_AEP_    4
#define AEP_SOCKET      4
#define AEP_REQUEST     1
#define AEP_REPLY       2
#define PRESENCE_MISSES 3       /* unanswered echo rounds before "gone" */
#define SCAN_SETTLE     2       /* seconds to collect lookup replies */
#define DHCP_SPORT      67
#define DHCP_CPORT      68
#define DHCP_RETRY      2       /* seconds between DHCP retransmissions */
#define DHCP_TRIES      4       /* before falling back to the pool */

#define D_NONE       0
#define D_SELECTING  1          /* DISCOVER sent */
#define D_REQUESTING 2          /* REQUEST sent */
#define D_BOUND      3
#define D_FAILED     4          /* no usable answer: pool or keep address */
#define LAN_MAX_ARP     128
#define ARP_TTL         300     /* seconds a learned LAN mapping is kept */
#define ARP_RETRY       1       /* seconds between ARP requests */
#define ARP_TRIES       3

#define CL_FREE    0
#define CL_PENDING 1    /* waiting for NBP names to build the identity */
#define CL_ACTIVE  2

struct lan_client {
    int state;
    uint32_t ip;
    struct sockaddr_at sat;
    uint8_t mac[6];
    int mac_fixed;              /* from configuration, never bumped */
    char key[LAN_KEY_LEN];
    long deadline;              /* identify by this time */
    long next_announce;
    /* identity candidates collected from NBP replies */
    char ws_name[NBPSTRLEN + 1];
    char cand_obj[NBPSTRLEN + 1];
    char cand_type[NBPSTRLEN + 1];
    int cand_sock;
    int cand_score;
    /* packets held while the client is being identified */
    char held[LAN_HOLD][MACIP_MTU];
    int held_len[LAN_HOLD];
    int nheld;
    /* AppleTalk-only presence */
    int presence;
    long last_reply;
    uint16_t aep_seq;
    uint16_t ping_seq;          /* AEP sequence that will answer the ping */
    char ping[1500];            /* LAN echo request waiting for that AEP */
    int ping_len;
    /* DHCP lease held on the client's behalf */
    int dhcp;                   /* D_* */
    int manual;                 /* the Mac chose its own address */
    uint32_t xid;
    int tries;
    long dhcp_next;
    uint32_t offered, server_ip;
    uint8_t server_mac[6];
    long renew_at, expire_at;
    char hostname[33];
};

/* a node seen in an NBP scan, for AppleTalk-only presence */
struct at_node {
    int used;
    uint16_t net;               /* network byte order, as in sat_addr */
    uint8_t node;
    long seen;
    char ws_name[NBPSTRLEN + 1];
    char cand_obj[NBPSTRLEN + 1];
    char cand_type[NBPSTRLEN + 1];
    int cand_sock;
    int cand_score;
};

struct arp_entry {
    int used;
    uint32_t ip;
    uint8_t mac[6];
    int resolved;
    long expires;
    long next_try;
    int tries;
    uint8_t mac_from[6];        /* client that asked, for the request */
    uint32_t ip_from;
    /* packets waiting for this next hop's MAC */
    char pending[LAN_HOLD][MACIP_MTU];
    int pending_len[LAN_HOLD];
    uint32_t pending_from[LAN_HOLD];
    int npending;
};

static struct {
    int fd;
    char name[IFNAMSIZ];
    uint32_t gwaddr;            /* macipgw's own MacIP address */
    uint32_t lan_net, lan_mask, router, host_ip;
    struct lan_config cfg;
    outputfunc_t to_macip;
    struct lan_client clients[LAN_MAX_CLIENTS];
    struct arp_entry arp[LAN_MAX_ARP];
    long last_lookup;
    struct at_node nodes[LAN_MAX_NODES];
    long next_scan;             /* next presence scan */
    long scan_time;             /* when the current scan was sent */
    int scan_pending;
} gLan;

static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static long lan_now(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec;
}

static const char *mactoa(const uint8_t m[6])
{
    static char s[4][18];
    static int i;
    i = (i + 1) & 3;
    snprintf(s[i], sizeof(s[i]), "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return s[i];
}

static uint16_t ip_cksum(const void *data, int len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += (uint32_t)(p[0] << 8 | p[1]);
        p += 2;
        len -= 2;
    }

    if (len) {
        sum += (uint32_t)(p[0] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return htons((uint16_t)(~sum & 0xffff));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

/* ------------------------------------------------------------------ */
/* Ethernet output                                                     */
/* ------------------------------------------------------------------ */

static void send_frame(const uint8_t dst[6], const uint8_t src[6],
                       uint16_t type, const void *payload, int len)
{
    uint8_t f[ETH_HLEN_ + 1600];

    if (len > 1500 || len < 0) {
        return;
    }

    memcpy(f, dst, 6);
    memcpy(f + 6, src, 6);
    f[12] = type >> 8;
    f[13] = type & 0xff;
    memcpy(f + ETH_HLEN_, payload, len);

    if (len < 46) {             /* pad to the Ethernet minimum */
        memset(f + ETH_HLEN_ + len, 0, 46 - len);
        len = 46;
    }

    if (write(gLan.fd, f, ETH_HLEN_ + len) < 0 && (gDebug & DEBUG_LAN)) {
        perror("lan: write");
    }
}

static void send_arp(uint16_t op, const uint8_t eth_dst[6],
                     const uint8_t sha[6], uint32_t spa,
                     const uint8_t tha[6], uint32_t tpa)
{
    uint8_t a[28];
    a[0] = 0;
    a[1] = 1;                   /* Ethernet */
    a[2] = 0x08;
    a[3] = 0x00;                /* IPv4 */
    a[4] = 6;
    a[5] = 4;
    a[6] = op >> 8;
    a[7] = op & 0xff;
    memcpy(a + 8, sha, 6);
    put32(a + 14, spa);
    memcpy(a + 18, tha, 6);
    put32(a + 24, tpa);
    send_frame(eth_dst, sha, ETHTYPE_ARP, a, sizeof(a));
}

static void route_out(struct lan_client *c, char *buffer, int len);
static void dhcp_start(struct lan_client *c);
static void dhcp_release(struct lan_client *c);

static void announce(struct lan_client *c)
{
    static const uint8_t zero[6] = { 0 };
    /* gratuitous ARP request: sender and target are the client itself */
    send_arp(1, bcast, c->mac, c->ip, zero, c->ip);
    c->next_announce = lan_now() + gLan.cfg.announce_interval;
}

/* ------------------------------------------------------------------ */
/* clients                                                             */
/* ------------------------------------------------------------------ */

static struct lan_client *client_by_ip(uint32_t ip)
{
    for (int i = 0; i < LAN_MAX_CLIENTS; i++)
        if (gLan.clients[i].state != CL_FREE && gLan.clients[i].ip == ip &&
                ip != 0) {
            return &gLan.clients[i];
        }

    return NULL;
}

static struct lan_client *client_by_mac(const uint8_t mac[6])
{
    for (int i = 0; i < LAN_MAX_CLIENTS; i++)
        if (gLan.clients[i].state == CL_ACTIVE &&
                memcmp(gLan.clients[i].mac, mac, 6) == 0) {
            return &gLan.clients[i];
        }

    return NULL;
}

static void request_names(void)
{
    long n = lan_now();

    if (n - gLan.last_lookup < 1) {
        return;
    }

    gLan.last_lookup = n;
    macip_nbp_lookup("=", "=");
}

static const struct lan_override *find_override(const char *key)
{
    for (int i = 0; i < gLan.cfg.noverrides; i++)
        if (strcasecmp(gLan.cfg.overrides[i].key, key) == 0) {
            return &gLan.cfg.overrides[i];
        }

    return NULL;
}

static int mac_in_use(const uint8_t mac[6], const struct lan_client *self)
{
    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        const struct lan_client *c = &gLan.clients[i];

        if (c != self && c->state == CL_ACTIVE && memcmp(c->mac, mac, 6) == 0) {
            return 1;
        }
    }

    for (int i = 0; i < LAN_MAX_ARP; i++) {
        const struct arp_entry *a = &gLan.arp[i];

        if (a->used && a->resolved && memcmp(a->mac, mac, 6) == 0) {
            return 1;
        }
    }

    return 0;
}

/* turn the collected NBP names into an identity and a MAC address */
static void activate(struct lan_client *c)
{
    char ipkey[24], nodekey[24];
    const struct lan_override *o;
    snprintf(ipkey, sizeof(ipkey), "%s", iptoa(c->ip));
    snprintf(nodekey, sizeof(nodekey), "node %u.%u",
             ntohs(c->sat.sat_addr.s_net), c->sat.sat_addr.s_node);

    if (lan_identity_key(c->ws_name, c->cand_obj, c->cand_type, c->key,
                         sizeof(c->key)) < 0) {
        snprintf(c->key, sizeof(c->key), "%s", nodekey);
    }

    /* configuration overrides: identity, then IP, then node */
    if ((o = find_override(c->key)) == NULL &&
            (o = find_override(ipkey)) == NULL) {
        o = find_override(nodekey);
    }

    if (o) {
        memcpy(c->mac, o->mac, 6);
        c->mac_fixed = 1;
        snprintf(c->hostname, sizeof(c->hostname), "%s", o->hostname);
    } else {
        lan_derive_mac(c->key, gLan.cfg.prefix, c->mac);
        c->mac_fixed = 0;

        for (int tries = 0; mac_in_use(c->mac, c) && tries < 255; tries++) {
            syslog(LOG_WARNING, "MAC %s for '%s' already in use; trying next",
                   mactoa(c->mac), c->key);
            c->mac[5]++;
        }
    }

    c->state = CL_ACTIVE;
    c->last_reply = lan_now();
    syslog(LOG_INFO, "client %s (%u.%u) is '%s', MAC %s%s%s", iptoa(c->ip),
           ntohs(c->sat.sat_addr.s_net), c->sat.sat_addr.s_node, c->key,
           mactoa(c->mac), c->mac_fixed ? " (configured)" : "",
           c->presence ? ", AppleTalk only" : "");

    if (gDebug & DEBUG_LAN)
        printf("lan: client %s is '%s' -> %s\n", iptoa(c->ip), c->key,
               mactoa(c->mac));

    dhcp_start(c);

    if (c->ip) {
        announce(c);
    }

    for (int i = 0; i < c->nheld; i++) {
        route_out(c, c->held[i], c->held_len[i]);
    }

    c->nheld = 0;
}

static void presence_drop(struct lan_client *c, const char *why)
{
    syslog(LOG_INFO, "client %s ('%s') %s", iptoa(c->ip), c->key, why);
    dhcp_release(c);
    macip_presence_release(c->ip);
    c->state = CL_FREE;
}

void lan_client_seen(uint32_t ip, const struct sockaddr_at *sat)
{
    struct lan_client *c;

    if (ip == gLan.gwaddr) {
        return;
    }

    /* an AppleTalk-only Mac that has started using MacIP: drop its presence
       entry; it is identified again and keeps the same MAC */
    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        struct lan_client *p = &gLan.clients[i];

        if (p->state != CL_FREE && p->presence && p->ip != ip &&
                p->sat.sat_addr.s_net == sat->sat_addr.s_net &&
                p->sat.sat_addr.s_node == sat->sat_addr.s_node) {
            presence_drop(p, "now uses MacIP");
        }
    }

    c = client_by_ip(ip);

    if (c) {
        if (c->sat.sat_addr.s_net == sat->sat_addr.s_net &&
                c->sat.sat_addr.s_node == sat->sat_addr.s_node) {
            return;
        }

        /* same IP from a different node: identify again */
        syslog(LOG_INFO, "client %s moved to node %u.%u", iptoa(ip),
               ntohs(sat->sat_addr.s_net), sat->sat_addr.s_node);
    } else {
        for (int i = 0; i < LAN_MAX_CLIENTS && !c; i++)
            if (gLan.clients[i].state == CL_FREE) {
                c = &gLan.clients[i];
            }

        if (!c) {
            syslog(LOG_ERR, "lan: client table full, %s ignored", iptoa(ip));
            return;
        }
    }

    memset(c, 0, sizeof(*c));
    c->state = CL_PENDING;
    c->ip = ip;
    c->sat = *sat;
    c->deadline = lan_now() + gLan.cfg.identify_timeout;
    gLan.last_lookup = 0;
    request_names();
}

void lan_client_gone(uint32_t ip)
{
    struct lan_client *c = client_by_ip(ip);

    if (c) {
        syslog(LOG_INFO, "client %s ('%s') gone", iptoa(ip), c->key);
        dhcp_release(c);
        c->state = CL_FREE;
    }
}

/* fold one NBP name into a node's identity candidates */
static void note_name(char *ws_name, char *cand_obj, char *cand_type,
                      int *cand_sock, int *cand_score, const char *obj,
                      const char *type, int sock)
{
    if (strcasecmp(type, "Workstation") == 0) {
        snprintf(ws_name, NBPSTRLEN + 1, "%s", obj);
        return;
    }

    /* prefer a model-like type (the Responder's name:model entry), then the
       highest socket */
    int score = lan_model_score(type);

    if (score == 0 || score < *cand_score ||
            (score == *cand_score && sock <= *cand_sock)) {
        return;
    }

    *cand_score = score;
    *cand_sock = sock;
    snprintf(cand_obj, NBPSTRLEN + 1, "%s", obj);
    snprintf(cand_type, NBPSTRLEN + 1, "%s", type);
}

static void scan_note(const struct nbpnve *nve, const char *obj,
                      const char *type)
{
    struct at_node *n = NULL, *free_slot = NULL;

    for (int i = 0; i < LAN_MAX_NODES; i++) {
        struct at_node *x = &gLan.nodes[i];

        if (x->used && x->net == nve->nn_sat.sat_addr.s_net &&
                x->node == nve->nn_sat.sat_addr.s_node) {
            n = x;
            break;
        }

        if (!x->used && !free_slot) {
            free_slot = x;
        }
    }

    if (!n) {
        if (!free_slot) {
            return;
        }

        n = free_slot;
        memset(n, 0, sizeof(*n));
        n->used = 1;
        n->net = nve->nn_sat.sat_addr.s_net;
        n->node = nve->nn_sat.sat_addr.s_node;
    }

    if (n->seen < gLan.scan_time) {     /* first answer in this scan */
        n->ws_name[0] = n->cand_obj[0] = n->cand_type[0] = 0;
        n->cand_sock = n->cand_score = 0;
    }

    n->seen = lan_now();
    note_name(n->ws_name, n->cand_obj, n->cand_type, &n->cand_sock,
              &n->cand_score, obj, type, nve->nn_sat.sat_port);
}

void lan_nbp_entry(const struct nbpnve *nve)
{
    char obj[NBPSTRLEN + 1], type[NBPSTRLEN + 1];

    memcpy(obj, nve->nn_obj, nve->nn_objlen);
    obj[nve->nn_objlen] = 0;
    memcpy(type, nve->nn_type, nve->nn_typelen);
    type[nve->nn_typelen] = 0;

    if (strcasecmp(type, "IPADDRESS") == 0 ||
            strcasecmp(type, "IPGATEWAY") == 0) {
        return;
    }

    if (gLan.cfg.presence && gLan.scan_pending) {
        scan_note(nve, obj, type);
    }

    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        struct lan_client *c = &gLan.clients[i];

        if (c->state != CL_PENDING ||
                c->sat.sat_addr.s_net != nve->nn_sat.sat_addr.s_net ||
                c->sat.sat_addr.s_node != nve->nn_sat.sat_addr.s_node) {
            continue;
        }

        /* a node answers a lookup with all of its names together, so once
           the first arrives there is little point waiting much longer */
        if (c->deadline > lan_now() + 1) {
            c->deadline = lan_now() + 1;
        }

        note_name(c->ws_name, c->cand_obj, c->cand_type, &c->cand_sock,
                  &c->cand_score, obj, type, nve->nn_sat.sat_port);

        if (gDebug & DEBUG_LAN)
            printf("lan: %s candidate '%s:%s' socket %u\n", iptoa(c->ip), obj,
                   type, nve->nn_sat.sat_port);
    }
}

/* ------------------------------------------------------------------ */
/* AppleTalk-only presence                                             */
/* ------------------------------------------------------------------ */

/* AppleTalk Echo to the client's node; the payload identifies the client */
static void aep_send(struct lan_client *c, uint16_t seq)
{
    struct sockaddr_at to = c->sat;
    char b[8];
    int idx = (int)(c - gLan.clients);

    to.sat_port = AEP_SOCKET;
    to.sat_family = AF_APPLETALK;
    b[0] = DDPTYPE_AEP_;
    b[1] = AEP_REQUEST;
    b[2] = 'M';
    b[3] = 'N';
    b[4] = (char) idx;
    b[5] = (char)(seq >> 8);
    b[6] = (char)(seq & 0xff);
    b[7] = 0;

    if (macip_send_ddp(&to, b, sizeof(b)) < 0 && (gDebug & DEBUG_LAN)) {
        perror("lan: AEP send");
    }
}

void lan_aep_reply(const struct sockaddr_at *sat, const char *data, int len)
{
    const uint8_t *d = (const uint8_t *) data;
    struct lan_client *c;
    uint16_t seq;

    if (len < 6 || d[0] != AEP_REPLY || d[1] != 'M' || d[2] != 'N' ||
            d[3] >= LAN_MAX_CLIENTS) {
        return;
    }

    c = &gLan.clients[d[3]];
    seq = (uint16_t)(d[4] << 8 | d[5]);

    if (c->state != CL_ACTIVE ||
            c->sat.sat_addr.s_net != sat->sat_addr.s_net ||
            c->sat.sat_addr.s_node != sat->sat_addr.s_node) {
        return;
    }

    c->last_reply = lan_now();

    if (c->presence && c->ping_len && seq == c->ping_seq) {
        /* the Mac is there: answer the LAN ping on its behalf */
        uint8_t *p = (uint8_t *) c->ping;
        int hl = (p[0] & 0x0f) * 4, tot = c->ping_len;
        uint8_t t[4];
        uint16_t sum;

        memcpy(t, p + 12, 4);
        memcpy(p + 12, p + 16, 4);
        memcpy(p + 16, t, 4);
        p[8] = 64;
        p[10] = p[11] = 0;
        sum = ip_cksum(p, hl);
        memcpy(p + 10, &sum, 2);
        p[hl] = 0;              /* echo reply */
        p[hl + 2] = p[hl + 3] = 0;
        sum = ip_cksum(p + hl, tot - hl);
        memcpy(p + hl + 2, &sum, 2);
        c->ping_len = 0;
        route_out(c, c->ping, tot);
    }
}

/* a LAN echo request for an AppleTalk-only Mac: ask the Mac first */
static void presence_ping(struct lan_client *c, const uint8_t *ip, int len)
{
    int hl = (ip[0] & 0x0f) * 4, tot = ip[2] << 8 | ip[3];

    if (ip[9] != 1 || tot < hl + 8 || tot > len || ip[hl] != 8 ||
            tot > (int) sizeof(c->ping) || (ip[6] & 0x3f) || ip[7]) {
        return;                 /* only whole ICMP echo requests */
    }

    memcpy(c->ping, ip, tot);
    c->ping_len = tot;
    c->ping_seq = ++c->aep_seq;
    aep_send(c, c->ping_seq);
}

static int node_has_macip_client(uint16_t net, uint8_t node)
{
    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        const struct lan_client *c = &gLan.clients[i];

        if (c->state != CL_FREE && !c->presence &&
                c->sat.sat_addr.s_net == net && c->sat.sat_addr.s_node == node) {
            return 1;
        }
    }

    return 0;
}

/* after a scan: give every Mac that is only on AppleTalk a presence */
static void presence_evaluate(void)
{
    struct sockaddr_at me;
    char key[LAN_KEY_LEN];
    long n = lan_now();

    memset(&me, 0, sizeof(me));
    macip_local_addr(&me);

    for (int i = 0; i < LAN_MAX_NODES; i++) {
        struct at_node *a = &gLan.nodes[i];
        struct lan_client *c = NULL;

        if (!a->used || a->seen < gLan.scan_time) {
            continue;
        }

        if ((a->net == me.sat_addr.s_net && a->node == me.sat_addr.s_node) ||
                node_has_macip_client(a->net, a->node)) {
            continue;           /* the gateway itself, or already on MacIP */
        }

        if (!a->ws_name[0] && a->cand_score < 2) {
            continue;           /* not recognisably a Mac (a printer, say) */
        }

        if (lan_identity_key(a->ws_name, a->cand_obj, a->cand_type, key,
                             sizeof(key)) < 0) {
            continue;
        }

        for (int j = 0; j < LAN_MAX_CLIENTS && !c; j++) {
            struct lan_client *x = &gLan.clients[j];

            if (x->state == CL_ACTIVE && x->presence &&
                    strcasecmp(x->key, key) == 0) {
                c = x;
            }
        }

        if (c) {                /* known; its node may have changed */
            c->sat.sat_addr.s_net = a->net;
            c->sat.sat_addr.s_node = a->node;
            continue;
        }

        for (int j = 0; j < LAN_MAX_CLIENTS && !c; j++)
            if (gLan.clients[j].state == CL_FREE) {
                c = &gLan.clients[j];
            }

        if (!c) {
            syslog(LOG_ERR, "lan: client table full, '%s' ignored", key);
            continue;
        }

        uint32_t ip = gLan.cfg.dhcp ? 0 : macip_presence_lease();

        if (!ip && !gLan.cfg.dhcp) {
            syslog(LOG_WARNING, "no free address for AppleTalk-only '%s'",
                   key);
            continue;
        }

        memset(c, 0, sizeof(*c));
        c->presence = 1;
        c->ip = ip;
        c->sat.sat_family = AF_APPLETALK;
        c->sat.sat_addr.s_net = a->net;
        c->sat.sat_addr.s_node = a->node;
        c->sat.sat_port = AEP_SOCKET;
        c->last_reply = n;
        snprintf(c->ws_name, sizeof(c->ws_name), "%s", a->ws_name);
        snprintf(c->cand_obj, sizeof(c->cand_obj), "%s", a->cand_obj);
        snprintf(c->cand_type, sizeof(c->cand_type), "%s", a->cand_type);
        activate(c);
    }
}

/*
 * periodic: echo-check every client (a Mac that stops answering is gone,
 * whether it used MacIP or only AppleTalk) and, with presence enabled, scan
 * for AppleTalk-only Macs
 */
static void check_idle(void)
{
    long n = lan_now();
    int interval = gLan.cfg.check_interval;

    if (gLan.scan_pending && n >= gLan.scan_time + SCAN_SETTLE) {
        gLan.scan_pending = 0;
        presence_evaluate();
    }

    if (n < gLan.next_scan) {
        return;
    }

    gLan.next_scan = n + interval;

    if (gLan.cfg.presence) {
        gLan.scan_time = n;
        gLan.scan_pending = 1;
        macip_nbp_lookup("=", "=");
    }

    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        struct lan_client *c = &gLan.clients[i];

        if (c->state != CL_ACTIVE) {
            continue;
        }

        if (n - c->last_reply <= (long) interval * PRESENCE_MISSES) {
            aep_send(c, ++c->aep_seq);
        } else if (c->presence) {
            presence_drop(c, "stopped answering, gone");
        } else {
            syslog(LOG_INFO, "client %s ('%s') stopped answering, gone",
                   iptoa(c->ip), c->key);
            macip_release_lease(c->ip);
            c->state = CL_FREE;
        }
    }
}

/* ------------------------------------------------------------------ */
/* DHCP on behalf of clients                                           */
/* ------------------------------------------------------------------ */

static int in_pool(uint32_t ip)
{
    return macip_pool_contains(ip);
}

/* "G3 AIO:Power Macintosh" -> "G3-AIO" */
static void make_hostname(const char *key, char *out, size_t len)
{
    size_t o = 0;
    int dash = 1;

    for (const char *p = key; *p && *p != ':' && o + 1 < len; p++) {
        if (isalnum((unsigned char) *p)) {
            out[o++] = *p;
            dash = 0;
        } else if (!dash) {
            out[o++] = '-';
            dash = 1;
        }
    }

    while (o > 0 && out[o - 1] == '-') {
        o--;
    }

    out[o] = 0;
}

/* build and broadcast (or unicast) a DHCP message from the client */
static void dhcp_send(struct lan_client *c, int type, uint32_t ciaddr,
                      uint32_t req_ip, uint32_t server)
{
    uint8_t pkt[20 + 8 + 300];
    uint8_t *ip = pkt, *udp = pkt + 20, *b = pkt + 28, *o;
    int unicast = (type == 7);              /* RELEASE goes to the server */
    uint32_t dst = unicast ? c->server_ip : 0xffffffff;
    uint16_t sum;

    memset(pkt, 0, sizeof(pkt));
    b[0] = 1;                               /* BOOTREQUEST */
    b[1] = 1;                               /* Ethernet */
    b[2] = 6;
    put32(b + 4, c->xid);

    if (!ciaddr) {
        b[10] = 0x80;                       /* ask for a broadcast reply */
    }

    put32(b + 12, ciaddr);
    memcpy(b + 28, c->mac, 6);
    put32(b + 236, 0x63825363);             /* magic cookie */
    o = b + 240;
    *o++ = 53;
    *o++ = 1;
    *o++ = (uint8_t) type;
    *o++ = 61;                              /* client identifier */
    *o++ = 7;
    *o++ = 1;
    memcpy(o, c->mac, 6);
    o += 6;

    if (c->hostname[0] && type != 7) {
        size_t n = strlen(c->hostname);
        *o++ = 12;
        *o++ = (uint8_t) n;
        memcpy(o, c->hostname, n);
        o += n;
    }

    if (req_ip) {
        *o++ = 50;
        *o++ = 4;
        put32(o, req_ip);
        o += 4;
    }

    if (server) {
        *o++ = 54;
        *o++ = 4;
        put32(o, server);
        o += 4;
    }

    if (type != 7) {
        /* Ask for the same parameters, in the same order, as the Mac OS 9
           (Open Transport) DHCP client, so DHCP fingerprinting (UniFi,
           Fingerbank) recognises the client as a Mac. */
        static const uint8_t prl[] = {
            1, 3, 6, 15, 33, 42, 44, 45, 46, 47, 69, 70, 71, 74, 78, 79
        };
        *o++ = 55;
        *o++ = sizeof(prl);
        memcpy(o, prl, sizeof(prl));
        o += sizeof(prl);
    }

    *o++ = 255;

    /* UDP 68 -> 67, checksum left at zero (allowed for IPv4) */
    udp[0] = 0;
    udp[1] = DHCP_CPORT;
    udp[2] = 0;
    udp[3] = DHCP_SPORT;
    udp[4] = (8 + 300) >> 8;
    udp[5] = (8 + 300) & 0xff;

    ip[0] = 0x45;
    ip[2] = sizeof(pkt) >> 8;
    ip[3] = sizeof(pkt) & 0xff;
    ip[8] = 64;
    ip[9] = 17;
    put32(ip + 12, ciaddr);
    put32(ip + 16, dst);
    sum = ip_cksum(ip, 20);
    memcpy(ip + 10, &sum, 2);

    send_frame(unicast ? c->server_mac : bcast, c->mac, ETHTYPE_IP, pkt,
               sizeof(pkt));
    c->dhcp_next = lan_now() + DHCP_RETRY;
}

static void dhcp_discover(struct lan_client *c)
{
    c->dhcp = D_SELECTING;
    dhcp_send(c, 1, 0, 0, 0);
}

static void dhcp_start(struct lan_client *c)
{
    if (!gLan.cfg.dhcp || c->dhcp != D_NONE) {
        return;
    }

    if (!c->hostname[0]) {
        make_hostname(c->key, c->hostname, sizeof(c->hostname));
    }
    c->xid = (uint32_t) random();
    c->tries = 1;

    if (c->ip && in_pool(c->ip)) {
        c->dhcp = D_FAILED;                 /* a pool address: no DHCP */
    } else if (c->ip) {
        /* the Mac already uses an address: ask the server to confirm it */
        c->manual = 1;
        c->dhcp = D_REQUESTING;
        dhcp_send(c, 3, 0, c->ip, 0);
    } else {
        dhcp_discover(c);
    }
}

static void dhcp_release(struct lan_client *c)
{
    if (c->dhcp == D_BOUND && c->server_ip) {
        dhcp_send(c, 7, c->ip, 0, c->server_ip);
    }

    c->dhcp = D_NONE;
}

static void dhcp_bound(struct lan_client *c, uint32_t yiaddr, uint32_t lease)
{
    long n = lan_now();
    int first = (c->dhcp != D_BOUND);

    if (lease == 0 || lease > 7 * 86400) {
        lease = 86400;
    }

    c->dhcp = D_BOUND;
    c->renew_at = n + lease / 2;
    c->expire_at = n + lease;

    if (!c->ip) {
        c->ip = yiaddr;
    }

    if (first) {
        syslog(LOG_INFO, "client '%s' leased %s from %s as '%s'", c->key,
               iptoa(c->ip), c->manual ? "DHCP (its own address)" : "DHCP",
               c->hostname);
        announce(c);
        macip_assign_ready(&c->sat);    /* answer a held address request */
    }
}

/* a DHCP reply on the LAN; 1 if it was for one of our clients */
static int dhcp_input(const uint8_t *frame, int len)
{
    const uint8_t *ip = frame + ETH_HLEN_, *b, *o, *end;
    int hl, type = 0;
    uint32_t xid, yiaddr, server = 0, lease = 0;
    struct lan_client *c = NULL;

    hl = (ip[0] & 0x0f) * 4;

    if (ip[9] != 17 || len < ETH_HLEN_ + hl + 8 + 240 ||
            (ip[hl + 2] << 8 | ip[hl + 3]) != DHCP_CPORT) {
        return 0;
    }

    b = ip + hl + 8;
    end = frame + len;

    if (b[0] != 2 || get32(b + 236) != 0x63825363) {
        return 0;
    }

    xid = get32(b + 4);
    yiaddr = get32(b + 16);

    for (int i = 0; i < LAN_MAX_CLIENTS && !c; i++) {
        struct lan_client *x = &gLan.clients[i];

        if (x->state == CL_ACTIVE && x->xid == xid &&
                memcmp(x->mac, b + 28, 6) == 0) {
            c = x;
        }
    }

    if (!c) {
        return 0;
    }

    for (o = b + 240; o < end && *o != 255;) {
        if (*o == 0) {
            o++;
            continue;
        }

        if (o + 2 > end || o + 2 + o[1] > end) {
            break;
        }

        if (o[0] == 53 && o[1] >= 1) {
            type = o[2];
        } else if (o[0] == 54 && o[1] == 4) {
            server = get32(o + 2);
        } else if (o[0] == 51 && o[1] == 4) {
            lease = get32(o + 2);
        }

        o += 2 + o[1];
    }

    if (type == 2 && c->dhcp == D_SELECTING) {          /* OFFER */
        c->offered = yiaddr;
        c->server_ip = server;
        memcpy(c->server_mac, frame + 6, 6);
        c->dhcp = D_REQUESTING;
        c->tries = 1;
        dhcp_send(c, 3, 0, yiaddr, server);
    } else if (type == 5 && (c->dhcp == D_REQUESTING ||
                             c->dhcp == D_BOUND)) {    /* ACK */
        if (server) {
            c->server_ip = server;
        }

        memcpy(c->server_mac, frame + 6, 6);
        dhcp_bound(c, yiaddr, lease);
    } else if (type == 6) {                             /* NAK */
        if (c->manual) {
            syslog(LOG_WARNING, "DHCP server refused %s for '%s'; it keeps "
                   "working, but consider a reservation", iptoa(c->ip),
                   c->key);
            c->dhcp = D_FAILED;
        } else if (c->dhcp != D_BOUND) {
            c->xid++;
            dhcp_discover(c);
        }
    }

    return 1;
}

static void dhcp_idle(struct lan_client *c)
{
    long n = lan_now();

    switch (c->dhcp) {
    case D_SELECTING:
    case D_REQUESTING:
        if (n < c->dhcp_next) {
            break;
        }

        if (++c->tries > DHCP_TRIES) {
            c->dhcp = D_FAILED;
            syslog(LOG_WARNING, "no DHCP answer for '%s'%s", c->key,
                   c->ip ? "; keeping its address" : "; using the pool");

            if (!c->ip && c->presence &&
                    (c->ip = macip_presence_lease()) != 0) {
                announce(c);
            }

            if (!c->presence) {
                macip_assign_ready(&c->sat);    /* falls back to the pool */
            }

            break;
        }

        if (c->dhcp == D_SELECTING) {
            dhcp_send(c, 1, 0, 0, 0);
        } else {
            dhcp_send(c, 3, 0, c->manual ? c->ip : c->offered,
                      c->manual ? 0 : c->server_ip);
        }

        break;

    case D_BOUND:
        if (n >= c->renew_at) {
            dhcp_send(c, 3, c->ip, 0, 0);       /* renew */
            c->renew_at = n + 60;
        }

        if (n >= c->expire_at) {
            syslog(LOG_WARNING, "DHCP lease for '%s' (%s) expired",
                   c->key, iptoa(c->ip));
            c->expire_at = n + 3600;
        }

        break;
    }
}

/* MacIP server address request (hook from macip.c) */
int lan_assign(const struct sockaddr_at *sat, uint32_t *ip, uint32_t *mask)
{
    struct lan_client *c = NULL;

    if (!gLan.cfg.dhcp) {
        return -1;
    }

    for (int i = 0; i < LAN_MAX_CLIENTS && !c; i++) {
        struct lan_client *x = &gLan.clients[i];

        if (x->state != CL_FREE &&
                x->sat.sat_addr.s_net == sat->sat_addr.s_net &&
                x->sat.sat_addr.s_node == sat->sat_addr.s_node) {
            c = x;
        }
    }

    if (c && c->presence) {
        /* an AppleTalk-only Mac that has started MacIP keeps its lease */
        syslog(LOG_INFO, "client '%s' now uses MacIP", c->key);
        c->presence = 0;
    }

    if (!c) {
        for (int i = 0; i < LAN_MAX_CLIENTS && !c; i++)
            if (gLan.clients[i].state == CL_FREE) {
                c = &gLan.clients[i];
            }

        if (!c) {
            return -1;
        }

        memset(c, 0, sizeof(*c));
        c->state = CL_PENDING;
        c->sat = *sat;
        c->deadline = lan_now() + gLan.cfg.identify_timeout;
        gLan.last_lookup = 0;
        request_names();
        return 0;
    }

    if (c->state == CL_ACTIVE && c->ip && c->dhcp == D_BOUND) {
        *ip = c->ip;
        *mask = gLan.cfg.client_mask;
        return 1;
    }

    if (c->state == CL_ACTIVE && c->dhcp == D_FAILED && !c->ip) {
        c->state = CL_FREE;     /* let the pool handle it */
        return -1;
    }

    return 0;
}

/* track a MacIP client address outside the pool? (hook from macip.c) */
int lan_accept_ip(uint32_t ip)
{
    return (ip & gLan.lan_mask) == gLan.lan_net && ip != gLan.host_ip &&
           ip != gLan.router && ip != gLan.lan_net &&
           ip != (gLan.lan_net | ~gLan.lan_mask);
}

/* ------------------------------------------------------------------ */
/* ARP cache for LAN hosts                                             */
/* ------------------------------------------------------------------ */

static struct arp_entry *arp_find(uint32_t ip)
{
    for (int i = 0; i < LAN_MAX_ARP; i++)
        if (gLan.arp[i].used && gLan.arp[i].ip == ip) {
            return &gLan.arp[i];
        }

    return NULL;
}

static struct arp_entry *arp_alloc(uint32_t ip)
{
    struct arp_entry *a = arp_find(ip), *oldest = NULL;
    long n = lan_now();

    if (a) {
        return a;
    }

    for (int i = 0; i < LAN_MAX_ARP; i++) {
        a = &gLan.arp[i];

        if (!a->used || a->expires < n) {
            break;
        }

        if (!oldest || a->expires < oldest->expires) {
            oldest = a;
        }

        a = NULL;
    }

    if (!a) {
        a = oldest;
    }

    memset(a, 0, sizeof(*a));
    a->used = 1;
    a->ip = ip;
    return a;
}

static void arp_learn(uint32_t ip, const uint8_t mac[6])
{
    struct arp_entry *a;

    if (ip == 0 || (ip & gLan.lan_mask) != gLan.lan_net || client_by_ip(ip)) {
        return;
    }

    a = arp_alloc(ip);
    memcpy(a->mac, mac, 6);
    a->resolved = 1;
    a->expires = lan_now() + ARP_TTL;

    for (int i = 0; i < a->npending; i++) {
        struct lan_client *c = client_by_ip(a->pending_from[i]);

        if (c && c->state == CL_ACTIVE) {
            send_frame(a->mac, c->mac, ETHTYPE_IP, a->pending[i],
                       a->pending_len[i]);
        }
    }

    a->npending = 0;
}

/* ------------------------------------------------------------------ */
/* packets from MacIP clients                                          */
/* ------------------------------------------------------------------ */

/* answer pings to the gateway's own MacIP address */
static void echo_reply(char *buffer, int len)
{
    uint8_t *p = (uint8_t *) buffer;
    int hl = (p[0] & 0x0f) * 4;
    uint8_t tmp[4];
    uint16_t s;

    if (len < hl + 8 || p[9] != 1 || p[hl] != 8) {
        return;                 /* not an ICMP echo request */
    }

    memcpy(tmp, p + 12, 4);
    memcpy(p + 12, p + 16, 4);
    memcpy(p + 16, tmp, 4);
    p[8] = 64;
    p[10] = p[11] = 0;
    s = ip_cksum(p, hl);
    memcpy(p + 10, &s, 2);
    p[hl] = 0;                  /* echo reply */
    p[hl + 2] = p[hl + 3] = 0;
    s = ip_cksum(p + hl, len - hl);
    memcpy(p + hl + 2, &s, 2);
    gLan.to_macip(buffer, len);
}

void lan_output(char *buffer, int len)
{
    const uint8_t *p = (const uint8_t *) buffer;
    uint32_t src, dst;
    struct lan_client *c;

    if (len < 20 || (p[0] >> 4) != 4) {
        return;
    }

    src = get32(p + 12);
    dst = get32(p + 16);

    if (dst == gLan.gwaddr) {
        echo_reply(buffer, len);
        return;
    }

    if (client_by_ip(dst) != NULL) {
        gLan.to_macip(buffer, len);    /* client to client, stays on AppleTalk */
        return;
    }

    c = client_by_ip(src);

    if (!c) {
        return;
    }

    c->last_reply = lan_now();

    if (c->state != CL_ACTIVE) {
        if (c->nheld < LAN_HOLD && len <= MACIP_MTU) {
            memcpy(c->held[c->nheld], buffer, len);
            c->held_len[c->nheld++] = len;
        } else if (gDebug & DEBUG_LAN) {
            printf("lan: %s not identified yet, packet dropped\n",
                   iptoa(src));
        }

        return;
    }

    route_out(c, buffer, len);
}

/* send a packet from an identified client towards the LAN */
static void route_out(struct lan_client *c, char *buffer, int len)
{
    const uint8_t *p = (const uint8_t *) buffer;
    uint32_t dst = get32(p + 16), hop;
    struct arp_entry *a;
    long n = lan_now();

    if (dst == 0xffffffff || dst == (gLan.lan_net | ~gLan.lan_mask)) {
        send_frame(bcast, c->mac, ETHTYPE_IP, buffer, len);
        return;
    }

    if ((dst & 0xf0000000) == 0xe0000000) {
        return;                 /* multicast not supported */
    }

    hop = ((dst & gLan.lan_mask) == gLan.lan_net) ? dst : gLan.router;

    if (hop == 0) {
        return;
    }

    a = arp_alloc(hop);

    if (a->resolved && a->expires >= n) {
        send_frame(a->mac, c->mac, ETHTYPE_IP, buffer, len);
        return;
    }

    /* hold the packet and ask for the next hop's MAC */
    if (a->npending < LAN_HOLD && len <= MACIP_MTU) {
        memcpy(a->pending[a->npending], buffer, len);
        a->pending_len[a->npending] = len;
        a->pending_from[a->npending++] = c->ip;
    }

    a->ip_from = c->ip;

    a->resolved = 0;

    if (a->next_try <= n) {
        static const uint8_t zero[6] = { 0 };
        memcpy(a->mac_from, c->mac, 6);
        send_arp(1, bcast, c->mac, c->ip, zero, hop);
        a->next_try = n + ARP_RETRY;
        a->tries++;
    }
}

/* ------------------------------------------------------------------ */
/* frames from the LAN                                                 */
/* ------------------------------------------------------------------ */

/* send an IP packet to a client, fragmenting to the MacIP MTU */
static void to_client(uint8_t *ip, int len)
{
    int hl = (ip[0] & 0x0f) * 4;
    int total = ip[2] << 8 | ip[3];
    uint8_t frag[MACIP_MTU];
    uint16_t s;

    if (total < hl || total > len) {
        return;
    }

    len = total;                /* drop Ethernet padding */

    if (len <= MACIP_MTU) {
        gLan.to_macip((char *) ip, len);
        return;
    }

    int chunk = (MACIP_MTU - hl) & ~7;
    int off0 = (ip[6] & 0x1f) << 8 | ip[7];   /* existing fragment offset */
    int more0 = ip[6] & 0x20;

    for (int pos = hl; pos < len; pos += chunk) {
        int n = len - pos < chunk ? len - pos : chunk;
        int more = (pos + n < len) || more0;
        int off = off0 + (pos - hl) / 8;

        memcpy(frag, ip, hl);
        memcpy(frag + hl, ip + pos, n);
        frag[2] = (hl + n) >> 8;
        frag[3] = (hl + n) & 0xff;
        frag[6] = (uint8_t)((ip[6] & 0x40) | (more ? 0x20 : 0) | (off >> 8));
        frag[7] = off & 0xff;
        frag[10] = frag[11] = 0;
        s = ip_cksum(frag, hl);
        memcpy(frag + 10, &s, 2);
        gLan.to_macip((char *) frag, hl + n);
    }
}

void lan_input(void)
{
    uint8_t f[2048];
    int len = read(gLan.fd, f, sizeof(f));
    uint16_t type;
    struct lan_client *c;

    if (len < ETH_HLEN_) {
        return;
    }

    type = f[12] << 8 | f[13];

    /* a frame from someone else using one of our MACs */
    if ((c = client_by_mac(f + 6)) != NULL) {
        syslog(LOG_WARNING, "MAC %s of '%s' is also used by another device",
               mactoa(c->mac), c->key);

        if (!c->mac_fixed) {
            c->mac[5]++;
            syslog(LOG_WARNING, "'%s' moved to MAC %s; pin a MAC in [clients]",
                   c->key, mactoa(c->mac));
            announce(c);
        }

        return;
    }

    if (type == ETHTYPE_ARP && len >= ETH_HLEN_ + 28) {
        uint8_t *a = f + ETH_HLEN_;
        int op = a[6] << 8 | a[7];
        uint32_t spa = get32(a + 14), tpa = get32(a + 24);

        if (a[0] != 0 || a[1] != 1 || a[2] != 8 || a[3] != 0) {
            return;
        }

        arp_learn(spa, a + 8);

        if (op == 1 && (c = client_by_ip(tpa)) != NULL &&
                c->state == CL_ACTIVE && spa != tpa) {
            send_arp(2, a + 8, c->mac, c->ip, a + 8, spa);
        }

        return;
    }

    if (type == ETHTYPE_IP && len >= ETH_HLEN_ + 20) {
        uint8_t *ip = f + ETH_HLEN_;

        if (gLan.cfg.dhcp && dhcp_input(f, len)) {
            return;
        }

        if ((c = client_by_mac(f)) == NULL || get32(ip + 16) != c->ip) {
            return;
        }

        if (c->presence) {
            presence_ping(c, ip, len - ETH_HLEN_);
            return;
        }

        to_client(ip, len - ETH_HLEN_);
    }
}

/* ------------------------------------------------------------------ */
/* housekeeping                                                        */
/* ------------------------------------------------------------------ */

void lan_idle(void)
{
    long n = lan_now();

    check_idle();

    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        struct lan_client *c = &gLan.clients[i];

        if (c->state == CL_PENDING) {
            if (n >= c->deadline) {
                activate(c);
            } else {
                request_names();
            }
        } else if (c->state == CL_ACTIVE) {
            dhcp_idle(c);

            if (c->ip && n >= c->next_announce) {
                announce(c);
            }
        }
    }

    for (int i = 0; i < LAN_MAX_ARP; i++) {
        struct arp_entry *a = &gLan.arp[i];

        if (!a->used || a->resolved) {
            continue;
        }

        if (a->tries >= ARP_TRIES && a->next_try <= n) {
            a->used = 0;        /* next hop not answering */
        } else if (a->next_try <= n && a->npending) {
            static const uint8_t zero[6] = { 0 };
            send_arp(1, bcast, a->mac_from, a->ip_from, zero, a->ip);
            a->next_try = n + ARP_RETRY;
            a->tries++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* setup                                                               */
/* ------------------------------------------------------------------ */

static uint32_t default_router(void)
{
    FILE *f = fopen("/proc/net/route", "r");
    char line[256], ifname[64];
    unsigned long dest, gw, mask;
    unsigned int flags;
    uint32_t r = 0;

    if (!f) {
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%63s %lx %lx %x %*s %*s %*s %lx", ifname, &dest, &gw,
                   &flags, &mask) == 5 && dest == 0 && mask == 0 && (flags & 2)) {
            r = ntohl((uint32_t) gw);
            break;
        }
    }

    fclose(f);
    return r;
}

static int if_ioctl(int sk, unsigned long req, const char *name,
                    struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(*ifr));
    snprintf(ifr->ifr_name, IFNAMSIZ, "%s", name);
    return ioctl(sk, req, ifr);
}

int lan_open(const struct lan_config *cfg, uint32_t gwaddr,
             outputfunc_t to_macip)
{
    struct ifreq ifr;
    int sk, idx;

    memset(&gLan, 0, sizeof(gLan));
    gLan.cfg = *cfg;
    gLan.gwaddr = gwaddr;
    gLan.to_macip = to_macip;

    if (gLan.cfg.announce_interval <= 0) {
        gLan.cfg.announce_interval = 60;
    }

    if (gLan.cfg.identify_timeout <= 0) {
        gLan.cfg.identify_timeout = 3;
    }

    if (gLan.cfg.check_interval <= 0) {
        gLan.cfg.check_interval = 30;
    }

    gLan.next_scan = lan_now() + 5;     /* let the MacIP clients settle first */

    if (gLan.cfg.client_mask == 0) {
        gLan.cfg.client_mask = 0xffffffff;
    }

    srandom((unsigned int)(lan_now() ^ getpid()));

    if ((gLan.fd = open("/dev/net/tun", O_RDWR)) < 0) {
        syslog(LOG_ERR, "lan: /dev/net/tun: %m");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "macip%%d");

    if (ioctl(gLan.fd, TUNSETIFF, &ifr) < 0) {
        syslog(LOG_ERR, "lan: TUNSETIFF: %m");
        close(gLan.fd);
        return -1;
    }

    snprintf(gLan.name, sizeof(gLan.name), "%s", ifr.ifr_name);

    if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "lan: socket: %m");
        return -1;
    }

    /* bring the TAP up at the LAN's MTU and add it to the bridge */
    if (if_ioctl(sk, SIOCGIFFLAGS, gLan.name, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP;
        ioctl(sk, SIOCSIFFLAGS, &ifr);
    }

    if_ioctl(sk, SIOCGIFINDEX, gLan.name, &ifr);
    idx = ifr.ifr_ifindex;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", gLan.cfg.bridge);
    ifr.ifr_ifindex = idx;

    if (ioctl(sk, SIOCBRADDIF, &ifr) < 0) {
        syslog(LOG_ERR, "lan: cannot add %s to bridge %s: %m", gLan.name,
               gLan.cfg.bridge);
        close(sk);
        close(gLan.fd);
        return -1;
    }

    /* learn the LAN from the bridge's own address */
    if (if_ioctl(sk, SIOCGIFADDR, gLan.cfg.bridge, &ifr) == 0) {
        gLan.host_ip = ntohl(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr);
    }

    if (if_ioctl(sk, SIOCGIFNETMASK, gLan.cfg.bridge, &ifr) == 0) {
        gLan.lan_mask = ntohl(((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr);
    }

    close(sk);

    if (gLan.host_ip == 0 || gLan.lan_mask == 0) {
        syslog(LOG_ERR, "lan: bridge %s has no IPv4 address", gLan.cfg.bridge);
        close(gLan.fd);
        return -1;
    }

    gLan.lan_net = gLan.host_ip & gLan.lan_mask;
    gLan.router = gLan.cfg.router ? gLan.cfg.router : default_router();

    {
        /* iptoa() returns a static buffer, so copy before the next call */
        char net[16], msk[16], rtr[16];
        snprintf(net, sizeof(net), "%s", iptoa(gLan.lan_net));
        snprintf(msk, sizeof(msk), "%s", iptoa(gLan.lan_mask));
        snprintf(rtr, sizeof(rtr), "%s", iptoa(gLan.router));
        syslog(LOG_INFO, "LAN mode: %s on bridge %s, LAN %s netmask %s, "
               "router %s, MAC prefix %02x:%02x:%02x", gLan.name,
               gLan.cfg.bridge, net, msk, rtr, gLan.cfg.prefix[0],
               gLan.cfg.prefix[1], gLan.cfg.prefix[2]);
    }

    if (gDebug & DEBUG_LAN) {
        printf("lan: %s on %s, LAN %s/", gLan.name, gLan.cfg.bridge,
               iptoa(gLan.lan_net));
        printf("%s, router ", iptoa(gLan.lan_mask));
        printf("%s\n", iptoa(gLan.router));
    }

    return gLan.fd;
}

void lan_close(void)
{
    if (gLan.fd > 0) {
        close(gLan.fd);         /* the kernel removes the TAP and its port */
    }
}
