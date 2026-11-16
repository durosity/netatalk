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
        if (gLan.clients[i].state != CL_FREE && gLan.clients[i].ip == ip) {
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
    syslog(LOG_INFO, "client %s (%u.%u) is '%s', MAC %s%s", iptoa(c->ip),
           ntohs(c->sat.sat_addr.s_net), c->sat.sat_addr.s_node, c->key,
           mactoa(c->mac), c->mac_fixed ? " (configured)" : "");

    if (gDebug & DEBUG_LAN)
        printf("lan: client %s is '%s' -> %s\n", iptoa(c->ip), c->key,
               mactoa(c->mac));

    announce(c);

    for (int i = 0; i < c->nheld; i++) {
        route_out(c, c->held[i], c->held_len[i]);
    }

    c->nheld = 0;
}

void lan_client_seen(uint32_t ip, const struct sockaddr_at *sat)
{
    struct lan_client *c = client_by_ip(ip);

    if (ip == gLan.gwaddr) {
        return;
    }

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
        c->state = CL_FREE;
    }
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

        if (strcasecmp(type, "Workstation") == 0) {
            snprintf(c->ws_name, sizeof(c->ws_name), "%s", obj);
        } else {
            /* prefer a model-like type (the Responder's name:model entry),
               then the highest socket */
            int score = lan_model_score(type);

            if (score == 0 || score < c->cand_score ||
                    (score == c->cand_score &&
                     nve->nn_sat.sat_port <= c->cand_sock)) {
                continue;
            }

            c->cand_score = score;
            c->cand_sock = nve->nn_sat.sat_port;
            snprintf(c->cand_obj, sizeof(c->cand_obj), "%s", obj);
            snprintf(c->cand_type, sizeof(c->cand_type), "%s", type);
        }

        if (gDebug & DEBUG_LAN)
            printf("lan: %s candidate '%s:%s' socket %u\n", iptoa(c->ip), obj,
                   type, nve->nn_sat.sat_port);
    }
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

        if ((c = client_by_mac(f)) == NULL || get32(ip + 16) != c->ip) {
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

    for (int i = 0; i < LAN_MAX_CLIENTS; i++) {
        struct lan_client *c = &gLan.clients[i];

        if (c->state == CL_PENDING) {
            if (n >= c->deadline) {
                activate(c);
            } else {
                request_names();
            }
        } else if (c->state == CL_ACTIVE && n >= c->next_announce) {
            announce(c);
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
