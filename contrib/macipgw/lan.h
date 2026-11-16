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
 * @brief LAN mode: present each MacIP client on the Ethernet as its own host
 *
 * In LAN mode macipgw attaches a TAP device to a Linux bridge that also holds
 * the host's LAN interface. Each MacIP client gets its own Ethernet MAC
 * address, derived from the name and model it registers over NBP (or set in
 * the configuration), and macipgw answers ARP and frames packets for it.
 */

#ifndef MACIPGW_LAN_H
#define MACIPGW_LAN_H

#include <stdint.h>
#include <netatalk/at.h>

#include "lan_ident.h"

#define LAN_KEY_LEN   80
#define LAN_MAX_OVERRIDES 64

struct lan_override {
    char key[LAN_KEY_LEN];   /* identity key, IP address or "node N.N" */
    uint8_t mac[6];
    char hostname[33];       /* optional DHCP hostname */
};

struct lan_config {
    char bridge[32];                /* bridge holding the LAN interface */
    uint8_t prefix[3];              /* OUI for generated MACs */
    uint32_t router;                /* 0 = take the host's default route */
    int announce_interval;          /* seconds between gratuitous ARPs */
    int identify_timeout;           /* seconds to wait for NBP names */
    int presence;                   /* give AppleTalk-only Macs a presence */
    int check_interval;             /* seconds between echo checks and scans */
    int dhcp;                       /* lease addresses from the LAN's DHCP */
    uint32_t client_mask;           /* netmask given to MacIP server clients */
    char status_file[256];          /* JSON list of clients, "" = none */
    int noverrides;
    struct lan_override overrides[LAN_MAX_OVERRIDES];
};

struct nbpnve;

extern int  lan_open(const struct lan_config *cfg, uint32_t gwaddr,
                     outputfunc_t to_macip);
extern void lan_close(void);
extern void lan_input(void);
extern void lan_output(char *buffer, int len);
extern void lan_idle(void);

/* hooks called from macip.c */
extern void lan_client_seen(uint32_t ip, const struct sockaddr_at *sat);
extern void lan_client_gone(uint32_t ip);
extern void lan_nbp_entry(const struct nbpnve *nve);
extern int  lan_assign(const struct sockaddr_at *sat, uint32_t *ip,
                       uint32_t *mask);
extern int  lan_accept_ip(uint32_t ip);
extern void lan_aep_reply(const struct sockaddr_at *sat, const char *data,
                          int len);


#endif /* MACIPGW_LAN_H */
