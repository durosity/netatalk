/*
 *
 * (c) 1997 Stefan Bethke. All rights reserved.
 * (c) 2025 Daniel Markstedt. All rights reserved.
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
 * @brief MacIP gateway configuration and packet output callback types
 */

typedef void (*outputfunc_t)(char *buffer, int len);

typedef struct {
    char *network;
    char *netmask;
    char *nameserver;
    char *zone;
    char *unprivileged_user;
    char *mode;                 /* "tun" (default) or "lan" */
    char *bridge;               /* LAN mode: bridge holding the LAN port */
    char *mac_prefix;           /* LAN mode: OUI for generated MACs */
    char *router;               /* LAN mode: next hop, default route if empty */
    int announce_interval;      /* LAN mode: seconds between announcements */
    int identify_timeout;       /* LAN mode: seconds to wait for NBP names */
    int presence;               /* LAN mode: AppleTalk-only Macs get a MAC/IP */
    int check_interval;         /* LAN mode: seconds between echo checks */
    int dhcp;                   /* LAN mode: lease addresses via DHCP */
    char *client_netmask;       /* LAN mode: mask for MacIP server clients */
} macip_options;

macip_options *read_options(const char *);
