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
 * @brief LAN mode client identity and MAC address derivation
 */

#ifndef MACIPGW_LAN_IDENT_H
#define MACIPGW_LAN_IDENT_H

#include <stdint.h>
#include <stddef.h>

#define LAN_NAME_LEN 33           /* NBP object/type: 32 chars + NUL */

/*! collapse runs of whitespace and trim, in place */
extern void lan_tidy(char *s);

/*! parse "aa:bb:cc:dd:ee:ff"; 0 on success */
extern int lan_parse_mac(const char *s, uint8_t mac[6]);

/*!
 * build "name:model" from the NBP names a Mac registered: its Workstation
 * name (System 7 and later, may be empty) and the Responder-style entry
 * name:type. Returns -1 if there is no name to use.
 */
extern int lan_identity_key(const char *ws_name, const char *cand_obj,
                            const char *cand_type, char *key, size_t keylen);

/*! prefix (3 bytes) followed by the first 3 bytes of MD5(key) */
extern void lan_derive_mac(const char *key, const uint8_t prefix[3],
                           uint8_t mac[6]);

#endif /* MACIPGW_LAN_IDENT_H */
