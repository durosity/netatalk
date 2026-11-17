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
 *
 * Kept free of system and AppleTalk dependencies so it can be unit tested.
 */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "lan_ident.h"

/* ------------------------------------------------------------------ */
/* MD5 (RFC 1321), used only to derive stable MAC addresses            */
/* ------------------------------------------------------------------ */

static void md5(const uint8_t *msg, size_t len, uint8_t out[16])
{
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const uint8_t R[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    uint32_t h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    size_t total = ((len + 8) / 64 + 1) * 64;
    uint8_t *buf = calloc(1, total);

    if (!buf) {
        memset(out, 0, 16);
        return;
    }

    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t) len * 8;

    for (int i = 0; i < 8; i++) {
        buf[total - 8 + i] = (uint8_t)(bits >> (8 * i));
    }

    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[16], a = h[0], b = h[1], c = h[2], d = h[3];

        for (int i = 0; i < 16; i++) {
            const uint8_t *q = buf + off + i * 4;
            w[i] = (uint32_t)q[0] | (uint32_t)q[1] << 8 |
                   (uint32_t)q[2] << 16 | (uint32_t)q[3] << 24;
        }

        for (int i = 0; i < 64; i++) {
            uint32_t f;
            int g;

            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }

            uint32_t t = d;
            d = c;
            c = b;
            uint32_t x = a + f + K[i] + w[g];
            b = b + ((x << R[i]) | (x >> (32 - R[i])));
            a = t;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
    }

    for (int i = 0; i < 4; i++) {
        out[i * 4] = (uint8_t) h[i];
        out[i * 4 + 1] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(h[i] >> 24);
    }

    free(buf);
}

/* collapse runs of whitespace and trim, in place */
void lan_tidy(char *s)
{
    char *d = s;
    int sp = 1;

    for (char *p = s; *p; p++) {
        if (isspace((unsigned char) *p)) {
            if (!sp) {
                *d++ = ' ';
            }

            sp = 1;
        } else {
            *d++ = *p;
            sp = 0;
        }
    }

    if (d > s && d[-1] == ' ') {
        d--;
    }

    *d = 0;
}

int lan_parse_mac(const char *s, uint8_t mac[6])
{
    unsigned int b[6];

    if (sscanf(s, " %2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3],
               &b[4], &b[5]) != 6) {
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t) b[i];
    }

    return 0;
}


/*
 * Two NBP object names for the same Mac. When the Responder finds its name
 * already registered (for example a stale entry after a quick restart),
 * classic Mac OS registers it again with "-1", "-2", ... appended; ignore
 * such a suffix on either name.
 */
static int same_mac_name(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);

    if (strcasecmp(a, b) == 0) {
        return 1;
    }

    /* strip "-<digits>" from the longer one and compare again */
    const char *l = la > lb ? a : b, *sh = la > lb ? b : a;
    size_t ll = la > lb ? la : lb, ls = la > lb ? lb : la;

    if (ll < ls + 2 || l[ls] != '-' || strncasecmp(l, sh, ls) != 0) {
        return 0;
    }

    for (size_t i = ls + 1; i < ll; i++) {
        if (!isdigit((unsigned char) l[i])) {
            return 0;
        }
    }

    return 1;
}

int lan_identity_key(const char *ws_name, const char *cand_obj,
                     const char *cand_type, char *key, size_t keylen)
{
    char name[LAN_NAME_LEN], model[LAN_NAME_LEN];

    snprintf(name, sizeof(name), "%s", ws_name[0] ? ws_name : cand_obj);
    model[0] = 0;

    /* the model only belongs to this Mac if it was registered under the
       same name as its Workstation entry (or there is no Workstation) */
    if (cand_type[0] && (!ws_name[0] || same_mac_name(cand_obj, ws_name))) {
        snprintf(model, sizeof(model), "%s", cand_type);
    }

    lan_tidy(name);
    lan_tidy(model);

    if (!name[0]) {
        return -1;
    }

    snprintf(key, keylen, "%s:%s", name, model);
    return 0;
}

void lan_derive_mac(const char *key, const uint8_t prefix[3], uint8_t mac[6])
{
    uint8_t h[16];

    md5((const uint8_t *) key, strlen(key), h);
    memcpy(mac, prefix, 3);
    memcpy(mac + 3, h, 3);
}

/* NBP types that are services, not a Mac's model */
static const char *const service_types[] = {
    "Workstation", "AFPServer", "LaserWriter", "ImageWriter", "TimeLord",
    "netatalk", "Multi-User Client", "ProDOS16 Image", "Apple //e Boot",
    "Apple //gs", "SNMP Agent", "IPADDRESS", "IPGATEWAY", NULL
};

/* prefixes the Responder uses for model names */
static const char *const model_prefixes[] = {
    "Macintosh", "Power Macintosh", "Power Mac", "PowerBook", "Mac ",
    "iMac", "eMac", "iBook", "Performa", "Quadra", "Centris", "Workgroup Server",
    NULL
};

int lan_model_score(const char *type)
{
    char t[LAN_NAME_LEN];

    snprintf(t, sizeof(t), "%s", type);
    lan_tidy(t);

    if (!t[0]) {
        return 0;
    }

    for (int i = 0; service_types[i]; i++)
        if (strcasecmp(t, service_types[i]) == 0 ||
                strncasecmp(t, "ARA", 3) == 0) {
            return 0;
        }

    for (int i = 0; model_prefixes[i]; i++)
        if (strncasecmp(t, model_prefixes[i], strlen(model_prefixes[i])) == 0) {
            return 2;
        }

    return 1;
}

void lan_make_hostname(const char *key, char *out, size_t len)
{
    size_t o = 0;
    int dash = 1;

    /* the name part of "name:model": letters and digits, anything else
       (spaces, punctuation, Mac Roman characters) becomes a single '-' */
    for (const char *p = key; *p && *p != ':' && o + 1 < len; p++) {
        if (isalnum((unsigned char) *p) && !((unsigned char) *p & 0x80)) {
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
