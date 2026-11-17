/*
 * Tests for macipgw LAN mode identity keys and MAC address derivation
 *
 * Copyright (c) 2026 Durosity
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
 */

#include <stdio.h>
#include <string.h>

#include "../../contrib/macipgw/lan_ident.h"

static int failures;

static void check_str(const char *what, const char *actual,
                      const char *expected)
{
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "FAIL %s: expected '%s', got '%s'\n", what, expected,
                actual);
        failures++;
    }
}

static void check_key(const char *ws, const char *obj, const char *type,
                      const char *expected)
{
    char key[80] = "";
    int r = lan_identity_key(ws, obj, type, key, sizeof(key));

    if (expected == NULL) {
        if (r != -1) {
            fprintf(stderr, "FAIL key(%s|%s|%s): expected no key, got '%s'\n",
                    ws, obj, type, key);
            failures++;
        }

        return;
    }

    check_str("identity key", key, expected);
}

static void check_mac(const char *key, const char *expected)
{
    static const uint8_t apple[3] = { 0x08, 0x00, 0x07 };
    uint8_t m[6];
    char s[18];

    lan_derive_mac(key, apple, m);
    snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2],
             m[3], m[4], m[5]);
    check_str(key, s, expected);
}

int main(void)
{
    uint8_t m[6];
    char t[64];

    /* Mac OS 8/9: Workstation name plus Responder entry with padded type */
    check_key("G3 AIO", "G3 AIO", "  Power Macintosh", "G3 AIO:Power Macintosh");
    /* System 6: Responder entry only (Chooser name : model) */
    check_key("", "Mike", "Macintosh II", "Mike:Macintosh II");
    /* Responder re-registered with a conflict suffix (seen on an LC 520) */
    check_key("Mac LC 520", "Mac LC 520-1", "Macintosh LC 520",
              "Mac LC 520:Macintosh LC 520");
    check_key("Mac LC 520", "Mac LC 520-12", "Macintosh LC 520",
              "Mac LC 520:Macintosh LC 520");
    /* but not a different name that happens to share the start */
    check_key("Mac LC", "Mac LC 520", "Macintosh LC 520", "Mac LC:");
    check_key("Mac LC 520", "Mac LC 520-x", "Macintosh LC 520", "Mac LC 520:");
    /* Responder name differs from Workstation name: no model */
    check_key("Studio", "Other", "Macintosh SE", "Studio:");
    /* nothing registered */
    check_key("", "", "", NULL);
    check_key("   ", "", "", NULL);

    /* matches the MAC already registered in UniFi during the 15 Nov test,
       and `printf %s 'G3 AIO:Power Macintosh' | md5sum` */
    check_mac("G3 AIO:Power Macintosh", "08:00:07:b8:23:66");
    /* MD5 test vectors from RFC 1321: "" = d41d8c..., "abc" = 900150... */
    check_mac("", "08:00:07:d4:1d:8c");
    check_mac("abc", "08:00:07:90:01:50");
    /* longer than one MD5 block */
    check_mac("12345678901234567890123456789012345678901234567890123456789012"
              "345678901234567890", "08:00:07:57:ed:f4");

    /* model scoring, using the G3 AIO's real registrations */
    static const struct {
        const char *type;
        int score;
    } scores[] = {
        {"  Power Macintosh", 2}, {"Macintosh II", 2}, {"PowerBook 170", 2},
        {"Workstation", 0}, {"AFPServer", 0}, {"ARA - Personal Server", 0},
        {"Multi-User Client", 0}, {"LaserWriter", 0}, {"", 0},
        {"Something Else", 1},
    };

    for (size_t i = 0; i < sizeof(scores) / sizeof(scores[0]); i++) {
        if (lan_model_score(scores[i].type) != scores[i].score) {
            fprintf(stderr, "FAIL model score '%s': expected %d, got %d\n",
                    scores[i].type, scores[i].score,
                    lan_model_score(scores[i].type));
            failures++;
        }
    }

    /* hostnames */
    static const struct {
        const char *key, *host;
    } hosts[] = {
        {"G3 AIO:Power Macintosh", "G3-AIO"},
        {"Macintosh II:Macintosh II", "Macintosh-II"},
        {"Mac LC 520:Macintosh LC 520", "Mac-LC-520"},
        {"node 9.85", "node-9-85"},
        {"Mike\xd5s Mac:Macintosh SE", "Mike-s-Mac"},   /* Mac Roman \xd5 = ' */
        {"  --Studio--  :Quadra", "Studio"},
        {"***:Macintosh", ""},
    };

    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        char h[33];
        lan_make_hostname(hosts[i].key, h, sizeof(h));
        check_str("hostname", h, hosts[i].host);
    }

    {
        char h[8];                  /* truncated to the buffer */
        lan_make_hostname("Macintosh Quadra 950:x", h, sizeof(h));
        check_str("hostname truncated", h, "Macinto");
    }

    snprintf(t, sizeof(t), "  a  b\tc  ");
    lan_tidy(t);
    check_str("tidy", t, "a b c");

    if (lan_parse_mac("08:00:07:b8:23:66", m) != 0 || m[0] != 0x08 ||
            m[5] != 0x66) {
        fprintf(stderr, "FAIL parse valid MAC\n");
        failures++;
    }

    if (lan_parse_mac("08:00:07", m) == 0) {
        fprintf(stderr, "FAIL parse short MAC\n");
        failures++;
    }

    if (failures == 0) {
        printf("all LAN identity tests passed\n");
    }

    return failures ? 1 : 0;
}
