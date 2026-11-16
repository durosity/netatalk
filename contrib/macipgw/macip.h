/*
 *
 * (c) 1997 Stefan Bethke. All rights reserved.
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
 * @brief MacIP gateway lifecycle and packet I/O interface
 */

extern int  macip_open(char *zone, uint32_t net, uint32_t mask, uint32_t ns,
                       outputfunc_t o);
extern void macip_close(void);
extern void macip_idle(void);

extern void macip_output(char *buffer, int len);
extern void macip_input(void);

struct sockaddr_at;
struct nbpnve;

/*! callbacks used by LAN mode; any may be NULL */
struct macip_hooks {
    void (*client_seen)(uint32_t ip, const struct sockaddr_at *sat);
    void (*client_gone)(uint32_t ip);
    void (*nbp_entry)(const struct nbpnve *nve);
    void (*aep_reply)(const struct sockaddr_at *sat, const char *data,
                      int len);
    /* MacIP server address request: 1 = *ip/*mask set, 0 = not ready yet
       (no reply; the client retries), -1 = lease from the pool */
    int (*assign)(const struct sockaddr_at *sat, uint32_t *ip,
                  uint32_t *mask);
    /* track a client address outside the pool? */
    int (*accept_ip)(uint32_t ip);
};

extern void macip_set_hooks(const struct macip_hooks *h);
extern void macip_nbp_lookup(char *obj, char *type);
extern uint32_t macip_presence_lease(void);
extern void macip_presence_release(uint32_t ip);
extern void macip_release_lease(uint32_t ip);
extern int macip_send_ddp(const struct sockaddr_at *to, const char *buf,
                          int len);
extern int macip_local_addr(struct sockaddr_at *sat);
extern int macip_pool_contains(uint32_t ip);
extern void macip_assign_ready(const struct sockaddr_at *node);

