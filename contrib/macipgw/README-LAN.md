# macipgw LAN mode

This branch adds a **LAN mode** to macipgw (Linux only). Instead of putting
MacIP clients behind a tunnel and NAT, it puts each one directly on your
network as a separate device, with its own MAC address, DHCP lease and
hostname, so it shows up in your router's client list like any other
machine. Optionally, Macs that only run AppleTalk get a presence too.

It was written for one particular home network (a Raspberry Pi gateway, a
Dayna LocalTalk bridge and a UniFi router) and has not been offered
upstream. It works there; use it elsewhere at your own risk. The full
reference is in `man macipgw` (doc/manpages/man8/macipgw.8.md).

## What a Mac looks like on the network

| | |
|---|---|
| Identity | Name and model from NBP: `G3 AIO:Power Macintosh` |
| MAC | `08:00:07` + first 3 bytes of MD5 of the identity: `08:00:07:b8:23:66` |
| Hostname | Name part, cleaned up: `G3-AIO` |
| Address | Leased from your DHCP server; reservations work |
| Online | While it answers AppleTalk Echo (checked every 30 s) |

The MAC follows the name, so it is stable until you rename the Mac. To
predict it: `printf %s 'G3 AIO:Power Macintosh' | md5sum` and take the
first six hex digits.

## Requirements

- Linux, with the LAN interface in a bridge that carries the host's own
  IPv4 address (macipgw adds its TAP device to that bridge).
- atalkd on the **bridge**, as seed router for the AppleTalk network.
- A DHCP server on the LAN (or a spare range for the fallback pool).

## Setup

### 1. Bridge (NetworkManager)

Give the bridge the LAN interface's MAC so the host keeps its address:

```sh
MAC=$(cat /sys/class/net/eth0/address)
nmcli con add type bridge ifname br0 con-name br0 \
    bridge.stp no bridge.forward-delay 0 bridge.mac-address "$MAC" \
    ipv4.method auto ipv6.method auto
nmcli con add type ethernet ifname eth0 con-name br0-port \
    master br0 slave-type bridge
nmcli con modify "Wired connection 1" connection.autoconnect no
nmcli con up br0-port && nmcli con up br0
```

Do this from the console, or with an automatic revert scheduled, in case
the host drops off the network.

### 2. atalkd.conf

atalkd must use the bridge, and seed the network so every node gets a
proper network number and zone. On a single interface use `-router`
(`-seed` is rejected):

```
br0 -router -phase 2 -net 9-10 -zone "Vintage"
```

LocalTalk bridges (a Dayna EtherPrint, for example) and the Macs behind
them may need restarting after the router first appears or restarts.

### 3. macipgw.conf

```ini
[Global]
mode = lan
bridge = br0
dhcp = yes
appletalk presence = yes
zone = Vintage
nameserver = 10.0.9.1
; fallback pool, used only if the DHCP server does not answer
network = 10.0.9.240
netmask = 255.255.255.240

[clients]
; optional: fix a MAC (and hostname) by identity, IP or "node net.node"
; Macintosh II:Macintosh II = 08:00:07:95:8d:dc, Mac-II
```

### 4. The Macs

- **Open Transport (Mac OS 7.5–9):** TCP/IP control panel, Connect via
  AppleTalk (MacIP), Configure **Using MacIP server**, zone as above.
- **MacTCP (System 6 and 7):** choose the AppleTalk icon and the zone;
  under More…, Obtain Address **Server**.
- **No TCP/IP at all:** nothing to do; with `appletalk presence = yes` the
  Mac still gets a MAC, hostname and address, and pings to that address
  are answered only while the Mac answers AppleTalk Echo.

Give every Mac a unique name (Sharing Setup on System 7+, the Chooser
name on System 6): the name is the identity.

## Checking it

```sh
journalctl -t macipgw -f
```

shows lines such as:

```
client 10.0.9.127 (9.80) is 'G3 AIO:Power Macintosh', MAC 08:00:07:b8:23:66
client 'G3 AIO:Power Macintosh' leased 10.0.9.127 from DHCP as 'G3-AIO'
client 'Macintosh II:Macintosh II' moves from 10.0.9.92 to 10.0.9.61
client 10.0.9.242 ('Mac LC 520:Macintosh LC 520') stopped answering, gone
```

`nbplkup` lists what each Mac registers on AppleTalk.

## Things to know

- **Netmask.** MacIP server clients are given 255.255.255.255 (`client
  netmask`), so they send everything, including traffic for their own LAN,
  through the gateway. Open Transport and MacTCP accept it. A Mac with a
  hand-typed Open Transport MacIP address cannot set a mask and assumes
  the class default; prefer "Using MacIP server".
- **Address changes** take effect when a Mac restarts its TCP/IP; classic
  Mac OS cannot change address while running.
- **Going offline** is detected within about 90 seconds, but routers may
  take much longer to show a device as offline (UniFi took 25–30 minutes).
  Pinging the Mac's address is the quickest live check.
- **Renaming** a Mac gives it a new MAC (and so a new device in the
  router), unless you pin the MAC in `[clients]`.
- **Pre-System 6 Macs** usually register no name and are identified by
  AppleTalk node number, which can change.

## Code

| File | Contents |
|---|---|
| `lan_linux.c` | TAP/bridge, ARP, framing, DHCP client, presence, liveness |
| `lan_ident.c` | Identity keys, model scoring, MAC and hostname derivation |
| `macip.c` | Hooks into the original gateway (assignment, NBP, AEP) |
| `test/macipgw/test_lanident.c` | Unit tests for `lan_ident.c` |

Tunnel mode (the default) is unchanged.
