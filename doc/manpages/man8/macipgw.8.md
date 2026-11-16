# Name

macipgw — MacIP Gateway Daemon

# Synopsis

**macipgw** [-d *debugclass*] [-f *configfile*] [-n *nameserver*] [-u *unprivileged-user*] [-z *zone*] [*network*] [*netmask*]

**macipgw** [-v | -V]

# Description

**macipgw** provides IP connectivity for devices connected through an
AppleTalk-only network, i.e. LocalTalk or Apple Remote Access (ARA).
**macipgw** is normally started out of */etc/rc*.

MacIP (formerly known as KIP) is a protocol that allows the
encapsulation of IP packets in AppleTalk packets. **macipgw** registers
itself as a MacIP gateway on the AppleTalk network and configures and
brings up a tunnel interface (see **tun**(4)). It then forwards IP packets
received from the AppleTalk network to the kernel through the tunnel
interface. Likewise, IP packets received through the tunnel are
forwarded to the AppleTalk device registered for the destination IP
address.

Unlike other MacIP gateways, **macipgw** needs its own IP (sub-)net to
operate, and does not use proxy-ARP for the addresses registered. The
gateway will always use the first address in the network for the local
address, i.e. 192.168.1.1 for the network 192.168.1.0/24.

If present, **macipgw** reads configuration options from the *macipgw.conf*
file located in the sysconf path. Command line options will take precedence
over configuration file options. See below for an example.

**macipgw** will log operational messages through **syslog**(3) under the
facility *LOG_DAEMON*.

# Options

**-d** *debugclass*

> Specifies that the daemon should not fork, and that a trace of all
actions be written to *stdout*. See the source code for useful values of
debugclass.

**-f** *configfile*

> Consult *configfile* instead of *macipgw.conf* for the configuration
information.

**-n** *nameserver*

> Specifies the IP address of a DNS name server the AppleTalk devices
connected through the gateway should use.

**-u** *unprivileged-user*

> Drop root privileges and change to user *unprivileged-user* after the
server has started.

**-z** *zone*

> Specifies that **macipgw** should register in *zone* instead of the default
zone.

**-v** | **-V**

> Show version information and exit.

*network*

> Specifies the network number to use for the clients.

*netmask*

> Specifies the netmask for the network.

# Client Configuration

Classic Mac TCP/IP clients discover **macipgw** through NBP as an
*IPGATEWAY* in the configured AppleTalk zone. When a client requests an
address, **macipgw** leases one from the configured network and returns
the subnet mask, broadcast address, and optional name server. The first
host address in the network is reserved for the gateway itself.

Configure routing or NAT on the host system separately if MacIP clients
should reach IP networks beyond the Netatalk host. **macipgw** only
creates and manages the tunnel interface used for the MacIP subnet.

# LAN Mode (Linux)

With *mode = lan* in *macipgw.conf*, **macipgw** puts MacIP clients
directly on the host's local network instead of behind a tunnel. It
creates a TAP interface, adds it to an existing Linux bridge that holds
the LAN interface and the host's own IPv4 address, and then presents
each client on the LAN as a separate host with its own Ethernet MAC
address. **macipgw** answers ARP for active clients, announces them
periodically, resolves next hops itself and frames packets with the
client's MAC, so no NAT, proxy ARP or kernel routing is needed and each
client appears in the router's client list. Packets from the LAN that
exceed the MacIP MTU are fragmented. The LAN, its netmask and the router
are taken from the bridge's address and the host's default route.

atalkd must run on the bridge rather than on the interface inside it,
and a seed router is needed for clients to be found reliably, for
example *br0 -router -phase 2 -net 9-10 -zone "Vintage"* in
*atalkd.conf*.

## Identity and MAC addresses

Each client's MAC address is derived from the names it registers over
NBP from its AppleTalk node: its Computer Name (*Workstation*) on System 7
and later, and the Responder entry that pairs a name with the Mac's model
(System 6's Responder uses the Chooser name). Together they give an
identity such as "G3 AIO:Power Macintosh" or "Macintosh II:Macintosh II".
Service types such as *AFPServer* are ignored when choosing the model.
The MAC is the configured prefix followed by the first three bytes of the
MD5 of the identity, so it stays the same as long as the Mac keeps its
name; renaming a Mac gives it a new MAC. Macs that register no name are
identified by their AppleTalk node number, which is usually but not
always stable. If a derived MAC is found in use by another device, the
next one is tried and a warning is logged.

New clients are identified as soon as their names arrive (normally well
under a second); packets sent meanwhile are held, not dropped. A Mac that
is renamed and restarted is noticed at the next scan (see *appletalk
presence*): it gets its new identity, MAC and hostname and keeps its
address, and the old MAC's DHCP lease is released.

## Addresses

With *dhcp = yes*, **macipgw** runs a DHCP client for each Mac, using
the Mac's MAC address and sending its name as the hostname (option 12;
"G3 AIO" becomes "G3-AIO"), so the DHCP server and router list each Mac
by name and fixed addresses can be reserved there as for any other
device. Requests carry the same parameter list as the Mac OS 9 DHCP
client, so DHCP fingerprinting recognises the clients as Macs. Leases
are renewed at half their lifetime and released when a Mac goes.

A Mac that asks the MacIP server for an address (Open Transport
"Using MacIP server", MacTCP "Server") is held while **macipgw**
identifies it and checks with the DHCP server: it keeps its address if
the server agrees and otherwise gets a fresh lease, so a reservation
made since its last lease takes effect at its next restart. Classic Mac
OS cannot change address while running; if the server refuses an
address at renewal, the Mac moves when it next asks. A Mac configured
with a fixed address keeps it, and **macipgw** asks the DHCP server to
confirm it, logging a warning if the server refuses.

The MacIP server tells clients to use *client netmask*, by default
255.255.255.255, so that they send everything, including traffic for
hosts on their own LAN, through the gateway rather than looking those
hosts up over NBP. Open Transport (Mac OS 8/9) and MacTCP accept it.

The pool (*network* and *netmask*) is used when *dhcp* is off, and as a
fallback when no DHCP server answers. It must be a range of the LAN that
no other host or DHCP server uses.

## Presence and liveness

Every *check interval* each client is sent an AppleTalk Echo; a client
that misses three checks in a row is treated as gone: it is no longer
announced or answered for, and its lease or pool address is freed.
Routers may take much longer than that to show it offline.

With *appletalk presence = yes*, Macs that run AppleTalk but not MacIP
(no MacTCP or TCP/IP installed) get a presence on the LAN too. Every
*check interval* **macipgw** looks up the names on the AppleTalk network
and treats any node with a *Workstation* or a Responder model entry as a
Mac; printers and the gateway itself are skipped. Each one gets the
identity, MAC, hostname and address it would have as a MacIP client.
ARP for that address is answered, and an ICMP echo request to it is
answered only when the Mac replies to an AppleTalk Echo, so pinging the
address shows whether the Mac is switched on. The Mac itself cannot use
IP. A Mac that later starts using MacIP keeps its identity, MAC and
lease. The scan is also what notices renamed Macs.

## Options

LAN mode options, in the *[Global]* section:

**mode** = *tun* | *lan*

> *tun* (default) uses a tunnel interface as described above.

**bridge** = *name*

> The bridge holding the LAN interface (default *br0*).

**dhcp** = *yes* | *no*

> Lease client addresses from the LAN's DHCP server (default *no*).

**client netmask** = *address*

> Netmask given to MacIP server clients (default 255.255.255.255).

**mac prefix** = *xx:xx:xx*

> First three bytes of derived MAC addresses (default *08:00:07*).

**router** = *address*

> Next hop for traffic leaving the LAN (default: the host's default route).

**announce interval** = *seconds*

> How often each client is announced with a gratuitous ARP (default 60).

**identify timeout** = *seconds*

> Longest wait for a new client's NBP names (default 3).

**check interval** = *seconds*

> How often clients are checked and the network scanned (default 30).

**appletalk presence** = *yes* | *no*

> Give AppleTalk-only Macs a presence on the LAN (default *no*).

The optional *[clients]* section fixes a client's MAC, and optionally its
hostname, keyed by identity, IP address or "node *net*.*node*":

    [clients]
    G3 AIO:Power Macintosh = 08:00:07:b8:23:66
    10.0.9.60 = 08:00:07:12:34:56, Mac-Plus
    node 9.85 = 08:00:07:ab:cd:ef

Keys are not case-sensitive. Use a client's real Ethernet MAC to make it
the same device on the LAN whether it is connected by Ethernet or by
LocalTalk (but not both at once).

# Examples

## Example: macipgw invocation

    macipgw -n 192.168.1.1 -z "Remote Users" 192.168.1.0 255.255.255.0

Starts **macipgw**, assigning the Class C network 192.168.1.0 for devices
connected through the gateway, specifying that the system **macipgw** is
running on can be used as a name server, and that it should register in
the zone Remote Users.

## Example: macipgw.conf configuration file

    [Global]
    network = 192.168.151.0
    netmask = 255.255.255.0
    nameserver = 8.8.8.8
    zone = My Zone
    unprivileged user = foobar

## Example: LAN mode

    [Global]
    mode = lan
    bridge = br0
    dhcp = yes
    appletalk presence = yes
    network = 10.0.9.240
    netmask = 255.255.255.240
    nameserver = 10.0.9.1
    zone = Vintage

    [clients]
    Macintosh II:Macintosh II = 08:00:07:95:8d:dc, Mac-II

Clients lease addresses from the LAN's DHCP server; 10.0.9.240/28 is the
fallback pool.

# See Also

tun(4), ip(4), atalkd(8), atalkd.conf(5), syslog(3), syslogd(8)

# Bugs

No information besides the log messages is available on which AppleTalk
devices are using the gateway.

LAN mode is available on Linux only.

# Author

Stefan Bethke <Stefan.Bethke@Hanse.DE>
