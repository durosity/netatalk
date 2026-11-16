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
exceed the MacIP MTU are fragmented.

The client address pool (*network* and *netmask*) must be a range of the
LAN that no other host or DHCP server uses. The LAN itself, its netmask
and the router are taken from the bridge's address and the host's
default route.

Each client's MAC address is derived from the name and model it
registers over NBP: its Computer Name (*Workstation*) on System 7 and
later, or the Responder entry on System 6, giving an identity such as
"G3 AIO:Power Macintosh" or "Mike:Macintosh II". The MAC is the
configured prefix followed by the first three bytes of the MD5 of that
identity, so it stays the same as long as the Mac keeps its name. Macs
that register no name are identified by their AppleTalk node number. If
a derived MAC is found in use by another device, the next one is tried
and a warning is logged.

Any client's MAC can be fixed in a *[clients]* section, keyed by
identity, IP address or "node *net*.*node*".

LAN mode options, in the *[Global]* section:

**mode** = *tun* | *lan*

> *tun* (default) uses a tunnel interface as described above.

**bridge** = *name*

> The bridge holding the LAN interface (default *br0*).

**mac prefix** = *xx:xx:xx*

> First three bytes of derived MAC addresses (default *08:00:07*).

**router** = *address*

> Next hop for traffic leaving the LAN (default: the host's default route).

**announce interval** = *seconds*

> How often each client is announced with a gratuitous ARP (default 60).

**identify timeout** = *seconds*

> How long to wait for a new client's NBP names (default 3).

**check interval** = *seconds*

> How often each client is checked with an AppleTalk Echo (default 30).
A client that misses three checks in a row is treated as gone: its
address is freed and it is no longer announced on the LAN.

**appletalk presence** = *yes* | *no*

> Also give Macs that run AppleTalk but not MacIP a presence on the LAN
(default *no*). Every *check interval* **macipgw** looks up the names on
the AppleTalk network and treats any node with a *Workstation* or a
Responder model entry as a Mac. Each one gets the identity and MAC it
would have as a MacIP client and an address from the pool. ARP for that
address is answered, and an ICMP echo request to it is answered only
when the Mac replies to an AppleTalk Echo, so pinging the address shows
whether the Mac is switched on. The Mac itself cannot use IP.

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
    network = 10.0.9.240
    netmask = 255.255.255.240
    nameserver = 10.0.9.1
    zone = Vintage
    appletalk presence = yes

    [clients]
    G3 AIO:Power Macintosh = 08:00:07:b8:23:66
    10.0.9.250 = 02:00:00:00:00:01

# See Also

tun(4), ip(4), atalkd(8), syslog(3), syslogd(8)

# Bugs

No information besides the log messages is available on which AppleTalk
devices are using the gateway.

LAN mode is available on Linux only.

# Author

Stefan Bethke <Stefan.Bethke@Hanse.DE>
