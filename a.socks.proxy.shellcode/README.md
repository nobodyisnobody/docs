## A socks proxy shellcode

### Prerequisites

you should read the first article first, to understand the shellcode generator usage.

[modern templates for shellcoding](https://github.com/nobodyisnobody/docs/tree/main/modern.templates.for.shellcoding)

### Introduction

I coded this shellcode some times ago, when I was doing a pwn challenge, involving the exploitation of a box , and pivoting on this box, to reach a second box in the internal network.

To go faster, I had the idea at this time of coding a small shellcode that spawn a socks proxy on the pivot machine, that will permits to pivot on this machine to reach the internal network.

To reduce the size of the shellcode, I have implemented only the socks4 protocol, where the dns resolving is done by the client

<https://en.wikipedia.org/wiki/SOCKS#SOCKS4>

The socks proxy shellcode is compatible with proxychains,
you can even use it to scan the internal network via connect scan.

if you want to use proxychains, edit `/etc/proxychains.conf`
like this, to indicates to use the socks4 protocol:

and leave proxy_dns commented.

```sh
# Proxy DNS requests - no leak for DNS data
#proxy_dns 

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  IP PORT
```

I used once again my advanced shellcoding template, to develop and debug this shellcode.

the syntax for the shellcode generator is:

```sh
python3 socks.x64.py <IP> <PORT> [RUN|EXE|GDB]
```

+ IP is local ip address to bind to
+ PORT is local port that the socks proxy will listen

and generator options:
+ RUN: to run the shellcode
+ GDB: to debug it
+ EXE: to generate an executable of the shellcode.


the shellcode once executed will fork a process that waits, for incoming connection on the selected port,

when a socks4 client is connected, it will forward its connection to the requested ip and port as a normal socks proxy will do..

+ [x64 version](./socks.x64.py) , the x64 version is actually 280 bytes long
+ [armv5 version](./socks.armv5.py) , the armv5 version is actually 244 bytes long
+ [armv7 version](./socks.armv7.py) , the armv5 version is actually 238 bytes long
+ [mips big endian version](./socks.mipseb.py) , the armv5 version is actually 452 bytes long


I will update them when I will optimize them more, or add new versions..

They were think for exploiting iot, to pivot on internal network.
