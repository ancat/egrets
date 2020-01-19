# egrets
Egrets is a proof of concept tool that uses eBPF, raw sockets, and kprobes to monitor egress traffic. Raw sockets are used to sniff for DNS queries and responses which are used to build a mapping of IP addresses to hostnames. Kprobes are used to watch syscalls that make network connections. Traditionally, these syscalls would at the most only have IP address information, but because we also have a mapping of hostnames to IP addresses, we can get a better understanding of what hosts processes are connecting to. This is much more reliable than say, whitelisting massive lists of IP addresses or relying on PTR records (which no one uses anyway.)

Egrets is compatible with Docker and will tag TCP connections with container metadata.

There is currently support for printing out events only. A future version will include support for killing processes and taking coredumps (see [Meatball](https://github.com/ancat/meatball)) I'm still learning go and ebpf, so there's still a lot of basic improvements that could be made. There are also some concurrency/synchronization issues so if you leave this program running long enough, it'll eventually crash.  Use this at your own risk! :~)

## Getting Started

There are a few prerequisites. First, you need to be running a "relatively" recent kernel; this was tested on 4.15+ kernels. You will also need to ensure that `debugfs` is mounted; `debug -t debugfs none /sys/kernel/debug` if it's not. And finally, you (maybe unsurprisingly) will need root.

```
# grab a copy of this repo
$ git clone https://github.com/ancat/egrets.git
$ cd egrets

# build
$ make

# run
sudo ./egrets
```

## Examples

In the examples below each type of event has its own tag. `dns.query` and `dns.answer` are DNS queries and responses respectively; `process.tcp_v4` are the network connections that tie together syscall + DNS information.

Running `curl facebook.com`:
```
INFO[0001] process.tcp_v4 comm=curl pid=2074 connection=67.207.67.3:53 dns.entry= container.image=none container.hostname=none container.ip=none
INFO[0001] dns.query hostname=facebook.com type=A
INFO[0001] dns.answer hostname=facebook.com response=31.13.71.36
INFO[0001] dns.query hostname=facebook.com type=AAAA
INFO[0001] dns.answer hostname=facebook.com response=2a03:2880:f112:83:face:b00c:0:25de
INFO[0001] process.tcp_v4 comm=curl pid=2074 connection=31.13.71.36:80 dns.entry=facebook.com container.image=none container.hostname=none container.ip=none
INFO[0001] process.tcp_v4 comm=curl pid=2073 connection=31.13.71.36:80 dns.entry=facebook.com container.image=none container.hostname=none container.ip=none
```

Running `apt update` from within a container:
```
INFO[0001] process.tcp_v4 comm=http pid=2735 connection=67.207.67.3:53 dns.entry= container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] dns.query hostname=security.debian.org type=A
INFO[0001] dns.answer hostname=security.debian.org response=149.20.4.14
INFO[0001] dns.answer hostname=security.debian.org response=128.61.240.73
INFO[0001] dns.answer hostname=security.debian.org response=128.31.0.63
INFO[0001] dns.answer hostname=security.debian.org response=128.101.240.215
INFO[0001] process.tcp_v4 comm=http pid=2735 connection=149.20.4.14:80 dns.entry=security.debian.org container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] process.tcp_v4 comm=http pid=2735 connection=128.61.240.73:80 dns.entry=security.debian.org container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] process.tcp_v4 comm=http pid=2735 connection=128.31.0.63:80 dns.entry=security.debian.org container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] process.tcp_v4 comm=http pid=2735 connection=128.101.240.215:80 dns.entry=security.debian.org container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] process.tcp_v4 comm=http pid=2735 connection=149.20.4.14:80 dns.entry=security.debian.org container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] dns.query hostname=deb.debian.org type=A
INFO[0001] process.tcp_v4 comm=http pid=2736 connection=67.207.67.3:53 dns.entry= container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
INFO[0001] dns.answer hostname=deb.debian.org response=debian.map.fastly.net
INFO[0001] dns.answer hostname=deb.debian.org response=199.232.38.133
INFO[0001] process.tcp_v4 comm=http pid=2736 connection=199.232.38.133:80 dns.entry=deb.debian.org container.image=gremlinweb container.hostname=0b1c6a890623 container.ip=172.17.0.2
```
