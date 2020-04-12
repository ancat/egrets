package egrets

import (
        "bytes"
        "encoding/binary"
        "flag"
        "fmt"
        "net"
        "os"
        "syscall"

        "github.com/google/gopacket"
        "github.com/google/gopacket/afpacket"
        "github.com/google/gopacket/layers"
        "github.com/iovisor/gobpf/elf"
        log "github.com/sirupsen/logrus"
)

type TextFormatter struct {
    PadLevelText bool
    ForceColors bool
    LoggerName string
    log.TextFormatter
}

type tcp_v4 struct {
    Pid    uint64
    Ts     uint64
    Comm   [16]byte
    Fd     uint64
    Uid    uint64
    Port   uint32
    Addr   uint32
    Family uint64
}

type exec_event struct {
    Pid    uint64
    Type   uint64
}

type EventConnectV4 struct {
    Comm              [16]byte
    Pid               uint
    Hostname          string
    Addr              uint32
    Port              uint32
    ContainerMetadata *ContainerInfo
}

func Long2ip(ipLong uint32) string {
    ipByte := make([]byte, 4)
    binary.BigEndian.PutUint32(ipByte, ipLong)
    ip := net.IP(ipByte)
    return ip.String()
}

var ip_to_hostname map[string]string
// consider caching namespace -> container info
var pid_to_namespace map[int]*ContainerInfo

var dump_config = flag.Bool("d", false, "dump the parsed config and exit")
var config_file = flag.String("f", "config.yaml", "config file (default `config.yaml`")
var config *EgretsConfig
var ipv4map = IpNode{}
var event_channel chan string
var stats = EgretsStats{}

func Main(ebpf_binary string) {
    flag.Parse()
    config = LoadEgretsConfig(*config_file)
	if *dump_config {
        DumpConfig(config)
        return
    }

    event_channel = make(chan string)
    go func() {
        for {
            event_string := <-event_channel
            fmt.Printf("%s", event_string)
        }
    }()

    ip_to_hostname = make(map[string]string)
    pid_to_namespace = make(map[int]*ContainerInfo)

    mod, err := LoadModuleElf(ebpf_binary)
    if err != nil {
        log.Fatalf("Failed to load ebpf binary: %s", err)
    }

    fd, socketFilter, err := GetSocketFilter(mod, "socket/filter_udp")
    if err != nil {
        log.Fatalf("Failed loading UDP socket filter: %s", err)
    }

    defer elf.DetachSocketFilter(socketFilter, fd)
    defer syscall.Close(fd)

    err = syscall.SetNonblock(fd, false)
    if err != nil {
        log.Fatalf("failed to set AF_PACKET to blocking: %s", err)
    }

    dns_stream := os.NewFile(uintptr(fd), "hehe")
    if dns_stream == nil {
        log.Fatalf("couldn't turn fd into a file")
    }

    // we only need these if we want container metadata asynchronously
    if config.Container_Metadata && config.Async_Container_Metadata {
        if err := mod.EnableTracepoint("tracepoint/sched/sched_process_fork"); err != nil {
            log.Fatalf("Failed to enable tracepoint: %s\nMake sure you are running as root and that debugfs is mounted!", err)
        }

        if err := mod.EnableKprobe("kprobe/sys_execve", 1); err != nil {
            log.Fatalf("Failed to set up kprobes: %s\nMake sure you are running as root and that debugfs is mounted!", err)
        }

        // this is used by both the sched_process_fork tp and the execve kp
        exec_channel := make(chan []byte)
        exec_lost_chan := make(chan uint64)
        err = GetMap(mod, "exec_events", exec_channel, exec_lost_chan)
        if err != nil {
            log.Fatalf("Failed to load exec events map: %s", err)
        }

        go process_execs(exec_channel, exec_lost_chan)
    }

    if err := mod.EnableKprobe("kprobe/sys_connect", 1); err != nil {
        log.Fatalf("Failed to set up kprobes: %s\nMake sure you are running as root and that debugfs is mounted!", err)
    }

    channel := make(chan []byte)
    lost_chan := make(chan uint64)
    err = GetMap(mod, "events", channel, lost_chan)
    if err != nil {
        log.Fatalf("Failed to load events map: %s", err)
    }


    go process_tcp(channel, lost_chan)

    if config.Use_Classic_BPF {
        afpacketHandle, err := GetPacketHandle("udp and port 53")
        if err != nil {
            panic(err)
        }

        defer afpacketHandle.Close()
        process_alt_dns(afpacketHandle)
    } else {
        process_dns(dns_stream)
    }
}

func process_dns(dns_stream *os.File) {
    log.Printf("starting dns boye")
    // we should be using channels for this
    // https://www.openwall.com/lists/musl/2018/10/11/2
    for {
        byte_chunk := make([]byte, 2048)
        length, _ := dns_stream.Read(byte_chunk)
        if length == 0 {
            continue
        }

        go process_packet(byte_chunk, length)
    }
}

func process_alt_dns(afpacketHandle *afpacket.TPacket) {
    log.Printf("starting alt dns boye")

    for {
        data, _, err := afpacketHandle.ZeroCopyReadPacketData()
        if err != nil {
            panic(err)
        }

        go process_packet(data, len(data))
        continue

        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
        dns_packet := packet.Layer(layers.LayerTypeDNS)
        if dns_packet == nil {
            continue
        }

        dns := dns_packet.(*layers.DNS)
        log_dns_event(dns)
    }
}

func process_execs(receiver chan []byte, lost chan uint64) {
        log.Printf("execves processing starting")

        for {
            select {
            case data, ok := <-receiver:
                if !ok {
                    return
                }

                buffer := bytes.NewBuffer(data)
                var event exec_event
                err := binary.Read(buffer, binary.LittleEndian, &event)
                if err != nil {
                    panic(err)
                }

                go func() {
                    pid := int(event.Pid & 0xFFFFFFFF)
                    var container_info *ContainerInfo
                    container_info = GetContainerInfo(pid)
                    // FIXME data race
                    pid_to_namespace[pid] = container_info
                }()
            case _, ok := <-lost:
                if !ok {
                    return
                }
            }
        }
}

func process_tcp(receiver chan []byte, lost chan uint64) {
        log.Printf("tcp processing starting")

        for {
            select {
            case data, ok := <-receiver:
                if !ok {
                    return
                }

                buffer := bytes.NewBuffer(data)
                var event tcp_v4
                err := binary.Read(buffer, binary.LittleEndian, &event)
                if err != nil {
                    panic(err)
                }

                stats.PacketsSeen++
                go parse_tcp_event(event)
            case _, ok := <-lost:
                if !ok {
                    return
                }
            }
        }
}

func parse_tcp_event(event tcp_v4) {
    // exclude stuff bound to 0.0.0.0
    // FIXME: remember that these include udp too
    if event.Addr == 0 {
        return
    }

    pid := int(event.Pid & 0xFFFFFFFF)
    var container_info *ContainerInfo
    container_hostname := "none"
    container_image := "none"
    container_ip := "none"

    if config.Container_Metadata {
        container_info = pid_to_namespace[pid]
        if container_info == nil && !config.Async_Container_Metadata {
            container_info = GetContainerInfo(pid)
            pid_to_namespace[pid] = container_info
        }
    }

    if container_info != nil {
        container_image = container_info.Image
        container_ip = container_info.IpAddress
        container_hostname = container_info.Hostname
    }

    if container_image == "fail" {
        event_channel <- fmt.Sprintf("container.missing comm=%s pid=%d\n", event.Comm, pid)
        stats.MissingContainer++
    }

    ip_address := Long2ip(event.Addr)
    if ip_address == config.Trusted_Dns {
        return
    }

    // FIXME: data race in ip_to_hostname
    dns_name := ip_to_hostname[ip_address]

    ip_tags  := ipv4map.get_tags(int(event.Addr))
    dns_name_alt := ""
    if ip_tags != nil {
        dns_name_alt = ip_tags[0]
    }

    // FIXME: this checks only the hash table, which assumes ip:host is 1:1
    // the bst assumes ip:host is 1:many (more realistic) but I don't
    // feel like implementing something to check if two arrays overlap
    // it also doesn't check the container specific allow list

    // FIXME: we should consider caching the decision too
    // if an IP is allowed/blocked now, it will not change later
    // what if one dns entry for an ip is allowed, and another dns entry is not?
    allowed := tag_exists(config.Allow, dns_name)
    if dns_name == "" {
        // FIXME: oddly enough, this only happens when container metadata is enabled
        event_channel <- fmt.Sprintf("process.missing comm=%s pid=%d connection=%s:%d\n", event.Comm, pid, ip_address, event.Port)
        stats.MissingDns++
    }

    if config.Log_Blocked {
        if !allowed {
            // syscall.Kill(pid, 9)
            event_channel <- fmt.Sprintf(
                "process.blocked comm=%s pid=%d connection=%s:%d dns.entry=%s container.image=%s container.hostname=%s container.ip=%s\n",
                event.Comm,
                pid,
                ip_address,
                event.Port,
                dns_name,
                container_image,
                container_hostname,
                container_ip,
            )
        }
    } else {
        event_channel <- fmt.Sprintf(
        "process.tcp_v4 comm=%s pid=%d connection=%s:%d allowed=%t dns.entry=%s dns.entry2=%s container.image=%s container.hostname=%s container.ip=%s\n",
        event.Comm,
        pid,
        ip_address,
        event.Port,
        allowed,
        dns_name,
        dns_name_alt,
        container_image,
        container_hostname,
        container_ip,
        )
    }
}

func extract_dns(chunk []byte, size int) gopacket.Packet {
    packet := gopacket.NewPacket(
        chunk[:size],
        layers.LayerTypeEthernet,
        gopacket.NoCopy,
    )

    dns_packet := packet.Layer(layers.LayerTypeDNS)
    if dns_packet == nil {
        return nil
    }

    return packet
}

func log_dns_event(dns *layers.DNS) {
    var dns_event string
    if len(dns.Answers) > 0 {
        for _, answer := range dns.Answers {
            switch answer.Type {
                default:
                    fmt.Printf("unknown dns type: %s\n", answer.Type.String())
                case layers.DNSTypeAAAA:
                    ip_to_hostname[string(answer.IP.String())] = string(dns.Questions[0].Name)
                    dns_event = fmt.Sprintf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.IP)
                case layers.DNSTypeA:
                    ipv4map.insert(ipv4toint(answer.IP), []string{string(dns.Questions[0].Name)})
                    ip_to_hostname[string(answer.IP.String())] = string(dns.Questions[0].Name)
                    dns_event = fmt.Sprintf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.IP)
                case layers.DNSTypeCNAME:
                    ip_to_hostname[string(answer.CNAME)] = string(dns.Questions[0].Name)
                    dns_event = fmt.Sprintf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.CNAME)
            }

            if config.Log_Dns {
                event_channel <- dns_event
            }
        }
    } else if len(dns.Questions) > 0 {
        if config.Log_Dns {
            dns_event = fmt.Sprintf("dns.query hostname=%s type=%s\n", dns.Questions[0].Name, dns.Questions[0].Type.String())
            event_channel <- dns_event
        }
    } else {
        fmt.Printf("we have no answers fuq\n")
    }

    if dns.QR && len(dns.Questions) > 0 && string(dns.Questions[0].Name) == "reset" {
        ip_to_hostname = make(map[string]string)
        stats.MissingDns = 0; stats.MissingContainer = 0; stats.PacketsSeen = 0; stats.QueriesSeen = 0;
    } else if dns.QR && len(dns.Questions) > 0 && string(dns.Questions[0].Name) == "dump" {
        fmt.Printf("Stats:\n%+v\n", stats)
    }
}

// experimental, nothing calls it yet
func process_packet_manual(chunk[]byte, length int) {
    var err error
    ether := layers.Ethernet{}
    if err = ether.DecodeFromBytes(chunk, gopacket.NilDecodeFeedback); err != nil {
        log.Println(err)
    }
    if ether.EthernetType != layers.EthernetTypeIPv4 {
        return// no ipv6 yet
    }
    ipv44 := layers.IPv4{}
    if err = ipv44.DecodeFromBytes(ether.Payload, gopacket.NilDecodeFeedback); err != nil {
        panic("wat")
    }
    udpp := layers.UDP{}
    if err = udpp.DecodeFromBytes(ipv44.Payload, gopacket.NilDecodeFeedback); err != nil {
        panic("no udp")
    }
    dns_packet := layers.DNS{}
    err = dns_packet.DecodeFromBytes(udpp.Payload, gopacket.NilDecodeFeedback);
    if err == nil {
        log_dns_event(&dns_packet)
    } else {
        panic(err)
    }
}

func process_packet(chunk []byte, length int) {
    packet := gopacket.NewPacket(chunk[:length], layers.LayerTypeEthernet, gopacket.NoCopy)

    dns_packet := packet.Layer(layers.LayerTypeDNS)
    if dns_packet == nil {
        return
    }

    dns := dns_packet.(*layers.DNS)
    log_dns_event(dns)
    stats.QueriesSeen++
}
