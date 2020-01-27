package egrets

import (
        "bytes"
        "encoding/binary"
        "encoding/json"
        "flag"
        "fmt"
        "net"
        "os"
        "regexp"
        "syscall"
        "unsafe"

        "github.com/google/gopacket"
        "github.com/google/gopacket/afpacket"
        "github.com/google/gopacket/layers"
        "github.com/google/gopacket/pcap"
        "github.com/iovisor/gobpf/elf"
        "golang.org/x/net/bpf"
        log "github.com/sirupsen/logrus"
)

import (

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

var processed_count int
var ip_to_hostname map[string]string
var pid_to_namespace map[int]*ContainerInfo
var dns_log *log.Logger
var acceptable_hosts *regexp.Regexp
var events []string
var use_bpf = flag.Bool("b", false, "whatever man")

func GetLogger(logger_name string) *log.Logger  {
    logger := log.New()
    //logger.SetLevel(log.WarnLevel)
    logger.Formatter = &TextFormatter{
        LoggerName: logger_name,
        ForceColors: true,
    }

    logger.SetOutput(os.Stdout)
    return logger
}

func Main(ebpf_binary string, host_match string) {
    flag.Parse()
    acceptable_hosts = regexp.MustCompile(host_match)
    dns_log = GetLogger("DNS")
    ip_to_hostname = make(map[string]string)
    pid_to_namespace = make(map[int]*ContainerInfo)
    var secParams = map[string]elf.SectionParams{
        "maps/events": elf.SectionParams{PerfRingBufferPageCount: 256},
    }

    mod := elf.NewModule(ebpf_binary)
    if mod == nil  {
        panic("nil module")
    }

    if err := mod.Load(secParams); err != nil  {
        panic(err)
    }

    // we should use old sk00l bpf here instead
    // https://godoc.org/github.com/google/gopacket/pcap#hdr-Reading_Live_Packets
    socketFilter := mod.SocketFilter("socket/filter_udp")
    if socketFilter == nil {
        panic("couldn't locate filter_udp")
    }

    fd, err := syscall.Socket(
        syscall.AF_PACKET,
        syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
        0x300,
    )

    sockaddr := syscall.RawSockaddrLinklayer{
        Family: syscall.AF_PACKET,
        Protocol: 0x0300,
        Ifindex: 2,
        Pkttype: syscall.PACKET_HOST,
    }

    _, _, e := syscall.Syscall(
        syscall.SYS_BIND,
        uintptr(fd),
        uintptr(unsafe.Pointer(&sockaddr)),
        unsafe.Sizeof(sockaddr));
    if e > 0 {
        panic(e)
    }

    if err != nil {
        panic(err)
    }
    defer syscall.Close(fd)

    if err := elf.AttachSocketFilter(socketFilter, fd); err != nil {
        dns_log.Fatalf("Failed to attach socket filter: %s\nMake sure you are running as root and that debugfs is mounted!", err)
    }

    defer elf.DetachSocketFilter(socketFilter, fd)

    if err := mod.EnableKprobe("kprobe/sys_connect", 1); err != nil {
        dns_log.Fatalf("Failed to set up kprobes: %s\nMake sure you are running as root and that debugfs is mounted!", err)
    }

    event_table := mod.Map("events")
    if event_table == nil {
        dns_log.Fatalf("Couldn't find events table!")
    }

    channel := make(chan []byte)
    lost_chan := make(chan uint64)
    pm, _ := elf.InitPerfMap(mod, "events", channel, lost_chan)
    pm.PollStart()

    log.Debugf("yer fd: %d\n", fd)

    err = syscall.SetNonblock(fd, false)
    if err != nil {
        log.Fatalf("failed to set AF_PACKET to blocking: %s", err)
    }

    dns_stream := os.NewFile(uintptr(fd), "hehe")
    if dns_stream == nil {
        log.Fatalf("couldn't turn fd into a file")
    }

    //go process_dns(dns_stream)
    afpacketHandle := get_packet_handle("udp and port 53")
    defer afpacketHandle.Close()
    go process_tcp(channel, lost_chan)
    if *use_bpf {
        process_alt_dns(afpacketHandle)
    } else {
        process_dns(dns_stream)
    }
}

func process_dns(dns_stream *os.File) {
    fmt.Printf("starting dns boye\n")
    // we should be using channels for this
    // https://www.openwall.com/lists/musl/2018/10/11/2
    for {
        byte_chunk := make([]byte, 2048)
        length, _ := dns_stream.Read(byte_chunk)
        if length == 0 {
            continue
        }

        go readAndProcess(byte_chunk, length)
    }
}

func get_packet_handle(bpf_filter string) *afpacket.TPacket {
    var afpacketHandle *afpacket.TPacket
    var err error

    afpacketHandle, err = afpacket.NewTPacket(
        afpacket.OptFrameSize(65536),
        afpacket.OptBlockSize(8388608),
        afpacket.OptNumBlocks(1),
        afpacket.OptAddVLANHeader(false),
        afpacket.OptPollTimeout(-10000000),
        afpacket.SocketRaw,
        afpacket.TPacketVersion3)

    if err != nil {
        panic(err)
    }

    pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65536, "udp and port 53")
    bpfIns := []bpf.RawInstruction{}
    for _, ins := range pcapBPF {
        bpfIns2 := bpf.RawInstruction{
            Op: ins.Code,
            Jt: ins.Jt,
            Jf: ins.Jf,
            K:  ins.K,
        }
        bpfIns = append(bpfIns, bpfIns2)
    }

    if afpacketHandle.SetBPF(bpfIns); err != nil {
        panic(err)
    }

    return afpacketHandle
}

func process_alt_dns(afpacketHandle *afpacket.TPacket) {
    fmt.Printf("starting alt dns boye\n")

    for {
        data, _, err := afpacketHandle.ZeroCopyReadPacketData()
        if err != nil {
            panic(err)
        }

        go readAndProcess(data, len(data))
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

func process_tcp(receiver chan []byte, lost chan uint64) {
        fmt.Printf("tcp processing starting\n")
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

                //events = append(events, fmt.Sprintf("tcpeve %d %d\n", tcp_start, event.Port))
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
    // remember that these include udp too
    if event.Addr == 0 {
        // dns_log.Errorf("family: %d, addr: %d\n", event.Family, event.Addr)
        return
    }

    pid := int(event.Pid & 0xFFFFFFFF)
    var container_info *ContainerInfo
    if pid_to_namespace[pid] != nil {
        container_info = pid_to_namespace[pid]
    } else {
        container_info = nil//GetContainerInfo(pid)
        pid_to_namespace[pid] = container_info
    }

    container_hostname := "none"
    container_image := "none"
    container_ip := "none"
    if container_info != nil {
        container_image = container_info.Image
        container_ip = container_info.IpAddress
        container_hostname = container_info.Hostname
    }

    ip_address := Long2ip(event.Addr)
    dns_name := ip_to_hostname[ip_address]
    /*if !acceptable_hosts.Match([]byte(dns_name)) {
        dns_log.Warnf(
            "alert.egress comm=%s pid=%d connection=%s:%d dns.entry=%s\n",
            event.Comm,
            pid,
            ip_address,
            event.Port,
            dns_name,
            )
    } else {*/
    events = append(events, fmt.Sprintf(
    "process.tcp_v4 comm=%s pid=%d connection=%s:%d dns.entry=%s container.image=%s container.hostname=%s container.ip=%s\n",
    event.Comm,
    pid,
    ip_address,
    event.Port,
    dns_name,
    container_image,
    container_hostname,
    container_ip,
    ))
    //}
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
    if dns.QR && len(dns.Questions) > 0 && string(dns.Questions[0].Name) == "dump" {
        fmt.Printf("====\n")
        for _, event := range events {
            fmt.Printf("event: %s", event)
        }

        events = make([]string, 0)

        if 1 == 0 {
            b, err := json.MarshalIndent(ip_to_hostname, "", "  ")
            if err == nil {
                fmt.Printf("%s\n", string(b))
            }
        }
    }

    if len(dns.Answers) > 0 {
        for _, answer := range dns.Answers {
            switch answer.Type {
                default:
                    fmt.Printf("unknown dns type: %s\n", answer.Type.String())
                case layers.DNSTypeAAAA:
                    ip_to_hostname[string(answer.IP.String())] = string(dns.Questions[0].Name)
                    events = append(
                        events,
                        fmt.Sprintf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.IP),
                        )
                case layers.DNSTypeA:
                    ip_to_hostname[string(answer.IP.String())] = string(dns.Questions[0].Name)
                    events = append(
                        events,
                        fmt.Sprintf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.IP),
                        )
                case layers.DNSTypeCNAME:
                    ip_to_hostname[string(answer.CNAME)] = string(dns.Questions[0].Name)
                    events = append(
                        events,
                        fmt.Sprintf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.CNAME),
                        )
            }
        }
    } else if len(dns.Questions) > 0 {
        events = append(
            events,
            fmt.Sprintf("dns.query hostname=%s type=%s\n", dns.Questions[0].Name, dns.Questions[0].Type.String()),
            )
    } else {
        fmt.Printf("we have no answers fuq\n")
    }
}

func readAndProcess(chunk []byte, length int) {
    packet := gopacket.NewPacket(chunk[:length], layers.LayerTypeEthernet, gopacket.NoCopy)

    dns_packet := packet.Layer(layers.LayerTypeDNS)
    if dns_packet == nil {
        return
    }

    processed_count += 1

    dns := dns_packet.(*layers.DNS)
    log_dns_event(dns)
    log.Debugf("processed %d packets\n", processed_count)
}
