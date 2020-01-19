package egrets

import (
        "bytes"
        "encoding/binary"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "net"
        "os"
        "regexp"
        "syscall"
        "unsafe"

        "github.com/google/gopacket"
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
var acceptable_hosts *regexp.Regexp;

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
    channel := make(chan []byte)
    lost_chan := make(chan uint64)
    pm, _ := elf.InitPerfMap(mod, "events", channel, lost_chan)
    pm.PollStart()
    if event_table == nil {
        dns_log.Fatalf("Couldn't find events table!")
    }

    log.Debugf("yer fd: %d\n", fd)

    err = syscall.SetNonblock(fd, false)
    if err != nil {
        log.Fatalf("failed to set AF_PACKET to blocking: %s", err)
    }

    pee := os.NewFile(uintptr(fd), "hehe")
    if pee == nil {
        log.Fatalf("couldn't turn fd into a file")
    }

    stopChan := make(chan struct{})
    go func() {
        for {
            select {
            case <-stopChan:
                return
            case data, ok := <-channel:
                if !ok {
                    return
                }

                var event tcp_v4
                buffer := bytes.NewBuffer(data)
                err := binary.Read(buffer, binary.LittleEndian, &event)
                if err != nil {
                    panic(err)
                }
                // exclude stuff bound to 0.0.0.0
                // remember that these include udp too
                if event.Addr == 0 {
                    // dns_log.Errorf("family: %d, addr: %d\n", event.Family, event.Addr)
                    continue
                }

                pid := int(event.Pid & 0xFFFFFFFF)
                var container_info *ContainerInfo
                if pid_to_namespace[pid] != nil {
                    container_info = pid_to_namespace[pid]
                } else {
                    container_info = GetContainerInfo(pid)
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
                if !acceptable_hosts.Match([]byte(dns_name)) {
                    dns_log.Warnf(
                        "alert.egress comm=%s pid=%d connection=%s:%d dns.entry=%s\n",
                        event.Comm,
                        pid,
                        ip_address,
                        event.Port,
                        dns_name,
                        )
                } else {
                    dns_log.Printf(
                    "process.tcp_v4 comm=%s pid=%d connection=%s:%d dns.entry=%s container.image=%s container.hostname=%s container.ip=%s\n",
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
            case _, ok := <-lost_chan:
                if !ok {
                    return
                }
            }
        }
    }()

    // we should be using channels for this
    // https://www.openwall.com/lists/musl/2018/10/11/2
    for {
        byte_chunk := make([]byte, 2048)
        readAndProcess(pee, byte_chunk)
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

func readAndProcess(handle *os.File, chunk []byte) {
    count, _ := handle.Read(chunk)
    if count == 0 {
        return
    }

    if 1 == 0 {
        encodedStr := hex.Dump(chunk)
        fmt.Printf("%s\n", encodedStr)
    }

    packet := gopacket.NewPacket(chunk[:count], layers.LayerTypeEthernet, gopacket.NoCopy)

    dns_packet := packet.Layer(layers.LayerTypeDNS)
    if dns_packet == nil {
        return
    }

    processed_count += 1

    dns := dns_packet.(*layers.DNS)
    if len(dns.Answers) == 0 && len(dns.Questions) > 0 && string(dns.Questions[0].Name) == "dump" {
        b, err := json.MarshalIndent(ip_to_hostname, "", "  ")

        if err != nil {
            fmt.Println("error:", err)
        }

        fmt.Printf("%s\n", string(b))
        return
    }

    if len(dns.Answers) > 0 {
        for _, answer := range dns.Answers {
            switch answer.Type {
                default:
                    fmt.Printf("unknown dns type: %s\n", answer.Type.String())
                case layers.DNSTypeAAAA:
                    ip_to_hostname[string(answer.IP.String())] = string(dns.Questions[0].Name)
                    dns_log.Printf("dns.answer hostname=%s response=%s", dns.Questions[0].Name, answer.IP)
                case layers.DNSTypeA:
                    ip_to_hostname[string(answer.IP.String())] = string(dns.Questions[0].Name)
                    dns_log.Printf("dns.answer hostname=%s response=%s\n", dns.Questions[0].Name, answer.IP)
                case layers.DNSTypeCNAME:
                    ip_to_hostname[string(answer.CNAME)] = string(dns.Questions[0].Name)
                    dns_log.Printf("dns.answer hostname=%s response=%s", dns.Questions[0].Name, answer.CNAME)
            }
        }
    } else if len(dns.Questions) > 0 {
        //fmt.Printf("[QUERY][%d ] dig %s\n", len(dns.Questions), dns.Questions[0].Name)
        dns_log.Printf("dns.query hostname=%s type=%s\n", dns.Questions[0].Name, dns.Questions[0].Type.String())
    } else {
        fmt.Printf("we have no answers fuq\n")
    }

    log.Debugf("processed %d packets\n", processed_count)
}
