package egrets

import (
        "errors"
        "fmt"
        "syscall"
        "unsafe"

        "github.com/google/gopacket/afpacket"
        "github.com/google/gopacket/layers"
        "github.com/google/gopacket/pcap"
        "golang.org/x/net/bpf"
        "github.com/iovisor/gobpf/elf"
)

func LoadModuleElf(path string) (*elf.Module, error) {
    mod := elf.NewModule(path)
    if mod == nil {
        return nil, fmt.Errorf("failed to load elf at %s", path)
    }

    var secParams = map[string]elf.SectionParams{}

    if err := mod.Load(secParams); err != nil  {
        return nil, err
    }

    return mod, nil
}

func GetSocketFilter(module *elf.Module, filter_name string) (int, *elf.SocketFilter, error) {
    socketFilter := module.SocketFilter(filter_name)
    if socketFilter == nil {
        return -1, nil, fmt.Errorf("failed to find socket filter %s", filter_name)
    }

    fd, err := syscall.Socket(
        syscall.AF_PACKET,
        syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
        0x300,
    )

    if err != nil {
        return -1, nil, err
    }

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
        return -1, nil, errors.New("failed to bind")
    }

    if err := elf.AttachSocketFilter(socketFilter, fd); err != nil {
        return -1, nil, err
    }

    return fd, socketFilter, nil
}

func GetMap(
    module *elf.Module,
    map_name string,
    map_chan chan []byte,
    lost_chan chan uint64,
    ) error {
    event_table := module.Map(map_name)
    if event_table == nil {
        return fmt.Errorf("couldn't find map %s", map_name)
    }

    pm, _ := elf.InitPerfMap(module, map_name, map_chan, lost_chan)
    pm.PollStart()

    return nil
}

func GetPacketHandle(bpf_filter string) (*afpacket.TPacket, error) {
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
        return nil, err
    }

    pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65536, bpf_filter)
    if err != nil {
        return nil, err
    }

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
        return nil, err
    }

    return afpacketHandle, nil
}
