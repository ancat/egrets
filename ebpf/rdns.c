#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#define ETH_LEN 14

// packet parsing state machine helpers
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

unsigned long long load_byte(void *skb,
                 unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
                 unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
                 unsigned long long off) asm("llvm.bpf.load.word");
unsigned long long load_dword(void *skb,
                 unsigned long long off) asm("llvm.bpf.load.dword");

#define MASK(_n) ((_n) < 64 ? (1ull << (_n)) - 1 : ((uint64_t)-1LL))
#define MASK128(_n) ((_n) < 128 ? ((unsigned __int128)1 << (_n)) - 1 : ((unsigned __int128)-1))
uint64_t bpf_dext_pkt(void *pkt, uint64_t off, uint64_t bofs, uint64_t bsz) {
  if (bofs == 0 && bsz == 8) {
    return load_byte(pkt, off);
  } else if (bofs + bsz <= 8) {
    return load_byte(pkt, off) >> (8 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 16) {
    return load_half(pkt, off);
  } else if (bofs + bsz <= 16) {
    return load_half(pkt, off) >> (16 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 32) {
    return load_word(pkt, off);
  } else if (bofs + bsz <= 32) {
    return load_word(pkt, off) >> (32 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 64) {
    return load_dword(pkt, off);
  } else if (bofs + bsz <= 64) {
    return load_dword(pkt, off) >> (64 - (bofs + bsz))  &  MASK(bsz);
  }
  return 0;
}
struct udp_t {
  unsigned short sport;
  unsigned short dport;
  unsigned short length;
  unsigned short crc;
} __attribute__((packed));;

struct ethernet_t {
  unsigned long long  dst:48;
  unsigned long long  src:48;
  unsigned int        type:16;
} __attribute__((packed));;

struct ip_t {
  unsigned char   ver:4;           // byte 0
  unsigned char   hlen:4;
  unsigned char   tos;
  unsigned short  tlen;
  unsigned short  identification; // byte 4
  unsigned short  ffo_unused:1;
  unsigned short  df:1;
  unsigned short  mf:1;
  unsigned short  foffset:13;
  unsigned char   ttl;             // byte 8
  unsigned char   nextp;
  unsigned short  hchecksum;
  unsigned int    src;            // byte 12
  unsigned int    dst;            // byte 16
} __attribute__((packed));;

# define printk(fmt, ...)                        \
        ({                            \
            char ____fmt[] = fmt;                \
            bpf_trace_printk(____fmt, sizeof(____fmt),    \
                     ##__VA_ARGS__);            \
        })

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

/*
    netevent.port = ({ typeof(__be16) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (u64)&poop->sin_port); _val; });
    netevent.address = ({ typeof(__be32) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (u64)&poop->sin_addr.s_addr); _val; });
    bpf_get_current_comm(&netevent.comm, sizeof(netevent.comm));
    bpf_perf_event_output(ctx, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &netevent, sizeof(netevent));
*/

struct bpf_map_def SEC("maps/events") tcp_v4 = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct netevent_t {
    uint64_t pid;
    uint64_t ts;
    char comm[TASK_COMM_LEN];
    uint64_t fd;
    uint64_t uid;
    uint16_t port;
    uint32_t address;
    uint32_t inet_family;
} ;

SEC("kprobe/sys_connect")
int kprobe__sys_connect(struct pt_regs *ctx) {
    // this handles all types of sockets
    // https://github.com/ancat/meatball/blob/master/meatball.c#L47 
    u32 cpu = bpf_get_smp_processor_id();
    struct netevent_t event = {0};
    event.ts = 69;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    //int kprobe__sys_connect(struct pt_regs *ctx, int sockfd, struct sockaddr* addr, int addrlen) {
    int sockfd = ctx->di;
    struct sockaddr* addr = (void*) ctx->si;//int addrlen = ctx->dx;
    struct sockaddr_in* poop = (struct sockaddr_in*) addr;

    sa_family_t family;
    bpf_probe_read(&family, sizeof(family), &poop->sin_family);
    if (family != AF_INET) {
        return 0;
    }

    uint16_t port;
    bpf_probe_read(&port, sizeof(port), &poop->sin_port);
    port = htons(port);

    uint32_t in_addr;
    bpf_probe_read(&in_addr, sizeof(in_addr), &poop->sin_addr);
    in_addr = __constant_ntohl(in_addr);

    event.fd = sockfd;
    event.port = port;
    event.pid = bpf_get_current_pid_tgid();
    event.address = in_addr;
    event.inet_family = family;
    bpf_perf_event_output(ctx, &tcp_v4, cpu, &event, sizeof(event));

    return 0;
}

SEC("socket/filter_udp")
int filter_udp(struct __sk_buff *skb) {
  uint8_t *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  unsigned int p_type = bpf_dext_pkt(skb, (uint64_t)ethernet+12, 0, 16);

  if (p_type == 0x800) {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    int proto = load_byte(skb, ETH_HLEN + offsetof(struct ip_t, nextp));
    if (proto == IPPROTO_UDP) {
      struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
      unsigned short dport = bpf_dext_pkt(skb, (uint64_t)udp + offsetof(struct udp_t, dport), 0, 16);
      unsigned short sport = bpf_dext_pkt(skb, (uint64_t)udp + offsetof(struct udp_t, sport), 0, 16);

      if (sport == 53) {
        return -1;
      } else if (dport == 53) {
        return -1;
      }
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
unsigned int _version SEC("version") = 0xFFFFFFFE;
