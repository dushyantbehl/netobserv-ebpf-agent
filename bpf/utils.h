#ifndef __UTILS_H__
#define __UTILS_H__

#include <vmlinux.h>
#include <bpf_helpers.h>

#include "flow.h"
#include "maps_definition.h"

#define DISCARD 1
#define SUBMIT 0

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;
volatile const u8 trace_messages = 0;

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
typedef enum {
    INGRESS         = 0,
    EGRESS          = 1,
    MAX_DIRECTION   = 2,
} direction_t;

// packet info structure passed around functions.
typedef struct pkt_info_t {
    flow_id *id;
    u64 current_ts; // ts recorded when pkt came.
    u16 flags;      // TCP specific
    void *l4_hdr;   // Stores the actual l4 header
    u64 rtt;        // rtt calculated from the flow if possible. else zero
} pkt_info;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80
// Custom flags exported
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

#define IS_SYN_PACKET(pkt)    ((pkt->flags & SYN_FLAG) || (pkt->flags & SYN_ACK_FLAG))
#define IS_ACK_PACKET(pkt)    ((pkt->flags & ACK_FLAG) || (pkt->flags & SYN_ACK_FLAG))

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x)        __builtin_bswap16(x)
#define bpf_htons(x)        __builtin_bswap16(x)
#define bpf_ntohl(x)        __builtin_bswap32(x)
#define bpf_htonl(x)        __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x)        (x)
#define bpf_htons(x)        (x)
#define bpf_ntohl(x)        (x)
#define bpf_htonl(x)        (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

// sets the TCP header flags for connection information
static inline void set_flags(struct tcphdr *th, u16 *flags) {
    //If both ACK and SYN are set, then it is server -> client communication during 3-way handshake. 
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
    } else if (th->ack && th->fin ) {
        // If both ACK and FIN are set, then it is graceful termination from server.
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst ) {
        // If both ACK and RST are set, then it is abrupt connection termination. 
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->ack) {
        *flags |= ACK_FLAG;
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    } else if (th->urg) {
        *flags |= URG_FLAG;
    } else if (th->ece) {
        *flags |= ECE_FLAG;
    } else if (th->cwr) {
        *flags |= CWR_FLAG;
    }
}

static __always_inline void fill_flow_seq_id(flow_seq_id *seq_id, pkt_info *pkt, u32 seq, u8 reversed) {
    flow_id *id = pkt->id;
    if (reversed) {
        __builtin_memcpy(seq_id->src_ip, id->dst_ip, IP_MAX_LEN);
        __builtin_memcpy(seq_id->dst_ip, id->src_ip, IP_MAX_LEN);
        seq_id->src_port = id->dst_port;
        seq_id->dst_port = id->src_port;
    } else {
        __builtin_memcpy(seq_id->src_ip, id->src_ip, IP_MAX_LEN);
        __builtin_memcpy(seq_id->dst_ip, id->dst_ip, IP_MAX_LEN);
        seq_id->src_port = id->src_port;
        seq_id->dst_port = id->dst_port;
    }
    seq_id->seq_id = seq;
}

// Extract L4 info for the supported protocols
static inline void fill_l4info(void *l4_hdr_start, void *data_end, u8 protocol,
                               pkt_info *pkt) {
    flow_id *id = pkt->id;
    id->transport_protocol = protocol;
    switch (protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4_hdr_start;
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = bpf_ntohs(tcp->source);
            id->dst_port = bpf_ntohs(tcp->dest);
            set_flags(tcp, &pkt->flags);
            pkt->l4_hdr = (void *) tcp;
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = l4_hdr_start;
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = bpf_ntohs(udp->source);
            id->dst_port = bpf_ntohs(udp->dest);
            pkt->l4_hdr = (void *) udp;
        }
    } break;
    case IPPROTO_SCTP: {
        struct sctphdr *sctph = l4_hdr_start;
        if ((void *)sctph + sizeof(*sctph) <= data_end) {
            id->src_port = bpf_ntohs(sctph->source);
            id->dst_port = bpf_ntohs(sctph->dest);
            pkt->l4_hdr = (void *) sctph;
        }
    } break;
    case IPPROTO_ICMP: {
        struct icmphdr *icmph = l4_hdr_start;
        if ((void *)icmph + sizeof(*icmph) <= data_end) {
            id->icmp_type = icmph->type;
            id->icmp_code = icmph->code;
            pkt->l4_hdr = (void *) icmph;
        }
    } break;
    case IPPROTO_ICMPV6: {
        struct icmp6hdr *icmp6h = l4_hdr_start;
         if ((void *)icmp6h + sizeof(*icmp6h) <= data_end) {
            id->icmp_type = icmp6h->icmp6_type;
            id->icmp_code = icmp6h->icmp6_code;
            pkt->l4_hdr = (void *) icmp6h;
        }
    } break;
    default:
        break;
    }
}

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, pkt_info *pkt) {
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    /* Save the IP Address to id directly. copy once. */
    __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));

    /* fill l4 header which will be added to id in flow_monitor function.*/
    fill_l4info(l4_hdr_start, data_end, ip->protocol, pkt);
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, pkt_info *pkt) {
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    /* Save the IP Address to id directly. copy once. */
    __builtin_memcpy(id->src_ip, ip->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(id->dst_ip, ip->daddr.in6_u.u6_addr8, 16);

    /* fill l4 header which will be added to id in flow_monitor function.*/
    fill_l4info(l4_hdr_start, data_end, ip->nexthdr, pkt);
    return SUBMIT;
}

// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, pkt_info *pkt) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    __builtin_memcpy(id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth->h_source, ETH_ALEN);
    id->eth_protocol = bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, pkt);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, pkt);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        __builtin_memset(&(id->src_ip), 0, sizeof(struct in6_addr));
        __builtin_memset(&(id->dst_ip), 0, sizeof(struct in6_addr));
        id->transport_protocol = 0;
        id->src_port = 0;
        id->dst_port = 0;
    }
    return SUBMIT;
}

static inline void set_key_with_l2_info(struct sk_buff *skb, flow_id *id, u16 *family) {
     struct ethhdr eth;
     __builtin_memset(&eth, 0, sizeof(eth));
     bpf_probe_read(&eth, sizeof(eth), (struct ethhdr *)(skb->head + skb->mac_header));
     id->eth_protocol = bpf_ntohs(eth.h_proto);
     __builtin_memcpy(id->dst_mac, eth.h_dest, ETH_ALEN);
     __builtin_memcpy(id->src_mac, eth.h_source, ETH_ALEN);
    if (id->eth_protocol == ETH_P_IP) {
        *family = AF_INET;
    } else if (id->eth_protocol == ETH_P_IPV6) {
        *family = AF_INET6;
    }
 }

static inline void set_key_with_l3_info(struct sk_buff *skb, u16 family, flow_id *id, u8 *protocol) {
     if (family == AF_INET) {
         struct iphdr ip;
         __builtin_memset(&ip, 0, sizeof(ip));
         bpf_probe_read(&ip, sizeof(ip), (struct iphdr *)(skb->head + skb->network_header));
         __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
         __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
         __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip.saddr, sizeof(ip.saddr));
         __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip.daddr, sizeof(ip.daddr));
         *protocol = ip.protocol;
     } else if (family == AF_INET6) {
         struct ipv6hdr ip;
         __builtin_memset(&ip, 0, sizeof(ip));
         bpf_probe_read(&ip, sizeof(ip), (struct ipv6hdr *)(skb->head + skb->network_header));
         __builtin_memcpy(id->src_ip, ip.saddr.in6_u.u6_addr8, IP_MAX_LEN);
         __builtin_memcpy(id->dst_ip, ip.daddr.in6_u.u6_addr8, IP_MAX_LEN);
         *protocol = ip.nexthdr;
     }
 }

static inline int set_key_with_tcp_info(struct sk_buff *skb, flow_id *id, u8 protocol, u16 *flags) {
     u16 sport = 0,dport = 0;
     struct tcphdr tcp;

     __builtin_memset(&tcp, 0, sizeof(tcp));
     bpf_probe_read(&tcp, sizeof(tcp), (struct tcphdr *)(skb->head + skb->transport_header));
     sport = bpf_ntohs(tcp.source);
     dport = bpf_ntohs(tcp.dest);
     set_flags(&tcp, flags);
     id->src_port = sport;
     id->dst_port = dport;
     id->transport_protocol = protocol;
     return tcp.doff * sizeof(u32);
 }

static inline int set_key_with_udp_info(struct sk_buff *skb, flow_id *id, u8 protocol) {
     u16 sport = 0,dport = 0;
     struct udphdr udp;

     __builtin_memset(&udp, 0, sizeof(udp));
     bpf_probe_read(&udp, sizeof(udp), (struct udp *)(skb->head + skb->transport_header));
     sport = bpf_ntohs(udp.source);
     dport = bpf_ntohs(udp.dest);
     id->src_port = sport;
     id->dst_port = dport;
     id->transport_protocol = protocol;
     return bpf_ntohs(udp.len);
 }

static inline long tcp_drop_lookup_and_update_flow(struct sk_buff *skb, flow_id *id, u8 state, u16 flags,
                                            enum skb_drop_reason reason) {
     flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, id);
     if (aggregate_flow != NULL) {
         aggregate_flow->tcp_drops.packets += 1;
         aggregate_flow->tcp_drops.bytes += skb->len;
         aggregate_flow->tcp_drops.latest_state = state;
         aggregate_flow->tcp_drops.latest_flags = flags;
         aggregate_flow->tcp_drops.latest_drop_cause = reason;
         long ret = bpf_map_update_elem(&aggregated_flows, id, aggregate_flow, BPF_ANY);
         if (trace_messages && ret != 0) {
             bpf_printk("error tcp drop updating flow %d\n", ret);
         }
         return 0;
      }
      return -1;
 }

#endif // __UTILS_H__