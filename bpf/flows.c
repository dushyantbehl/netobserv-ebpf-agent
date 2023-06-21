/*
    Flows v2. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
        4) When hash collision is detected, we send the new entry to userpace via ringbuffer.
*/
#include "utils.h"
#include "tcp_drops.h"
#include "dns_tracker.h"

static __always_inline void calculate_flow_rtt(pkt_info *pkt, u8 direction, void *data_end) {
    flow_seq_id seq_id;
    __builtin_memset(&seq_id, 0, sizeof(flow_seq_id));

    switch (pkt->id->transport_protocol)
    {
    case IPPROTO_TCP: {
            struct tcphdr *tcp = (struct tcphdr *) pkt->l4_hdr;
            if ( !tcp || ((void *)tcp + sizeof(*tcp) > data_end) ) {
                break;
            }
            if ((direction == EGRESS) && IS_SYN_PACKET(pkt)) {
                // Record the outgoing syn sequence number
                u32 seq = bpf_ntohl(tcp->seq);
                fill_flow_seq_id(&seq_id, pkt, seq, 0);

                long ret = bpf_map_update_elem(&flow_sequences, &seq_id, &pkt->current_ts, BPF_ANY);
                if (trace_messages && ret != 0) {
                    bpf_printk("err saving flow sequence record %d", ret);
                }
                break;
            }
            if ((direction == INGRESS) && IS_ACK_PACKET(pkt)) {
                // Stored sequence should be ack_seq - 1
                u32 seq = bpf_ntohl(tcp->ack_seq) - 1;
                // check reversed flow
                fill_flow_seq_id(&seq_id, pkt, seq, 1); 

                u64 *prev_ts = bpf_map_lookup_elem(&flow_sequences, &seq_id);
                if (prev_ts != NULL) {
                    pkt->rtt = pkt->current_ts - *prev_ts;
                    // Delete the flow from flow sequence map so if it
                    // restarts we have a new RTT calculation.
                    long ret = bpf_map_delete_elem(&flow_sequences, &seq_id);
                    if (trace_messages && ret != 0) {
                        bpf_printk("error evicting flow sequence: %d", ret);
                    }
                }
                break;
            }
        } break;
    default:
        break;
    }
}

static inline int flow_monitor(struct __sk_buff *skb, u8 direction) {

    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_OK;
    }

    // Record the current time first.
    u64 current_time = bpf_ktime_get_ns();

    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));

    pkt_info pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));

    pkt.id = &id;
    pkt.current_ts = current_time;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if (fill_ethhdr(eth, data_end, &pkt) == DISCARD) {
        return TC_ACT_OK;
    }

    calculate_flow_rtt(&pkt, direction, data_end);

    //Set extra fields
    id.if_index = skb->ifindex;
    id.direction = direction;

    // TODO: we need to add spinlock here when we deprecate versions prior to 5.1, or provide
    // a spinlocked alternative version and use it selectively https://lwn.net/Articles/779120/
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += skb->len;
        aggregate_flow->end_mono_time_ts = current_time;
        aggregate_flow->flags |= pkt.flags;
        if (pkt.rtt != 0) { // If it is non zero then
            aggregate_flow->flow_rtt = pkt.rtt;
        }
        long ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            // usually error -16 (-EBUSY) is printed here.
            // In this case, the flow is dropped, as submitting it to the ringbuffer would cause
            // a duplicated UNION of flows (two different flows with partial aggregation of the same packets),
            // which can't be deduplicated.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            bpf_printk("error updating flow %d\n", ret);
        }
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_metrics new_flow = {
            .packets = 1,
            .bytes = skb->len,
            .start_mono_time_ts = current_time,
            .end_mono_time_ts = current_time,
            .flags = pkt.flags,
            .flow_rtt = pkt.rtt
        };

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
        if (ret != 0) {
            // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
            // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
            // a repeated INTERSECTION of flows (different flows aggregating different packets),
            // which can be re-aggregated at userpace.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_printk("error adding flow %d\n", ret);
            }

            new_flow.errno = -ret;
            flow_record *record = bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
            if (!record) {
                if (trace_messages) {
                    bpf_printk("couldn't reserve space in the ringbuf. Dropping flow");
                }
                return TC_ACT_OK;
            }
            record->id = id;
            record->metrics = new_flow;
            bpf_ringbuf_submit(record, 0);
        }
    }
    return TC_ACT_OK;
}

SEC("tc_ingress")
int ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
int egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}

char _license[] SEC("license") = "GPL";

