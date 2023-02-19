#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT -1
#define ETH_P_IP 0x0800
#define MAX_ENTRIES 64
#define AF_INET		2

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") redirect_map_ipv4 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") redirect_map_ipv6 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = 4*sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = MAX_ENTRIES,
};


SEC("tc_redirect")
int redirect(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct bpf_redir_neigh neighInfo = {0};

    u32 key = 0;
	u32 *interfaceId = 0;
    iph = data + sizeof(*eth);

    char called_str[] = "called";
    char not_ip_str[] = "not ip, %x fede";
    char notfound_str[] = "notfound %u %u";
    
    bpf_trace_printk(called_str, sizeof(called_str));

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) // TODO IPv6
        return TC_ACT_OK;

    key = bpf_ntohl(iph->daddr);
	interfaceId = bpf_map_lookup_elem(&redirect_map_ipv4, &key);
    if (interfaceId == NULL) {
        bpf_trace_printk(notfound_str, sizeof(notfound_str), iph->daddr, bpf_ntohl(iph->saddr));
        return TC_ACT_OK;
    }
    
	// bpf_redir_neigh -> next
    if (interfaceId != NULL) {
        char redir_str[] = "redir";
        bpf_trace_printk(redir_str, sizeof(redir_str));
        neighInfo.ipv4_nh = bpf_htonl(175103253); // 10.111.221.21
        neighInfo.nh_family = AF_INET;
	    return bpf_redirect_neigh(*interfaceId, &neighInfo, sizeof(neighInfo), 0);
    }
    return TC_ACT_OK;

}