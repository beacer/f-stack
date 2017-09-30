#ifndef _FF_PCAP_H_
#define _FF_PCAP_H_

#define FF_PCAP_RING_RD     "ff_pcap_ring_rd_" /* read by pcap app */
#define FF_PCAP_POOL        "ff_pcap_pool"

#define FF_PCAP_MAX_BUF     65536

struct ff_pcap_pkt {
    unsigned int    ifindex;
    struct timeval  ts;
    uint32_t        vlan:1;
    uint16_t        vlan_tci;   /* host byte order */
    uint16_t        pkt_len;
    uint16_t        offset;     /* data offset, may leave some head room. */
    uint8_t         buffer[FF_PCAP_MAX_BUF];
} __attribute__((packed)) __rte_cache_aligned;

#endif /* _FF_PCAP_H_ */
