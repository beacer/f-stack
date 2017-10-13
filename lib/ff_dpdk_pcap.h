/*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _FSTACK_DPDK_PCAP_H
#define _FSTACK_DPDK_PCAP_H

#include <rte_config.h>
#include <rte_mbuf.h>

#define FF_PCAP_RING_RD     "ff_pcap_ring_rd_" /* read by pcap app */
#define FF_PCAP_POOL        "ff_pcap_pool"

#define FF_PCAP_MAX_BUF     65536

struct ff_pcap_pkt {
    unsigned int    ifindex;    /* bsd ifindex */
    struct timeval  ts;
    uint8_t         vlan:1,     /* 802.1q tag present */
                    strip:1,    /* packet stripped due to buf not enough */
                    __unused:6;
    uint16_t        vlan_tci;   /* host byte order, valid if @vlan is set */
    uint16_t        pkt_len;
    uint16_t        offset;     /* data offset, may leave some head room. */
    uint8_t         buffer[FF_PCAP_MAX_BUF];
} __attribute__((packed)) __rte_cache_aligned;

int ff_pcap_init(int numa_id, int nb_procs, int proc_id);
int ff_pcap_dump_pkt(struct rte_mbuf *mbuf, uint8_t portid);

#endif /* ifndef _FSTACK_DPDK_PCAP_H */
