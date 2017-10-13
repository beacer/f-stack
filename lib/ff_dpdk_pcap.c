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

#include <sys/time.h>
#include <unistd.h>

#include "ff_dpdk_if.h"
#include "ff_dpdk_pcap.h"

#define PCAP_RING_SIZE      32      /* max num pkts queued for one proc */
#define PCAP_DEF_OFFSET     4       /* for 802.1q vlan tag */

static struct rte_mempool *pcap_pool;
static struct rte_ring *pcap_ring_rd;

int ff_pcap_init(int numa_id, int nb_procs, int proc_id)
{
    char name[RTE_RING_NAMESIZE];

    /* get global pcap pool */
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        pcap_pool = rte_mempool_create(FF_PCAP_POOL,
                                       PCAP_RING_SIZE * nb_procs,
                                       sizeof(struct ff_pcap_pkt),
                                       PCAP_RING_SIZE / 2, 0,
                                       NULL, NULL, NULL, NULL,
                                       numa_id, 0);
    } else {
        pcap_pool = rte_mempool_lookup(FF_PCAP_POOL);
    }

    if (!pcap_pool)
        rte_panic("Create pcap mempool failed\n");

    /* per-proc ring */
    snprintf(name, sizeof(name), "%s%u", FF_PCAP_RING_RD, proc_id);
    pcap_ring_rd = rte_ring_lookup(name);

    if (!pcap_ring_rd) {
        pcap_ring_rd = rte_ring_create(name, PCAP_RING_SIZE, numa_id,
                                       RING_F_SP_ENQ | RING_F_SP_ENQ);

        if (!pcap_ring_rd)
            rte_panic("Create pcap ring: %s failed\n", name);
    }

    return 0;
}

int
ff_pcap_dump_pkt(struct rte_mbuf *mbuf, uint8_t portid)
{
    int ifindex = ff_if_idtoindex(portid);
    struct ff_pcap_pkt *pkt;
    struct timespec tp;
    struct rte_mbuf *seg;
    int left, err;

    if (unlikely(!pcap_pool || !pcap_ring_rd))
        return -EPIPE;

    if (unlikely(ifindex <= 0))
        return -EINVAL;

    if (unlikely(rte_ring_full(pcap_ring_rd)))
        return -ENOBUFS; /* avoid copy if ring is already full */

    if (rte_mempool_get(pcap_pool, (void **)&pkt) != 0)
        return -ENOENT;
    memset(pkt, 0, sizeof(*pkt));

    pkt->ifindex = ifindex;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    pkt->ts.tv_sec = tp.tv_sec;
    pkt->ts.tv_usec = tp.tv_nsec / 1000;
    if (mbuf->ol_flags & PKT_RX_VLAN_STRIPPED) {
        pkt->vlan = 1;
        pkt->vlan_tci = mbuf->vlan_tci;
    }

    pkt->pkt_len = 0;
    pkt->offset = PCAP_DEF_OFFSET;
    left = sizeof(pkt->buffer) - pkt->offset;

    /* copy all mbuf segments util no space left. */
    for (seg = mbuf; seg; seg = mbuf->next) {
        if (left < seg->data_len) {
            pkt->strip = 1; /* hint */
            break;
        }

        memcpy(pkt->buffer + pkt->pkt_len,
               rte_pktmbuf_mtod(seg, void *), seg->data_len);

        pkt->pkt_len += seg->data_len;
        left -= seg->data_len;
    }

    err = rte_ring_enqueue(pcap_ring_rd, pkt);
    if (err != 0 && err != -EDQUOT) {
        rte_mempool_put(pcap_pool, pkt);
        return -ENOBUFS;
    }

    return 0;
}
