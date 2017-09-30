#include <assert.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h> /* good ? */

#include "net/if.h"
#include "compat.h"
#include "ff_ipc.h"
#include "ff_dpdk_pcap.h"

#include "pcap-int.h"
#include "pcap/vlan.h"

static struct rte_mempool *pcap_pool;
static struct rte_ring *pcap_ring_rd;

struct pcap_fstack {
    char        ifname[IFNAMSIZ];
    int         ifindex;

    uint64_t    pkt_read;
    uint64_t    pkt_drop;
    uint64_t    pkt_miss;

    uint64_t    close_promisc:1;
};

int
pcap_ff_init(int prog)
{
    char ring_name[RTE_RING_NAMESIZE];

    ff_ipc_init();
    ff_set_proc_id(prog);

    pcap_pool = rte_mempool_lookup(FF_PCAP_POOL);
    if (!pcap_pool)
        rte_exit(EXIT_FAILURE, "fail to lookup pcap mempool\n");

    snprintf(ring_name, RTE_RING_NAMESIZE, "%s%d", FF_PCAP_RING_RD, prog);
    pcap_ring_rd = rte_ring_lookup(ring_name);
    if (!pcap_ring_rd)
        rte_exit(EXIT_FAILURE, "fail to lookup pcap ring_rd\n");

    return 0;
}

static int
pcap_ff_set_promisc(const char *ifname, bool on)
{
#if 0
    int flags;
    struct ifreq ifr = {};

    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    /* fd is not used in fstack ioctl */
    if (ioctl(-1, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
        return -1;

    flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);

    if (on)
        flags |= IFF_PROMISC;
    else
        flags &= ~IFF_PROMISC;

    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;

    if (ioctl(-1, SIOCSIFFLAGS, (caddr_t)&ifr) < 0)
        return -1;
#endif

    return 0;
}

static int
pcap_ff_ipc(pcap_t *pcap, ff_pcap_op_t oper,
            int (*hdl_reply)(void *user, const struct ff_msg *reply),
            void *user)
{
    struct ff_msg *msg = NULL;
    int err = PCAP_ERROR;

    msg = ff_ipc_msg_alloc();
    if (!msg) {
        snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE, "no memory");
        goto done;
    }

    msg->msg_type = FF_PCAP;

    memset(&msg->pcap, 0, sizeof(struct ff_pcap_args));
    msg->pcap.oper = oper;
    snprintf(msg->pcap.ifname, IFNAMSIZ, "%s", pcap->opt.device);

    if (ff_ipc_send(msg) < 0) {
        snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE, "send msg error");
        goto done;
    }

    /* wait for response */
    while (1) {
        struct ff_msg *retmsg;

        if (ff_ipc_recv(&retmsg) < 0) {
            snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE, "recv msg error");
            goto done;
        }

        if (retmsg == msg)
            break;
        else /* not what we need */
            ff_ipc_msg_free(retmsg);
    }

    if (msg->result != 0) {
        snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE, "fail to oper %d", oper);
        goto done;
    }

    if (hdl_reply)
        err = hdl_reply(pcap, msg);
    else
        err = 0; /* success */

done:
    if (msg)
        ff_ipc_msg_free(msg);
    return err;
}

static int
pcap_ff_handle_pkt(pcap_t *pcap, pcap_handler cb, u_char *user,
                   struct ff_pcap_pkt *pkt)
{
    int pkt_len, cap_len;
    uint8_t *bp;
    struct pcap_pkthdr caphdr;

    pkt_len = pkt->pkt_len;

    bp = pkt->buffer + pkt->offset;

    if (pkt->vlan) {
        struct vlan_tag *tag;

        if (pkt->offset < VLAN_TAG_LEN) {
            /* head room not enough, drop (or copy it ?) */
            return -1;
        }

        bp -= VLAN_TAG_LEN;
        memmove(bp, bp + VLAN_TAG_LEN, 2 * ETH_ALEN);

        tag = (struct vlan_tag *)(bp + 2 * ETH_ALEN);
        tag->vlan_tpid = htons(ETH_P_8021Q);
        tag->vlan_tci = htons(pkt->vlan_tci);

        pkt_len += VLAN_TAG_LEN;
    }

    cap_len = pkt_len;
    if (cap_len > pcap->snapshot)
        cap_len = pcap->snapshot;

    if (timerisset(&pkt->ts)) {
        caphdr.ts = pkt->ts;
    } else {
        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);

        caphdr.ts.tv_sec = tp.tv_sec;
        caphdr.ts.tv_usec = tp.tv_nsec / 1000;
    }

    caphdr.caplen = cap_len;
    caphdr.len = pkt_len;

    cb(user, &caphdr, bp);

    return 0;
}

static int
pcap_ff_read(pcap_t *pcap, int max, pcap_handler cb, u_char *user)
{
    int quota = max;
    struct ff_pcap_pkt *pkt;
    struct pcap_pkthdr caphdr;
    struct pcap_fstack *priv = pcap->priv;

    assert(pcap_pool && pcap_ring_rd);

    while (quota-- > 0) {
        if (rte_ring_dequeue(pcap_ring_rd, (void **)&pkt) != 0)
            break;

        if (priv->ifindex && pkt->ifindex != priv->ifindex)
            priv->pkt_miss++;
        else if (pcap_ff_handle_pkt(pcap, cb, user, pkt) == 0)
            priv->pkt_read++;
        else
            priv->pkt_drop++;

        rte_mempool_put(pcap_pool, pkt);
    }

    return 0;
}

static int
handle_stats_reply(void *user, const struct ff_msg *reply)
{
    struct pcap_stat *stats = user;

    stats->ps_ifdrop = reply->pcap.ifdrops;
    return 0;
}

static int
pcap_ff_stats(pcap_t *pcap, struct pcap_stat *stats)
{
    struct pcap_fstack *priv = pcap->priv;

    stats->ps_recv = priv->pkt_read;
    stats->ps_drop = priv->pkt_drop;

    return pcap_ff_ipc(pcap, FF_PCAP_STATS, handle_stats_reply, stats);
}

static void
pcap_ff_cleanup(pcap_t *pcap)
{
    struct pcap_fstack *priv = pcap->priv;

    if (priv->close_promisc)
        pcap_ff_set_promisc(priv->ifname, false);

    pcap_ff_ipc(pcap, FF_PCAP_STOP, NULL, NULL);
    return;
}

static int
pcap_ff_check(const char *name _U_)
{
	return 1; /* always usable */
}

static int
pcap_activate_ff(pcap_t *pcap)
{
    struct pcap_fstack *priv = pcap->priv;
    const char *device;
    int err = 0;

    device = pcap->opt.device;
    if (strlen(device) >= sizeof(IFNAMSIZ)) {
        err = PCAP_ERROR_NO_SUCH_DEVICE;
        goto errout;
    }

    snprintf(priv->ifname, IFNAMSIZ, "%s", device);
    priv->ifindex = if_nametoindex(device);
    if (priv->ifindex == 0 && strcmp(device, "any") != 0) {
        err = PCAP_ERROR_NO_SUCH_DEVICE;
        goto errout;
    }

    pcap->cleanup_op = pcap_ff_cleanup;
    pcap->read_op = pcap_ff_read;
    pcap->stats_op = pcap_ff_stats;

    if (strcmp(device, "any") == 0) {
        if (pcap->opt.promisc) {
            pcap->opt.promisc = 0;
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
			         "Promiscuous mode not supported on the \"any\" device");
            err = PCAP_WARNING_PROMISC_NOTSUP;
        }
    } else { /* not "any" device */
        if (pcap->opt.promisc) {
            if (pcap_ff_set_promisc(device, true) != 0) {
                snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
                        "fail to set promisc mode");
                err = PCAP_WARNING_PROMISC_NOTSUP;
            }

            priv->close_promisc = 1;
        }
    }

    if (pcap->snapshot <= 0 || pcap->snapshot > MAXIMUM_SNAPLEN)
        pcap->snapshot = MAXIMUM_SNAPLEN;

    /* use ff_pcap_pkt.buffer directly instead of pcap->buffer,
     * to reduce a copy. */

    return pcap_ff_ipc(pcap, FF_PCAP_START, NULL, NULL);

errout:
    pcap_ff_cleanup(pcap);
    return err;
}

pcap_t *
pcap_create_interface(const char *device, char *ebuf)
{
    pcap_t *pcap;

    pcap = pcap_create_common(ebuf, sizeof(struct pcap_fstack));
    if (!pcap)
        return NULL;

    pcap->activate_op = pcap_activate_ff;
}

int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
    /* getifaddrs works on f-stack () */
    return pcap_findalldevs_interfaces(alldevsp, errbuf, pcap_ff_check);
}
