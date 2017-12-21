/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_string_fns.h>
#include <cmdline.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_socket.h>
#ifdef RTE_LIBRTE_PYTHON
#include <rte_python.h>
#endif

#include "testpmd.h"

#define PKTGEN_ROUND_END 0x1
#define PKTGEN_TASK_END 0x0
#define PKTGEN_TASK_START 0x3
struct pktgen_task_stats{
	uint8_t active;
	uint16_t round;		/* number txrx */
	uint64_t count;
	uint64_t start; 	/* start tsc */
	uint64_t end;		/* end tsc */
};

struct pktgen_task {
	void *data;		/* rx: tx; tx: mbuf[] */
	uint64_t count;
	char *field;		/* field to match */
	uint64_t val;		/* field value */
	uint16_t round;		/* number txrx */
	uint16_t cnt_mbufs;	/* number of templates */
	uint8_t verbose:7;
	uint8_t txrx:1; 	/* txrx type task */
	struct pktgen_task_stats stats;
} __rte_cache_aligned;

static void *pktgen_tx_tasks;
static void *pktgen_rx_tasks;
static int pktgen_idle_mode = 2; /* 0-drop 1-loopback 2-forward 3-switch */
static int pktgen_busy = 0;

static inline struct rte_mbuf *
pg_task_template_get(struct pktgen_task* task, uint32_t idx)
{
	struct rte_mbuf **mbufs = task->data;

	return mbufs ? mbufs[idx % task->cnt_mbufs] : NULL;
}

static inline struct pktgen_task *
task_tx(portid_t port, queueid_t queue)
{
	RTE_ASSERT(pktgen_tx_tasks);
	struct pktgen_task (*tasks)[nb_txq] = pktgen_tx_tasks;
	return &tasks[port][queue];
}

static inline struct pktgen_task *
task_rx(portid_t port, queueid_t queue)
{
	RTE_ASSERT(pktgen_rx_tasks);
	struct pktgen_task (*tasks)[nb_rxq] = pktgen_rx_tasks;
	return &tasks[port][queue];
}

/********************************************************/
/* Forwarding thread functions                          */
/********************************************************/

static inline void
pg_dump_mbuf_header(struct rte_mbuf *mbuf, struct fwd_stream* fs, int is_rx) {
	char buf[256];

	printf("%s P:%hu Q:%hu len:%hu ptype:0x%x ol_flags:0x%lx rss:0x%08x fdir:0x%x\n",
			is_rx ? "RX" : "TX",
			is_rx ? fs->rx_port : fs->tx_port,
			is_rx ? fs->rx_queue : fs->tx_queue,
			mbuf->data_len, mbuf->packet_type,
			mbuf->ol_flags,
			mbuf->hash.rss, mbuf->hash.fdir.hi
			);
	if (mbuf->packet_type) {
		rte_get_ptype_name(mbuf->packet_type, buf, sizeof(buf));
		printf("  ptype: %s\n", buf);
	}
	if (mbuf->tx_offload)
		printf("  header len:%d/%d/%d/%d/%d tso len:%hu\n",
				mbuf->outer_l2_len, mbuf->outer_l3_len,
				mbuf->l2_len, mbuf->l3_len, mbuf->l4_len,
				mbuf->tso_segsz);
	else if (mbuf->ol_flags){
		rte_get_rx_ol_flag_list(mbuf->ol_flags, buf, sizeof(buf));
		printf("  ol_flags: %s\n", buf);
	}
}

static inline void
pg_debug(struct rte_mbuf *mbuf, uint8_t level, struct fwd_stream* fs, int is_rx)
{
	/* xxxx xxxx
	 *   ||	  L- 1: summary 2: repr 3:show
	 *   |L----- mbuf header
	 *   L------ hex dump
	 */
	if (level & 0x10)
		pg_dump_mbuf_header(mbuf, fs, is_rx);
#ifdef RTE_LIBRTE_PYTHON
	if (level)
		rte_python_scapy_dump(mbuf, level);
#else
	(void) mbuf;
#endif
}

static int
pg_mbuf_field_expect(struct fwd_stream* fs, struct pktgen_task *task,
		struct rte_mbuf *mbuf)
{
	#define OFF(field) offsetof(struct rte_mbuf, field)
	unsigned int i;
	uint64_t val;
	static struct {
		const char *name;
		uint8_t offset;
		uint8_t shift;
		uint64_t mask;
	} fields [] = {
		{"port", 	OFF(port), 		0, UINT16_MAX},
		{"ptype",	OFF(packet_type), 	0, UINT32_MAX},
		{"rss", 	OFF(hash.rss),		0, UINT32_MAX},
		{"fdir", 	OFF(hash.fdir.hi),	0, UINT32_MAX},
		/* ignore rss bit */
		{"ol_flags",	OFF(ol_flags), 		0, UINT64_MAX &
							   ~PKT_RX_RSS_HASH},
	};

	RTE_ASSERT(task && mbuf);
	if (!task->field || strlen(task->field) == 0)
		return 0;
	if (!strcmp(task->field, "queue")) {
		if (fs->rx_queue != task->val) {
			printf("Failed: queue expect: 0x%lu received:0x%hu\n",
					task->val, fs->rx_queue);
			return 1;
		} else
			return 0;
	}
	for (i = 0; i < RTE_DIM(fields); i++) {
		if (strcmp(task->field, fields[i].name))
			continue;
		val = *((uint64_t *)(void *)((char *)(void *)mbuf + fields[i].offset));
		val &= fields[i].mask;
		if ((val != (task->val & fields[i].mask))) {
			printf("Failed: %s mask: 0x%lx expect: 0x%lx received: 0x%lx\n",
				fields[i].name, fields[i].mask,
				task->val & fields[i].mask, val);
			return 1;
		} else
			return 0;
	}
	printf("Failed: unknown field '%s', valid names: queue,", task->field);
	for (i = 0; i < RTE_DIM(fields); i++)
		printf("%s%s", fields[i].name,
		       i == RTE_DIM(fields) - 1 ? ",non(0)\n" : ",");
	return 0;
}

static int
pg_mbuf_expect(struct fwd_stream* fs, struct pktgen_task *task,
		struct rte_mbuf *mbuf, uint32_t idx)
{
	int r = 0;
	struct rte_mbuf *exp;

	RTE_ASSERT(task && task->data && mbuf);
	exp = pg_task_template_get(task->data, idx); /* tx->mbuf */
	if (!exp) {
		RTE_LOG(ERR, USER1, "packet tempalte not found, timeout?\n");
		return -1;
	}
	r |= pg_mbuf_field_expect(fs, task, mbuf);
	if (exp->data_len != mbuf->data_len) {
		printf("Failed: packet length not same: %hu/%hu",
				 mbuf->data_len, exp->data_len);
		r |= 2;
	} else if (memcmp(
			rte_pktmbuf_mtod(mbuf, void *),
			rte_pktmbuf_mtod(exp, void *),
			mbuf->data_len)) {
		printf("Failed: packet not same:\n");
		r |= 4;
#ifdef RTE_LIBRTE_PYTHON
		rte_python_scapy_hexdiff(
			rte_pktmbuf_mtod(exp, void *), exp->data_len,
			rte_pktmbuf_mtod(mbuf, void *), mbuf->data_len);
#endif
	}
	return r;
}

static inline void
pg_mbuf_switch(struct rte_mbuf **pkts, uint16_t nb_to_tx)
{
	uint32_t i;
	struct ether_hdr *eth;
	struct ether_addr addr;

	for (i = 0; i < nb_to_tx; i++) {
		eth = rte_pktmbuf_mtod(pkts[i], struct ether_hdr *);
		ether_addr_copy(&eth->d_addr, &addr);
		ether_addr_copy(&eth->s_addr, &eth->d_addr);
		ether_addr_copy(&addr, &eth->s_addr);
	}
}

static inline uint16_t
pg_tx_burst(struct fwd_stream* fs, int mode,
		struct rte_mbuf **pkts_burst, uint16_t nb_to_tx)
{
	uint32_t retry;
	uint16_t nb_tx, i;
	portid_t port = mode == 1 ? fs->rx_port : fs->tx_port;
	queueid_t queue = mode == 1 ? fs->rx_queue : fs->tx_queue;

	if (unlikely(mode == 3))
		pg_mbuf_switch(pkts_burst, nb_to_tx);
	nb_tx = rte_eth_tx_burst(port, queue, pkts_burst,
			nb_to_tx);
	/* Retry if necessary */
	if (unlikely(nb_tx < nb_to_tx) && fs->retry_enabled)
	{
		retry = 0;
		while (nb_tx < nb_to_tx && retry++ < burst_tx_retry_num)
		{
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(port, queue,
					&pkts_burst[nb_tx], nb_to_tx - nb_tx);
		}
	}
	/* Drop packets failed to send */
	if (unlikely(nb_tx < nb_to_tx))
	{
		fs->fwd_dropped += (nb_to_tx - nb_tx);
		i = nb_tx;
		do {
			rte_pktmbuf_free(pkts_burst[i]);
		} while (++i < nb_to_tx);
	}
	return nb_tx;
}

static inline int
pg_tx_fill(struct rte_mbuf **pkts_burst, uint64_t nb_to_tx,
		struct pktgen_task *task, struct fwd_stream* fs)
{
	uint32_t i;
	struct rte_mbuf *exp;

	exp = pg_task_template_get(task, task->stats.count);
	RTE_ASSERT(exp && exp->pool);
	RTE_ASSERT(task->cnt_mbufs > 0);
	if (rte_pktmbuf_alloc_bulk(exp->pool, pkts_burst, nb_to_tx))
		return -1;
	for (i = 0; i < nb_to_tx; i++) {
		exp = pg_task_template_get(task, task->stats.count + i);
#ifdef MUBF_COPY
		(void)fs;
		rte_pktmbuf_attach(pkts_burst[i], exp);
#else
		rte_memcpy(rte_pktmbuf_mtod(pkts_burst[i], void *),
				rte_pktmbuf_mtod(exp, void *),
				RTE_ALIGN(exp->data_len, RTE_CACHE_LINE_SIZE));
		pkts_burst[i]->pkt_len = exp->pkt_len;
		pkts_burst[i]->data_len = exp->data_len;
		pkts_burst[i]->ol_flags = exp->ol_flags;
		pg_debug(pkts_burst[i], task->verbose, fs, 0);
#endif
	}
	return 0;
}

static inline int
pg_start(struct pktgen_task *task, uint64_t start_tsc)
{
	/* even round end, has to check tx stats */
	if (unlikely(task->stats.active == PKTGEN_TASK_END))
		return -1;
	if (unlikely(!task->stats.start))
		task->stats.start = start_tsc;
	return 0;
}

static inline int
pg_round_end(struct pktgen_task *task)
{
	/* if not txrx task, keep busy */
	if (unlikely(task->txrx))
		task->stats.active = PKTGEN_ROUND_END;
	task->stats.round += 1;
	return task->round == task->stats.round;
}

static inline void
pg_end(struct pktgen_task *task)
{
	task->stats.active = PKTGEN_TASK_END;
}

/* return -1 if nothing to do */
static inline int
pg_tx(struct fwd_stream* fs, struct pktgen_task *task,
		uint64_t start_tsc)
{
	struct rte_mbuf *pkts_burst[nb_pkt_per_burst];
	uint64_t nb_to_tx = 0;
	uint64_t nb_tx;

	if (pg_start(task, start_tsc))
		return -1;
	if (unlikely(task->stats.active != PKTGEN_TASK_START))
		return -1;
	if (task->count) {
		nb_to_tx = task->count - task->stats.count;
		if (nb_to_tx > nb_pkt_per_burst)
			nb_to_tx = nb_pkt_per_burst;
	} else
			nb_to_tx = nb_pkt_per_burst;
	if (likely((nb_to_tx && task->data))) {
		if (unlikely((pg_tx_fill(pkts_burst, nb_to_tx, task, fs))))
			return -1;
		nb_tx = pg_tx_burst(fs, 2, pkts_burst, nb_to_tx);
		fs->tx_packets += nb_tx;
		task->stats.count += nb_tx;
	}
	if (unlikely(task->stats.count == task->count)) {
		if (pg_round_end(task)) /* end of taks? */
			pg_end(task);
	}
	return 0;
}

static inline void
mbuf_free_bulk(struct rte_mbuf *pkts[], uint16_t nb)
{
	struct rte_mbuf *to_free[32];
	struct rte_mbuf *m;
	struct rte_mbuf *m_next;
	uint16_t i, n = 0;

	for (i = 0; i < nb; i++) {
		__rte_mbuf_sanity_check(pkts[i], 1);
		m = pkts[i];
		while (m != NULL) {
			m_next = m->next;
			m = rte_pktmbuf_prefree_seg(m);
			if (likely(m != NULL)) {
				RTE_ASSERT(RTE_MBUF_DIRECT(m));
				RTE_ASSERT(rte_mbuf_refcnt_read(m) == 1);
				RTE_ASSERT(m->next == NULL);
				RTE_ASSERT(m->nb_segs == 1);
				__rte_mbuf_sanity_check(m, 0);
				to_free[n++] = m;
				if (unlikely(n == 32)) {
					rte_mempool_put_bulk(m->pool, (void *)to_free, n);
					n = 0;
				}
			}
			m = m_next;
		}
	}
	if (n)
		rte_mempool_put_bulk(to_free[0]->pool, (void *)to_free, n);
}

/* return -1 if nothing to do */
static inline int
pg_rx(struct fwd_stream* fs, struct pktgen_task *task, uint64_t start_tsc)
{
	struct rte_mbuf *pkts_burst[nb_pkt_per_burst];
	uint16_t nb_to_rx;
	uint16_t nb_rx;
	uint32_t i;
	uint8_t verbose;
	struct pktgen_task *tx_task;
	int r;

	if (unlikely(pg_start(task, start_tsc)))
		return -1;
	if (unlikely(task->count)) {
		nb_to_rx = task->count - task->stats.count;
		if (nb_to_rx > nb_pkt_per_burst)
			nb_to_rx = nb_pkt_per_burst;
	} else /* endless rx */
		nb_to_rx = nb_pkt_per_burst;
	if (likely(nb_to_rx && task->stats.active == PKTGEN_TASK_START)) {
		nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
				pkts_burst, nb_pkt_per_burst);
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
		fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
		if (unlikely(nb_rx == 0))
			return 0;
		verbose = task->verbose;
		for (i = 0; i < nb_rx; i++) {
			if (unlikely(task->txrx && task->data)) {
				r = pg_mbuf_expect(fs, task, pkts_burst[i], task->stats.count + i);
				if (r < 0) /* task timeout */
					return r;
				else if (r) /* compare failed, simple dump */
					verbose |= 0x10;
			}
			pg_debug(pkts_burst[i], verbose, fs, 1);
		}
		mbuf_free_bulk(pkts_burst, nb_rx);
		task->stats.end = start_tsc;
		fs->rx_packets += nb_rx;
		task->stats.count += nb_rx;
	}
	if (unlikely(task->count && task->stats.count >= task->count)) {
		tx_task = task->data;
		if (task->stats.active == PKTGEN_TASK_START && pg_round_end(task))
			pg_end(task);
		else if (tx_task && tx_task->stats.active==PKTGEN_ROUND_END) {
			/* has tx task, next round */
			tx_task->stats.active =	PKTGEN_TASK_START;
			tx_task->stats.count = 0;
			task->stats.active = PKTGEN_TASK_START;
			task->stats.count = 0;
		}
	}
	return 0;
}

static void
pg_idle_set(int mode)
{
	const char *names[] = {
			"drop(0)",
			"loopback(1)",
			"io_forward(2)",
			"mac_switch(3)"};
	if (pktgen_idle_mode != mode)
		printf("PktGen idle mode changed from %s to %s\n",
		       names[pktgen_idle_mode], names[mode]);
	pktgen_idle_mode = mode;
}

static inline int
pg_rx_idle(struct fwd_stream* fs)
{
	struct rte_mbuf *pkts_burst[nb_pkt_per_burst];
	uint16_t nb_rx;
	uint32_t i;

	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
				pkts_burst, nb_pkt_per_burst);
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	if (unlikely(nb_rx == 0))
		return 0;
	fs->rx_packets += nb_rx;
	if (verbose_level & 0xff)
		for (i = 0; i < nb_rx; i++)
			pg_debug(pkts_burst[i], verbose_level & 0xff, fs, 1);
	if (pktgen_idle_mode) /* no drop */
		pg_tx_burst(fs, pktgen_idle_mode, pkts_burst, nb_rx);
	else /* drop */
		for (i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(pkts_burst[i]);
	return 0;
}

/*
 * TX and RX pacets according to traffic generator command.
 */
static void
pg_fwd(struct fwd_stream *fs)
{
	uint64_t start;
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif

	start = rte_rdtsc();
	if (likely(pktgen_busy)) {
		pg_tx(fs, task_tx(fs->tx_port, fs->tx_queue), start);
		pg_rx(fs, task_rx(fs->rx_port, fs->rx_queue), start);
	} else
		pg_rx_idle(fs);
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles += fs->core_cycles + core_cycles;
#endif
}

static void
pktgen_begin(portid_t pi __rte_unused)
{
	if (!pktgen_tx_tasks)
		pktgen_tx_tasks = rte_malloc(NULL,
			sizeof(struct pktgen_task) * nb_ports * nb_txq, 0);
	if (!pktgen_tx_tasks)
		RTE_LOG(ERR, USER1, "out of memory?\n");
	if (!pktgen_rx_tasks)
		pktgen_rx_tasks = rte_malloc(NULL,
			sizeof(struct pktgen_task) * nb_ports * nb_rxq, 0);
	if (!pktgen_rx_tasks)
		RTE_LOG(ERR, USER1, "out of memory?\n");
}

static void
pktgen_end(portid_t pi __rte_unused)
{
	if (pktgen_tx_tasks)
		rte_free(pktgen_tx_tasks);
	pktgen_tx_tasks = NULL;
	if (pktgen_rx_tasks)
		rte_free(pktgen_rx_tasks);
	pktgen_rx_tasks = NULL;
}

struct fwd_engine pktgen_engine = {
	.fwd_mode_name  = "pktgen",
	.port_fwd_begin = pktgen_begin,
	.port_fwd_end   = pktgen_end,
	.packet_fwd     = pg_fwd,
};

/********************************************************/
/* Control thread functions                             */
/********************************************************/

#ifdef RTE_LIBRTE_PYTHON

#define US_TSC(us) ((us) * (rte_get_timer_hz() / 1000000L));
#define TSC_US(tsc) ((tsc) * 1e6 / rte_get_timer_hz())

struct cmd_pktgen_cmd {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t pattern;
	portid_t port;
	uint64_t count;
	uint64_t round;
	uint16_t timeout; /* unit: ms */
	uint16_t verbose;
	struct pktgen_task_stats stats;
};

struct cmd_pg_txrx_cmd {
	cmdline_fixed_string_t expect;
	struct cmd_pktgen_cmd tx;
	struct cmd_pktgen_cmd rx;
	cmdline_fixed_string_t field;
	uint64_t val;
};

/*
 * get min/max time and count sum
 */
static void
cmd_pg_port_poll(portid_t port, struct pktgen_task_stats *sum, int tx)
{
	struct pktgen_task* task;
	queueid_t i, n;

	n = tx ? nb_txq : nb_rxq;
	for (i = 0, sum->count = 0; i < n; i++) {
		task = tx ? task_tx(port, i) : task_rx(port, i);
		sum->count += task->stats.count;
		if (task->stats.round > sum->round)
			sum->round = task->stats.round;
		if (task->stats.start) {
			if (sum->start && task->stats.start < sum->start)
				sum->start = task->stats.start;
			if (!sum->start)
				sum->start = task->stats.start;
			if (sum->end < task->stats.end)
				sum->end = task->stats.end;
		}
	}
}

static struct rte_mbuf **
cmd_pg_scapy_to_mbuf(char *scapy, portid_t port, uint16_t *count)
{
	int socket;
	struct rte_mempool *pool;

	if (numa_support) {
		socket = port_numa[port];
		if (socket == NUMA_NO_CONFIG)
			socket = ports[port].socket_id;
	} else
		socket = socket_num;
	if (socket_num == UMA_NO_CONFIG)
		socket = 0;
	pool = mbuf_pool_find(socket);
	return rte_python_scapy_to_mbufs(pool, scapy, count);
}

static inline int
cmd_pg_init(void)
{
	if (rte_python_init())
		return -1;
	if (pktgen_idle_mode != 0) {
		pg_idle_set(0);
		rte_delay_ms(1);
	}
	if (cur_fwd_eng != &pktgen_engine) {
		set_pkt_forwarding_mode(pktgen_engine.fwd_mode_name);
		if (!test_done)
			stop_packet_forwarding();
	}
	if (test_done)
		start_packet_forwarding(0);
	/* reset task memory */
	RTE_ASSERT(pktgen_tx_tasks && pktgen_rx_tasks);
	memset(pktgen_tx_tasks, 0,
			nb_ports * nb_txq * sizeof(struct pktgen_task));
	memset(pktgen_rx_tasks, 0,
			nb_ports * nb_rxq * sizeof(struct pktgen_task));
	return 0;
}

static void
cmd_pg_cleanup(struct cmd_pg_txrx_cmd *cmd)
{
	struct pktgen_task *task;
	queueid_t q;
	uint16_t m;

	RTE_ASSERT(pktgen_tx_tasks && pktgen_rx_tasks);
	rte_delay_ms(100); /* wait active tasks */
	/* free all tx queue mbufs */
	for (q = 0; q < nb_txq; q++) {
		task = task_tx(cmd->tx.port, q);
		if (!task->data || !task->cnt_mbufs)
			continue;
		m = task->cnt_mbufs;
		while(m)
			rte_pktmbuf_free(pg_task_template_get(task, --m));
		rte_free(task->data);
	}
}

static void
cmd_pg_rx(struct cmd_pg_txrx_cmd *cmd)
{
	struct pktgen_task *task;
	int i;

	RTE_ASSERT(cmd);
	memset(&cmd->rx.stats, 0, sizeof(cmd->rx.stats));
	for (i = 0; i < nb_rxq; i++) {
		task = task_rx(cmd->rx.port, i);
		if (cmd->tx.count)
			task->data = task_tx(cmd->tx.port, 0);
		task->count = cmd->rx.count;
		task->round = cmd->rx.round;
		task->verbose = cmd->rx.verbose & 0xff;
		if (cmd->field && strlen(cmd->field)) {
				task->field = cmd->field;
				task->val = cmd->val;
		}
		task->stats.active = PKTGEN_TASK_START;
	}
}

static int
cmd_pg_tx(struct cmd_pktgen_cmd* cmd, int txrx)
{
	struct pktgen_task *task;
	uint16_t n_pkts = 0;
	uint16_t i;
	uint64_t count = 0;
	queueid_t q;
	struct rte_mbuf** mbufs;
	struct rte_mbuf** qbufs;

	RTE_ASSERT(cmd);
	mbufs = cmd_pg_scapy_to_mbuf(cmd->pattern, cmd->port, &n_pkts);
	if (!mbufs) {
		printf("Wrong syntax or out of memory\n");
		return -1;
	}
	if (cmd->count == UINT64_MAX) /* auto detection */
		cmd->count = n_pkts;
	if (txrx && (!cmd->count || cmd->count > n_pkts))
		txrx = 0; /* don't compare result */
	for (q = 0; q < nb_txq; q++) {
		if (cmd->count) {
			count = cmd->count / nb_txq +
				((cmd->count % nb_txq) > q ? 1 : 0);
			if (!count)
				break;
		}
		task = task_tx(cmd->port, q);
		memset(&cmd->stats, 0, sizeof(cmd->stats));
		if (q == 0)
			task->data = mbufs;
		else {
			qbufs = rte_malloc(NULL, sizeof(void *) * n_pkts, 0);
			if (!qbufs) {
				printf("Out of memory?\n");
				return -1;
			}
			for (i = 0; i < n_pkts; i++) {
				rte_pktmbuf_refcnt_update(mbufs[i], 1);
				qbufs[i] = mbufs[i];
			}
			task->data = qbufs;
		}
		task->cnt_mbufs = n_pkts;
		task->count = count;
		task->round = cmd->round;
		task->verbose = cmd->verbose & 0xff;
		task->txrx = txrx;
		task->stats.active = PKTGEN_TASK_START;
	}
	return 0;
}

static void
cmd_pg_wait(struct cmdline *cl, struct cmd_pktgen_cmd* cmd,
		uint64_t timeout, int tx)
{
	char c = 0;
	int flags;
	uint64_t start = rte_rdtsc();

	flags = fcntl(cl->s_in, F_GETFL, 0);
	RTE_ASSERT(flags >= 0);
	fcntl(cl->s_in, F_SETFL, flags | O_NONBLOCK);
	memset(&cmd->stats, 0, sizeof(cmd->stats));
	while (1) {
		cmd_pg_port_poll(cmd->port, &cmd->stats, tx);
		if (cmd->count && cmd->round == cmd->stats.round)
			break;
		if (timeout && rte_rdtsc() > timeout)
			break;
		/* detect ctrl+c or ctrl+d if cmd longer than 3 sec */
		if (TSC_US(rte_rdtsc() - start) > 1e6 /* (!timeout && !cmd->count) */
		    && read(cl->s_in, &c, 1) && (c == 3 || c == 4))
			break;
		rte_delay_ms(1);
	}
	if (!cmd->stats.end)
		cmd->stats.end = rte_rdtsc();
	fcntl(cl->s_in, F_SETFL, flags);
}

/* expect command */
cmdline_parse_token_string_t cmd_expect_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pg_txrx_cmd, expect, "expect");
cmdline_parse_token_num_t cmd_expect_tx_port =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.port, UINT16);
cmdline_parse_token_num_t cmd_expect_rx_port =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, rx.port, UINT16);
cmdline_parse_token_string_t cmd_expect_pattern =
	TOKEN_STRING_INITIALIZER(struct cmd_pg_txrx_cmd, tx.pattern, NULL);
cmdline_parse_token_num_t cmd_expect_count =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.count, UINT64);
cmdline_parse_token_num_t cmd_expect_round =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.round, UINT64);
cmdline_parse_token_num_t cmd_expect_rx_timeout =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, rx.timeout, UINT64);
cmdline_parse_token_num_t cmd_expect_verbose =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.verbose, UINT16);
cmdline_parse_token_string_t cmd_expect_field =
	TOKEN_STRING_INITIALIZER(struct cmd_pg_txrx_cmd, field, NULL);
cmdline_parse_token_num_t cmd_expect_val =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, val, UINT64);

static void
cmd_expect_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pg_txrx_cmd *cmd = parsed_result;
	struct pktgen_task_stats *stats_tx = &cmd->tx.stats;
	struct pktgen_task_stats *stats_rx = &cmd->rx.stats;
	uint64_t timeout = 0;

	if (port_id_is_invalid(cmd->tx.port, ENABLED_WARN) ||
		port_id_is_invalid(cmd->rx.port, ENABLED_WARN))
		return;
	if (cmd_pg_init())
		return;
	if (!strcmp(cmd->field, "non") || !strcmp(cmd->field, "0"))
		cmd->field[0] = 0;
	cmd->rx.verbose = cmd->tx.verbose & 0xff;
	cmd->tx.verbose = cmd->tx.verbose >> 8;
	cmd->rx.round = cmd->tx.round;
	cmd->rx.count = cmd->tx.count;
	/* prepare task */
	if (cmd_pg_tx(&cmd->tx, 1))
		return;
	if (cmd->rx.count == UINT64_MAX)
		cmd->rx.count = cmd->tx.count;
	cmd_pg_rx(cmd);
	/* wait task */
	if (cmd->rx.timeout)
		timeout = rte_rdtsc() + US_TSC(cmd->rx.timeout * 1000) ;
	pktgen_busy = 1;
	cmd_pg_wait(cl, &cmd->tx, timeout, 1);
	cmd_pg_wait(cl, &cmd->rx, timeout, 0);
	pktgen_busy = 0;
	/* print stats */
	float t_tx = TSC_US(stats_tx->end - stats_tx->start);
	float t_rx = TSC_US(stats_rx->end - stats_rx->start);
	float t_ttl = TSC_US(RTE_MAX(stats_rx->end, stats_tx->end) -
			RTE_MIN(stats_rx->start, stats_tx->start));
	if (cmd->rx.count == 0)
		stats_rx->round = 1;
	int failed = (stats_tx->round != cmd->tx.round ||
			stats_rx->round != cmd->rx.round ||
			stats_rx->count != cmd->rx.count);
	if (stats_tx->round == 0)
		stats_tx->round = 1;
	if (stats_rx->round == 0)
		stats_rx->round = 1;
	uint64_t nb_tx = stats_tx->count + cmd->tx.count * (stats_tx->round - 1);
	uint64_t nb_rx = stats_rx->count + cmd->rx.count * (stats_rx->round - 1);
	if (failed || !(verbose_level & 0x40)) /* mute */
		printf("%s"
			"tx: %lu/%lu %.3fus %fmpps"
			"\trx: %lu/%lu %.3fus %fmpps"
			"\tround: %u/%lu %.3fus"
			"\ttotal: %.3fus %fmpps\n",
			failed ? "Failed " : "",
			nb_tx, cmd->tx.count * cmd->tx.round, t_tx, nb_tx/t_tx,
			nb_rx, cmd->rx.count * cmd->rx.round, t_rx, nb_rx/t_rx,
			stats_rx->round, cmd->rx.round, t_ttl / stats_rx->round,
			t_ttl, nb_rx / t_ttl);
	/* clean up */
	cmd_pg_cleanup(cmd);
}

cmdline_parse_inst_t cmd_expect = {
	.f = cmd_expect_parsed,
	.data = NULL,
	.help_str = "expect <tx_port> <rx_port> <scapy> <count> <round> <timeout(ms)> <verbose> <field> <val>\n"
			"\t\t\tSend packet and expecting same back",
	.tokens = {
		(void *)&cmd_expect_cmd,
		(void *)&cmd_expect_tx_port,
		(void *)&cmd_expect_rx_port,
		(void *)&cmd_expect_pattern,
		(void *)&cmd_expect_count,
		(void *)&cmd_expect_round,
		(void *)&cmd_expect_rx_timeout,
		(void *)&cmd_expect_verbose,
		(void *)&cmd_expect_field,
		(void *)&cmd_expect_val,
		NULL,
	},
};

static void
cmd_expect_short_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pg_txrx_cmd *res = parsed_result;

	/* memory not clean, have to clear unused fields */
	res->tx.round = 1;
	res->tx.count = UINT64_MAX; /* detect from pattern */
	res->tx.verbose = verbose_level;
	res->rx.timeout = 20;
	res->rx.verbose = verbose_level & 0xff;
	res->field[0] = 0;
	cmd_expect_parsed(res, cl, data);

}

cmdline_parse_inst_t cmd_expect_short = {
	.f = cmd_expect_short_parsed,
	.data = NULL,
	.help_str = "expect <tx_port> <rx_port> <scapy>: tx 1 and expect 1",
	.tokens = {
		(void *)&cmd_expect_cmd,
		(void *)&cmd_expect_tx_port,
		(void *)&cmd_expect_rx_port,
		(void *)&cmd_expect_pattern,
		NULL,
	},
};

/* tx command */

cmdline_parse_token_string_t cmd_tx_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pg_txrx_cmd, tx.cmd, "tx");
cmdline_parse_token_string_t cmd_tx_pattern =
	TOKEN_STRING_INITIALIZER(struct cmd_pg_txrx_cmd, tx.pattern, NULL);
cmdline_parse_token_num_t cmd_tx_port =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.port, UINT16);
cmdline_parse_token_num_t cmd_tx_count =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.count, UINT64);
cmdline_parse_token_num_t cmd_tx_verbose =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, tx.verbose, UINT16);

static void
cmd_tx_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pg_txrx_cmd *cmd = parsed_result;

	if (port_id_is_invalid(cmd->tx.port, ENABLED_WARN))
		return;
	if (cmd_pg_init())
		return;
	memset(&cmd->rx, 0, sizeof(cmd->rx));
	cmd->tx.round = 1;
	if (cmd_pg_tx(&cmd->tx, 0))
		return;
	pktgen_busy = 1;
	cmd_pg_wait(cl, &cmd->tx, 0, 1);
	pktgen_busy = 0;
	double t = TSC_US(cmd->tx.stats.end - cmd->tx.stats.start);
	printf("%s%lu/%lu packets sent in %.3fus %fmpps\n",
			cmd->tx.count && cmd->tx.stats.count != cmd->tx.count ?
					"Failed: " : "",
			cmd->tx.stats.count, cmd->tx.count, t,
			cmd->tx.stats.count / t);
	cmd_pg_cleanup(cmd);
}

cmdline_parse_inst_t cmd_tx = {
	.f = cmd_tx_parsed,
	.data = NULL,
	.help_str = "tx <port> <scapy> <count> <verbose>",
	.tokens = {
		(void *)&cmd_tx_cmd,
		(void *)&cmd_tx_port,
		(void *)&cmd_tx_pattern,
		(void *)&cmd_tx_count,
		(void *)&cmd_tx_verbose,
		NULL,
	},
};

static void
cmd_tx_short_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pg_txrx_cmd *cmd = parsed_result;

	cmd->tx.count = 0;
	cmd->tx.verbose = verbose_level >> 8;
	cmd_tx_parsed(cmd, cl, data);
}

cmdline_parse_inst_t cmd_tx_short = {
	.f = cmd_tx_short_parsed,
	.data = NULL,
	.help_str = "tx <port> <scapy>: tx 0 Ether()/IP()/UDP()",
	.tokens = {
		(void *)&cmd_tx_cmd,
		(void *)&cmd_tx_port,
		(void *)&cmd_tx_pattern,
		NULL,
	},
};

/* rx command */
cmdline_parse_token_string_t cmd_rx_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pg_txrx_cmd, rx, "rx");
cmdline_parse_token_num_t cmd_rx_port =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, rx.port, UINT16);
cmdline_parse_token_num_t cmd_rx_count =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, rx.count, UINT64);
cmdline_parse_token_num_t cmd_rx_timeout =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, rx.timeout, UINT16);
cmdline_parse_token_num_t cmd_rx_verbose =
	TOKEN_NUM_INITIALIZER(struct cmd_pg_txrx_cmd, rx.verbose, UINT16);

/* Common result structure for rx commands */
static void
cmd_rx_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pg_txrx_cmd *cmd = parsed_result;
	uint64_t timeout = 0;

	if (port_id_is_invalid(cmd->rx.port, ENABLED_WARN))
		return;
	if (cmd_pg_init())
		return;
	memset(&cmd->tx, 0, sizeof(cmd->tx));
	cmd->field[0] = 0;
	cmd->rx.round = 1;
	cmd_pg_rx(cmd);
	if (cmd->rx.timeout)
		timeout =  rte_rdtsc() + US_TSC(cmd->rx.timeout * 1e6);
	pktgen_busy = 1;
	cmd_pg_wait(cl, &cmd->rx, timeout, 0);
	pktgen_busy = 0;
	/* print stats */
	float t = TSC_US(cmd->rx.stats.end - cmd->rx.stats.start);
	printf("%s%lu/%lu packets received in %.3fus %fmpps\n",
			cmd->rx.count && cmd->rx.stats.count != cmd->rx.count ?
					"Failed: " : "",
			cmd->rx.stats.count, cmd->rx.count, t,
			t ? cmd->rx.stats.count / t : 0);
	/* clean up */
	cmd_pg_cleanup(cmd);
}

cmdline_parse_inst_t cmd_rx = {
	.f = cmd_rx_parsed,
	.data = NULL,
	.help_str = "rx <port> <count> <timeout(s)> <verbose>",
	.tokens = {
		(void *)&cmd_rx_cmd,
		(void *)&cmd_rx_port,
		(void *)&cmd_rx_count,
		(void *)&cmd_rx_timeout,
		(void *)&cmd_rx_verbose,
		NULL,
	},
};

static void
cmd_rx_short_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pg_txrx_cmd *cmd = parsed_result;

	cmd->rx.count = 0; /* endless */
	cmd->rx.timeout = 0; /* endless */
	cmd->rx.verbose = verbose_level;
	cmd_rx_parsed(cmd, cl, data);
}

cmdline_parse_inst_t cmd_rx_short = {
	.f = cmd_rx_short_parsed,
	.data = NULL,
	.help_str = "rx <port>",
	.tokens = {
		(void *)&cmd_rx_cmd,
		(void *)&cmd_rx_port,
		NULL,
	},
};

#endif

/* "pktgen loopback" command */
struct cmd_pktgen_cmd_result {
	cmdline_fixed_string_t pktgen;
	cmdline_fixed_string_t cmd;
	uint8_t mode;
};

cmdline_parse_token_string_t cmd_pktgen_cmd_pktgen =
	TOKEN_STRING_INITIALIZER(struct cmd_pktgen_cmd_result, pktgen, "pktgen");
cmdline_parse_token_string_t cmd_pktgen_cmd_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pktgen_cmd_result, cmd, "idle");
cmdline_parse_token_string_t cmd_pktgen_cmd_mode =
		TOKEN_NUM_INITIALIZER(struct cmd_pktgen_cmd_result, mode, UINT8);

static void
cmd_pktgen_cmd_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pktgen_cmd_result *res = parsed_result;

	pg_idle_set(res->mode);
}

cmdline_parse_inst_t cmd_pktgen_cmd = {
	.f = cmd_pktgen_cmd_parsed,
	.data = NULL,
	.help_str = "pktgen idle <mode>: 0-drop 1-loopback 2-forward 3-switch",
	.tokens = {
		(void *)&cmd_pktgen_cmd_pktgen,
		(void *)&cmd_pktgen_cmd_cmd,
		(void *)&cmd_pktgen_cmd_mode,
		NULL,
	},
};
