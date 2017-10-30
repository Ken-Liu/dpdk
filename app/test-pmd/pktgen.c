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
	if (rte_pktmbuf_alloc_bulk(exp->pool,
			pkts_burst, nb_to_tx))
		return -1;
	for (i = 0; i < nb_to_tx; i++) {
		exp = pg_task_template_get(task, task->stats.count + i);
		rte_memcpy(rte_pktmbuf_mtod(pkts_burst[i], void *),
				rte_pktmbuf_mtod(exp, void *),
				exp->data_len);
		pkts_burst[i]->pkt_len = exp->pkt_len;
		pkts_burst[i]->data_len = exp->data_len;
		pkts_burst[i]->ol_flags = exp->ol_flags;
		pg_debug(pkts_burst[i], task->verbose, fs, 0);
	}
	return 0;
}

static inline int
pg_start(struct pktgen_task *task, uint64_t start_tsc)
{
	/* even round end, has to check tx stats */
	if (unlikely(task->stats.active == PKTGEN_TASK_END))
		return -1;
	if (!task->stats.start)
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
	task->stats.end = rte_rdtsc();
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
	if (task->stats.count == task->count) {
		if (pg_round_end(task)) /* end of taks? */
			pg_end(task);
	}
	return 0;
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

	if (pg_start(task, start_tsc))
		return -1;
	if (task->count) {
		nb_to_rx = task->count - task->stats.count;
		if (nb_to_rx > nb_pkt_per_burst)
			nb_to_rx = nb_pkt_per_burst;
	} else /* endless rx */
		nb_to_rx = nb_pkt_per_burst;
	if (nb_to_rx && task->stats.active == PKTGEN_TASK_START) {
		nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
				pkts_burst, nb_pkt_per_burst);
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
		fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
		if (unlikely(nb_rx == 0))
			return 0;
		for (i = 0; i < nb_rx; i++) {
			verbose = task->verbose;
			if (task->data) {
				r = pg_mbuf_expect(fs, task, pkts_burst[i], task->stats.count + i);
				if (r < 0) /* task timeout */
					return r;
				else if (r) /* compare failed, simple dump */
					verbose |= 0x10;
			}
			pg_debug(pkts_burst[i], verbose, fs, 1);
			rte_pktmbuf_free(pkts_burst[i]);
		}
		fs->rx_packets += nb_rx;
		task->stats.count += nb_rx;
	}
	if (task->count && task->stats.count >= task->count) {
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

	pktgen_idle_mode = res->mode;
	printf("PktGen idle mode: %hhu\n", res->mode);
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
