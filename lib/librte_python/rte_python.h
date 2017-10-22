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

#ifndef _RTE_REORDER_H_
#define _RTE_REORDER_H_

/**
 * @file
 * RTE python
 *
 * Python library is a component which is designed to
 * provide embedded python support, major functions:
 * 1. use of scapy module to generate or display packet
 * 2. evaluate mbuf result with expression *
 */


#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int rte_python_debug;

int rte_python_init(void);
void rte_python_close(void);
struct rte_mbuf *rte_python_scapy_to_mbuf(struct rte_mempool *pool,
					  char *pattern);
struct rte_mbuf **rte_python_scapy_to_mbufs(struct rte_mempool *pool,
					    char *pattern, uint16_t *count);
int rte_python_scapy_dump(struct rte_mbuf *mbuf, int verbose);
int rte_python_scapy_hexdiff(void *src, int slen, void *dst, int dlen);
int rte_python_shell(void);
int rte_python_run(char *cmd);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_REORDER_H_ */
