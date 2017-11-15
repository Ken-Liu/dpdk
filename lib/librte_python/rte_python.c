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

#include <inttypes.h>
#include <string.h>

#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include "rte_python.h"
#include <python2.7/Python.h>
#include <python2.7/object.h>
#include <python2.7/dictobject.h>
#include <python2.7/stringobject.h>


typedef PyObject *PyPtr;


#define PKT_MIN_LEN	60

#define DBG(o) py_priv_debug(# o, o);

#define CHK(o, expr)									\
	do {										\
		o = (expr);								\
		if (!o) {								\
			RTE_LOG(WARNING, PYTHON, "%s = %s: null\n", # o, # expr);	\
			goto err;							\
		}									\
	} while (0);

#define CHKP(o, expr) do {CHK(o, expr); DBG(o);} while (0);

#define CHKZ(o, expr) 									\
	do {										\
		o = (expr);								\
		if (o) {								\
			RTE_LOG(WARNING, PYTHON, "%s = %s: not null\n", # o, # expr);	\
			goto err;							\
		}									\
	} while (0);

struct {
	PyPtr mod;		/* Default module */
	PyPtr dict_mod;	/* Module dict */
	PyPtr dict_local;	/* Local variable */
	PyPtr cls_ether;	/* Ether class */
	PyPtr cls_packet;	/* Packet class */
	PyPtr func_hexdump;	/* hexdump function */
	PyPtr func_hexdiff;	/* hexdiff function */
	PyPtr scapy_info;	/* scapy_info function */
} g;

static rte_spinlock_t lock;

int rte_python_debug = 0;


static inline void
py_priv_debug(const char *name, PyObject *o)
{
	if (o && rte_python_debug)
		RTE_LOG(DEBUG, PYTHON, "%s(%ld): %s\n", name,
				o->ob_refcnt, o->ob_type->tp_name);
}

static inline void
py_priv_check_err(void)
{
	if (PyErr_Occurred()) {
		PyErr_Print();
		PyErr_Clear();
	}
}

static inline void
py_priv_free(void *ptrs, int size)
{
	PyObject *ptr;

	size = size / sizeof(ptr);
	while(size) {
		ptr = ((PyObject **)ptrs)[--size];
		if (ptr)
			Py_DECREF(ptr);
	}
}

void
rte_python_close(void)
{
	rte_spinlock_lock(&lock);
	Py_Finalize();
	py_priv_free(&g, sizeof(g));
	memset(&g, 0, sizeof(g));
	rte_spinlock_unlock(&lock);
}

int
rte_python_init(void)
{
	int r = 0;

	if (g.mod)
		return 0;
	rte_spinlock_lock(&lock);
	Py_Initialize();
	if (!Py_IsInitialized()) {
		RTE_LOG(ERR, PYTHON, "Failed to init python\n");
		goto err;
	}
	CHKZ(r, PyRun_SimpleString("import sys;from scapy.all import *"));
	CHKP(g.mod, PyImport_AddModule("__main__"));
	CHKP(g.cls_ether, PyObject_GetAttrString(g.mod, "Ether"));
	CHKP(g.cls_packet, PyObject_GetAttrString(g.mod, "Packet"));
	CHKP(g.func_hexdump, PyObject_GetAttrString(g.mod, "hexdump"));
	CHKP(g.func_hexdiff, PyObject_GetAttrString(g.mod, "hexdiff"));
	CHKP(g.dict_mod, PyModule_GetDict(g.mod));
	CHKP(g.dict_local, PyDict_New());
	rte_spinlock_unlock(&lock);
	return 0;
err:
	py_priv_check_err();
	rte_spinlock_unlock(&lock);
	rte_python_close();
	return -1;
}

int
rte_python_shell(void)
{
	int r;

	rte_spinlock_lock(&lock);
	r = PyRun_InteractiveLoop(stdin, "<stdin>");
	rte_spinlock_unlock(&lock);
	return r;
}

int
rte_python_run(const char *cmd)
{
	struct {
		PyPtr r;
	} v = { 0 };
	int r;

	if (!cmd)
		return 0;
	rte_spinlock_lock(&lock);
	CHKP(v.r, PyRun_String(cmd, Py_single_input, g.dict_mod, g.dict_local));
	goto end;
err:
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	rte_spinlock_unlock(&lock);
	return r;
}

static const char *code_scapy_info =
	"L3_TYPES = {IP:1, IPv6:2}\n"
	"L4_TYPES = {TCP:1, SCTP:2, UDP:3}\n"
	"TUNNEL_TYPES = {VXLAN:1, GRE:2} # VXLAN-GPE:6\n"
	"end_types = {NoPayload, Raw}\n"
	"def scapy_info(pkt):\n"
	"    l2_len=0;\n"
	"    l3_len=0;\n"
	"    l4_len=0;\n"
	"    outer_l3_len = 0;\n"
	"    outer_l2_len = 0;\n"
	"    outer_l3_type = 0; \n"
	"    outer_l4_type = 0;\n"
	"    l3_type = 0;\n"
	"    l4_type = 0;\n"
	"    tunnel_type = 0;\n"
	"    sz = 0; \n"
	"    \n"
	"    while(pkt and isinstance(pkt, Packet)):\n"
	"	if (pkt.__class__ in L3_TYPES):\n"
	"	    l3_type = L3_TYPES[pkt.__class__];\n"
	"	if (pkt.__class__ in L4_TYPES):\n"
	"	    l4_type = L4_TYPES[pkt.__class__]\n"
	"	if (pkt.__class__ in TUNNEL_TYPES):\n"
	"	    tunnel_type = TUNNEL_TYPES[pkt.__class__]\n"
	"	    if (isinstance(pkt, VXLAN) and pkt.reserved1 > 0): \n"
	"		tunnel_type = 14; #vxlan-gpe\n"
	"	    if (isinstance(pkt, GRE) and pkt.flags > 0): \n"
	"		tunnel_type = 13; #vxlan-gpe\n"
	"	    outer_l2_len = l2_len;\n"
	"	    outer_l3_len = l3_len;\n"
	"	    l2_len = l4_len;\n"
	"	    l3_len = 0;\n"
	"	    l4_len = 0;\n"
	"	    outer_l3_type = l3_type;\n"
	"	    outer_l4_type = l4_type;\n"
	"	    l3_type = 0;\n"
	"	    l4_type = 0;\n"
	"	if (pkt.__class__ in end_types):\n"
	"	    break;\n"
	"	sz = len(pkt.self_build());\n"
	"	pkt = pkt.payload\n"
	"	if (l4_type > 0):\n"
	"	    l4_len += sz;\n"
	"	else:\n"
	"	    if (l3_type > 0):\n"
	"		l3_len += sz;\n"
	"	    else:\n"
	"		l2_len += sz;\n"
	"    return (outer_l3_type, outer_l4_type, l3_type, l4_type, tunnel_type, outer_l2_len, outer_l3_len, l2_len, l3_len, l4_len)\n"
	"\n";

static int
scapy_packet_info(PyObject *pkt, struct rte_mbuf *mbuf)
{
	int r = 0;
	struct {
		PyPtr ret, args;
	} v = { 0 };

	if (!g.scapy_info) {
		CHKP(v.ret, PyRun_String(code_scapy_info, Py_file_input, g.dict_mod, g.dict_mod));
		CHKP(g.scapy_info, PyObject_GetAttrString(g.mod, "scapy_info"));
	}
	CHKP(v.args, PyTuple_Pack(1, pkt));
	CHKP(v.ret, PyObject_CallObject(g.scapy_info, v.args));
	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 0)) == 1)
		mbuf->ol_flags |= PKT_TX_OUTER_IPV4;
	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 0)) == 2)
		mbuf->ol_flags |= PKT_TX_OUTER_IPV6;
//	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 1)) == 3)
//		mbuf->ol_flags |= PKT_TX_OUTER_UDP;
	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 2)) == 1)
		mbuf->ol_flags |= PKT_TX_IPV4;
	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 2)) == 2)
		mbuf->ol_flags |= PKT_TX_IPV6;
	if (mbuf->ol_flags & PKT_TX_L4_MASK) {
		mbuf->ol_flags &= ~PKT_TX_L4_MASK;
		mbuf->ol_flags |= PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 3))  << 52;
	}
	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 3)) != 1) /* not TCP */
		mbuf->ol_flags &= ~PKT_TX_TCP_SEG;
	if (PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 4)))
		mbuf->ol_flags |= PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 4)) << 45;
	mbuf->outer_l2_len = PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 5));
	mbuf->outer_l3_len = PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 6));
	mbuf->l2_len = PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 7));
	mbuf->l3_len = PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 8));
	mbuf->l4_len = PyInt_AsLong(PyTuple_GET_ITEM(v.ret, 9));
	goto end;
err:
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	return r;
}

static int
scapy2mbuf(PyObject *o, struct rte_mbuf *mbuf,
	struct rte_mempool *pool, struct rte_mbuf *tmpl)
{
	char *data;
	Py_ssize_t len, len_left, seg_len;
	int r = 0;
	struct {
		PyPtr str;
	} v = { 0 };
	struct rte_mbuf *mbuf_seg = NULL;
	struct rte_mbuf *mbuf_last = NULL;
	uint16_t seg = tmpl == NULL ? 0 : tmpl->data_len;
	int nb_segs = 0;

	CHKP(v.str, PyObject_Str(o));
	CHKZ(r, PyString_AsStringAndSize(v.str, &data, &len));
	len_left = len;
	mbuf_seg = mbuf;
	if (!seg)
		seg = len;
	do {
		seg_len = len_left > seg ? seg : len_left;
		len_left -= seg_len;
		if (!mbuf_seg)
			mbuf_seg = rte_pktmbuf_alloc(pool);
		if (!mbuf_seg) {
			RTE_LOG(ERR, PYTHON, "out of memory?");
			goto err;
		}
		rte_memcpy(rte_pktmbuf_mtod(mbuf_seg, void *), data, seg_len);
		if (mbuf_last)
			mbuf_last->next = mbuf_seg;
		mbuf_seg->data_len = seg_len;
		data += seg_len;
		mbuf_last = mbuf_seg;
		mbuf_seg = NULL;
		nb_segs ++;
	} while (len_left > 0);
	if (len < PKT_MIN_LEN) {
		memset(rte_pktmbuf_mtod_offset(mbuf, void *, len),
			0, PKT_MIN_LEN - len + 4);
		mbuf->pkt_len = PKT_MIN_LEN;
		mbuf->data_len = PKT_MIN_LEN;
	}	else
		mbuf->pkt_len = len;
	mbuf->tso_segsz = tmpl->tso_segsz;
	mbuf->ol_flags = tmpl->ol_flags;
	mbuf->vlan_tci = tmpl->vlan_tci;
	mbuf->udata64 = tmpl->udata64;
	mbuf->nb_segs = nb_segs;
	if (tmpl->ol_flags & (PKT_TX_TCP_SEG | PKT_TX_OUTER_IP_CKSUM |
			      PKT_TX_IP_CKSUM | PKT_TX_L4_MASK))
		scapy_packet_info(o, mbuf); /* figure out l*len, pkt_tx_* type */
	goto end;
err:
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	return r;
}

/* @deprecated */
struct rte_mbuf *
rte_python_scapy_to_mbuf(struct rte_mempool *pool, char *pattern)
{
	struct {
		PyPtr pkt;
	} v = { 0 };
	struct rte_mbuf *mbuf = NULL;
	int r;

	RTE_ASSERT(pool && pattern);
	if (rte_python_init())
		return NULL;
	rte_spinlock_lock(&lock);
	if(!(mbuf = rte_mbuf_raw_alloc(pool))) {
		RTE_LOG(ERR, PYTHON, "out of memory?");
		goto err;
	}
	CHKP(v.pkt, PyRun_String(pattern, Py_eval_input, g.dict_mod, g.dict_local));
	CHKZ(r, scapy2mbuf(v.pkt, mbuf, pool, NULL));
	goto end;
err:
	if (mbuf)
		rte_pktmbuf_free(mbuf);
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	rte_spinlock_unlock(&lock);
	return mbuf;
}

struct rte_mbuf **
rte_python_scapy_to_mbufs(struct rte_mempool *pool, char *pattern, uint16_t *count,
			  struct rte_mbuf *tmpl)
{
	struct {
		PyPtr pkts, list;
		PyPtr udata;
	} v = { 0 };
	struct rte_mbuf **mbufs = NULL;
	Py_ssize_t size = 0;
	Py_ssize_t i = 0;
	int r = 0;
	int is_list = 0;

	RTE_ASSERT(pool && pattern);
	if (rte_python_init())
		return NULL;
	rte_spinlock_lock(&lock);
	v.udata = PyDict_GetItemString(g.dict_local, "udata");
	if (v.udata)
		tmpl->udata64 = PyInt_AsUnsignedLongMask(v.udata);
	/* parse python/scapy pattern */
	CHKP(v.pkts, PyRun_String(pattern, Py_eval_input, g.dict_mod, g.dict_local));
	/* get size */
	if (PyIter_Check(v.pkts) || PyList_Check(v.pkts) || PyTuple_Check(v.pkts))
		is_list = 1;
	else if (PyObject_IsInstance(v.pkts, g.cls_packet))
		is_list = 1;
	if (is_list) {
		CHKP(v.list, PySequence_Fast(v.pkts, NULL));
		size = PySequence_Fast_GET_SIZE(v.list);
	} else
		size = 1;
	/* alloc mbufs */
	if ((mbufs = rte_malloc_socket(NULL, sizeof(void *) * size,
			0, pool->socket_id)) == NULL ||
		rte_pktmbuf_alloc_bulk(pool, mbufs, size)) {
		RTE_LOG(ERR, PYTHON, "out of memory?");
		goto err;
	}
	/* copy to mbufs */
	if (is_list) {
		for (i = 0; i < size; ++i)
			CHKZ(r, scapy2mbuf(
				PySequence_Fast_GET_ITEM(v.list, i), mbufs[i],
				pool, tmpl));
		*count = size;
	} else {
		CHKZ(r, scapy2mbuf(v.pkts, mbufs[0],
					     pool, tmpl));
		*count = 1;
	}
	goto end;
err:
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	if (r && mbufs) {
		while (size--)
			if (mbufs[size])
				rte_pktmbuf_free(mbufs[size]);
		rte_free(mbufs);
		mbufs = NULL;
	}
	rte_spinlock_unlock(&lock);
	return mbufs;
}

int
rte_python_scapy_dump(struct rte_mbuf *mbuf, int verbose)
{
	struct {
		PyPtr str, pkt, non, args, summary, args1;
	} v = { 0 };
	char *data;
	int r = 0;
	char hide_defaults[] = "hide_defaults";
	char show[] = "show";
	char summary[] = "summary";

	if (!mbuf || !verbose)
		return 0;
	if (rte_python_init())
		return -1;
	rte_spinlock_lock(&lock);
	data = rte_pktmbuf_mtod_offset(mbuf, void *, 0);
	CHKP(v.str, PyString_FromStringAndSize(data, mbuf->data_len));
	CHKP(v.args, PyTuple_Pack(1, v.str));
	CHKP(v.pkt, PyObject_CallObject(g.cls_ether, v.args));
	CHKP(v.non, PyObject_CallMethod(v.pkt, hide_defaults, NULL));
	if ((verbose & 0xf) == 1) { /* pkt.summary() */
		CHKP(v.summary, PyObject_CallMethod(v.pkt, summary, NULL));
		puts(PyString_AsString(v.summary));
	} else if ((verbose & 0xf) == 2) { /* repr(pkt) */
		CHKZ(r, PyObject_Print(v.pkt, stdout, 0));
		puts("");
	} else if ((verbose & 0xf) >= 3) { /* pkt.show() */
		CHKP(v.non, PyObject_CallMethod(v.pkt, show, NULL));
	}
	if ((verbose & 0x20)) { /* hexdump(pkt); */
		CHKP(v.args1, PyTuple_Pack(1, v.pkt));
		CHKP(v.non, PyObject_Call(g.func_hexdump, v.args1, NULL));
	}
	goto end;
err:
	printf("Error!\n");
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	rte_spinlock_unlock(&lock);
	return r;
}

int
rte_python_scapy_hexdiff(void *src, int slen, void *dst, int dlen)
{
	struct {
		PyPtr sstr, dstr, args, r;
	} v = { 0 };
	int r = 0;

	if (!src || !dst)
		return 0;
	if (rte_python_init())
		return -1;
	rte_spinlock_lock(&lock);
	CHKP(v.sstr, PyString_FromStringAndSize(src, slen));
	CHKP(v.dstr, PyString_FromStringAndSize(dst, dlen));
	CHKP(v.args, PyTuple_Pack(2, v.sstr, v.dstr));
	CHKP(v.r, PyObject_CallObject(g.func_hexdiff, v.args));
	goto end;
err:
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	rte_spinlock_unlock(&lock);
	return r;
}
