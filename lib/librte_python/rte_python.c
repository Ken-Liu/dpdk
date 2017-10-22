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
rte_python_run(char *cmd)
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

static int
py_priv_obj_set_mbuf(PyObject *o, struct rte_mbuf *mbuf)
{
	char *data;
	Py_ssize_t len;
	int r = 0;
	struct {
		PyPtr str;
	} v = { 0 };

	CHKP(v.str, PyObject_Str(o));
	CHKZ(r, PyString_AsStringAndSize(v.str, &data, &len));
	/* TODO check max len */
	rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, void *, 0), data, len);
	if (len < PKT_MIN_LEN) {
		memset(rte_pktmbuf_mtod_offset(mbuf, void *, len),
			0, PKT_MIN_LEN - len + 4);
		len = PKT_MIN_LEN;
	}
	mbuf->pkt_len = len;
	mbuf->data_len = len;
	goto end;
err:
	r = -1;
end:
	py_priv_check_err();
	py_priv_free(&v, sizeof(v));
	return r;
}

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
	CHKZ(r, py_priv_obj_set_mbuf(v.pkt, mbuf));
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
rte_python_scapy_to_mbufs(struct rte_mempool *pool, char *pattern, uint16_t *count)
{
	struct {
		PyPtr pkts, list;
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
			CHKZ(r, py_priv_obj_set_mbuf(
				PySequence_Fast_GET_ITEM(v.list, i), mbufs[i]));
		*count = size;
	} else {
		CHKZ(r, py_priv_obj_set_mbuf(v.pkts, mbufs[0]));
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
