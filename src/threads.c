#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include "ne.h"

static void setaffinity(unsigned int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static int mid_insert_wan_marker(struct ne_pair *zc, struct ne_job *j)
{
	uint8_t *pkt = ne_ptr(zc, j->umem_addr);
	struct ethhdr *eth = (struct ethhdr *)pkt;
	uint32_t pay_len;
	struct ne_marker *m;

	if (j->len < ETH_ALEN)
		return -1;
	if ((uint64_t)j->len + NE_MARKER_SIZE > zc->frame_size)
		return -1;

	pay_len = j->len - ETH_ALEN;
	if (pay_len != 0)
		memmove(pkt + NE_ENCAP_OVERHEAD, pkt + ETH_ALEN, pay_len);

	m = (struct ne_marker *)(pkt + NE_MARKER_OFFSET);
	memset(m, 0, sizeof(*m));
	m->frag_idx = 0;
	m->total = 1;
	eth->h_proto = htons(NE_MAGIC_ETHERTYPE);

	j->len += NE_MARKER_SIZE;
	j->conn_id = 0;
	j->pair_id = 0;
	j->frag_idx = 0;
	j->total = 1;
	return 0;
}

static void *loc_worker(void *arg)
{
	struct ne_ctx *ctx = arg;
	uint32_t len;
	uint64_t addr;
	struct ne_job j;

	setaffinity(NE_CPU_LOC);
	for (;;) {
		if (ctx->stop)
			break;
		ne_drain_cq_loc(&ctx->zc);
		ne_refill_fq_loc(&ctx->zc);
		(void)ne_tx_drain_loc(&ctx->zc, &ctx->w_to_loc);
		if (ne_recv_loc(&ctx->zc, &len, &addr, 1) > 0) {
			memset(&j, 0, sizeof(j));
			j.umem_addr = addr;
			j.len = len;
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->ing_to_mid, &j) != 0)
				(void)ne_tx_drain_loc(&ctx->zc, &ctx->w_to_loc);
			if (!ctx->stop)
				ne_recv_loc_release(&ctx->zc, 1u);
		}
	}
	return NULL;
}

static void *wan_worker(void *arg)
{
	struct ne_ctx *ctx = arg;
	uint32_t len;
	uint64_t addr;
	struct ne_job j;

	setaffinity(NE_CPU_WAN);
	for (;;) {
		if (ctx->stop)
			break;
		ne_drain_cq_wan(&ctx->zc);
		ne_drain_cq_wan2(&ctx->zc);
		ne_refill_fq_wan(&ctx->zc);
		ne_refill_fq_wan2(&ctx->zc);
		(void)ne_tx_drain_wan_rr(&ctx->zc, &ctx->w_to_wan);
		if (ne_recv_wan(&ctx->zc, &len, &addr, 1) > 0) {
			memset(&j, 0, sizeof(j));
			j.umem_addr = addr;
			j.len = len;
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->wan_to_mid, &j) != 0)
				(void)ne_tx_drain_wan_rr(&ctx->zc, &ctx->w_to_wan);
			if (!ctx->stop)
				ne_recv_wan_release(&ctx->zc, 1u);
		}
		if (ne_recv_wan2(&ctx->zc, &len, &addr, 1) > 0) {
			memset(&j, 0, sizeof(j));
			j.umem_addr = addr;
			j.len = len;
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->wan_to_mid, &j) != 0)
				(void)ne_tx_drain_wan_rr(&ctx->zc, &ctx->w_to_wan);
			if (!ctx->stop)
				ne_recv_wan2_release(&ctx->zc, 1u);
		}
	}
	return NULL;
}

static void *mid_worker(void *arg)
{
	struct ne_ctx *ctx = arg;
	struct ne_job j;

	setaffinity(NE_CPU_MID);
	for (;;) {
		if (ctx->stop)
			break;

		if (ne_ring_try_pop(&ctx->ing_to_mid, &j) == 0) {
			if (mid_insert_wan_marker(&ctx->zc, &j) != 0) {
				(void)ne_pool_push(&ctx->zc.pool, &j.umem_addr, 1);
				continue;
			}
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->w_to_wan, &j) != 0)
				;
		}
		if (ne_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->w_to_loc, &j) != 0)
				;
		}
	}
	return NULL;
}

int ne_run(struct ne_ctx *ctx, const char *loc_if, const char *wan_if,
	   const char *wan2_if, const char *bpf_loc, const char *bpf_wan)
{
	memset(ctx, 0, sizeof(*ctx));
	if (ne_pair_open(&ctx->zc, loc_if, wan_if, wan2_if, bpf_loc, bpf_wan) < 0)
		return -1;
	if (ne_ring_init(&ctx->ing_to_mid, NE_RING) ||
	    ne_ring_init(&ctx->wan_to_mid, NE_RING) ||
	    ne_ring_init(&ctx->w_to_wan, NE_RING) ||
	    ne_ring_init(&ctx->w_to_loc, NE_RING)) {
		ne_pair_close(&ctx->zc);
		return -1;
	}
	ctx->stop = 0;
	if (pthread_create(&ctx->th_loc, NULL, loc_worker, ctx) != 0) {
		fprintf(stderr, "necz1: pthread_create loc: %s\n",
			strerror(errno));
		goto fail_pt;
	}
	if (pthread_create(&ctx->th_mid, NULL, mid_worker, ctx) != 0) {
		fprintf(stderr, "necz1: pthread_create mid: %s\n",
			strerror(errno));
		goto fail_mid;
	}
	if (pthread_create(&ctx->th_wan, NULL, wan_worker, ctx) != 0) {
		fprintf(stderr, "necz1: pthread_create wan: %s\n",
			strerror(errno));
		goto fail_wan;
	}
	return 0;

fail_wan:
	ctx->stop = 1;
	pthread_join(ctx->th_mid, NULL);
fail_mid:
	ctx->stop = 1;
	pthread_join(ctx->th_loc, NULL);
fail_pt:
	ne_pair_close(&ctx->zc);
	return -1;
}

void ne_ctx_stop(struct ne_ctx *ctx)
{
	ctx->stop = 1;
}

void ne_ctx_join(struct ne_ctx *ctx)
{
	pthread_join(ctx->th_loc, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_wan, NULL);
	ne_ring_destroy(&ctx->ing_to_mid);
	ne_ring_destroy(&ctx->wan_to_mid);
	ne_ring_destroy(&ctx->w_to_wan);
	ne_ring_destroy(&ctx->w_to_loc);
	ne_pair_close(&ctx->zc);
}
