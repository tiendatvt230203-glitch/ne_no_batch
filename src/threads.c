#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>

#include "ne.h"

static void setaffinity(unsigned int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
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
		ne_drain_cq_loc2(&ctx->zc);
		ne_refill_fq_loc(&ctx->zc);
		ne_refill_fq_loc2(&ctx->zc);
		(void)ne_tx_drain_loc(&ctx->zc, &ctx->w_to_loc);
		if (ne_recv_loc(&ctx->zc, &len, &addr, 1) > 0) {
			memset(&j, 0, sizeof(j));
			j.umem_addr = addr;
			j.len = len;
			j.rx_ifidx = (uint32_t)ctx->zc.loc.ifindex;
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->ing_to_mid, &j) != 0)
				(void)ne_tx_drain_loc(&ctx->zc, &ctx->w_to_loc);
			if (!ctx->stop)
				ne_recv_loc_release(&ctx->zc, 1u);
		}
		if (ne_recv_loc2(&ctx->zc, &len, &addr, 1) > 0) {
			memset(&j, 0, sizeof(j));
			j.umem_addr = addr;
			j.len = len;
			j.rx_ifidx = (uint32_t)ctx->zc.loc2.ifindex;
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->ing_to_mid, &j) != 0)
				(void)ne_tx_drain_loc(&ctx->zc, &ctx->w_to_loc);
			if (!ctx->stop)
				ne_recv_loc2_release(&ctx->zc, 1u);
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
		ne_refill_fq_wan(&ctx->zc);
		(void)ne_tx_drain_wan(&ctx->zc, &ctx->w_to_wan);
		if (ne_recv_wan(&ctx->zc, &len, &addr, 1) > 0) {
			memset(&j, 0, sizeof(j));
			j.umem_addr = addr;
			j.len = len;
			j.rx_ifidx = 0;
			while (!ctx->stop &&
			       ne_ring_try_push(&ctx->wan_to_mid, &j) != 0)
				(void)ne_tx_drain_wan(&ctx->zc, &ctx->w_to_wan);
			if (!ctx->stop)
				ne_recv_wan_release(&ctx->zc, 1u);
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

int ne_run(struct ne_ctx *ctx, const char *loc_if, const char *loc2_if,
	   const char *wan_if, const char *bpf_loc, const char *bpf_wan)
{
	memset(ctx, 0, sizeof(*ctx));
	if (ne_pair_open(&ctx->zc, loc_if, loc2_if, wan_if, bpf_loc,
			 bpf_wan) < 0)
		return -1;
	if (ne_ring_init(&ctx->ing_to_mid, NE_RING) ||
	    ne_ring_init(&ctx->wan_to_mid, NE_RING) ||
	    ne_ring_init(&ctx->w_to_wan, NE_RING) ||
	    ne_ring_init(&ctx->w_to_loc, NE_RING)) {
		ne_pair_close(&ctx->zc);
		return -1;
	}
	ctx->stop = 0;
	pthread_create(&ctx->th_loc, NULL, loc_worker, ctx);
	pthread_create(&ctx->th_mid, NULL, mid_worker, ctx);
	pthread_create(&ctx->th_wan, NULL, wan_worker, ctx);
	return 0;
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
