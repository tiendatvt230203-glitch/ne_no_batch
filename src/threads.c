#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "ne.h"
#include "mac.h"

static inline void cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#else
	__asm__ volatile("" ::: "memory");
#endif
}

static void setaffinity(unsigned int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void rewrite_eth(struct ne_pair *zc, uint64_t addr, enum ne_dir d)
{
	uint8_t *pkt = ne_ptr(zc, addr);
	static const uint8_t wan_dst[] = { MAC_WAN_DST };
	static const uint8_t wan_src[] = { MAC_WAN_SRC };
	static const uint8_t loc_dst[] = { MAC_LOC_DST };
	static const uint8_t loc_src[] = { MAC_LOC_SRC };

	if (d == NE_DIR_TO_WAN) {
		memcpy(pkt, wan_dst, ETH_ALEN);
		memcpy(pkt + ETH_ALEN, wan_src, ETH_ALEN);
	} else {
		memcpy(pkt, loc_dst, ETH_ALEN);
		memcpy(pkt + ETH_ALEN, loc_src, ETH_ALEN);
	}
}

static void ne_maintain(struct ne_ctx *ctx)
{
	ne_drain_cq_loc(&ctx->zc);
	ne_drain_cq_wan(&ctx->zc);
	ne_refill_fq_loc(&ctx->zc);
	ne_refill_fq_wan(&ctx->zc);
}

static void *worker(void *arg)
{
	struct ne_ctx *ctx = arg;
	uint32_t len;
	uint64_t addr;

	setaffinity(NE_CPU_LOC);
	for (;;) {
		if (ctx->stop)
			break;

		ne_maintain(ctx);

		if (ne_recv_wan(&ctx->zc, &len, &addr, 1) > 0) {
			rewrite_eth(&ctx->zc, addr, NE_DIR_TO_LOC);
			while (!ctx->stop &&
			       ne_tx_one_loc(&ctx->zc, addr, len) != 0) {
				ne_maintain(ctx);
				cpu_relax();
			}
			if (!ctx->stop)
				ne_recv_wan_release(&ctx->zc, 1u);
			continue;
		}

		if (ne_recv_loc(&ctx->zc, &len, &addr, 1) > 0) {
			rewrite_eth(&ctx->zc, addr, NE_DIR_TO_WAN);
			while (!ctx->stop &&
			       ne_tx_one_wan(&ctx->zc, addr, len) != 0) {
				ne_maintain(ctx);
				cpu_relax();
			}
			if (!ctx->stop)
				ne_recv_loc_release(&ctx->zc, 1u);
			continue;
		}

		cpu_relax();
	}
	return NULL;
}

int ne_run(struct ne_ctx *ctx, const char *loc_if, const char *wan_if,
	   const char *bpf_loc, const char *bpf_wan)
{
	memset(ctx, 0, sizeof(*ctx));
	if (ne_pair_open(&ctx->zc, loc_if, wan_if, bpf_loc, bpf_wan) < 0)
		return -1;
	ctx->stop = 0;
	pthread_create(&ctx->th, NULL, worker, ctx);
	return 0;
}

void ne_ctx_stop(struct ne_ctx *ctx)
{
	ctx->stop = 1;
}

void ne_ctx_join(struct ne_ctx *ctx)
{
	pthread_join(ctx->th, NULL);
	ne_pair_close(&ctx->zc);
}
