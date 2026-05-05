#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "ne.h"

#define MAC_WAN_DST 0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4d
#define MAC_WAN_SRC 0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xcf

static struct ne_ctx g;

static void pin_cpu(unsigned cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void mac_to_wan(struct ne_pair *p, uint64_t addr)
{
	uint8_t *pkt = ne_umem_ptr(p, addr);
	static const uint8_t dst[] = { MAC_WAN_DST };
	static const uint8_t src[] = { MAC_WAN_SRC };

	memcpy(pkt, dst, ETH_ALEN);
	memcpy(pkt + ETH_ALEN, src, ETH_ALEN);
}

static void *worker(void *arg)
{
	struct ne_ctx *ctx = arg;
	uint32_t len;
	uint64_t addr;

	pin_cpu(NE_CPU);
	for (;;) {
		if (ctx->stop)
			break;
		ne_maintain(&ctx->zc);
		{
			int ok;

			do {
				ok = 0;
				if (ne_rx_peek(&ctx->zc, &len, &addr)) {
					mac_to_wan(&ctx->zc, addr);
					while (!ctx->stop &&
					       ne_tx_out(&ctx->zc, addr,
							 len) != 0)
						ne_maintain(&ctx->zc);
					if (!ctx->stop)
						ne_rx_release(&ctx->zc, 1u);
					ok = 1;
				}
			} while (!ctx->stop && ok);
		}
	}
	return NULL;
}

static void on_sig(int sig)
{
	(void)sig;
	g.stop = 1;
}

int main(int argc, char **argv)
{
	const char *if_in = "enp7s0";
	const char *if_out = "enp4s0";
	const char *bpf_o = "bpf/xdp.o";

	if (argc >= 3) {
		if_in = argv[1];
		if_out = argv[2];
	}

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	memset(&g, 0, sizeof(g));
	if (ne_open(&g.zc, if_in, if_out, bpf_o) < 0)
		return 1;
	g.stop = 0;
	pthread_create(&g.th, NULL, worker, &g);

	while (!g.stop)
		pause();

	pthread_join(g.th, NULL);
	ne_close(&g.zc);
	return 0;
}
