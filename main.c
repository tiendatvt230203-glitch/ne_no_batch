#include <signal.h>
#include <unistd.h>

#include "ne.h"

static struct ne_ctx g_ctx;

static void on_sig(int sig)
{
	(void)sig;
	ne_ctx_stop(&g_ctx);
}

int main(int argc, char **argv)
{
	const char *loc = "enp8s0";
	const char *wan = "enp5s0";
	const char *wan2 = "enp7s0";
	const char *bpf_loc = "bpf/xdp_local.o";
	const char *bpf_wan = "bpf/xdp_wan.o";

	if (argc >= 4) {
		loc = argv[1];
		wan = argv[2];
		wan2 = argv[3];
	}

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	if (ne_run(&g_ctx, loc, wan, wan2, bpf_loc, bpf_wan))
		return 1;

	while (!g_ctx.stop)
		pause();

	ne_ctx_join(&g_ctx);
	return 0;
}
