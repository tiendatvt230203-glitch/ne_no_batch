#ifndef NE_H
#define NE_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;

#define NE_FRAME    2048u
#define NE_N_FRAMES 8192u
#define NE_FQ_INIT  2048u
#define NE_CPU      0u

struct ne_zc_port {
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	int ifindex;
};

struct ne_pair {
	void *bufs;
	size_t bufsize;
	uint32_t frame_size;
	uint32_t n_frames;
	struct xsk_umem *umem;
	struct ne_zc_port in;
	struct ne_zc_port out;
	uint64_t *pool_buf;
	uint32_t pool_cap;
	uint32_t pool_mask;
	__attribute__((aligned(64))) volatile uint32_t pool_head;
	__attribute__((aligned(64))) volatile uint32_t pool_tail;
	struct bpf_object *bpf;
	uint8_t xdp_in_on;
	uint8_t xdp_out_on;
};

void *ne_umem_ptr(struct ne_pair *p, uint64_t addr);

int ne_open(struct ne_pair *p, const char *if_in, const char *if_out,
	    const char *bpf_o);
void ne_close(struct ne_pair *p);

int ne_rx_peek(struct ne_pair *p, uint32_t *len, uint64_t *addr);
void ne_rx_release(struct ne_pair *p, unsigned int n);
int ne_tx_out(struct ne_pair *p, uint64_t addr, uint32_t len);
void ne_maintain(struct ne_pair *p);

struct ne_ctx {
	volatile sig_atomic_t stop;
	struct ne_pair zc;
	pthread_t th;
};

#endif
