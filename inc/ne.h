#ifndef NE_H
#define NE_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;

#define NE_RING       4096u
#define NE_FRAME      2048u
#define NE_N_FRAMES   8192u
#define NE_FQ_INIT    2048u
#define NE_CPU_LOC    0u
#define NE_CPU_MID    3u
#define NE_CPU_WAN    11u


struct ne_job {
	uint64_t umem_addr;
	uint32_t len;
};

struct ne_ring {
	struct ne_job *buf;
	uint32_t cap;
	uint32_t mask;
	__attribute__((aligned(64))) volatile uint32_t head;
	__attribute__((aligned(64))) volatile uint32_t tail;
};

struct ne_pool {
	uint64_t *buf;
	uint32_t cap;
	uint32_t mask;
	uint32_t head;
	uint32_t tail;
	pthread_spinlock_t lock;
};

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
	struct ne_zc_port loc;
	struct ne_zc_port wan;
	struct ne_pool pool;
	struct bpf_object *bpf_loc;
	struct bpf_object *bpf_wan;
	uint8_t xdp_loc_on;
	uint8_t xdp_wan_on;
};

int ne_ring_init(struct ne_ring *r, uint32_t cap);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_pop(struct ne_ring *r, struct ne_job *j);
int ne_ring_try_push(struct ne_ring *r, const struct ne_job *j);
uint32_t ne_ring_count(const struct ne_ring *r);

int ne_pool_init(struct ne_pool *p, uint32_t cap);
void ne_pool_destroy(struct ne_pool *p);
uint32_t ne_pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n);
uint32_t ne_pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n);

int ne_pair_open(struct ne_pair *p, const char *loc_if, const char *wan_if,
		 const char *bpf_loc_o, const char *bpf_wan_o);
void ne_pair_close(struct ne_pair *p);

int ne_recv_loc(struct ne_pair *p, uint32_t *lens, uint64_t *addrs, int max);
int ne_recv_wan(struct ne_pair *p, uint32_t *lens, uint64_t *addrs, int max);
void ne_recv_loc_release(struct ne_pair *p, unsigned int n);
void ne_recv_wan_release(struct ne_pair *p, unsigned int n);
int ne_tx_drain_loc(struct ne_pair *p, struct ne_ring *src);
int ne_tx_drain_wan(struct ne_pair *p, struct ne_ring *src);
void ne_drain_cq_loc(struct ne_pair *p);
void ne_drain_cq_wan(struct ne_pair *p);
void ne_refill_fq_loc(struct ne_pair *p);
void ne_refill_fq_wan(struct ne_pair *p);
void *ne_ptr(struct ne_pair *p, uint64_t addr);

struct ne_ctx {
	volatile sig_atomic_t stop;
	struct ne_pair zc;
	struct ne_ring ing_to_mid;
	struct ne_ring wan_to_mid;
	struct ne_ring w_to_wan;
	struct ne_ring w_to_loc;
	pthread_t th_loc;
	pthread_t th_mid;
	pthread_t th_wan;
};

int ne_run(struct ne_ctx *ctx, const char *loc_if, const char *wan_if,
	   const char *bpf_loc, const char *bpf_wan);
void ne_ctx_stop(struct ne_ctx *ctx);
void ne_ctx_join(struct ne_ctx *ctx);

#endif