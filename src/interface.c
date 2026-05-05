#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#include "ne.h"

struct bpf_xdp_attach_opts;
int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags,
		   const struct bpf_xdp_attach_opts *opts);
int bpf_xdp_detach(int ifindex, __u32 flags,
		   const struct bpf_xdp_attach_opts *opts);

static int ne_xskmap_bind(struct xsk_socket *xsk, int map_fd)
{
	int key = 0;
	int xfd = xsk_socket__fd(xsk);

	if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
		return 0;
	return bpf_map_update_elem(map_fd, &key, &xfd, BPF_ANY);
}

int ne_addr_ring_init(struct ne_addr_ring *r, uint32_t cap)
{
	memset(r, 0, sizeof(*r));
	r->buf = calloc(cap, sizeof(uint64_t));
	r->cap = cap;
	r->mask = cap - 1;
	return 0;
}

void ne_addr_ring_destroy(struct ne_addr_ring *r)
{
	free(r->buf);
	r->buf = NULL;
}

uint32_t ne_addr_ring_push(struct ne_addr_ring *r, const uint64_t *addrs,
			    uint32_t n)
{
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
	uint32_t free_slots = r->cap - (head - tail);
	uint32_t i;

	if (n > free_slots)
		n = free_slots;
	for (i = 0; i < n; i++)
		r->buf[(head + i) & r->mask] = addrs[i];
	__atomic_store_n(&r->head, head + n, __ATOMIC_RELEASE);
	return n;
}

uint32_t ne_addr_ring_pop(struct ne_addr_ring *r, uint64_t *addrs,
			   uint32_t n)
{
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
	uint32_t avail = head - tail;
	uint32_t i;

	if (n > avail)
		n = avail;
	for (i = 0; i < n; i++)
		addrs[i] = r->buf[(tail + i) & r->mask];
	__atomic_store_n(&r->tail, tail + n, __ATOMIC_RELEASE);
	return n;
}

void *ne_ptr(struct ne_pair *p, uint64_t addr)
{
	return xsk_umem__get_data(p->bufs, addr);
}

static int ne_sock_open(struct ne_pair *p, struct ne_zc_port *port,
			 const char *ifn)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_ZEROCOPY,
	};

	return xsk_socket__create_shared(&port->xsk, ifn, 0, p->umem,
					 &port->rx, &port->tx,
					 &port->fq, &port->cq, &cfg);
}

int ne_pair_open(struct ne_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o)
{
#define NE_TRY(expr) do { if (expr) goto fail; } while (0)
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	struct xsk_umem_config ucfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = NE_FRAME,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct bpf_program *pl;
	struct bpf_program *pw;
	struct bpf_map *ml;
	struct bpf_map *mw;
	uint32_t half = NE_N_FRAMES / 2;
	uint32_t i, pi, idx, per_fq, want;
	uint64_t a;

	memset(p, 0, sizeof(*p));
	p->frame_size = NE_FRAME;
	p->n_frames = NE_N_FRAMES;
	p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;
	setrlimit(RLIMIT_MEMLOCK, &rl);
	p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p->bufs == MAP_FAILED)
		return -1;
	NE_TRY(ne_addr_ring_init(&p->pool_loc, half));
	NE_TRY(ne_addr_ring_init(&p->pool_wan, half));
	for (i = 0; i < half; i++) {
		uint64_t a = (uint64_t)i * p->frame_size;

		ne_addr_ring_push(&p->pool_loc, &a, 1);
	}
	for (i = half; i < p->n_frames; i++) {
		uint64_t a = (uint64_t)i * p->frame_size;

		ne_addr_ring_push(&p->pool_wan, &a, 1);
	}
	NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->loc.fq,
				&p->loc.cq, &ucfg));
	NE_TRY(ne_sock_open(p, &p->loc, loc_if));
	p->loc.ifindex = if_nametoindex(loc_if);
	NE_TRY(!p->loc.ifindex);
	NE_TRY(ne_sock_open(p, &p->wan, wan_if));
	p->wan.ifindex = if_nametoindex(wan_if);
	NE_TRY(!p->wan.ifindex);
	per_fq = NE_FQ_INIT > ucfg.fill_size ? ucfg.fill_size : NE_FQ_INIT;
	for (pi = 0; pi < 2; pi++) {
		struct ne_zc_port *port = pi ? &p->wan : &p->loc;
		struct ne_addr_ring *pool = pi ? &p->pool_wan : &p->pool_loc;

		for (want = per_fq; want > 0; want--) {
			if (ne_addr_ring_pop(pool, &a, 1) != 1)
				break;
			if (xsk_ring_prod__reserve(&port->fq, 1, &idx) != 1) {
				(void)ne_addr_ring_push(pool, &a, 1);
				break;
			}
			*xsk_ring_prod__fill_addr(&port->fq, idx) = a;
			xsk_ring_prod__submit(&port->fq, 1);
		}
	}
	p->bpf_loc = bpf_object__open_file(bpf_loc_o, NULL);
	p->bpf_wan = bpf_object__open_file(bpf_wan_o, NULL);
	NE_TRY(!p->bpf_loc || !p->bpf_wan);
	NE_TRY(bpf_object__load(p->bpf_loc));
	NE_TRY(bpf_object__load(p->bpf_wan));
	pl = bpf_object__find_program_by_name(p->bpf_loc, "xdp_redirect_prog");
	pw = bpf_object__find_program_by_name(p->bpf_wan,
					      "xdp_wan_redirect_prog");
	NE_TRY(!pl || !pw);
	NE_TRY(bpf_xdp_attach(p->loc.ifindex, bpf_program__fd(pl),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_loc_on = 1;
	NE_TRY(bpf_xdp_attach(p->wan.ifindex, bpf_program__fd(pw),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_wan_on = 1;
	ml = bpf_object__find_map_by_name(p->bpf_loc, "xsks_map");
	mw = bpf_object__find_map_by_name(p->bpf_wan, "wan_xsks_map");
	NE_TRY(!ml || !mw);
	NE_TRY(ne_xskmap_bind(p->loc.xsk, bpf_map__fd(ml)));
	NE_TRY(ne_xskmap_bind(p->wan.xsk, bpf_map__fd(mw)));
#undef NE_TRY
	return 0;
fail:
	ne_pair_close(p);
#undef NE_TRY
	return -1;
}

void ne_pair_close(struct ne_pair *p)
{
	if (p->xdp_wan_on)
		bpf_xdp_detach(p->wan.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (p->xdp_loc_on)
		bpf_xdp_detach(p->loc.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	p->xdp_wan_on = 0;
	p->xdp_loc_on = 0;
	if (p->bpf_wan)
		bpf_object__close(p->bpf_wan);
	if (p->bpf_loc)
		bpf_object__close(p->bpf_loc);
	p->bpf_wan = NULL;
	p->bpf_loc = NULL;
	if (p->wan.xsk)
		xsk_socket__delete(p->wan.xsk);
	if (p->loc.xsk)
		xsk_socket__delete(p->loc.xsk);
	p->wan.xsk = NULL;
	p->loc.xsk = NULL;
	if (p->umem)
		xsk_umem__delete(p->umem);
	p->umem = NULL;
	ne_addr_ring_destroy(&p->pool_loc);
	ne_addr_ring_destroy(&p->pool_wan);
	if (p->bufs)
		munmap(p->bufs, p->bufsize);
	p->bufs = NULL;
}

static int ne_recv_port(struct ne_zc_port *port, uint32_t *lens,
			 uint64_t *addrs, int max)
{
	uint32_t idx;
	unsigned int n;
	unsigned int i;

	n = xsk_ring_cons__peek(&port->rx, (uint32_t)max, &idx);
	for (i = 0; i < n; i++) {
		const struct xdp_desc *d =
			xsk_ring_cons__rx_desc(&port->rx, idx + i);

		addrs[i] = d->addr;
		lens[i] = d->len;
	}
	return (int)n;
}

int ne_recv_loc(struct ne_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return ne_recv_port(&p->loc, lens, addrs, max);
}

int ne_recv_wan(struct ne_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return ne_recv_port(&p->wan, lens, addrs, max);
}

void ne_recv_loc_release(struct ne_pair *p, unsigned int n)
{
	if (n)
		xsk_ring_cons__release(&p->loc.rx, n);
}

void ne_recv_wan_release(struct ne_pair *p, unsigned int n)
{
	if (n)
		xsk_ring_cons__release(&p->wan.rx, n);
}

static int ne_tx_one_port(struct ne_zc_port *port, uint64_t addr, uint32_t len,
			  uint32_t max_frame)
{
	uint32_t idx;
	struct xdp_desc *d;

	if (len > max_frame)
		len = max_frame;
	if (xsk_ring_prod__reserve(&port->tx, 1, &idx) != 1)
		return -1;
	d = xsk_ring_prod__tx_desc(&port->tx, idx);
	d->addr = addr;
	d->len = len;
	xsk_ring_prod__submit(&port->tx, 1);
	return 0;
}

int ne_tx_one_loc(struct ne_pair *p, uint64_t addr, uint32_t len)
{
	return ne_tx_one_port(&p->loc, addr, len, p->frame_size);
}

int ne_tx_one_wan(struct ne_pair *p, uint64_t addr, uint32_t len)
{
	return ne_tx_one_port(&p->wan, addr, len, p->frame_size);
}

static void ne_drain_cq_port(struct ne_zc_port *port,
			      struct ne_addr_ring *target_pool)
{
	uint32_t idx;
	uint32_t n;
	uint64_t a;

	for (;;) {
		n = xsk_ring_cons__peek(&port->cq, 1, &idx);
		if (!n)
			break;
		a = *xsk_ring_cons__comp_addr(&port->cq, idx);
		xsk_ring_cons__release(&port->cq, 1);
		(void)ne_addr_ring_push(target_pool, &a, 1);
	}
}

void ne_drain_cq_loc(struct ne_pair *p)
{
	ne_drain_cq_port(&p->loc, &p->pool_wan);
}

void ne_drain_cq_wan(struct ne_pair *p)
{
	ne_drain_cq_port(&p->wan, &p->pool_loc);
}

static void ne_refill_fq_port(struct ne_zc_port *port,
			       struct ne_addr_ring *source_pool)
{
	uint64_t a;
	uint32_t idx;

	for (;;) {
		if (xsk_prod_nb_free(&port->fq, 1) < 1)
			break;
		if (ne_addr_ring_pop(source_pool, &a, 1) != 1)
			break;
		if (xsk_ring_prod__reserve(&port->fq, 1, &idx) != 1) {
			(void)ne_addr_ring_push(source_pool, &a, 1);
			break;
		}
		*xsk_ring_prod__fill_addr(&port->fq, idx) = a;
		xsk_ring_prod__submit(&port->fq, 1);
	}
}

void ne_refill_fq_loc(struct ne_pair *p)
{
	ne_refill_fq_port(&p->loc, &p->pool_loc);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
	ne_refill_fq_port(&p->wan, &p->pool_wan);
}
