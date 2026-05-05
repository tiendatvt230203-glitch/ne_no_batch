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

static void pool_push1(struct ne_pair *p, uint64_t a)
{
	uint32_t head = __atomic_load_n(&p->pool_head, __ATOMIC_RELAXED);
	uint32_t tail = __atomic_load_n(&p->pool_tail, __ATOMIC_ACQUIRE);

	if ((uint32_t)(head - tail) >= p->pool_cap)
		return;
	p->pool_buf[head & p->pool_mask] = a;
	__atomic_store_n(&p->pool_head, head + 1, __ATOMIC_RELEASE);
}

static int pool_pop1(struct ne_pair *p, uint64_t *a)
{
	uint32_t tail = __atomic_load_n(&p->pool_tail, __ATOMIC_RELAXED);
	uint32_t head = __atomic_load_n(&p->pool_head, __ATOMIC_ACQUIRE);

	if (tail == head)
		return -1;
	*a = p->pool_buf[tail & p->pool_mask];
	__atomic_store_n(&p->pool_tail, tail + 1, __ATOMIC_RELEASE);
	return 0;
}

static int xskmap_bind(struct xsk_socket *xsk, int map_fd)
{
	int key = 0;
	int xfd = xsk_socket__fd(xsk);

	if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
		return 0;
	return bpf_map_update_elem(map_fd, &key, &xfd, BPF_ANY);
}

void *ne_umem_ptr(struct ne_pair *p, uint64_t addr)
{
	return xsk_umem__get_data(p->bufs, addr);
}

static int sock_open(struct ne_pair *p, struct ne_zc_port *port,
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

static void fq_fill(struct ne_pair *p, struct ne_zc_port *port)
{
	uint64_t a;
	uint32_t idx;

	for (;;) {
		if (xsk_prod_nb_free(&port->fq, 1) < 1)
			break;
		if (pool_pop1(p, &a) != 0)
			break;
		if (xsk_ring_prod__reserve(&port->fq, 1, &idx) != 1) {
			pool_push1(p, a);
			break;
		}
		*xsk_ring_prod__fill_addr(&port->fq, idx) = a;
		xsk_ring_prod__submit(&port->fq, 1);
	}
}

static void cq_drain_out(struct ne_pair *p)
{
	struct ne_zc_port *port = &p->out;
	uint32_t idx;
	uint32_t n;
	uint64_t a;

	for (;;) {
		n = xsk_ring_cons__peek(&port->cq, 1, &idx);
		if (!n)
			break;
		a = *xsk_ring_cons__comp_addr(&port->cq, idx);
		xsk_ring_cons__release(&port->cq, 1);
		pool_push1(p, a);
	}
}

void ne_maintain(struct ne_pair *p)
{
	cq_drain_out(p);
	fq_fill(p, &p->in);
	fq_fill(p, &p->out);
}

int ne_open(struct ne_pair *p, const char *if_in, const char *if_out,
	    const char *bpf_o)
{
#define NE_TRY(x) do { if (x) goto fail; } while (0)
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	struct xsk_umem_config ucfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = NE_FRAME,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct bpf_program *pin, *pout;
	struct bpf_map *map;
	uint32_t i, pi, idx, per_fq, want;
	uint64_t a;

	memset(p, 0, sizeof(*p));
	p->frame_size = NE_FRAME;
	p->n_frames = NE_N_FRAMES;
	p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;
	p->pool_cap = p->n_frames;
	p->pool_mask = p->n_frames - 1;
	setrlimit(RLIMIT_MEMLOCK, &rl);
	p->pool_buf = calloc(p->pool_cap, sizeof(uint64_t));
	NE_TRY(!p->pool_buf);
	p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	NE_TRY(p->bufs == MAP_FAILED);
	for (i = 0; i < p->n_frames; i++)
		pool_push1(p, (uint64_t)i * p->frame_size);
	NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->in.fq,
				&p->in.cq, &ucfg));
	NE_TRY(sock_open(p, &p->in, if_in));
	p->in.ifindex = if_nametoindex(if_in);
	NE_TRY(!p->in.ifindex);
	NE_TRY(sock_open(p, &p->out, if_out));
	p->out.ifindex = if_nametoindex(if_out);
	NE_TRY(!p->out.ifindex);
	per_fq = NE_FQ_INIT > ucfg.fill_size ? ucfg.fill_size : NE_FQ_INIT;
	for (pi = 0; pi < 2; pi++) {
		struct ne_zc_port *port = pi ? &p->out : &p->in;

		for (want = per_fq; want > 0; want--) {
			if (pool_pop1(p, &a) != 0)
				break;
			if (xsk_ring_prod__reserve(&port->fq, 1, &idx) != 1) {
				pool_push1(p, a);
				break;
			}
			*xsk_ring_prod__fill_addr(&port->fq, idx) = a;
			xsk_ring_prod__submit(&port->fq, 1);
		}
	}
	p->bpf = bpf_object__open_file(bpf_o, NULL);
	NE_TRY(!p->bpf);
	NE_TRY(bpf_object__load(p->bpf));
	pin = bpf_object__find_program_by_name(p->bpf, "xdp_redirect_prog");
	pout = bpf_object__find_program_by_name(p->bpf, "xdp_wan_pass_prog");
	NE_TRY(!pin || !pout);
	NE_TRY(bpf_xdp_attach(p->in.ifindex, bpf_program__fd(pin),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_in_on = 1;
	NE_TRY(bpf_xdp_attach(p->out.ifindex, bpf_program__fd(pout),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_out_on = 1;
	map = bpf_object__find_map_by_name(p->bpf, "xsks_map");
	NE_TRY(!map);
	NE_TRY(xskmap_bind(p->in.xsk, bpf_map__fd(map)));
#undef NE_TRY
	return 0;
fail:
	ne_close(p);
	return -1;
}

void ne_close(struct ne_pair *p)
{
	if (p->xdp_out_on)
		bpf_xdp_detach(p->out.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (p->xdp_in_on)
		bpf_xdp_detach(p->in.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	p->xdp_out_on = 0;
	p->xdp_in_on = 0;
	if (p->bpf)
		bpf_object__close(p->bpf);
	p->bpf = NULL;
	if (p->out.xsk)
		xsk_socket__delete(p->out.xsk);
	if (p->in.xsk)
		xsk_socket__delete(p->in.xsk);
	p->out.xsk = NULL;
	p->in.xsk = NULL;
	if (p->umem)
		xsk_umem__delete(p->umem);
	p->umem = NULL;
	free(p->pool_buf);
	p->pool_buf = NULL;
	if (p->bufs)
		munmap(p->bufs, p->bufsize);
	p->bufs = NULL;
}

int ne_rx_peek(struct ne_pair *p, uint32_t *len, uint64_t *addr)
{
	struct xsk_ring_cons *rx = &p->in.rx;
	uint32_t idx;
	unsigned int n;

	n = xsk_ring_cons__peek(rx, 1, &idx);
	if (!n)
		return 0;
	{
		const struct xdp_desc *d = xsk_ring_cons__rx_desc(rx, idx);

		*addr = d->addr;
		*len = d->len;
	}
	return 1;
}

void ne_rx_release(struct ne_pair *p, unsigned int n)
{
	if (n)
		xsk_ring_cons__release(&p->in.rx, n);
}

int ne_tx_out(struct ne_pair *p, uint64_t addr, uint32_t len)
{
	struct xsk_ring_prod *tx = &p->out.tx;
	uint32_t idx;
	struct xdp_desc *d;

	if (len > p->frame_size)
		len = p->frame_size;
	if (xsk_ring_prod__reserve(tx, 1, &idx) != 1)
		return -1;
	d = xsk_ring_prod__tx_desc(tx, idx);
	d->addr = addr;
	d->len = len;
	xsk_ring_prod__submit(tx, 1);
	return 0;
}
