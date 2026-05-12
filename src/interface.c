#define _GNU_SOURCE
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
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

int ne_ring_init(struct ne_ring *r, uint32_t cap)
{
	memset(r, 0, sizeof(*r));
	r->buf = calloc(cap, sizeof(struct ne_job));
	if (!r->buf)
		return -1;
	r->cap = cap;
	r->mask = cap - 1;
	return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
	free(r->buf);
	r->buf = NULL;
}

int ne_ring_try_push(struct ne_ring *r, const struct ne_job *j)
{
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);

	if ((uint32_t)(head - tail) >= r->cap)
		return -1;
	memcpy(&r->buf[head & r->mask], j, sizeof(*j));
	__atomic_thread_fence(__ATOMIC_RELEASE);
	__atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
	return 0;
}

int ne_ring_try_pop(struct ne_ring *r, struct ne_job *j)
{
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);

	if (tail == head)
		return -1;
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	memcpy(j, &r->buf[tail & r->mask], sizeof(*j));
	__atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
	return 0;
}

uint32_t ne_ring_count(const struct ne_ring *r)
{
	uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
	uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);

	return head - tail;
}

int ne_pool_init(struct ne_pool *p, uint32_t cap)
{
	memset(p, 0, sizeof(*p));
	p->buf = calloc(cap, sizeof(uint64_t));
	if (!p->buf)
		return -1;
	p->cap = cap;
	p->mask = cap - 1;
	if (pthread_spin_init(&p->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
		free(p->buf);
		p->buf = NULL;
		return -1;
	}
	return 0;
}

void ne_pool_destroy(struct ne_pool *p)
{
	if (p->buf) {
		pthread_spin_destroy(&p->lock);
		free(p->buf);
		p->buf = NULL;
	}
}

uint32_t ne_pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n)
{
	uint32_t free_slots, put, i;

	pthread_spin_lock(&p->lock);
	free_slots = p->cap - (p->head - p->tail);
	put = n < free_slots ? n : free_slots;
	for (i = 0; i < put; i++)
		p->buf[(p->head + i) & p->mask] = addrs[i];
	p->head += put;
	pthread_spin_unlock(&p->lock);
	return put;
}

uint32_t ne_pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n)
{
	uint32_t avail, got, i;

	pthread_spin_lock(&p->lock);
	avail = p->head - p->tail;
	got = n < avail ? n : avail;
	for (i = 0; i < got; i++)
		addrs[i] = p->buf[(p->tail + i) & p->mask];
	p->tail += got;
	pthread_spin_unlock(&p->lock);
	return got;
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
		.bind_flags = XDP_COPY,
	};

	return xsk_socket__create_shared(&port->xsk, ifn, 0, p->umem,
					 &port->rx, &port->tx,
					 &port->fq, &port->cq, &cfg);
}

int ne_pair_open(struct ne_pair *p, const char *loc_if, const char *wan_if,
		 const char *wan2_if, const char *bpf_loc_o, const char *bpf_wan_o)
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
	struct bpf_program *pw2;
	struct bpf_map *ml;
	struct bpf_map *mw;
	struct bpf_map *mw2;
	uint64_t a;
	uint32_t i, pi, idx, per_fq, want;

	memset(p, 0, sizeof(*p));
	p->frame_size = NE_FRAME;
	p->n_frames = NE_N_FRAMES;
	p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;
	setrlimit(RLIMIT_MEMLOCK, &rl);
	p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p->bufs == MAP_FAILED)
		return -1;
	NE_TRY(ne_pool_init(&p->pool, NE_N_FRAMES));
	for (i = 0; i < p->n_frames; i++) {
		a = (uint64_t)i * p->frame_size;
		(void)ne_pool_push(&p->pool, &a, 1);
	}
	NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->loc.fq,
				&p->loc.cq, &ucfg));
	NE_TRY(ne_sock_open(p, &p->loc, loc_if));
	p->loc.ifindex = if_nametoindex(loc_if);
	NE_TRY(!p->loc.ifindex);
	NE_TRY(ne_sock_open(p, &p->wan, wan_if));
	p->wan.ifindex = if_nametoindex(wan_if);
	NE_TRY(!p->wan.ifindex);
	NE_TRY(ne_sock_open(p, &p->wan2, wan2_if));
	p->wan2.ifindex = if_nametoindex(wan2_if);
	NE_TRY(!p->wan2.ifindex);
	per_fq = NE_FQ_INIT > ucfg.fill_size ? ucfg.fill_size : NE_FQ_INIT;
	for (pi = 0; pi < 3; pi++) {
		struct ne_zc_port *port =
		    pi == 0 ? &p->loc : (pi == 1 ? &p->wan : &p->wan2);

		for (want = per_fq; want > 0; want--) {
			if (ne_pool_pop(&p->pool, &a, 1) != 1)
				break;
			if (xsk_ring_prod__reserve(&port->fq, 1, &idx) != 1) {
				(void)ne_pool_push(&p->pool, &a, 1);
				break;
			}
			*xsk_ring_prod__fill_addr(&port->fq, idx) = a;
			xsk_ring_prod__submit(&port->fq, 1);
		}
	}
	p->bpf_loc = bpf_object__open_file(bpf_loc_o, NULL);
	p->bpf_wan = bpf_object__open_file(bpf_wan_o, NULL);
	p->bpf_wan2 = bpf_object__open_file(bpf_wan_o, NULL);
	NE_TRY(!p->bpf_loc || !p->bpf_wan || !p->bpf_wan2);
	NE_TRY(bpf_object__load(p->bpf_loc));
	NE_TRY(bpf_object__load(p->bpf_wan));
	NE_TRY(bpf_object__load(p->bpf_wan2));
	pl = bpf_object__find_program_by_name(p->bpf_loc, "xdp_redirect_prog");
	pw = bpf_object__find_program_by_name(p->bpf_wan, "xdp_wan_redirect_prog");
	pw2 = bpf_object__find_program_by_name(p->bpf_wan2,
					       "xdp_wan_redirect_prog");
	NE_TRY(!pl || !pw || !pw2);
	NE_TRY(bpf_xdp_attach(p->loc.ifindex, bpf_program__fd(pl),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_loc_on = 1;
	NE_TRY(bpf_xdp_attach(p->wan.ifindex, bpf_program__fd(pw),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_wan_on = 1;
	NE_TRY(bpf_xdp_attach(p->wan2.ifindex, bpf_program__fd(pw2),
			      XDP_FLAGS_DRV_MODE, NULL));
	p->xdp_wan2_on = 1;
	ml = bpf_object__find_map_by_name(p->bpf_loc, "xsks_map");
	mw = bpf_object__find_map_by_name(p->bpf_wan, "wan_xsks_map");
	mw2 = bpf_object__find_map_by_name(p->bpf_wan2, "wan_xsks_map");
	NE_TRY(!ml || !mw || !mw2);
	NE_TRY(ne_xskmap_bind(p->loc.xsk, bpf_map__fd(ml)));
	NE_TRY(ne_xskmap_bind(p->wan.xsk, bpf_map__fd(mw)));
	NE_TRY(ne_xskmap_bind(p->wan2.xsk, bpf_map__fd(mw2)));
#undef NE_TRY
	return 0;
fail:
	ne_pair_close(p);
	return -1;
}

void ne_pair_close(struct ne_pair *p)
{
	if (p->xdp_wan2_on)
		bpf_xdp_detach(p->wan2.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (p->xdp_wan_on)
		bpf_xdp_detach(p->wan.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (p->xdp_loc_on)
		bpf_xdp_detach(p->loc.ifindex, XDP_FLAGS_DRV_MODE, NULL);
	p->xdp_wan2_on = 0;
	p->xdp_wan_on = 0;
	p->xdp_loc_on = 0;
	if (p->bpf_wan2)
		bpf_object__close(p->bpf_wan2);
	if (p->bpf_wan)
		bpf_object__close(p->bpf_wan);
	if (p->bpf_loc)
		bpf_object__close(p->bpf_loc);
	p->bpf_wan2 = NULL;
	p->bpf_wan = NULL;
	p->bpf_loc = NULL;
	if (p->wan2.xsk)
		xsk_socket__delete(p->wan2.xsk);
	if (p->wan.xsk)
		xsk_socket__delete(p->wan.xsk);
	if (p->loc.xsk)
		xsk_socket__delete(p->loc.xsk);
	p->wan2.xsk = NULL;
	p->wan.xsk = NULL;
	p->loc.xsk = NULL;
	if (p->umem)
		xsk_umem__delete(p->umem);
	p->umem = NULL;
	ne_pool_destroy(&p->pool);
	if (p->bufs)
		munmap(p->bufs, p->bufsize);
	p->bufs = NULL;
}

static int ne_recv_port(struct ne_zc_port *port, uint32_t *lens,
			uint64_t *addrs, int max)
{
	uint32_t idx;
	unsigned int n, i;

	n = xsk_ring_cons__peek(&port->rx, (uint32_t)max, &idx);
	for (i = 0; i < n; i++) {
		const struct xdp_desc *d = xsk_ring_cons__rx_desc(&port->rx, idx + i);

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

int ne_recv_wan2(struct ne_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return ne_recv_port(&p->wan2, lens, addrs, max);
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

void ne_recv_wan2_release(struct ne_pair *p, unsigned int n)
{
	if (n)
		xsk_ring_cons__release(&p->wan2.rx, n);
}


static int ne_tx_drain_port(int xfd, struct xsk_ring_prod *tx_ring, 
                            struct ne_ring *src, uint32_t max_frame)
{
    struct ne_job j;
    uint32_t idx;
    uint32_t tx_len;
    int sent = 0;

    for (;;) {
        struct xdp_desc *d;

        if (xsk_prod_nb_free(tx_ring, 1) < 1)
            break;

        if (ne_ring_try_pop(src, &j) != 0)
            break;

        if (xsk_ring_prod__reserve(tx_ring, 1, &idx) != 1) {
            while (ne_ring_try_push(src, &j) != 0)
                ;
            break;
        }

        d = xsk_ring_prod__tx_desc(tx_ring, idx);
        d->addr = j.umem_addr;
        tx_len = j.len;
        d->len = tx_len > max_frame ? max_frame : tx_len;
        
        xsk_ring_prod__submit(tx_ring, 1);
        sent++;
    }

    if (sent > 0) {
        if (xsk_ring_prod__needs_wakeup(tx_ring)) {
            (void)sendto(xfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
    }

    return sent;
}

int ne_tx_drain_loc(struct ne_pair *p, struct ne_ring *src)
{
    int xfd = xsk_socket__fd(p->loc.xsk);
    struct xsk_ring_prod *tx_ring = &p->loc.tx;

    return ne_tx_drain_port(xfd, tx_ring, src, p->frame_size);
}

int ne_tx_drain_wan(struct ne_pair *p, struct ne_ring *src)
{
    int xfd = xsk_socket__fd(p->wan.xsk);
    struct xsk_ring_prod *tx_ring = &p->wan.tx;

    return ne_tx_drain_port(xfd, tx_ring, src, p->frame_size);
}

int ne_tx_drain_wan_rr(struct ne_pair *p, struct ne_ring *src)
{
	static unsigned alt;
	struct ne_job j;
	uint32_t idx;
	struct xdp_desc *d;
	int xfd;
	struct xsk_ring_prod *tx;
	int sent = 0;

	for (;;) {
		if (ne_ring_try_pop(src, &j) != 0)
			break;

		if ((alt++ & 1u) == 0) {
			xfd = xsk_socket__fd(p->wan.xsk);
			tx = &p->wan.tx;
		} else {
			xfd = xsk_socket__fd(p->wan2.xsk);
			tx = &p->wan2.tx;
		}

		if (xsk_prod_nb_free(tx, 1) < 1) {
			while (ne_ring_try_push(src, &j) != 0)
				;
			break;
		}

		if (xsk_ring_prod__reserve(tx, 1, &idx) != 1) {
			while (ne_ring_try_push(src, &j) != 0)
				;
			break;
		}

		d = xsk_ring_prod__tx_desc(tx, idx);
		d->addr = j.umem_addr;
		d->len = j.len > p->frame_size ? p->frame_size : j.len;
		xsk_ring_prod__submit(tx, 1);
		sent++;

		if (xsk_ring_prod__needs_wakeup(tx))
			(void)sendto(xfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	}

	return sent;
}

static void ne_drain_cq_port(struct ne_zc_port *port, struct ne_pool *pool)
{
	uint32_t idx;
	unsigned int n;
	uint64_t a;

	for (;;) {
		n = xsk_ring_cons__peek(&port->cq, 1, &idx);
		if (!n)
			break;
		a = *xsk_ring_cons__comp_addr(&port->cq, idx);
		xsk_ring_cons__release(&port->cq, 1);
		(void)ne_pool_push(pool, &a, 1);
	}
}

void ne_drain_cq_loc(struct ne_pair *p)
{
	ne_drain_cq_port(&p->loc, &p->pool);
}

void ne_drain_cq_wan(struct ne_pair *p)
{
	ne_drain_cq_port(&p->wan, &p->pool);
}

void ne_drain_cq_wan2(struct ne_pair *p)
{
	ne_drain_cq_port(&p->wan2, &p->pool);
}

static void ne_refill_fq_port(struct ne_zc_port *port, struct ne_pool *pool)
{
	uint64_t a;
	uint32_t idx;

	for (;;) {
		if (xsk_prod_nb_free(&port->fq, 1) < 1)
			break;

		if (ne_pool_pop(pool, &a, 1) != 1)
			break;

		if (xsk_ring_prod__reserve(&port->fq, 1, &idx) != 1) {
			(void)ne_pool_push(pool, &a, 1);
			break;
		}
		*xsk_ring_prod__fill_addr(&port->fq, idx) = a;
		xsk_ring_prod__submit(&port->fq, 1);
	}
}

void ne_refill_fq_loc(struct ne_pair *p)
{
	ne_refill_fq_port(&p->loc, &p->pool);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
	ne_refill_fq_port(&p->wan, &p->pool);
}

void ne_refill_fq_wan2(struct ne_pair *p)
{
	ne_refill_fq_port(&p->wan2, &p->pool);
}
