#include <linux/module.h>
#include <net/tcp.h>

#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/kernel.h>

#define ELEGANT_SCALE 6
#define ELEGANT_UNIT (1 << ELEGANT_SCALE)          // 64
#define E_UNIT_SQ_SHIFT (2 * ELEGANT_SCALE)        // 12
#define E_UNIT_SQ (1ULL << E_UNIT_SQ_SHIFT)     // 4096

#define ALPHA_SHIFT	7
#define ALPHA_SCALE	(1u<<ALPHA_SHIFT)
#define ALPHA_MAX	(10*ALPHA_SCALE)	/* 10.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX
#define BETA_SUM   (BETA_SCALE + BETA_MIN + BETA_MAX)

#define BASE_RTT_RESET_INTERVAL (10 * HZ) /* 10 seconds for base_rtt reset */
#define INV_M_SHIFT 32

static const u32 bbr_lt_intvl_min_rtts = 4;
static const u32 bbr_cwnd_min_target = 4;

static int win_thresh __read_mostly = 20; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int rtt0 __read_mostly = 25;
module_param(rtt0, int, 0644);
MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");

struct elegant {
	u64   sum_rtt;               /* sum of RTTs in last round */
	
    u32   rtt_curr;              /* current RTT, per-ACK update */
    u32   rtt_max;               /* decaying max used in wwf */
    u32   base_rtt;              /* base RTT */
    u32   next_rtt_delivered;    /* delivered count at round start */
    u32   cached_wwf;            /* cached window‐width factor */
	u32   max_rtt;               /* max RTT in last round */
    u32   last_base_rtt;		 /* last base RTT */
    u32   last_rtt_reset_jiffies; /* jiffies of last RTT reset */
	
	u16   cnt_rtt;               /* samples in this RTT */

    u8    prev_ca_state;         /* last CA state */
	u8    lt_rtt_cnt:7,          /* rtt-round counter */
		  wwf_valid:1;           /* have we calc’d WWF this RTT? */

    u32   beta;  				 /* multiplicative decrease factor */
    u32   prior_cwnd;			 /* cwnd before loss recovery */
} __attribute__((aligned(64)));

static void rtt_reset(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;
}

static void tcp_elegant_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->rtt_max = tp->srtt_us >> 3;
	ca->rtt_curr = ca->rtt_max;
	ca->base_rtt = ca->rtt_curr;
	ca->last_base_rtt = ca->base_rtt;
	ca->max_rtt = ca->last_base_rtt;
	ca->last_rtt_reset_jiffies = jiffies;

	ca->beta = BETA_BASE;
	ca->next_rtt_delivered = tp->delivered;
	ca->prior_cwnd = TCP_INIT_CWND;
	ca->cached_wwf = 0;

	rtt_reset(sk);

	ca->lt_rtt_cnt = 0;
	ca->prev_ca_state = TCP_CA_Open;

	ca->wwf_valid = false;
}

/* Calculate value scaled by beta */
static inline u32 calculate_beta_scaled_value(const struct elegant *ca, u32 value)
{
	return (value * ca->beta) >> BETA_SHIFT;
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	
	ca->prior_cwnd = tp->snd_cwnd;

	return max(tp->snd_cwnd - calculate_beta_scaled_value(ca, tp->snd_cwnd), 2U);
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct elegant *ca)
{
	return ca->max_rtt - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(const struct elegant *ca)
{
	u64 t = ca->sum_rtt;

	do_div(t, ca->cnt_rtt);
	return t - ca->base_rtt;
}

static u32 beta(const struct rate_sample *rs, u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 10;
	if (rs->is_app_limited || da <= d2)
		return BETA_MIN;

	d3 = (8 * dm) / 10;
	if (da >= d3 || d3 <= d2)
		return BETA_MAX;

	/*
	 * Based on:
	 *
	 *       bmin d3 - bmax d2
	 * k3 = -------------------
	 *         d3 - d2
	 *
	 *       bmax - bmin
	 * k4 = -------------
	 *         d3 - d2
	 *
	 * b = k3 + k4 da
	 */
	return (BETA_MIN * d3 - BETA_MAX * d2 + (BETA_MAX - BETA_MIN) * da)
		/ (d3 - d2);
}

static void update_params(const struct rate_sample *rs, struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (tp->snd_cwnd < win_thresh) {
		ca->beta = BETA_BASE;
	} else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->beta = beta(rs, da, dm);
	}

	rtt_reset(sk);
}

static void tcp_elegant_reset(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->beta = BETA_BASE;
	rtt_reset(sk);
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->prev_ca_state = TCP_CA_Loss;
		tcp_elegant_reset(sk);
	}
}

static inline u32 hybla_factor(const struct tcp_sock *tp, const struct elegant *ca)
{
    /* 1. Clamp to 25 ms floor */
    u32 srtt = max(tp->srtt_us, 25000U);

    /* 2. Ensure nonzero divisor */
    u32 rtt  = ca->rtt_curr ?: 1U;

    /* 3. Integer ratio and branchless clamp to [1,4] */
    return clamp(rtt / srtt, 1U, 4U);
}

static u32 isqrt_u64(u64 x)
{
    /* Get highest set bit: similar to fls64 */
    int msb = 63 - __builtin_clzll(x);
    int shift = msb >> 1;

    /* Initial guess: 1 << shift */
    u64 r = 1ULL << shift;
    u64 r_next;
	
	if (x == 0 || x == 1)
        return (u32)x;

    while (1) {
        u64 div = x / r;
        r_next = (r + div) >> 1;
        if (r_next >= r)
            break;
        r = r_next;
    }
    return (u32)r;
}

static inline u64 fast_isqrt(u64 x)
{
    u64 r;

    if (x < 2)
        return x;

    /* Initial guess: 1 << (floor(log2(x)) / 2) */
    r = 1ULL << ((fls64(x) - 1) >> 1);

    /* one Newton iteration */
    r = (r + x / r) >> 1;
	//r = (r + x / r) >> 1;

    return r;
}

static inline u32 calc_wwf(const struct tcp_sock *tp, const struct elegant *ca)
{
	u32 wwf;
	u32 inv_beta = BETA_SUM - ca->beta; 
    u32 d        = max(ca->rtt_max,    ca->max_rtt);
    u32 c        = min(ca->base_rtt,   ca->last_base_rtt);
    u32 m        = (13U * ca->rtt_curr + 3U * c) >> 4;

	u64 numer	 = (u64)tp->snd_cwnd * d << E_UNIT_SQ_SHIFT;

	do_div(numer, m);

    wwf = fast_isqrt(numer);

    return (wwf >> ELEGANT_SCALE * inv_beta + (BETA_SCALE >> 1)) >> BETA_SHIFT;
}

static void tcp_elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 wwf;

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		u32 p    = hybla_factor(tp, ca);

        wwf = tcp_slow_start(tp, acked * p);
		if (!wwf)
			return;
	} else {
		/* Compute WWF once per RTT boundary */
		if (!ca->wwf_valid) {
			ca->cached_wwf = calc_wwf(tp, ca);
			ca->wwf_valid  = true;
        }

        wwf = max(ca->cached_wwf, acked);
	}

	tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
}

static void tcp_elegant_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 rtt_us = rs->rtt_us;
	u32 acked = rs->delivered - rs->prior_delivered;
	bool first_sample = (ca->cnt_rtt == 0);
	bool only_sack    = (acked == 0 && rs->acked_sacked > 0);

	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	if (rtt_us > RTT_MAX)
		rtt_us = RTT_MAX;

	if (first_sample || (acked > 0 && !only_sack && !rs->is_ack_delayed)) {
		ca->rtt_curr = rtt_us;
		++ca->cnt_rtt;
		ca->sum_rtt += rtt_us;
	}

	ca->base_rtt = min(ca->base_rtt, rtt_us);
	ca->base_rtt = min(tp->srtt_us >> 3, ca->base_rtt);

	/* and max */
	if (ca->max_rtt < rtt_us)
		ca->max_rtt = rtt_us;
}

static void tcp_elegant_update(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (unlikely(rs->delivered < 0 || rs->interval_us <= 0))
		return; /* Not a valid observation */
	
	if (after(tcp_jiffies32, ca->last_rtt_reset_jiffies + BASE_RTT_RESET_INTERVAL)) {
		ca->rtt_max = ca->max_rtt;
		ca->max_rtt = tp->srtt_us >> 3;
		ca->last_rtt_reset_jiffies = jiffies;
	}

	if (ca->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		update_params(rs, sk);
		ca->lt_rtt_cnt = 0;
		if (ca->last_base_rtt < ca->base_rtt) {
			ca->last_base_rtt = (ca->last_base_rtt >> 1) + (ca->base_rtt >> 1);
		} else {
			ca->last_base_rtt = ca->base_rtt;
		}
		ca->base_rtt = U32_MAX;
	}

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		ca->lt_rtt_cnt++;
		ca->wwf_valid = false;
	}

	tcp_elegant_pkts_acked(sk, rs);

}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u8 prev_state = ca->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	tcp_elegant_update(sk, rs);

	if (!rs->acked_sacked)
		goto done;  /* no packet fully ACKed; just apply caps */

	if (state == TCP_CA_Open)
		goto done;

	ca->prev_ca_state = state;

	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		ca->next_rtt_delivered = tp->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = max(cwnd, tcp_packets_in_flight(tp) + rs->acked_sacked);
		ca->wwf_valid = false;
		goto done;
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		cwnd = max(cwnd, ca->prior_cwnd);
	}

	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->lt_rtt_cnt = 0;
	
	return max(tp->snd_cwnd, ca->prior_cwnd);
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.name			= "elegant",
	.owner			= THIS_MODULE,
	.init			= tcp_elegant_init,
	.ssthresh		= tcp_elegant_ssthresh,
	.undo_cwnd		= tcp_elegant_undo_cwnd,
	.cong_avoid		= tcp_elegant_cong_avoid,
	.cong_control	= tcp_elegant_cong_control,
	.set_state		= tcp_elegant_set_state
};

static int __init elegant_register(void)
{
	BUILD_BUG_ON(sizeof(struct elegant) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_elegant);
}

static void __exit elegant_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_elegant);
}

module_init(elegant_register);
module_exit(elegant_unregister);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Elegant TCP");

