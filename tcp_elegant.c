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

static const u32 lt_intvl_min_rtts = 4;
static const u32 cwnd_min_target = 4;

static int win_thresh __read_mostly = 20; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int rtt0 __read_mostly = 25;
module_param(rtt0, int, 0644);
MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");

struct elegant {
	u64   sum_rtt;               /* sum of RTTs in last round */

    u32   base_rtt;              /* base RTT */
    u32   max_rtt;               /* max RTT in last round */
	u32   rtt_curr;              /* current RTT, per-ACK update */
    u32   cnt_rtt:16,            /* samples in this RTT */
          lt_rtt_cnt:7,          /* rtt-round counter */
          lt_is_sampling:1,      /* have we calc’d WWF this RTT? */
          unused:7,
          wwf_valid:1;           /* last CA state */

    u32   beta;  				 /* multiplicative decrease factor */
    u32   max_rtt_trend;         /* decaying max used in wwf */
    u32   base_rtt_trend;		 /* last base RTT */
    u32   cached_wwf;            /* cached window‐width factor */
    u32   next_rtt_delivered;    /* delivered count at round start */

} __attribute__((__packed__));

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

	ca->sum_rtt = 0;

    ca->base_rtt = U32_MAX;
    ca->max_rtt = 0;
    ca->rtt_curr = 0;
	ca->cnt_rtt = 0;
	ca->lt_rtt_cnt = 0;
	ca->lt_is_sampling = false;
	ca->wwf_valid = false;

    ca->beta = BETA_BASE;
    ca->max_rtt_trend = 0;
    ca->base_rtt_trend = 0;
    ca->cached_wwf = 0;
    ca->next_rtt_delivered = tp->delivered;

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

static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 10;
	if (da <= d2)
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

static void update_params(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

    if (tp->snd_cwnd < win_thresh) {
        ca->beta = BETA_BASE;
    } else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->beta = beta(da, dm);
	}

	rtt_reset(sk);
}

static void tcp_elegant_reset(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

    ca->sum_rtt = 0;
	ca->base_rtt = U32_MAX;
	ca->max_rtt = 0;
	ca->rtt_curr = 0;
    ca->cnt_rtt = 0;
	ca->beta = BETA_BASE;
    ca->max_rtt_trend = 0;
    ca->base_rtt_trend = 0;

}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		tcp_elegant_reset(sk);
		ca->wwf_valid = false;
	}
}

static inline u32 hybla_factor(const struct tcp_sock *tp, const struct elegant *ca)
{
    u32 srtt = max(tp->srtt_us, 25000U);
    u32 rtt  = ca->rtt_curr ?: 1U;

    return clamp(rtt / srtt, 1U, 4U);
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

    return r;
}

static inline u32 calc_wwf(const struct tcp_sock *tp, const struct elegant *ca)
{
	u32 wwf;
	u32 inv_beta = BETA_SUM - ca->beta; 
    u32 d        = max(ca->max_rtt,    ca->max_rtt_trend);
    u32 c        = min(ca->base_rtt,   ca->base_rtt_trend);
    u32 m        = (13U * ca->rtt_curr + 3U * c) >> 4;

	u64 numer	 = (u64)tp->snd_cwnd * d << E_UNIT_SQ_SHIFT;

	do_div(numer, m);

    wwf = fast_isqrt(numer) >> ELEGANT_SCALE;

    return (wwf * inv_beta + (BETA_SCALE >> 1)) >> BETA_SHIFT;
}

static void tcp_elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 wwf;

	if (tcp_in_slow_start(tp)) {
		u32 p    = hybla_factor(tp, ca);

        wwf = tcp_slow_start(tp, acked * p);
		if (!wwf)
			return;
	} else {
		/* Compute WWF once per RTT boundary */
		if (!ca->wwf_valid || ca->cached_wwf == 0) {
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
	bool first_sample = (ca->cnt_rtt == 0) || (ca->rtt_curr == 0);
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
	ca->base_rtt = min(ca->base_rtt_trend, ca->base_rtt);

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

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		ca->lt_rtt_cnt++;
		ca->wwf_valid = false;
		ca->max_rtt_trend = (ca->max_rtt_trend >> 1) + (ca->max_rtt >> 1);
		ca->base_rtt_trend = (ca->base_rtt_trend >> 1) + (ca->base_rtt >> 1);
		update_params(sk);
	}

	if (!ca->lt_is_sampling && rs->losses) {
		ca->lt_rtt_cnt = 0;
		ca->lt_is_sampling = true;
	}

	if (rs->is_app_limited) {
		ca->lt_rtt_cnt = 0;
		ca->lt_is_sampling = false;
	}

	if (ca->lt_is_sampling && ca->lt_rtt_cnt > 4 * lt_intvl_min_rtts) {
		ca->lt_rtt_cnt = 0;
		ca->lt_is_sampling = false;
	}

	tcp_elegant_pkts_acked(sk, rs);

}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_elegant_update(sk, rs);

    if (rs->losses > 0) {
        tp->snd_cwnd = max_t(s32, tp->snd_cwnd - rs->losses, cwnd_min_target);
    }

}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->lt_rtt_cnt = 0;
	ca->lt_is_sampling = false;
	ca->wwf_valid = false;

	return tcp_reno_undo_cwnd(sk);
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

