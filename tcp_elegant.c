#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <asm/div64.h>
#include <linux/bitops.h>
#include <net/tcp.h>

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

#define ELEGANT_SCALE 6
#define ELEGANT_UNIT (1 << ELEGANT_SCALE)
#define ELEGANT_UNIT_SQ_SHIFT (2 * ELEGANT_SCALE)        // 12
#define ELEGANT_UNIT_SQUARED (1ULL << (2 * ELEGANT_SCALE))

static int scale __read_mostly = 96U; // 1.5 * BETA_SCALE

static int win_thresh __read_mostly = 15; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

struct elegant {
	u64 sum_rtt;               /* sum of RTTs in last round */
    u32 cnt_rtt;            /* samples in this RTT */
	u32	round_base_rtt;	/* min of all rtt in usec */
	u32	round_rtt_max;
	u32	base_rtt;	/* min of all rtt in usec */
    u32	rtt_max;
	u32	rtt_curr;
	u32	cache_wwf;
	u32 beta;  				 /* multiplicative decrease factor */
    u32 round_start;
	u32	next_rtt_delivered;
	u32 prior_cwnd;
};

static void elegant_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
	ca->round_base_rtt = UINT_MAX;
	ca->round_rtt_max = 0;
	ca->base_rtt = UINT_MAX;
	ca->rtt_max = 0;
	ca->rtt_curr = 0;
	ca->cache_wwf = 0;
	ca->beta = BETA_MIN;
	ca->round_start = 0;
	ca->next_rtt_delivered = tp->delivered;
	ca->prior_cwnd = tp->snd_cwnd;
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	//struct elegant *ca = inet_csk_ca(sk);

	return max(tp->snd_cwnd >> 1, 2U);
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct elegant *ca)
{
    return ca->rtt_max - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(struct elegant *ca)
{
	u64 t = ca->sum_rtt;

	do_div(t, ca->cnt_rtt);

	ca->rtt_curr = t;

	return t - ca->base_rtt;
}

static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 10;
	if (da <= d2)
		return BETA_MIN;

	d3 = d2 << 3;
	if (da >= d3)
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

static inline void rtt_reset(struct tcp_sock *tp, struct elegant *ca)
{
	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
}

static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

    if (tp->snd_cwnd < win_thresh) {
        ca->beta = BETA_BASE;
    } else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->beta = beta(da, dm);

		tp->snd_ssthresh = max(2U, ca->rtt_curr / (da * (BETA_SCALE - ca->beta)));
		ca->prior_cwnd = tp->snd_ssthresh;
	}

	rtt_reset(tp, ca);
}

static void elegant_update_pacing_rate(struct sock *sk, struct elegant *ca)
{
	struct tcp_sock *tp = tcp_sk(sk);

    u64 rate = (u64)tp->mss_cache * ((USEC_PER_SEC/100) << 3);
	u64 temp = (u64)(scale - ca->beta + 8U);
    u64 scale = (temp * temp * 100ULL) >> (BETA_SHIFT * 2);

	if (tp->snd_cwnd < (tp->snd_ssthresh >> 1)) {
		scale = max(200ULL, scale);
	}

	rate *= scale;
    rate *= max(tp->snd_cwnd, tp->packets_out);

    if (likely(tp->srtt_us))
        do_div(rate, tp->srtt_us);

    WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, sk->sk_max_pacing_rate));
}

static inline u64 fast_isqrt(u64 x)
{
	u64 r;
	int i=0;
    if (x < 2)
        return x;

    /* Initial guess: 1 << (floor(log2(x)) / 2) */
    r = 1ULL << ((fls64(x) - 1) >> 1);

    /* three Newton iteration */
    for (i; i<3; i++)
		r = (r + x / r) >> 1;

	if (r*r>x)
		r--;

    return r;
}

static void elegant_cong_avoid(struct sock *sk, struct elegant *ca, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	u32 wwf;
	u32 acked = rs->acked_sacked;

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		tcp_slow_start(tp, acked);
	} else {
		wwf = ca->cache_wwf;
		if (ca->round_start || wwf == 0) {
			u64 wwf64 = tp->snd_cwnd * ca->rtt_max << ELEGANT_UNIT_SQ_SHIFT;
			do_div(wwf64, ca->rtt_curr);
			wwf = fast_isqrt(wwf64) >> ELEGANT_SCALE;
			ca->cache_wwf = wwf;
		}
		tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
	}
}

static void elegant_update_rtt(struct elegant *ca, const struct rate_sample *rs)
{
	u32 rtt_us;

	/* dup ack, no rtt sample */
	if (rs->rtt_us < 0)
		return;

	rtt_us = rs->rtt_us;

	ca->sum_rtt += rtt_us;
	ca->cnt_rtt++;

	/* keep track of minimum RTT seen so far */
	if (rtt_us < ca->round_base_rtt)
		ca->round_base_rtt = rtt_us;

	if (rtt_us > ca->round_rtt_max)
		ca->round_rtt_max = rtt_us;
}

static void tcp_elegant_round(struct sock *sk, struct elegant *ca, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	ca->round_start = 0;
	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (rs->interval_us > 0 && !before(rs->prior_delivered, ca->next_rtt_delivered)) {
		if (ca->round_base_rtt != UINT_MAX) {
			ca->base_rtt = ca->round_base_rtt;
			ca->rtt_max = ca->round_rtt_max;
			update_params(sk);
			ca->round_base_rtt = UINT_MAX;
			ca->round_rtt_max = 0;
		}
		ca->round_start = 1;
		ca->next_rtt_delivered = tp->delivered;
	} else 	if (ca->round_base_rtt != UINT_MAX && ca->round_base_rtt > tp->srtt_us >> 1) {
		ca->cache_wwf = 0;
	}
}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (ca->cnt_rtt == 0 || (rs->interval_us > 0 && rs->delivered > 0)) {
		elegant_update_rtt(ca, rs);
	}

	tcp_elegant_round(sk, ca, rs);
	elegant_cong_avoid(sk, ca, rs);

	elegant_update_pacing_rate(sk, ca);
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		rtt_reset(tp, ca);
		ca->round_base_rtt = UINT_MAX;
		ca->cache_wwf = 0;
		ca->round_start = 1;
	}
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
    struct elegant *ca = inet_csk_ca(sk);

	ca->cache_wwf = 0;

    return max(tp->snd_cwnd, ca->prior_cwnd);
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.name		= "elegant",
	.owner		= THIS_MODULE,
	.init		= elegant_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_elegant_undo_cwnd,
	.cong_control	= tcp_elegant_cong_control,
	.set_state  = tcp_elegant_set_state
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
