#include <linux/module.h>
#include <linux/skbuff.h>
#include <asm/div64.h>
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

static const u32 lt_intvl_min_rtts = 4;
static int scale __read_mostly = 96U; // 1.5 * BETA_SCALE
static int max_scale __read_mostly = 88U;

static int win_thresh __read_mostly = 15; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

struct elegant {
	u32	rtt_curr;
	u32	rtt_max;
	u32	base_rtt;	/* min of all rtt in usec */
	u64 sum_rtt;               /* sum of RTTs in last round */
    u32 cnt_rtt;            /* samples in this RTT */
	u32	cache_wwf;
	u32 beta;  				 /* multiplicative decrease factor */
	u32 inv_beta;
    u32 round_start:1,
		prev_ca_state:3,
		unused:28;
	u32	next_rtt_delivered;
};

static void elegant_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->rtt_curr = 0;
	ca->rtt_max = 0;
	ca->base_rtt = 0x7fffffff;
	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
	ca->cache_wwf = 0;
	ca->beta = BETA_MIN;
	ca->inv_beta = max_scale; // 96 - 8 = 88 (1.375)
	ca->round_start = 0;
	ca->prev_ca_state = TCP_CA_Open;
	ca->next_rtt_delivered = tp->delivered;
}

static inline u32 calculate_beta_scaled_value(u32 beta, u32 value)
{
    return (value * beta) >> BETA_SHIFT;
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	return max(tp->snd_cwnd - calculate_beta_scaled_value(ca->beta, tp->snd_cwnd), 2U);
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct elegant *ca)
{
    return ca->rtt_max - ca->base_rtt;
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
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;
}

static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 avg_delay_val = avg_delay(ca);
	u32 thresh = win_thresh + ilog2((avg_delay_val / ca->base_rtt)+1) + ilog2((avg_delay_val / 1000) + 1);

    if (tp->snd_cwnd < thresh) {
        ca->beta = BETA_BASE;
		ca->inv_beta = max_scale;
    } else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay_val;

		ca->beta = beta(da, dm);
		ca->inv_beta = scale - ca->beta;
	}

	rtt_reset(tp, ca);
}

static void elegant_update_pacing_rate(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
    u64 rate;

    if (tp->srtt_us == 0)
        rate = ~0ULL;
    else {
        // Base rate: (cwnd * mss * scaling) / srtt_us
        rate = (u64)tp->snd_cwnd * tp->mss_cache;
        rate <<= 3;
        do_div(rate, tp->srtt_us);  // Divide to get bytes/usec
        rate *= USEC_PER_SEC;

        rate = (rate * ca->inv_beta) >> BETA_SHIFT;
    }

	WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, sk->sk_max_pacing_rate));
}

static inline u32 ema_value(u32 old, u32 new, u32 alpha_shift) {
	//(e.g., shift=3 for 1/8)
    return (old * ((1<<alpha_shift)-1) + new) >> alpha_shift;
}

static inline u64 fast_isqrt(u64 x)
{
    if (x < 2)
        return x;

    /* Initial guess: 1 << (floor(log2(x)) / 2) */
    u64 r = 1ULL << ((fls64(x) - 1) >> 1);

    /* two Newton iteration */
    for (int i=0; i<3; i++)
		r = (r + x / r) >> 1;
	
	if (r*r>x)
		r--;

    return r;
}

static void elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	u32 wwf;
	if (tcp_in_slow_start(tp)) {
		wwf = tcp_slow_start(tp, acked);
		if (!wwf)
			return;
		wwf = ((wwf * ca->inv_beta) >> BETA_SHIFT);
	} else {
		wwf = ca->cache_wwf;
		if (ca->round_start || wwf == 0) {
			u32 rtt = ema_value(ca->rtt_curr, ca->base_rtt, 3);
			if (rtt > 0) {
				u64 wwf64 = tp->snd_cwnd * ca->rtt_max << ELEGANT_UNIT_SQ_SHIFT;
				div_u64(wwf64, rtt);
				wwf64 = fast_isqrt(wwf64);
				wwf = wwf64 >> ELEGANT_SCALE;
				if (wwf > acked) {
					ca->cache_wwf = wwf;
				} else {
					wwf = acked;
				}
				wwf = ((wwf * ca->inv_beta) >> BETA_SHIFT);
			}
		}
	}
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
	elegant_update_pacing_rate(sk);
}

static void elegant_update_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);

	/* dup ack, no rtt sample */
	if (rs->rtt_us < 0)
		return;

	u32 rtt_us = rs->rtt_us;

	ca->rtt_curr = rtt_us;
	if (ca->rtt_curr > ca->rtt_max) {
		ca->rtt_max = ca->rtt_curr;
	}

	/* keep track of minimum RTT seen so far */
	if (ca->base_rtt > rtt_us)
		ca->base_rtt = rtt_us;

	ca->cnt_rtt++;
	ca->sum_rtt += rtt_us;
}

static void tcp_elegant_round(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->round_start = 0;
	ca->prev_ca_state = inet_csk(sk)->icsk_ca_state;
	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (rs->interval_us > 0 && !before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		update_params(sk);
		ca->round_start = 1;
	}
}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);
	
	if (ca->cnt_rtt == 0 || rs->delivered > rs->prior_delivered)
		elegant_update_rtt(sk, rs);

	tcp_elegant_round(sk, rs);

	if (rs->is_app_limited)
		ca->inv_beta = scale;
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->rtt_max = ca->rtt_curr;
		rtt_reset(tp, ca);
		ca->cache_wwf = 0;
		ca->round_start = 1;
		ca->prev_ca_state = TCP_CA_Loss;
	}
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
    struct elegant *ca = inet_csk_ca(sk);

	ca->cache_wwf = 0;

    return max(tp->snd_cwnd, tp->prior_cwnd);
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.name		= "elegant",
	.owner		= THIS_MODULE,
	.init		= elegant_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_elegant_undo_cwnd,
	.cong_avoid	= elegant_cong_avoid,
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
