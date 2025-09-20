#include <linux/module.h>
#include <net/tcp.h>
#include <linux/bitops.h>
#include <linux/math64.h>

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

#define ELEGANT_SCALE 6
#define ELEGANT_UNIT (1 << ELEGANT_SCALE)
#define ELEGANT_UNIT_SQUARED ((u64)ELEGANT_UNIT * ELEGANT_UNIT)

static int scale __read_mostly = 96U; // 1.5 * BETA_SCALE

static int win_thresh __read_mostly = 24; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

struct elegant {
	u32	rtt_curr;
	u32	rtt_max;
	u32	base_rtt;	/* min of all rtt in usec */
	u32 beta;  				 /* multiplicative decrease factor */
	u64 sum_rtt;               /* sum of RTTs in last round */
    u32 cnt_rtt;            /* samples in this RTT */
	u32 prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	next_rtt_delivered;
	u32	cache_wwf;
	u32 inv_beta;
	u8  prev_ca_state:7,
	    round_start:1;
};

static void elegant_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->rtt_curr = 0;
	ca->rtt_max = 0;
	ca->base_rtt = 0x7fffffff;
	ca->beta = BETA_MIN;
	ca->sum_rtt = 0;
	ca->cnt_rtt = 0;
	ca->prior_cwnd = tp->prior_cwnd;
	ca->next_rtt_delivered = tp->delivered;
	ca->cache_wwf = 0;
	ca->inv_beta = scale - BETA_MIN; // 96 - 8 = 88 (1.375)
	ca->prev_ca_state = TCP_CA_Open;
	ca->round_start = 0;
}

static inline u32 calculate_beta_scaled_value(u32 beta, u32 value)
{
    return (value * beta) >> BETA_SHIFT;
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 cwnd = tp->snd_cwnd;

	if (ca->prev_ca_state < TCP_CA_Recovery)
		ca->prior_cwnd = cwnd;
	else
		ca->prior_cwnd = max(ca->prior_cwnd,  cwnd);

	return max(cwnd - calculate_beta_scaled_value(ca->beta, cwnd), 2U);
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct elegant *ca)
{
    return ca->rtt_max - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(const struct elegant *ca)
{
    return ca->cnt_rtt ? (ca->sum_rtt / ca->cnt_rtt) - ca->base_rtt : 0;
}

/*
 * Beta used for multiplicative decrease.
 * For small window sizes returns same value as Reno (0.5)
 *
 * If delay is small (10% of max) then beta = 1/8
 * If delay is up to 80% of max then beta = 1/2
 * In between is a linear function
 */
static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;
	
	if (dm < 100 || dm == 0)
        return BETA_MAX;

	d2 = dm / 10;
	d3 = 8 * d2;
	if (da <= d2)
		return BETA_MIN;

	
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

    if (tp->snd_cwnd < win_thresh) {
        ca->beta = BETA_BASE;
		ca->inv_beta = scale - BETA_BASE; // 96 - 32 = 64 (1.0)
    } else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->beta = beta(da, dm);
		ca->inv_beta = scale - ca->beta; // 96 - beta
	}

	rtt_reset(tp, ca);
}

static inline u64 fast_isqrt(u64 x)
{
    if (x < 2)
        return x;

    /* Initial guess: 1 << (floor(log2(x)) / 2) */
    u64 r = 1ULL << ((fls64(x) - 1) >> 1);

    /* two Newton iteration */
    r = (r + x / r) >> 1;
	r = (r + x / r) >> 1;

    return r;
}

static void elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		tcp_slow_start(tp, acked);
	} else {
		u32 wwf = ca->cache_wwf;
		if (ca->round_start || wwf == 0) {
			u64 wwf64 = int_sqrt64((u64)tp->snd_cwnd*ca->rtt_max*ELEGANT_UNIT_SQUARED/(ca->rtt_curr | 1U));
			wwf = (u32)(wwf64 >> ELEGANT_SCALE);
			wwf = ((wwf * ca->inv_beta) >> BETA_SHIFT) | 1U;
            ca->cache_wwf = wwf;
		}
		wwf = max(wwf, acked);
		tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
	}
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

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	
	if (ca->cnt_rtt == 0 || rs->delivered > rs->prior_delivered)
		elegant_update_rtt(sk, rs);

	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	ca->round_start = 0;
	/* See if we've reached the next RTT */
	if (rs->interval_us > 0 && !before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		update_params(sk);
		ca->round_start = 1;
	}

	ca->prev_ca_state = inet_csk(sk)->icsk_ca_state;
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->rtt_max = ca->rtt_curr;
		ca->beta = BETA_BASE;
		rtt_reset(tp, ca);
		ca->cache_wwf = 0;
		ca->inv_beta = scale - BETA_BASE;
		ca->prev_ca_state = TCP_CA_Loss;
	} else if (ca->prev_ca_state == TCP_CA_Loss && new_state != TCP_CA_Loss) {
		tp->snd_cwnd = max(tp->snd_cwnd, ca->prior_cwnd);
	}
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
    struct elegant *ca = inet_csk_ca(sk);

	ca->cache_wwf = 0;

    return ca->prior_cwnd;
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
