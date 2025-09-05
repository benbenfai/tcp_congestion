#include <linux/module.h>
#include <net/tcp.h>

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

#define ELEGANT_SCALE 6
#define ELEGANT_UNIT (1 << ELEGANT_SCALE)

static int win_thresh __read_mostly = 20; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

struct elegant {
	u64 sum_rtt;               /* sum of RTTs in last round */
    u32 cnt_rtt;            /* samples in this RTT */
	u32	base_rtt;	/* min of all rtt in usec */
	u32	rtt_max;
	u32	rtt_curr;
	u32	end_seq;	/* right edge of current RTT */
	u32 beta;  				 /* multiplicative decrease factor */
	u32 prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u8  prev_ca_state;
};

static void elastic_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	*ca = (struct elegant) {
			.base_rtt = 0x7fffffff,
			.beta = BETA_BASE,
			.prior_cwnd = tp->snd_cwnd
		};
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
    return ca->cnt_rtt ? (u32)(ca->sum_rtt / ca->cnt_rtt) - ca->base_rtt : 0;
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

static inline void rtt_reset(struct tcp_sock *tp, struct elegant *ca)
{
	ca->end_seq = tp->snd_nxt;
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;
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

static void elastic_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (after(ack, ca->end_seq))
		update_params(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);
	else {
		u64 wwf64 = fast_isqrt(tp->snd_cwnd*ELEGANT_UNIT*ELEGANT_UNIT*ca->rtt_max/ca->rtt_curr);
		u32 wwf = wwf64 >> ELEGANT_SCALE;
		tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
	}
}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	ca->prev_ca_state = inet_csk(sk)->icsk_ca_state;

}

static void elastic_update_rtt(struct sock *sk, const struct ack_sample *sample)
{
	struct elegant *ca = inet_csk_ca(sk);
	s32 rtt_us = sample->rtt_us;
	
	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	/* keep track of minimum RTT seen so far */
	if (ca->base_rtt > rtt_us)
		ca->base_rtt = rtt_us;

	++ca->cnt_rtt;
	ca->sum_rtt += rtt_us;

	ca->rtt_curr = rtt_us + 1;
	if (ca->rtt_curr > ca->rtt_max) {
		ca->rtt_max = ca->rtt_curr;
	}
}

static void elastic_event(struct sock *sk, enum tcp_ca_event event)
{
	struct elegant *ca = inet_csk_ca(sk);
	if (event == CA_EVENT_LOSS) {
		ca->rtt_max = 0;
	}
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->beta = BETA_BASE;
		rtt_reset(tp, ca);
	} else if (ca->prev_ca_state == TCP_CA_Loss && new_state != TCP_CA_Loss) {
		tp->snd_cwnd = max(tp->snd_cwnd, ca->prior_cwnd);
	}
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	return ca->prior_cwnd;
}

static struct tcp_congestion_ops tcp_elastic __read_mostly = {
	.name		= "elegant",
	.owner		= THIS_MODULE,
	.init		= elastic_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_elegant_undo_cwnd,
	.cong_avoid	= elastic_cong_avoid,
	.cong_control	= tcp_elegant_cong_control,
	.pkts_acked	= elastic_update_rtt,
	.cwnd_event	= elastic_event,
	.set_state  = tcp_elegant_set_state
};

static int __init elastic_register(void)
{
	BUILD_BUG_ON(sizeof(struct elegant) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_elastic);
}

static void __exit elastic_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_elastic);
}

module_init(elastic_register);
module_exit(elastic_unregister);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Elastic TCP");