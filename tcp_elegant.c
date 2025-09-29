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
#define ELEGANT_UNIT_SQ_SHIFT (2 * ELEGANT_SCALE)        // 12
#define ELEGANT_UNIT_SQUARED (1ULL << (2 * ELEGANT_SCALE))

static const u32 lt_intvl_min_rtts = 4;
static int scale __read_mostly = 96U; // 1.5 * BETA_SCALE
static int max_scale __read_mostly = 88U;

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
    u32 round_start:1,
	    lt_is_sampling:1,      /* have we calc’d WWF this RTT? */
		lt_rtt_cnt:7,          /* rtt-round counter */
		had_loss_this_rtt:1,
		loss_cnt:7,
		beta_lock:1,
		beta_lock_cnt:7,
		prev_ca_state:3,
		unused:4;
	u32	cache_wwf;
	u32 inv_beta;
	u32 prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	next_rtt_delivered;
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
	ca->round_start = 0;
	ca->lt_is_sampling = 0;
	ca->lt_rtt_cnt = 0;
	ca->had_loss_this_rtt = 0;	
	ca->loss_cnt = 0;
	ca->beta_lock = 0;
	ca->beta_lock_cnt = 0;
	ca->prev_ca_state = TCP_CA_Open;
	ca->cache_wwf = 0;
	ca->inv_beta = max_scale; // 96 - 8 = 88 (1.375)
	ca->prior_cwnd = tp->prior_cwnd;
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

static inline u32 ema_value(u32 old, u32 new) {
    return (old * 7 + new) >> 3;
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
	} else {
		wwf = ca->cache_wwf;
		if (ca->round_start || wwf == 0) {
			u32 rtt = ema_value(ca->rtt_curr, ca->base_rtt);
			if (rtt > 0) {
				u64 wwf64 = int_sqrt64(((u64)tp->snd_cwnd * ca->rtt_max << ELEGANT_UNIT_SQ_SHIFT)/rtt);
				wwf = (u32)(wwf64 >> ELEGANT_SCALE);
				if ((ca->lt_is_sampling && ca->loss_cnt > 2) || ca->beta_lock) {
					wwf = ((wwf * ca->inv_beta) >> BETA_SHIFT);
				} else {
					wwf = ((wwf * max_scale) >> BETA_SHIFT);
				}
				ca->cache_wwf = wwf;
			}
		}
		wwf = max(wwf, acked);
	}
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
}

static void lt_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);
	u32 smoothed = ema_value(avg_delay(ca), ca->rtt_curr);
    bool delay_spike = (smoothed > 2 * ca->base_rtt) &&
                       (smoothed / ca->base_rtt > ca->rtt_max / ca->base_rtt);  // min/max ratio

	if (!ca->lt_is_sampling) {
		if (rs->losses || delay_spike) {
			ca->lt_is_sampling = true;
			ca->lt_rtt_cnt = 0;
			ca->had_loss_this_rtt = 0;
			if (rs->losses) ca->loss_cnt++;
		} else if (ca->round_start && ca->beta_lock == 1 && ca->beta_lock_cnt >= 2) {
			ca->beta_lock = 0;
			ca->beta_lock_cnt = 0;
		} else if (ca->round_start && ca->beta_lock == 1 && !delay_spike) {
			ca->beta_lock_cnt++;
		} else {
			ca->loss_cnt = 0;
		}
	} else {
		if (rs->is_app_limited) {
			ca->lt_is_sampling = false;
			ca->lt_rtt_cnt = 0;
			ca->had_loss_this_rtt = 0;
		} else {
			if (rs->losses && !ca->had_loss_this_rtt) {
				ca->loss_cnt++;
				ca->had_loss_this_rtt = 1;
			}
			if (ca->round_start) {
				ca->lt_rtt_cnt++;
				ca->had_loss_this_rtt = 0;	
			} else if (ca->lt_rtt_cnt > 4 * lt_intvl_min_rtts) {
				ca->lt_is_sampling = false;
				ca->lt_rtt_cnt = 0;
				ca->beta_lock = 1;
				ca->had_loss_this_rtt = 0;
			}
		}
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

	lt_sampling(sk, rs);

	ca->prev_ca_state = inet_csk(sk)->icsk_ca_state;
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		ca->rtt_max = ca->rtt_curr;
		ca->beta = BETA_BASE;
		rtt_reset(tp, ca);
		lt_sampling(sk, &rs);
		ca->cache_wwf = 0;
		ca->inv_beta = scale - BETA_BASE;
		ca->prev_ca_state = TCP_CA_Loss;
	} else if (ca->prev_ca_state == TCP_CA_Loss && new_state != TCP_CA_Loss) {
		ca->lt_is_sampling = false;
		ca->had_loss_this_rtt = 0;
		tp->snd_cwnd = max(tp->snd_cwnd, ca->prior_cwnd);
	}
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
    struct elegant *ca = inet_csk_ca(sk);

	ca->lt_is_sampling = false;
	ca->had_loss_this_rtt = 0;
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
