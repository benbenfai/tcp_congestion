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

static const u32 lt_intvl_min_rtts = 4;
static const u32 cwnd_min_target = 4;

static int win_thresh __read_mostly = 20; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int rtt0 __read_mostly = 25;
module_param(rtt0, int, 0644);
MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");

/* resolution of owd */
#define LP_RESOL       TCP_TS_HZ

/**
 * enum tcp_lp_state
 * @LP_VALID_RHZ: is remote HZ valid?
 * @LP_VALID_OWD: is OWD valid?
 * @LP_WITHIN_THR: are we within threshold?
 * @LP_WITHIN_INF: are we within inference?
 *
 * TCP-LP's state flags.
 * We create this set of state flag mainly for debugging.
 */
enum tcp_lp_state {
	LP_VALID_RHZ = (1 << 0),
	LP_VALID_OWD = (1 << 1),
	LP_WITHIN_THR = (1 << 3),
	LP_WITHIN_INF = (1 << 4),
};

struct elegant {

	u32 flag;
	u32 sowd;
	u32 owd_min;
	u32 owd_max;
	u32 owd_max_rsv;
	u32 remote_hz;
	u32 remote_ref_time;
	u32 local_ref_time;
	u32 last_drop;
	u32 inference;
	u32 frozen_ssthresh;

	u64   sum_rtt;               /* sum of RTTs in last round */

    u32   base_rtt;              /* base RTT */
    u32   max_rtt;               /* max RTT in last round */
	u32   rtt_curr;              /* current RTT, per-ACK update */
    u32   cnt_rtt:16,            /* samples in this RTT */
          unused:12,
		  prev_ca_state:3,
          wwf_valid:1;           /* last CA state */

    u32   beta;  				 /* multiplicative decrease factor */
    u32   max_rtt_trend;         /* decaying max used in wwf */
    u32   base_rtt_trend;		 /* last base RTT */
    u32   cached_wwf;            /* cached window‐width factor */
    u32   next_rtt_delivered;    /* delivered count at round start */

	u32   prior_cwnd;	/* prior cwnd upon entering loss recovery */
    u32   last_rtt_reset_jiffies; /* jiffies of last RTT reset */

};

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

	ca->flag = 0;
	ca->sowd = 0;
	ca->owd_min = 0xffffffff;
	ca->owd_max = 0;
	ca->owd_max_rsv = 0;
	ca->remote_hz = 0;
	ca->remote_ref_time = 0;
	ca->local_ref_time = 0;
	ca->last_drop = 0;
	ca->inference = 0;
	ca->frozen_ssthresh = 0;

	ca->sum_rtt = 0;

    ca->base_rtt = U32_MAX;
    ca->max_rtt = 0;
    ca->rtt_curr = 0;
	ca->cnt_rtt = 0;
	ca->prev_ca_state = TCP_CA_Open;
	ca->wwf_valid = false;

    ca->beta = BETA_BASE;
    ca->max_rtt_trend = 0;
    ca->base_rtt_trend = 0;
    ca->cached_wwf = 0;
    ca->next_rtt_delivered = tp->delivered;

	ca->prior_cwnd = 0;
    ca->last_rtt_reset_jiffies = jiffies;

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
	
	if (ca->prev_ca_state < TCP_CA_Recovery)
		ca->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		ca->prior_cwnd = max(ca->prior_cwnd,  tp->snd_cwnd);

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
	ca->frozen_ssthresh = 0;

}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		tcp_elegant_reset(sk);
		ca->prev_ca_state = TCP_CA_Loss;
		ca->wwf_valid = false;
	}
}

static u32 tcp_lp_remote_hz_estimator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	s64 rhz = ca->remote_hz << 6;	/* remote HZ << 6 */
	s64 m = 0;

	/* not yet record reference time
	 * go away!! record it before come back!! */
	if (ca->remote_ref_time == 0 || ca->local_ref_time == 0)
		goto out;

	/* we can't calc remote HZ with no different!! */
	if (tp->rx_opt.rcv_tsval == ca->remote_ref_time ||
	    tp->rx_opt.rcv_tsecr == ca->local_ref_time)
		goto out;

	m = TCP_TS_HZ *
	    (tp->rx_opt.rcv_tsval - ca->remote_ref_time) /
	    (tp->rx_opt.rcv_tsecr - ca->local_ref_time);
	if (m < 0)
		m = -m;

	if (rhz > 0) {
		m -= rhz >> 6;	/* m is now error in remote HZ est */
		rhz += m;	/* 63/64 old + 1/64 new */
	} else
		rhz = m << 6;

 out:
	/* record time for successful remote HZ calc */
	if ((rhz >> 6) > 0)
		ca->flag |= LP_VALID_RHZ;
	else
		ca->flag &= ~LP_VALID_RHZ;

	/* record reference time stamp */
	ca->remote_ref_time = tp->rx_opt.rcv_tsval;
	ca->local_ref_time = tp->rx_opt.rcv_tsecr;

	return rhz >> 6;
}

static u32 tcp_lp_owd_calculator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	s64 owd = 0;

	ca->remote_hz = tcp_lp_remote_hz_estimator(sk);

	if (ca->flag & LP_VALID_RHZ) {
		owd =
		    tp->rx_opt.rcv_tsval * (LP_RESOL / ca->remote_hz) -
		    tp->rx_opt.rcv_tsecr * (LP_RESOL / TCP_TS_HZ);
		if (owd < 0)
			owd = -owd;
	}

	if (owd > 0)
		ca->flag |= LP_VALID_OWD;
	else
		ca->flag &= ~LP_VALID_OWD;

	return owd;
}

static void tcp_lp_rtt_sample(struct sock *sk, u32 rtt)
{
	struct elegant *ca = inet_csk_ca(sk);
	s64 mowd = tcp_lp_owd_calculator(sk);

	/* sorry that we don't have valid data */
	if (!(ca->flag & LP_VALID_RHZ) || !(ca->flag & LP_VALID_OWD))
		return;

	/* record the next min owd */
	if (mowd < ca->owd_min)
		ca->owd_min = mowd;

	/* always forget the max of the max
	 * we just set owd_max as one below it */
	if (mowd > ca->owd_max) {
		if (mowd > ca->owd_max_rsv) {
			if (ca->owd_max_rsv == 0)
				ca->owd_max = mowd;
			else
				ca->owd_max = ca->owd_max_rsv;
			ca->owd_max_rsv = mowd;
		} else
			ca->owd_max = mowd;
	}

	/* calc for smoothed owd */
	if (ca->sowd != 0) {
		mowd -= ca->sowd >> 3;	/* m is now error in owd est */
		ca->sowd += mowd;	/* owd = 7/8 owd + 1/8 new */
	} else
		ca->sowd = mowd << 3;	/* take the measured time be owd */
}

static void tcp_lp_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 now = tcp_time_stamp(tp);
	u32 delta;

	/* calc inference */
	delta = now - tp->rx_opt.rcv_tsecr;
	if ((s32)delta > 0)
		ca->inference = 3 * delta;

	/* test if within inference */
	if (ca->last_drop && (now - ca->last_drop < ca->inference)) {
		if (!(ca->flag & LP_WITHIN_INF)) {
            /* Just entered inference — snapshot ssthresh */
            ca->frozen_ssthresh = tp->snd_ssthresh;
        }
		ca->flag |= LP_WITHIN_INF;
		tp->snd_ssthresh = max(tp->snd_ssthresh, ca->frozen_ssthresh);
	} else {
		if (ca->flag & LP_WITHIN_INF) {
			/* Just exited inference */
			ca->frozen_ssthresh = 0;
		}
		ca->flag &= ~LP_WITHIN_INF;
	}

	/* test if within threshold */
	if (ca->sowd >> 3 <
	    ca->owd_min + calculate_beta_scaled_value(ca, 100) * (ca->owd_max - ca->owd_min) / 100)
		ca->flag |= LP_WITHIN_THR;
	else
		ca->flag &= ~LP_WITHIN_THR;

	if (ca->flag & LP_WITHIN_THR)
		return;

	/* FIXME: try to reset owd_min and owd_max here
	 * so decrease the chance the min/max is no longer suitable
	 * and will usually within threshold when whithin inference */
	ca->owd_min = ca->sowd >> 3;
	ca->owd_max = ca->sowd >> 2;
	ca->owd_max_rsv = ca->sowd >> 2;

	/* happened within inference
	 * drop snd_cwnd into 1 */
	if (ca->flag & LP_WITHIN_INF) {
		tp->snd_cwnd = max(tp->snd_cwnd - calculate_beta_scaled_value(ca, tp->snd_cwnd), 1U);
	}

	/* record this drop time */
	ca->last_drop = now;
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
	
	if (!(ca->flag & LP_WITHIN_INF)) {

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
	} else {
		tcp_reno_cong_avoid(sk, ack, acked);
	}
}

static void tcp_elegant_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 rtt_us = rs->rtt_us;
	bool first_sample = (ca->cnt_rtt == 0) || (ca->rtt_curr == 0);

	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	if (rtt_us > RTT_MAX)
		rtt_us = RTT_MAX;

	if (first_sample || !rs->is_ack_delayed) {
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

	ca->prev_ca_state = inet_csk(sk)->icsk_ca_state;

	u32 acked = rs->delivered - rs->prior_delivered;
	bool only_sack    = (acked == 0 && rs->acked_sacked > 0);

	if (rs->rtt_us > 0 && (ca->cnt_rtt == 0 || (acked > 0 && !only_sack))) {
		tcp_lp_rtt_sample(sk, rs->rtt_us);
		tcp_elegant_pkts_acked(sk, rs);
	}

	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		ca->wwf_valid = false;
		ca->max_rtt_trend = (ca->max_rtt_trend >> 1) + (ca->max_rtt >> 1);
		ca->base_rtt_trend = (ca->base_rtt_trend >> 1) + (ca->base_rtt >> 1);
		if (rs->delivered > 0) {
			tcp_lp_pkts_acked(sk, rs);
			update_params(sk);
		}
	}
	
	if (rs->is_app_limited)
		ca->flag &= ~LP_WITHIN_INF;

	if (after(tcp_jiffies32, ca->last_rtt_reset_jiffies + BASE_RTT_RESET_INTERVAL) && !rs->is_ack_delayed) {
		ca->max_rtt = ca->max_rtt_trend;
		ca->base_rtt = ca->base_rtt_trend;
		ca->last_rtt_reset_jiffies = jiffies;
	}

}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_elegant_update(sk, rs);

}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->wwf_valid = false;

	return ca->prior_cwnd;
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

