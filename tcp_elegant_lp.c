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
#define ALPHA_MIN	((3*ALPHA_SCALE)/10)	/* ~0.3 */
#define ALPHA_MAX	(12*ALPHA_SCALE)	/* 10.0 */
#define ALPHA_BASE	ALPHA_SCALE		/* 1.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/16)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX
#define BETA_SUM   (BETA_SCALE + BETA_MIN + BETA_MAX)

static const u32 lt_intvl_min_rtts = 4;
static const u32 cwnd_min_target = 4;

static int win_thresh __read_mostly = 20; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");

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

	u64   sum_rtt;               /* sum of RTTs in last round */

    u32   base_rtt;              /* base RTT */
    u32   max_rtt;               /* max RTT in last round */
	u32   rtt_curr;              /* current RTT, per-ACK update */
    u32   next_rtt_delivered;    /* delivered count at round start */

	u32   prior_cwnd;	/* prior cwnd upon entering loss recovery */
    u32   cached_wwf;            /* cached window‐width factor */
    u32	  alpha;				 /* Additive increase */
    u32   beta;  				 /* multiplicative decrease factor */

    u32   acked:16,
	      rtt_above:8,
          rtt_low:8;

    u32   cnt_rtt:16,            /* samples in this RTT */
	      prev_ca_state:3,
          round_start:1,	     /* start of packet-timed tx->ack round? */
          lt_is_sampling:1,      /* have we calc’d WWF this RTT? */
		  lt_rtt_cnt:7,          /* rtt-round counter */
		  unused:3,
          wwf_valid:1;           /* last CA state */
};

static inline void rtt_reset(struct elegant *ca)
{
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;
}

static void tcp_elegant_init(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct elegant *ca = inet_csk_ca(sk);

	*ca = (struct elegant) {
			.owd_min = U32_MAX,
			.base_rtt = U32_MAX,
			.next_rtt_delivered = tp->delivered,
			.alpha = ALPHA_MAX,
			.beta = BETA_BASE,
			.prior_cwnd = tp->snd_cwnd
		};

}

/* Calculate value scaled by beta */
static inline u32 calculate_beta_scaled_value(u32 beta, u32 value)
{
    return (value * beta) >> BETA_SHIFT;
}

static inline u32 ema_value(u32 old, u32 new) {
    return (old * 7 + new) >> 3;
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	
	if (ca->prev_ca_state < TCP_CA_Recovery)
		ca->prior_cwnd = tp->snd_cwnd;
	else
		ca->prior_cwnd = max(ca->prior_cwnd,  tp->snd_cwnd);

	if (ca->flag & LP_WITHIN_INF)
		return max(tp->snd_cwnd - (tp->snd_cwnd>>3), 2U);

	return max(tp->snd_cwnd - calculate_beta_scaled_value(ca->beta, tp->snd_cwnd), 2U);
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct elegant *ca)
{
	return ca->max_rtt - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(const struct elegant *ca) {
    return ca->cnt_rtt ? div64_u64(ca->sum_rtt, ca->cnt_rtt) - ca->base_rtt : 0;
}

static u32 alpha(struct elegant *ca, u32 da, u32 dm)
{
	u32 d1 = dm / 100;	/* Low threshold */

	if (da <= d1) {
		/* If never got out of low delay zone, then use max */
		if (!ca->rtt_above)
			return ALPHA_MAX;

		/* Wait for 5 good RTT's before allowing alpha to go alpha max.
		 * This prevents one good RTT from causing sudden window increase.
		 */
		if (++ca->rtt_low < theta)
			return ca->alpha;

		ca->rtt_low = 0;
		ca->rtt_above = 0;
		return ALPHA_MAX;
	}

	ca->rtt_above = 1;

	/*
	 * Based on:
	 *
	 *      (dm - d1) amin amax
	 * k1 = -------------------
	 *         amax - amin
	 *
	 *       (dm - d1) amin
	 * k2 = ----------------  - d1
	 *        amax - amin
	 *
	 *             k1
	 * alpha = ----------
	 *          k2 + da
	 */

	dm -= d1;
	da -= d1;
	return (dm * ALPHA_MAX) /
		(dm + (da  * (ALPHA_MAX - ALPHA_MIN)) / ALPHA_MIN);
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
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

    if (tp->snd_cwnd < win_thresh) {
		ca->alpha = ALPHA_BASE;
        ca->beta = BETA_BASE;
    } else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->alpha = alpha(ca, da, dm);
		ca->beta = beta(da, dm);
	}

	rtt_reset(ca);
}

static void tcp_elegant_reset(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

    ca->sum_rtt = 0;
    ca->cnt_rtt = 0;
	ca->rtt_curr = 0;
	ca->alpha = ALPHA_BASE;
	ca->beta = BETA_BASE;
	ca->rtt_low = 0;
	ca->rtt_above = 0;

}

static void lt_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (!ca->lt_is_sampling) {
		if (rs->losses) {
			ca->lt_is_sampling = true;
			ca->lt_rtt_cnt = 0;
		}
	} else {
		if (rs->is_app_limited) {
			ca->lt_is_sampling = false;
			ca->lt_rtt_cnt = 0;
		} else if (ca->round_start) {
			ca->lt_rtt_cnt++;
            if (ca->flag & LP_WITHIN_INF) {
                ca->flag &= ~LP_WITHIN_INF;
                ca->last_drop = 0;
            }
		} else if (ca->lt_rtt_cnt > 4 * lt_intvl_min_rtts) {
			ca->lt_is_sampling = false;
			ca->lt_rtt_cnt = 0;
		}
	}
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		tcp_elegant_reset(sk);
		ca->prev_ca_state = TCP_CA_Loss;
		ca->round_start = 1;
		ca->wwf_valid = false;
		lt_sampling(sk, &rs);
	} else if (ca->prev_ca_state == TCP_CA_Loss && new_state != TCP_CA_Loss) {
		ca->last_drop = 0;
		ca->lt_is_sampling = false;
        ca->lt_rtt_cnt = 0;
		tp->snd_cwnd = max(tp->snd_cwnd, ca->prior_cwnd);
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

    /* Adaptive EMA for OWD */
    u32 rtt_var = ca->max_rtt - ca->base_rtt;
    u32 alpha = rtt_var > ca->base_rtt / 2 ? 2 : 3; /* 1/4 weight for high variability, 1/8 for low */
    if (ca->sowd != 0) {
        mowd -= ca->sowd >> alpha;
        ca->sowd += mowd;
    } else {
        ca->sowd = mowd << alpha;
    }
}

static void tcp_lp_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 now = tcp_time_stamp(tp);
	u32 delta;
	u32 base_rtt = 2 * ca->base_rtt;

	ca->acked = sample->pkts_acked;

	/* calc inference */
	delta = now - tp->rx_opt.rcv_tsecr;
	if ((s32)delta > 0) {
		ca->inference = max(3 * delta, base_rtt);
	}

	/* test if within inference */
	if (ca->last_drop && (now - ca->last_drop < ca->inference))
		ca->flag |= LP_WITHIN_INF;	
	else
		ca->flag &= ~LP_WITHIN_INF;

	/* test if within threshold */
	if (ca->sowd >> 3 <
	    ca->owd_min + calculate_beta_scaled_value(ca->beta, 100) * (ca->owd_max - ca->owd_min) / 100)
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
	if (ca->flag & LP_WITHIN_INF && !ca->lt_is_sampling && (now - ca->last_drop > base_rtt)) {
		/* record this drop time */
		ca->last_drop = now;
	}

}

static void tcp_illinois_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	/* In slow start */
	if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);
	else {
		u32 delta;

		/* snd_cwnd_cnt is # of packets since last cwnd increment */
		tp->snd_cwnd_cnt += ca->acked;
		ca->acked = 1;

		/* This is close approximation of:
		 * tp->snd_cwnd += alpha/tp->snd_cwnd
		*/
		delta = (tp->snd_cwnd_cnt * ca->alpha) >> ALPHA_SHIFT;
		if (delta >= tp->snd_cwnd) {
			tp->snd_cwnd = min(tp->snd_cwnd + delta / tp->snd_cwnd,
					   (u32)tp->snd_cwnd_clamp);
			tp->snd_cwnd_cnt = 0;
		}
	}
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

static inline u32 calc_wwf(const struct tcp_sock *tp, const struct elegant *ca)
{
	u64 numer	 = (u64)tp->snd_cwnd * ca->max_rtt << E_UNIT_SQ_SHIFT;
    u32 m        = ema_value(ca->rtt_curr, ca->base_rtt);

	do_div(numer, m);

    u32 wwf = fast_isqrt(numer) >> ELEGANT_SCALE;

    return (wwf * (BETA_SUM - ca->beta) + (BETA_SCALE >> 1)) >> BETA_SHIFT;
}

static void tcp_elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (!(ca->flag & LP_WITHIN_INF)) {
		tcp_illinois_cong_avoid(sk, ack, acked);
	} else {
		u32 wwf;

		if (tcp_in_slow_start(tp)) {
			wwf = tcp_slow_start(tp, acked);
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
}

static void tcp_elegant_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	struct elegant *ca = inet_csk_ca(sk);

	u32 rtt_us = rs->rtt_us;

	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	if (rtt_us > RTT_MAX && !(ca->flag & LP_WITHIN_INF))
		rtt_us = RTT_MAX;

	ca->rtt_curr = rtt_us;
	ca->sum_rtt += rtt_us;
	++ca->cnt_rtt;

	ca->base_rtt = min(ca->base_rtt, rtt_us);
	ca->max_rtt = max(ca->max_rtt, rtt_us);
}

static void tcp_elegant_update(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (rs->rtt_us > 0 && (ca->cnt_rtt == 0 || rs->delivered> rs->prior_delivered)) {
		tcp_lp_rtt_sample(sk, rs->rtt_us);
		tcp_elegant_pkts_acked(sk, rs);
	}

	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	ca->prev_ca_state = inet_csk(sk)->icsk_ca_state;
	ca->round_start = 0;
	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		ca->round_start = 1;
		ca->wwf_valid = false;
		update_params(sk);
	}

	lt_sampling(sk, rs);

}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{

	tcp_elegant_update(sk, rs);

}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->lt_is_sampling = false;
	ca->lt_rtt_cnt = 0;
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
	.pkts_acked	    = tcp_lp_pkts_acked,
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

