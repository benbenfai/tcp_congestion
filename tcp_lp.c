// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP Low Priority (TCP-LP)
 *
 * TCP Low Priority is a distributed algorithm whose goal is to utilize only
 *   the excess network bandwidth as compared to the ``fair share`` of
 *   bandwidth as targeted by TCP.
 *
 * As of 2.6.13, Linux supports pluggable congestion control algorithms.
 * Due to the limitation of the API, we take the following changes from
 * the original TCP-LP implementation:
 *   o We use newReno in most core CA handling. Only add some checking
 *     within cong_avoid.
 *   o Error correcting in remote HZ, therefore remote HZ will be keeped
 *     on checking and updating.
 *   o Handling calculation of One-Way-Delay (OWD) within rtt_sample, since
 *     OWD have a similar meaning as RTT. Also correct the buggy formular.
 *   o Handle reaction for Early Congestion Indication (ECI) within
 *     pkts_acked, as mentioned within pseudo code.
 *   o OWD is handled in relative format, where local time stamp will in
 *     tcp_time_stamp format.
 *
 * Original Author:
 *   Aleksandar Kuzmanovic <akuzma@northwestern.edu>
 * Available from:
 *   http://www.ece.rice.edu/~akuzma/Doc/akuzma/TCP-LP.pdf
 * Original implementation for 2.4.19:
 *   http://www-ece.rice.edu/networks/TCP-LP/
 *
 * 2.6.x module Authors:
 *   Wong Hoi Sing, Edison <hswong3i@gmail.com>
 *   Hung Hing Lun, Mike <hlhung3i@gmail.com>
 * SourceForge project page:
 *   http://tcp-lp-mod.sourceforge.net/
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <asm/div64.h>
#include <net/tcp.h>


#include <linux/mm.h>
#include <linux/win_minmax.h>

/* resolution of owd */
#define LP_RESOL       TCP_TS_HZ
#define TCP_SCALABLE_AI_CNT	 100U
#define TCP_SCALABLE_MD_SCALE	3

#define ALPHA_SHIFT	7
#define ALPHA_SCALE	(1u<<ALPHA_SHIFT)
#define ALPHA_MIN	((3*ALPHA_SCALE)/10)	/* ~0.3 */
#define ALPHA_MAX	(10*ALPHA_SCALE)	/* 10.0 */
#define ALPHA_BASE	ALPHA_SCALE		/* 1.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

static const u32 bbr_cwnd_min_target = 4;

static int win_thresh __read_mostly = 15;
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");

static int rtt0 = 25;
module_param(rtt0, int, 0644);
MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");


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

/**
 * struct lp
 * @flag: TCP-LP state flag
 * @sowd: smoothed OWD << 3
 * @owd_min: min OWD
 * @owd_max: max OWD
 * @owd_max_rsv: reserved max owd
 * @remote_hz: estimated remote HZ
 * @remote_ref_time: remote reference time
 * @local_ref_time: local reference time
 * @last_drop: time for last active drop
 * @inference: current inference
 *
 * TCP-LP's private struct.
 * We get the idea from original TCP-LP implementation where only left those we
 * found are really useful.
 */
struct lp {
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
	
	u64	sum_rtt;	/* sum of rtt's measured within last rtt */
	u16	cnt_rtt;	/* # of rtts measured within last rtt */
	u32	base_rtt;	/* min of all rtt in usec */
	u32	max_rtt;	/* max of all rtt in usec */
	//u32	end_seq;	/* right edge of current RTT */
	u32	alpha;		/* Additive increase */
	u32	beta;		/* Muliplicative decrease */
	u16	acked;		/* # packets acked by current ACK */
	u8	rtt_above;	/* average rtt has gone above threshold */
	u8	rtt_low;	/* # of rtts measurements below threshold */
	u32 next_rtt_delivered; /* scb->tx.delivered at end of round */

	u32 prior_cwnd;
	u8  prev_ca_state;
	
	u8  delack;

	u32 snd_cwnd_cents; /* Keeps increment values when it is <1, <<7 */
	u32 rho;	      /* Rho parameter, integer part  */
	u32 rho2;	      /* Rho * Rho, integer part */
	u32 rho_3ls;	      /* Rho parameter, <<3 */
	u32 rho2_7ls;	      /* Rho^2, <<7	*/
	u32 minrtt_us;      /* Minimum smoothed round trip time value seen */

};

static void rtt_reset(struct sock *sk)
{
	struct lp *ca = inet_csk_ca(sk);

	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;

}

/* This is called to refresh values for hybla parameters */
static inline void hybla_recalc_param (struct sock *sk)
{
	struct lp *ca = inet_csk_ca(sk);

	ca->rho_3ls = max_t(u32,
			    tcp_sk(sk)->srtt_us / (rtt0 * USEC_PER_MSEC),
			    8U);
	ca->rho = ca->rho_3ls >> 3;
	ca->rho2_7ls = (ca->rho_3ls * ca->rho_3ls) << 1;
	ca->rho2 = ca->rho2_7ls >> 7;
}

/**
 * tcp_lp_init
 * @sk: socket to initialize congestion control algorithm for
 *
 * Init all required variables.
 * Clone the handling from Vegas module implementation.
 */
static void tcp_lp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);

	lp->flag = 0;
	lp->sowd = 0;
	lp->owd_min = 0xffffffff;
	lp->owd_max = 0;
	lp->owd_max_rsv = 0;
	lp->remote_hz = 0;
	lp->remote_ref_time = 0;
	lp->local_ref_time = 0;
	lp->last_drop = 0;
	lp->inference = 0;
	
	lp->alpha = ALPHA_MAX;
	lp->beta = BETA_BASE;
	lp->base_rtt = 0x7fffffff;
	lp->max_rtt = 0;
	lp->next_rtt_delivered = tp->delivered;

	lp->acked = 0;
	lp->rtt_low = 0;
	lp->rtt_above = 0;

	rtt_reset(sk);

	//lp->prior_cwnd = TCP_INIT_CWND;
	lp->prior_cwnd = tp->prior_cwnd;
	lp->prev_ca_state = TCP_CA_Open;
	
	lp->rho = 0;
	lp->rho2 = 0;
	lp->rho_3ls = 0;
	lp->rho2_7ls = 0;
	lp->snd_cwnd_cents = 0;
	tp->snd_cwnd = 2;
	tp->snd_cwnd_clamp = 65535;

	/* 1st Rho measurement based on initial srtt */
	hybla_recalc_param(sk);

	/* set minimum rtt as this is the 1st ever seen */
	lp->minrtt_us = tp->srtt_us;
	tp->snd_cwnd = lp->rho;

}

static u32 tcp_lp_ssthresh(struct sock *sk)
{

	const struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	
	lp->prior_cwnd = tp->snd_cwnd;

	return max(tp->snd_cwnd - ((tp->snd_cwnd * lp->beta) >> BETA_SHIFT), 2U);
	
}

static void tcp_illinois_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lp *ca = inet_csk_ca(sk);
	
	u32 rtt_us = rs->rtt_us;
	
	/* ignore bogus values, this prevents wraparound in alpha math */
	if (rtt_us > RTT_MAX)
		rtt_us = RTT_MAX;
	
	/* A heuristic for filtering delayed ACKs, adapted from:
	 * D.A. Hayes. "Timing enhancements to the FreeBSD kernel to support
	 * delay and rate based TCP mechanisms." TR 100219A. CAIA, 2010.
	 */
	if (tp->sacked_out == 0) {
		if (rs->acked_sacked == 1 && ca->delack) {
			/* A delayed ACK is only used for the minimum if it is
			 * provenly lower than an existing non-zero minimum.
			 */
			ca->base_rtt = min(ca->base_rtt, rtt_us);
			ca->delack--;
			return;
		} else if (rs->acked_sacked > 1 && ca->delack < 5) {
			ca->delack++;
		}
	}

	ca->base_rtt = min_not_zero(ca->base_rtt, rtt_us);

	/* and max */
	if (ca->max_rtt < rtt_us)
		ca->max_rtt = rtt_us;

	++ca->cnt_rtt;
	ca->sum_rtt += rtt_us;
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct lp *ca)
{
	return ca->max_rtt - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(const struct lp *ca)
{
	u64 t = ca->sum_rtt;

	do_div(t, ca->cnt_rtt);
	return t - ca->base_rtt;
}

static u32 alpha(struct lp *ca, u32 da, u32 dm)
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
	struct lp *ca = inet_csk_ca(sk);

	if (tp->snd_cwnd < win_thresh) {
		ca->alpha = ALPHA_BASE;
		ca->beta = BETA_BASE;
	} else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->alpha = alpha(ca, da, dm);
		ca->beta = beta(da, dm);
	}

	rtt_reset(sk);
}

static inline u32 hybla_fraction(u32 odds)
{
	static const u32 fractions[] = {
		128, 139, 152, 165, 181, 197, 215, 234,
	};

	return (odds < ARRAY_SIZE(fractions)) ? fractions[odds] : 128;
}

/* TCP Hybla main routine.
 * This is the algorithm behavior:
 *     o Recalc Hybla parameters if min_rtt has changed
 *     o Give cwnd a new value based on the model proposed
 *     o remember increments <1
 */
static void hybla_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *ca = inet_csk_ca(sk);
	u32 increment, odd, rho_fractions;
	int is_slowstart = 0;

	/*  Recalculate rho only if this srtt is the lowest */
	if (tp->srtt_us < ca->minrtt_us) {
		hybla_recalc_param(sk);
		ca->minrtt_us = tp->srtt_us;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (ca->rho == 0)
		hybla_recalc_param(sk);
	
	rho_fractions = ca->rho_3ls - (ca->rho << 3);

	if (tcp_in_slow_start(tp)) {
		/*
		 * slow start
		 *      INC = 2^RHO - 1
		 * This is done by splitting the rho parameter
		 * into 2 parts: an integer part and a fraction part.
		 * Inrement<<7 is estimated by doing:
		 *	       [2^(int+fract)]<<7
		 * that is equal to:
		 *	       (2^int)	*  [(2^fract) <<7]
		 * 2^int is straightly computed as 1<<int,
		 * while we will use hybla_slowstart_fraction_increment() to
		 * calculate 2^fract in a <<7 value.
		 */
		is_slowstart = 1;
		increment = ((1 << min(ca->rho, 16U)) *
			hybla_fraction(rho_fractions)) - 128;
	} else {
		/*
		 * congestion avoidance
		 * INC = RHO^2 / W
		 * as long as increment is estimated as (rho<<7)/window
		 * it already is <<7 and we can easily count its fractions.
		 */
		increment = ca->rho2_7ls / tp->snd_cwnd;
		if (increment < 128)
			tp->snd_cwnd_cnt++;
	}

	odd = increment % 128;
	tp->snd_cwnd = (tp->snd_cwnd + (increment >> 7));
	ca->snd_cwnd_cents += odd;

	/* check when fractions goes >=128 and increase cwnd by 1. */
	while (ca->snd_cwnd_cents >= 128) {
		tp->snd_cwnd = (tp->snd_cwnd + 1);
		ca->snd_cwnd_cents -= 128;
		tp->snd_cwnd_cnt = 0;
	}
	/* check when cwnd has not been incremented for a while */
	if (increment == 0 && odd == 0 && tp->snd_cwnd_cnt >= tp->snd_cwnd) {
		tp->snd_cwnd = (tp->snd_cwnd + 1);
		tp->snd_cwnd_cnt = 0;
	}
	/* clamp down slowstart cwnd to ssthresh value. */
	if (is_slowstart)
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);

	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}

/**
 * tcp_lp_cong_avoid
 * @sk: socket to avoid congesting
 *
 * Implementation of cong_avoid.
 * Will only call newReno CA when away from inference.
 * From TCP-LP's paper, this will be handled in additive increasement.
 */
static void tcp_lp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct lp *lp = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!(lp->flag & LP_WITHIN_INF)) {
		
		/* RFC2861 only increase cwnd if fully utilized */
		if (!tcp_is_cwnd_limited(sk))
			return;

		/* In slow start */
		if (tcp_in_slow_start(tp)) {
			hybla_cong_avoid(sk, ack, acked);
		} else {

			u32 delta;

			/* snd_cwnd_cnt is # of packets since last cwnd increment */
			tp->snd_cwnd_cnt += lp->acked;
			lp->acked = 1;

			/* This is close approximation of:
			 * tp->snd_cwnd += alpha/tp->snd_cwnd
			*/
			delta = (tp->snd_cwnd_cnt * lp->alpha) >> ALPHA_SHIFT;
			if (delta >= tp->snd_cwnd) {
				tp->snd_cwnd = min(tp->snd_cwnd + delta / tp->snd_cwnd,
						   (u32)tp->snd_cwnd_clamp);
				tp->snd_cwnd_cnt = 0;
			}

		}
	}

}

static void tcp_illinois_reset(struct sock *sk)
{
	struct lp *ca = inet_csk_ca(sk);

	ca->alpha = ALPHA_BASE;
	ca->beta = BETA_BASE;
	ca->rtt_low = 0;
	ca->rtt_above = 0;
	rtt_reset(sk);
}


static void tcp_illinois_state(struct sock *sk, u8 new_state)
{
	struct lp *lp = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {

		lp->prev_ca_state = TCP_CA_Loss;

		tcp_illinois_reset(sk);

	}
}


/**
 * tcp_lp_remote_hz_estimator
 * @sk: socket which needs an estimate for the remote HZs
 *
 * Estimate remote HZ.
 * We keep on updating the estimated value, where original TCP-LP
 * implementation only guest it for once and use forever.
 */
static u32 tcp_lp_remote_hz_estimator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	s64 rhz = lp->remote_hz << 6;	/* remote HZ << 6 */
	s64 m = 0;

	/* not yet record reference time
	 * go away!! record it before come back!! */
	if (lp->remote_ref_time == 0 || lp->local_ref_time == 0)
		goto out;

	/* we can't calc remote HZ with no different!! */
	if (tp->rx_opt.rcv_tsval == lp->remote_ref_time ||
	    tp->rx_opt.rcv_tsecr == lp->local_ref_time)
		goto out;

	m = TCP_TS_HZ *
	    (tp->rx_opt.rcv_tsval - lp->remote_ref_time) /
	    (tp->rx_opt.rcv_tsecr - lp->local_ref_time);
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
		lp->flag |= LP_VALID_RHZ;
	else
		lp->flag &= ~LP_VALID_RHZ;

	/* record reference time stamp */
	lp->remote_ref_time = tp->rx_opt.rcv_tsval;
	lp->local_ref_time = tp->rx_opt.rcv_tsecr;

	return rhz >> 6;
}

/**
 * tcp_lp_owd_calculator
 * @sk: socket to calculate one way delay for
 *
 * Calculate one way delay (in relative format).
 * Original implement OWD as minus of remote time difference to local time
 * difference directly. As this time difference just simply equal to RTT, when
 * the network status is stable, remote RTT will equal to local RTT, and result
 * OWD into zero.
 * It seems to be a bug and so we fixed it.
 */
static u32 tcp_lp_owd_calculator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	s64 owd = 0;

	lp->remote_hz = tcp_lp_remote_hz_estimator(sk);

	if (lp->flag & LP_VALID_RHZ) {
		owd =
		    tp->rx_opt.rcv_tsval * (LP_RESOL / lp->remote_hz) -
		    tp->rx_opt.rcv_tsecr * (LP_RESOL / TCP_TS_HZ);
		if (owd < 0)
			owd = -owd;
	}

	if (owd > 0)
		lp->flag |= LP_VALID_OWD;
	else
		lp->flag &= ~LP_VALID_OWD;

	return owd;
}

/**
 * tcp_lp_rtt_sample
 * @sk: socket to add a rtt sample to
 * @rtt: round trip time, which is ignored!
 *
 * Implementation or rtt_sample.
 * Will take the following action,
 *   1. calc OWD,
 *   2. record the min/max OWD,
 *   3. calc smoothed OWD (SOWD).
 * Most ideas come from the original TCP-LP implementation.
 */
static void tcp_lp_rtt_sample(struct sock *sk, u32 rtt)
{
	struct lp *lp = inet_csk_ca(sk);
	s64 mowd = tcp_lp_owd_calculator(sk);

	/* sorry that we don't have valid data */
	if (!(lp->flag & LP_VALID_RHZ) || !(lp->flag & LP_VALID_OWD))
		return;

	/* record the next min owd */
	if (mowd < lp->owd_min)
		lp->owd_min = mowd;

	/* always forget the max of the max
	 * we just set owd_max as one below it */
	if (mowd > lp->owd_max) {
		if (mowd > lp->owd_max_rsv) {
			if (lp->owd_max_rsv == 0)
				lp->owd_max = mowd;
			else
				lp->owd_max = lp->owd_max_rsv;
			lp->owd_max_rsv = mowd;
		} else
			lp->owd_max = mowd;
	}

	/* calc for smoothed owd */
	if (lp->sowd != 0) {
		mowd -= lp->sowd >> 3;	/* m is now error in owd est */
		lp->sowd += mowd;	/* owd = 7/8 owd + 1/8 new */
	} else
		lp->sowd = mowd << 3;	/* take the measured time be owd */
}

static void tcp_lp_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);

	u32 delta;

	if (rs->rtt_us > 0) {
		tcp_lp_rtt_sample(sk, rs->rtt_us);
		tcp_illinois_pkts_acked(sk, rs);
	}

	/* calc inference */
	delta = tcp_jiffies32 - tp->rx_opt.rcv_tsecr;
	if ((s32)delta > 0)
		lp->inference = 3 * delta;

	/* test if within inference */
	if (lp->last_drop && (tcp_jiffies32 - lp->last_drop < lp->inference))
		lp->flag |= LP_WITHIN_INF;
	else
		lp->flag &= ~LP_WITHIN_INF;

	/* test if within threshold */
	if (lp->sowd >> 3 <
	    lp->owd_min + 15 * (lp->owd_max - lp->owd_min) / 100)
		lp->flag |= LP_WITHIN_THR;
	else
		lp->flag &= ~LP_WITHIN_THR;

	if (lp->flag & LP_WITHIN_THR || inet_csk(sk)->icsk_ca_state >= TCP_CA_Recovery)
		return;

	/* FIXME: try to reset owd_min and owd_max here
	 * so decrease the chance the min/max is no longer suitable
	 * and will usually within threshold when within inference */
	lp->owd_min = lp->sowd >> 3;
	lp->owd_max = lp->sowd >> 2;
	lp->owd_max_rsv = lp->sowd >> 2;

	/* happened within inference
	 * drop snd_cwnd into 1 */
	if (lp->flag & LP_WITHIN_INF) {

		lp->prior_cwnd = tp->snd_cwnd = max(tp->snd_cwnd - ((tp->snd_cwnd * lp->beta) >> BETA_SHIFT), 2U);

	}

	/* happened after inference
	 * cut snd_cwnd into half */
	else {

		tp->snd_cwnd = max(tp->snd_cwnd - (tp->snd_cwnd>>TCP_SCALABLE_MD_SCALE), 2U);

	}

	/* record this drop time */
	lp->last_drop = tcp_jiffies32;
}

/* Extract info for Tcp socket info provided via netlink. */
static size_t tcp_lp_info(struct sock *sk, u32 ext, int *attr,union tcp_cc_info *info)
{
	const struct lp *lp = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		info->vegas.tcpv_enabled = 1;
		info->vegas.tcpv_rttcnt = lp->cnt_rtt;
		info->vegas.tcpv_minrtt = lp->base_rtt;
		info->vegas.tcpv_rtt = 0;

		if (info->vegas.tcpv_rttcnt > 0) {
			u64 t = lp->sum_rtt;

			do_div(t, info->vegas.tcpv_rttcnt);
			info->vegas.tcpv_rtt = t;
		}
		*attr = INET_DIAG_VEGASINFO;
		return sizeof(struct tcpvegas_info);
	}
	return 0;
}

static void illinois_update(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *ca = inet_csk_ca(sk);

	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		update_params(sk);
		ca->base_rtt = 0x7fffffff;
		ca->max_rtt = tp->srtt_us;
		ca->delack = 0;
		tcp_lp_pkts_acked(sk, rs);
		return;
	}

	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tcp_lp_pkts_acked(sk, rs);
	}

}

static void tcp_lp_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	u8 prev_state = lp->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;
	
	illinois_update(sk, rs);

	if (!rs->acked_sacked)
		goto done;  /* no packet fully ACKed; just apply caps */

	if (state == TCP_CA_Open)
		goto done;

	if (rs->losses > 0)
		cwnd = max_t(s32, tp->snd_cwnd - rs->losses, 1);

	lp->prev_ca_state = state;

	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		cwnd = max(cwnd, tcp_packets_in_flight(tp) + rs->acked_sacked);
		lp->next_rtt_delivered = tp->delivered;
		goto done;
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		cwnd = max(cwnd, lp->prior_cwnd);
	}

	if (tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + rs->acked_sacked;

	cwnd = max(cwnd, tcp_packets_in_flight(tp) + bbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
}

static struct tcp_congestion_ops tcp_lp __read_mostly = {
	.init = tcp_lp_init,
	.ssthresh = tcp_lp_ssthresh,
	.cong_avoid = tcp_lp_cong_avoid,
	.set_state	= tcp_illinois_state,
	.cong_control  = tcp_lp_cong_control,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= tcp_lp_info,

	.owner = THIS_MODULE,
	.name = "lp"
};

static int __init tcp_lp_register(void)
{
	BUILD_BUG_ON(sizeof(struct lp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_lp);
}

static void __exit tcp_lp_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_lp);
}

module_init(tcp_lp_register);
module_exit(tcp_lp_unregister);

MODULE_AUTHOR("Wong Hoi Sing Edison, Hung Hing Lun Mike");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Low Priority");
