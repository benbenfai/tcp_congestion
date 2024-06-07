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

//from bbr
#define CAL_SCALE 8
#define CAL_UNIT (1 << CAL_SCALE)

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

static int win_thresh __read_mostly = 15;
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");


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
	u32	end_seq;	/* right edge of current RTT */
	u32	alpha;		/* Additive increase */
	u32	beta;		/* Muliplicative decrease */
	u16	acked;		/* # packets acked by current ACK */
	u8	rtt_above;	/* average rtt has gone above threshold */
	u8	rtt_low;	/* # of rtts measurements below threshold */

	u32    last_bdp;
	u32    rtt_cnt;
	u32    next_rtt_delivered;
	struct minmax bw;
	u32    prior_cwnd;
	u8     prev_ca_state;
	
	u8  delack;
};

static void rtt_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *ca = inet_csk_ca(sk);

	ca->end_seq = tp->snd_nxt;
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;

	/* TODO: age max_rtt? */
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

	lp->acked = 0;
	lp->rtt_low = 0;
	lp->rtt_above = 0;

	rtt_reset(sk);
	
	lp->last_bdp = TCP_INIT_CWND;
	lp->rtt_cnt = 0;
	lp->prior_cwnd = TCP_INIT_CWND;
	minmax_reset(&lp->bw, lp->cnt_rtt, 0);
	lp->next_rtt_delivered = 0;
}

static u32 tcp_lp_ssthresh(struct sock *sk)
{

	const struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	
	u32 decr;

	/* Multiplicative decrease */
	decr = (tp->snd_cwnd * lp->beta) >> BETA_SHIFT;

	lp->prior_cwnd = max(tp->snd_cwnd - decr, 2U);
	
	return lp->prior_cwnd;
	
}

static void tcp_illinois_rtt_update(struct sock *sk, s32 rtt_us, u32 acked)
{
	
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lp *ca = inet_csk_ca(sk);
	
	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	/* ignore bogus values, this prevents wraparound in alpha math */
	if (rtt_us > RTT_MAX)
		rtt_us = RTT_MAX;

	/* A heuristic for filtering delayed ACKs, adapted from:
	 * D.A. Hayes. "Timing enhancements to the FreeBSD kernel to support
	 * delay and rate based TCP mechanisms." TR 100219A. CAIA, 2010.
	 */
	if (tp->sacked_out == 0) {
		if (acked == 1 && ca->delack) {
			/* A delayed ACK is only used for the minimum if it is
			 * provenly lower than an existing non-zero minimum.
			 */
			ca->base_rtt = min(ca->base_rtt, (u32) rtt_us);
			ca->delack--;
			return;
		} else if (acked > 1 && ca->delack < 5) {
			ca->delack++;
		}
	}

	ca->base_rtt = min_not_zero(ca->base_rtt, (u32) rtt_us);

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
	
	if (after(ack, lp->end_seq))
		update_params(sk);

	if (!(lp->flag & LP_WITHIN_INF)) {
		
		/* RFC2861 only increase cwnd if fully utilized */
		if (!tcp_is_cwnd_limited(sk))
			return;

		/* In slow start */
		if (tcp_in_slow_start(tp))
			tcp_slow_start(tp, acked);

		else {
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


static void tcp_lp_owd_reset(struct sock *sk)
{
	struct lp *lp = inet_csk_ca(sk);

	lp->owd_min = lp->sowd >> 3;
	lp->owd_max = lp->sowd >> 2;
	lp->owd_max_rsv = lp->sowd >> 2;

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
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->base_rtt = 0xffffffff;
		tcp_illinois_reset(sk);
		//ca->alpha = ALPHA_BASE;
		//ca->beta = BETA_BASE;
		//ca->rtt_low = 0;
		//ca->rtt_above = 0;
		ca->rtt_cnt = 0;
		minmax_reset(&ca->bw, ca->cnt_rtt, 0);
		//rtt_reset(sk);
	
		tcp_lp_owd_reset(sk);

		tp->snd_cwnd = tcp_packets_in_flight(tp) + 1;

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

static void tcp_lp_pkts_acked_function(struct sock *sk, s32 rtt_us, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	u32 now = tcp_jiffies32;
	u32 delta;
	u32 decr;
		
	lp->acked = acked;
	
	tcp_illinois_rtt_update(sk, rtt_us, acked);

	if (rtt_us > 0)
		tcp_lp_rtt_sample(sk, rtt_us);

	/* calc inference */
	delta = now - tp->rx_opt.rcv_tsecr;
	if ((s32)delta > 0)
		lp->inference = 3 * delta;

	/* test if within inference */
	if (lp->last_drop && (now - lp->last_drop < lp->inference))
		lp->flag |= LP_WITHIN_INF;
	else
		lp->flag &= ~LP_WITHIN_INF;

	/* test if within threshold */
	if (lp->sowd >> 3 <
	    lp->owd_min + 15 * (lp->owd_max - lp->owd_min) / 100)
		lp->flag |= LP_WITHIN_THR;
	else
		lp->flag &= ~LP_WITHIN_THR;

	if (lp->flag & LP_WITHIN_THR)
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
		
		/* Multiplicative decrease */
		decr = (tp->snd_cwnd * lp->beta) >> BETA_SHIFT;

		tp->snd_cwnd = max(tp->snd_cwnd - decr, 2U);

		//tp->snd_cwnd = 1U;
		//tcp_illinois_reset(sk);
	}

	/* happened after inference
	 * cut snd_cwnd into half */
	else {

		tp->snd_cwnd = max(tp->snd_cwnd - (tp->snd_cwnd>>TCP_SCALABLE_MD_SCALE), 2U);
		//tp->snd_cwnd = max(lp->prior_cwnd, 2U);
	}

	/* record this drop time */
	lp->last_drop = now;
}

/* Extract info for Tcp socket info provided via netlink. */
static size_t tcp_lp_info(struct sock *sk, u32 ext, int *attr,
				union tcp_cc_info *info)
{
	const struct lp *ca = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		info->vegas.tcpv_enabled = 1;
		info->vegas.tcpv_rttcnt = ca->cnt_rtt;
		info->vegas.tcpv_minrtt = ca->base_rtt;
		info->vegas.tcpv_rtt = 0;

		if (info->vegas.tcpv_rttcnt > 0) {
			u64 t = ca->sum_rtt;

			do_div(t, info->vegas.tcpv_rttcnt);
			info->vegas.tcpv_rtt = t;
		}
		*attr = INET_DIAG_VEGASINFO;
		return sizeof(struct tcpvegas_info);
	}
	return 0;
}

static u32 tcp_lp_cwnd_reduction(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct lp *lp = inet_csk_ca(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);

	tp->prr_delivered += lp->acked;
	if (tcp_packets_in_flight(tp) > tp->snd_ssthresh) {
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered + tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else {
		sndcnt = min_t(int, delta, max_t(int, tp->prr_delivered - tp->prr_out, lp->acked) + 1);
	}

	sndcnt = max(sndcnt, 1);
	return tcp_packets_in_flight(tp) + sndcnt;
}

static void tcp_lp_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *w = inet_csk_ca(sk);
	u8 prev_state = w->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u64 bw, bdp;
	
	tcp_lp_pkts_acked_function(sk, rs->rtt_us, rs->acked_sacked);
	
	if (!before(rs->prior_delivered, w->next_rtt_delivered)) {
		w->next_rtt_delivered = tp->delivered;
		w->rtt_cnt++;
	}

	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);
	minmax_running_max(&w->bw, 10, w->rtt_cnt, bw);

	w->prev_ca_state = state;
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		if (w->base_rtt == 0x7fffffff)
			w->last_bdp = TCP_INIT_CWND;
		else {
			bw = minmax_get(&w->bw);
			bdp = (u64)bw * w->base_rtt;
			w->last_bdp = (((bdp * CAL_UNIT) >> CAL_SCALE) + BW_UNIT - 1) / BW_UNIT;
		}
		tp->snd_ssthresh = max_t(u32, 2, tp->snd_cwnd >> 1);
	} else if (state == TCP_CA_Open && prev_state != TCP_CA_Open) {
		tp->snd_cwnd = tcp_lp_cwnd_reduction(sk);
	} else if (state == TCP_CA_Open) {
		tcp_lp_cong_avoid(sk, 0, rs->acked_sacked);
	}
}

static u32 tcp_lp_undo_cwnd(struct sock *sk)
{
	struct lp *lp = inet_csk_ca(sk);

	return max_t(u32, 2, lp->prior_cwnd);
}


/*
 * If the connection is idle and we are restarting,
 * then we don't want to do any Vegas calculations
 * until we get fresh RTT samples.  So when we
 * restart, we reset our Vegas state to a clean
 * slate. After we get acks for this flight of
 * packets, _then_ we can make Vegas calculations
 * again.
 */
void tcp_lp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lp *lp = inet_csk_ca(sk);
	
	switch (event) {
		case CA_EVENT_CWND_RESTART:
			tcp_lp_owd_reset(sk);
			rtt_reset(sk);
			lp->base_rtt = 0x7fffffff;
			break;
		case CA_EVENT_TX_START:
			tcp_lp_owd_reset(sk);
			rtt_reset(sk);
			lp->base_rtt = 0x7fffffff;
			break;
		case CA_EVENT_COMPLETE_CWR:
			tp->snd_cwnd = tp->snd_ssthresh = max(lp->last_bdp, lp->prior_cwnd);
			break;
		default:
			break;
	}

}

static struct tcp_congestion_ops tcp_lp __read_mostly = {
	.init = tcp_lp_init,
	.ssthresh = tcp_lp_ssthresh,
	.cong_avoid = tcp_lp_cong_avoid,
	.set_state	= tcp_illinois_state,
	.cwnd_event	= tcp_lp_cwnd_event,
	.cong_control   = tcp_lp_cong_control,
	.undo_cwnd = tcp_lp_undo_cwnd,
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