#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/int_sqrt.h>
#include <linux/math64.h>
#include <linux/time64.h>
#include <net/tcp.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
static inline u32 tcp_snd_cwnd(const struct tcp_sock *tp)
{
	return tp->snd_cwnd;
}

static inline void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
	tp->snd_cwnd = val;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
#define tcp_time_stamp_ts(tp)	tcp_time_stamp(tp)
#endif

#define ELEGANT_SCALE		6
#define E_UNIT_SQ_SHIFT		(2 * ELEGANT_SCALE)

#define ALPHA_SHIFT		7
#define ALPHA_SCALE		(1u << ALPHA_SHIFT)
#define ALPHA_MIN		((3 * ALPHA_SCALE) / 10)
#define ALPHA_MAX		(10 * ALPHA_SCALE)
#define ALPHA_BASE		ALPHA_SCALE
#define RTT_MAX			(U32_MAX / ALPHA_MAX)

#define BETA_SHIFT		6
#define BETA_SCALE		(1u << BETA_SHIFT)
#define BETA_MIN		(BETA_SCALE / 8)
#define BETA_MAX		(BETA_SCALE / 2)
#define BETA_BASE		BETA_MAX

#define LP_SOWD_SHIFT		3
#define LP_OWD_MAX		(U32_MAX >> LP_SOWD_SHIFT)

#define LP_INFERENCE_MAX_MS	10000u
#define LP_REMOTE_HZ_MAX	1000000u
#define WWF_CAP_MAX		(1u << 20)

static const u32 lt_intvl_min_rtts = 4;
static const u32 cwnd_min_target = 4;

static int win_thresh __read_mostly = 20;
module_param(win_thresh, int, 0644);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0644);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");

enum tcp_lp_state {
	LP_VALID_RHZ	= (1 << 0),
	LP_VALID_OWD	= (1 << 1),
	LP_WITHIN_THR	= (1 << 2),
	LP_WITHIN_INF	= (1 << 3),
};

struct elegant {
	u64	sum_rtt_us;

	u32	flag;
	u32	sowd_scaled;
	u32	owd_min_ts;
	u32	owd_max_ts;
	u32	owd_max_rsv_ts;
	u32	remote_hz;
	u32	remote_ref_time;
	u32	local_ref_time;
	u32	last_drop_ts;
	u32	inference_ts;
	u32	round_end_seq;
	u32	max_rtt_us;
	u32	round_max_rtt_us;
	u32	rtt_curr_us;
	u32	prior_cwnd;
	u32	cached_wwf;
	u32	alpha;
	u32	beta;

	u16	cnt_rtt;

	u8	rtt_low_rounds;
	u8	lt_rtt_cnt;
	u8	rtt_above:1,
		lt_is_sampling:1,
		wwf_valid:1;
};

static inline u32 elegant_win_thresh(void)
{
	return (u32)clamp_t(int, win_thresh, 2, 65535);
}

static inline u32 elegant_theta(void)
{
	return (u32)clamp_t(int, theta, 1, 127);
}

static inline u32 beta_scaled(u32 beta, u32 value)
{
	return (u32)(((u64)value * beta) >> BETA_SHIFT);
}

static inline u32 lp_ts_hz(const struct tcp_sock *tp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	return tp->tcp_usec_ts ? (u32)USEC_PER_SEC : (u32)TCP_TS_HZ;
#else
	return (u32)TCP_TS_HZ;
#endif
}

static inline u32 usecs_to_ts(const struct tcp_sock *tp, u32 us)
{
	u32 hz = lp_ts_hz(tp);

	return hz >= USEC_PER_SEC ? us : us / (u32)(USEC_PER_SEC / hz);
}

static inline u32 lp_inference_max_ts(const struct tcp_sock *tp)
{
	return max(usecs_to_ts(tp, LP_INFERENCE_MAX_MS * (u32)USEC_PER_MSEC),
		   1U);
}

static inline u32 elegant_base_rtt(const struct tcp_sock *tp)
{
	u32 min_rtt = tcp_min_rtt(tp);

	return min_rtt == ~0U ? 0 : max(min_rtt, 1U);
}

static inline u32 max_delay(const struct elegant *ca, u32 base_rtt)
{
	return ca->max_rtt_us > base_rtt ? ca->max_rtt_us - base_rtt : 0;
}

static inline u32 avg_delay(const struct elegant *ca, u32 base_rtt)
{
	u32 avg;

	if (!ca->cnt_rtt)
		return 0;

	avg = (u32)div_u64(ca->sum_rtt_us, ca->cnt_rtt);

	return avg > base_rtt ? avg - base_rtt : 0;
}

static void rtt_reset(struct elegant *ca, u32 base_rtt)
{
	u32 decayed;

	if (ca->max_rtt_us < base_rtt)
		ca->max_rtt_us = base_rtt;

	decayed = base_rtt + (((ca->max_rtt_us - base_rtt) * 7) >> 3);
	ca->max_rtt_us = max3(ca->round_max_rtt_us, decayed, base_rtt);

	ca->round_max_rtt_us = 0;
	ca->cnt_rtt = 0;
	ca->sum_rtt_us = 0;
}

static void tcp_elegant_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	*ca = (struct elegant) {
		.owd_min_ts	= U32_MAX,
		.alpha		= ALPHA_MAX,
		.beta		= BETA_BASE,
		.prior_cwnd	= tcp_snd_cwnd(tp),
		.round_end_seq	= tp->snd_nxt,
	};
}

static u32 alpha(struct elegant *ca, u32 da, u32 dm)
{
	u32 d1 = dm / 100;
	u64 num, den;

	if (da <= d1) {
		if (!ca->rtt_above)
			return ALPHA_MAX;

		if (++ca->rtt_low_rounds < elegant_theta())
			return ca->alpha;

		ca->rtt_low_rounds = 0;
		ca->rtt_above = 0;
		return ALPHA_MAX;
	}

	ca->rtt_above = 1;

	dm -= d1;
	da -= d1;

	num = (u64)dm * ALPHA_MAX;
	den = (u64)dm + div_u64((u64)da * (ALPHA_MAX - ALPHA_MIN), ALPHA_MIN);
	if (!den)
		return ALPHA_MAX;

	return clamp_t(u32, div64_u64(num, den), ALPHA_MIN, ALPHA_MAX);
}

static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;
	s64 num;

	d2 = dm / 10;
	if (da <= d2)
		return BETA_MIN;

	d3 = (8 * dm) / 10;
	if (da >= d3 || d3 <= d2)
		return BETA_MAX;

	num = (s64)BETA_MIN * d3 - (s64)BETA_MAX * d2 +
	      (s64)(BETA_MAX - BETA_MIN) * da;

	return clamp_t(u32, div_s64(num, d3 - d2), BETA_MIN, BETA_MAX);
}

static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 base_rtt = elegant_base_rtt(tp);

	if (tcp_snd_cwnd(tp) < elegant_win_thresh() || !base_rtt) {
		ca->alpha = ALPHA_BASE;
		ca->beta = BETA_BASE;
	} else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca, base_rtt);
		u32 da = avg_delay(ca, base_rtt);

		if (dm) {
			ca->alpha = alpha(ca, da, dm);
			ca->beta = beta(da, dm);
		}
	}

	rtt_reset(ca, base_rtt);
	ca->round_end_seq = tp->snd_nxt;
	ca->wwf_valid = false;
}

static void lt_round_elapsed(struct elegant *ca)
{
	if (!ca->lt_is_sampling)
		return;

	if (ca->lt_rtt_cnt < U8_MAX)
		ca->lt_rtt_cnt++;

	if (ca->lt_rtt_cnt > 4 * lt_intvl_min_rtts) {
		ca->lt_is_sampling = false;
		ca->lt_rtt_cnt = 0;
	}
}

static u32 tcp_elegant_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 b = ca->beta;

	if (inet_csk(sk)->icsk_ca_state < TCP_CA_Recovery)
		ca->prior_cwnd = cwnd;
	else
		ca->prior_cwnd = max(ca->prior_cwnd, cwnd);

	if (ca->flag & LP_WITHIN_INF)
		b = BETA_MAX;

	return max(cwnd - beta_scaled(b, cwnd), 2U);
}

static u32 tcp_lp_remote_hz_estimator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	s64 rhz = (s64)ca->remote_hz << 6;
	s32 dr, dl;
	s64 m = 0;

	if (ca->remote_ref_time == 0 || ca->local_ref_time == 0)
		goto out;

	dr = (s32)(tp->rx_opt.rcv_tsval - ca->remote_ref_time);
	dl = (s32)(tp->rx_opt.rcv_tsecr - ca->local_ref_time);
	if (!dr || !dl)
		goto out;

	m = div_s64((s64)lp_ts_hz(tp) * dr, dl);
	if (m < 0)
		m = -m;

	if (rhz > 0) {
		m -= rhz >> 6;
		rhz += m;
	} else {
		rhz = m << 6;
	}

	rhz = clamp_t(s64, rhz, 0, (s64)LP_REMOTE_HZ_MAX << 6);

out:
	if ((rhz >> 6) > 0)
		ca->flag |= LP_VALID_RHZ;
	else
		ca->flag &= ~LP_VALID_RHZ;

	ca->remote_ref_time = tp->rx_opt.rcv_tsval;
	ca->local_ref_time = tp->rx_opt.rcv_tsecr;

	return (u32)(rhz >> 6);
}

static u32 tcp_lp_owd_calculator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	s64 owd = 0;

	ca->remote_hz = tcp_lp_remote_hz_estimator(sk);

	if ((ca->flag & LP_VALID_RHZ) && ca->remote_hz) {
		owd = (s64)div_u64((u64)tp->rx_opt.rcv_tsval * lp_ts_hz(tp),
				   ca->remote_hz) -
		      (s64)tp->rx_opt.rcv_tsecr;
		if (owd < 0)
			owd = -owd;

		owd = min_t(s64, owd, LP_OWD_MAX);
	}

	if (owd > 0)
		ca->flag |= LP_VALID_OWD;
	else
		ca->flag &= ~LP_VALID_OWD;

	return (u32)owd;
}

static void tcp_lp_rtt_sample(struct sock *sk, u32 base_rtt)
{
	struct elegant *ca = inet_csk_ca(sk);
	u32 mowd = tcp_lp_owd_calculator(sk);
	u32 gain;
	s64 err;

	if (!(ca->flag & LP_VALID_RHZ) || !(ca->flag & LP_VALID_OWD))
		return;

	if (mowd < ca->owd_min_ts)
		ca->owd_min_ts = mowd;

	if (mowd > ca->owd_max_ts) {
		if (mowd > ca->owd_max_rsv_ts) {
			if (ca->owd_max_rsv_ts == 0)
				ca->owd_max_ts = mowd;
			else
				ca->owd_max_ts = ca->owd_max_rsv_ts;
			ca->owd_max_rsv_ts = mowd;
		} else {
			ca->owd_max_ts = mowd;
		}
	}

	gain = (base_rtt && max_delay(ca, base_rtt) > base_rtt / 2) ? 2 : 3;

	if (!ca->sowd_scaled) {
		ca->sowd_scaled = mowd << LP_SOWD_SHIFT;
	} else {
		err = ((s64)mowd << LP_SOWD_SHIFT) - ca->sowd_scaled;
		ca->sowd_scaled = (u32)((s64)ca->sowd_scaled + (err >> gain));
	}
}

static void elegant_early_response(struct sock *sk, u32 now, u32 base_rtt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd, target, guard;

	if (inet_csk(sk)->icsk_ca_state != TCP_CA_Open || ca->lt_is_sampling)
		return;

	guard = max(2 * usecs_to_ts(tp, base_rtt), 1U);
	if (ca->last_drop_ts && (s32)(now - ca->last_drop_ts) < (s32)guard)
		return;

	cwnd = tcp_snd_cwnd(tp);
	if (ca->flag & LP_WITHIN_INF)
		target = max(cwnd >> 1, cwnd_min_target);
	else
		target = max(cwnd - beta_scaled(ca->beta, cwnd),
			     cwnd_min_target);

	if (target < cwnd) {
		tp->snd_ssthresh = max(target, 2U);
		tcp_snd_cwnd_set(tp, target);
	}

	ca->last_drop_ts = now;
}

static void tcp_elegant_pkts_acked(struct sock *sk,
				   const struct ack_sample *sample)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 now = tcp_time_stamp_ts(tp);
	u32 rtt_us, base_rtt, delta, inf_max, thr;

	if (sample->rtt_us <= 0)
		return;

	rtt_us = min_t(u32, sample->rtt_us, RTT_MAX);

	ca->rtt_curr_us = rtt_us;
	ca->sum_rtt_us += rtt_us;
	if (ca->cnt_rtt < U16_MAX)
		ca->cnt_rtt++;
	ca->round_max_rtt_us = max(ca->round_max_rtt_us, rtt_us);
	ca->max_rtt_us = max(ca->max_rtt_us, rtt_us);

	base_rtt = elegant_base_rtt(tp);

	tcp_lp_rtt_sample(sk, base_rtt);

	delta = now - tp->rx_opt.rcv_tsecr;
	if ((s32)delta > 0) {
		inf_max = lp_inference_max_ts(tp);
		ca->inference_ts = clamp_t(u32,
					   max(3 * min(delta, inf_max / 3),
					       2 * usecs_to_ts(tp, base_rtt)),
					   1U, inf_max);
	}

	if (ca->last_drop_ts &&
	    (s32)(now - ca->last_drop_ts) < (s32)ca->inference_ts)
		ca->flag |= LP_WITHIN_INF;
	else
		ca->flag &= ~LP_WITHIN_INF;

	thr = ca->owd_max_ts > ca->owd_min_ts ?
	      ca->owd_max_ts - ca->owd_min_ts : 0;
	thr = ca->owd_min_ts + beta_scaled(ca->beta, thr);

	if ((ca->sowd_scaled >> LP_SOWD_SHIFT) < thr) {
		ca->flag |= LP_WITHIN_THR;
		return;
	}
	ca->flag &= ~LP_WITHIN_THR;

	ca->owd_min_ts = ca->sowd_scaled >> LP_SOWD_SHIFT;
	ca->owd_max_ts = ca->sowd_scaled >> (LP_SOWD_SHIFT - 1);
	ca->owd_max_rsv_ts = ca->owd_max_ts;

	elegant_early_response(sk, now, base_rtt);
}

static u32 calc_wwf(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 base_rtt = elegant_base_rtt(tp);
	u32 m, wwf, cap;
	u64 numer;

	m = (u32)max_t(u64, ((u64)ca->rtt_curr_us * 7 + base_rtt) >> 3, 1);

	numer = ((u64)cwnd * ca->max_rtt_us) << E_UNIT_SQ_SHIFT;
	wwf = (u32)(int_sqrt64(div_u64(numer, m)) >> ELEGANT_SCALE);

	wwf = (u32)(((u64)wwf * (BETA_SCALE + BETA_MAX - ca->beta) +
		     (BETA_SCALE >> 1)) >> BETA_SHIFT);

	cap = clamp_t(u32, cwnd >> 3, 1U, WWF_CAP_MAX);

	return clamp_t(u32, wwf, 1U, cap);
}

static void elegant_cong_avoid_ai(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 eff_alpha = ca->alpha;
	u32 delta;

	if (!cwnd)
		return;

	if (!(ca->flag & LP_WITHIN_INF) && (ca->flag & LP_WITHIN_THR) &&
	    cwnd >= elegant_win_thresh()) {
		if (!ca->wwf_valid) {
			ca->cached_wwf = calc_wwf(sk);
			ca->wwf_valid = true;
		}
		eff_alpha = max(eff_alpha, ca->cached_wwf * ALPHA_SCALE);
	}

	tp->snd_cwnd_cnt += acked;

	delta = (u32)(((u64)tp->snd_cwnd_cnt * eff_alpha) >> ALPHA_SHIFT);
	if (delta >= cwnd) {
		tcp_snd_cwnd_set(tp, min(cwnd + delta / cwnd,
					 (u32)tp->snd_cwnd_clamp));
		tp->snd_cwnd_cnt = 0;
	}
}

static void tcp_elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (after(ack, ca->round_end_seq)) {
		lt_round_elapsed(ca);
		update_params(sk);
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}

	elegant_cong_avoid_ai(sk, acked);
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state != TCP_CA_Loss)
		return;

	ca->alpha = ALPHA_BASE;
	ca->beta = BETA_BASE;
	ca->rtt_low_rounds = 0;
	ca->rtt_above = 0;
	ca->wwf_valid = false;
	ca->lt_is_sampling = true;
	ca->lt_rtt_cnt = 0;

	rtt_reset(ca, elegant_base_rtt(tcp_sk(sk)));
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->lt_is_sampling = false;
	ca->lt_rtt_cnt = 0;
	ca->wwf_valid = false;
	ca->last_drop_ts = 0;
	ca->flag &= ~LP_WITHIN_INF;

	return max(tcp_snd_cwnd(tp), ca->prior_cwnd);
}

static void tcp_elegant_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (event != CA_EVENT_CWND_RESTART && event != CA_EVENT_TX_START)
		return;

	ca->flag = 0;
	ca->sowd_scaled = 0;
	ca->owd_min_ts = U32_MAX;
	ca->owd_max_ts = 0;
	ca->owd_max_rsv_ts = 0;
	ca->remote_hz = 0;
	ca->remote_ref_time = 0;
	ca->local_ref_time = 0;
	ca->last_drop_ts = 0;
	ca->inference_ts = 0;
	ca->max_rtt_us = 0;
	ca->round_max_rtt_us = 0;
	ca->rtt_curr_us = 0;
	ca->wwf_valid = false;
	ca->round_end_seq = tp->snd_nxt;

	rtt_reset(ca, elegant_base_rtt(tp));
}

static struct tcp_congestion_ops tcp_elegant __read_mostly = {
	.name		= "elegant",
	.owner		= THIS_MODULE,
	.init		= tcp_elegant_init,
	.ssthresh	= tcp_elegant_ssthresh,
	.undo_cwnd	= tcp_elegant_undo_cwnd,
	.cong_avoid	= tcp_elegant_cong_avoid,
	.pkts_acked	= tcp_elegant_pkts_acked,
	.set_state	= tcp_elegant_set_state,
	.cwnd_event	= tcp_elegant_cwnd_event,
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

MODULE_DESCRIPTION("TCP Elegant");
