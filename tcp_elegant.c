#include <linux/module.h>
#include <net/tcp.h>

#include <linux/skbuff.h>
#include <asm/div64.h>
#include <linux/math64.h>

#define ELEGANT_SCALE 6
#define ELEGANT_UNIT (1 << ELEGANT_SCALE)

#define ALPHA_SHIFT	7
#define ALPHA_SCALE	(1u<<ALPHA_SHIFT)
#define ALPHA_MAX	(10*ALPHA_SCALE)	/* 10.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

#define BASE_RTT_RESET_INTERVAL (10 * HZ) /* 10 seconds for base_rtt reset */
#define INV_M_SHIFT 32

static const u32 bbr_lt_intvl_min_rtts = 4;
static const u32 bbr_cwnd_min_target = 4;

static int win_thresh __read_mostly = 20; /* Increased threshold for adaptive alpha/beta */
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int rtt0 = 25;
module_param(rtt0, int, 0644);
MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");

struct elegant {
	u64	sum_rtt;	/* sum of rtt's measured within last rtt */

	u32	rtt_max;        /* Max RTT used for wwf, decays */
	u32	rtt_curr;
	u32	base_rtt;	/* min of all rtt in usec */
	u32	last_base_rtt;
	u32	max_rtt;	/* max rtt of the current round for alpha/beta */
	u32	beta;		/* Muliplicative decrease */
	u32 next_rtt_delivered; /* scb->tx.delivered at end of round */
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32 last_rtt_reset_jiffies; /* For periodic base_rtt reset */
	u32 cached_wwf;

	u16	cnt_rtt;	/* # of rtts measured within last rtt */
	
	u8 lt_rtt_cnt;
	u8 prev_ca_state;     /* CA state on previous ACK */
	u8 delack;

	bool wwf_valid;

} __attribute__((__packed__));

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

	ca->rtt_max = tp->srtt_us;
	ca->rtt_curr = ca->rtt_max;
	ca->base_rtt = U32_MAX;
	ca->last_base_rtt = tp->srtt_us;
	ca->max_rtt = tp->srtt_us;
	ca->beta = BETA_BASE;
	ca->next_rtt_delivered = tp->delivered;
	ca->prior_cwnd = TCP_INIT_CWND;
	ca->last_rtt_reset_jiffies = jiffies;
	ca->cached_wwf = 0;

	rtt_reset(sk);

	ca->lt_rtt_cnt = 0;
	ca->prev_ca_state = TCP_CA_Open;
	ca->delack = 0;

	ca->wwf_valid = false;
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
	
	ca->prior_cwnd = tp->snd_cwnd;

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

static u32 beta(const struct rate_sample *rs, u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 10;
	if (rs->is_app_limited || da <= d2)
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

static void update_params(const struct rate_sample *rs, struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (tp->snd_cwnd < win_thresh) {
		ca->beta = BETA_BASE;
	} else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->beta = beta(rs, da, dm);
	}

	rtt_reset(sk);
}

static void tcp_elegant_reset(struct sock *sk)
{
	struct elegant *ca = inet_csk_ca(sk);

	ca->beta = BETA_BASE;
	rtt_reset(sk);
}

static void tcp_elegant_set_state(struct sock *sk, u8 new_state)
{
	struct elegant *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->prev_ca_state = TCP_CA_Loss;
		tcp_elegant_reset(sk);
		ca->delack = 0;
	}
}

static void tcp_elegant_pkts_acked(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 rtt_us = rs->rtt_us;
	u32 acked = rs->delivered - rs->prior_delivered;
	bool delayed = acked == 1 && ca->delack;
	bool is_delayed = rs->is_ack_delayed || (tp->sacked_out == 0 && delayed);

	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	/* ignore bogus values, this prevents wraparound in alpha math */
	if (rtt_us > RTT_MAX)
		rtt_us = RTT_MAX;

	if (tp->sacked_out == 0) {
		if (acked > 1 && ca->delack < 5)
			ca->delack++;
		else if (delayed)
			ca->delack--;
	}

	if ((!rs->acked_sacked && !is_delayed) || ca->rtt_curr > rtt_us || ca->rtt_curr == 0)
		ca->rtt_curr = rtt_us;

	ca->base_rtt = min(ca->base_rtt, rtt_us);
	ca->base_rtt = min(tp->srtt_us, ca->base_rtt);

	/* and max */
	if (ca->max_rtt < rtt_us)
		ca->max_rtt = rtt_us;

	++ca->cnt_rtt;
	ca->sum_rtt += rtt_us;
}

static inline u32 hybla_factor(const struct tcp_sock *tp, const struct elegant *ca)
{
    u32 cur = max(ca->rtt_curr, 1U);
    u32 p   = cur / min(tp->srtt_us, 25000U);
    return clamp(p, 1U, 4U);
}

static u32 fast_sqrt(u32 x)
{
	int shift = fls(x) - 1;
	u32 res = 1U << (shift >> 1);
    if (x == 0) return 0;
    res = (res + x / res) >> 1;
    res = (res + x / res) >> 1;
    return res;
}

static void tcp_elegant_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u32 wwf;

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		u32 p    = hybla_factor(tp, ca);
		u32 incr = acked * p;
		tp->snd_cwnd += incr;
		return;
	} else {
		/* Compute WWF once per RTT boundary */
		if (!ca->wwf_valid) {
            u32 min_base = min(ca->base_rtt, ca->last_base_rtt);
            u32 mean    = (4U * ca->rtt_curr + min_base) / 5;
            u64 inv_m   = mean ? ((1ULL << INV_M_SHIFT) / mean) : 0;

            u32 peak = max(ca->rtt_max, ca->max_rtt);
            u64 raw  = (u64)tp->snd_cwnd * ELEGANT_UNIT * ELEGANT_UNIT * peak;
            u32 root = fast_sqrt((u32)((raw * inv_m) >> INV_M_SHIFT));

            ca->cached_wwf = root >> ELEGANT_SCALE;
            ca->wwf_valid  = true;
        }

        wwf = max(ca->cached_wwf, acked);
	}

	tcp_cong_avoid_ai(tp, tp->snd_cwnd, wwf);
}

static void tcp_elegant_update(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */
	
	if (after(tcp_jiffies32, ca->last_rtt_reset_jiffies + BASE_RTT_RESET_INTERVAL)) {
		ca->rtt_max = ca->max_rtt;
		ca->max_rtt = ca->base_rtt;
		ca->last_rtt_reset_jiffies = jiffies;
	}

	if (ca->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		update_params(rs, sk);
		ca->lt_rtt_cnt = 0;
		if (ca->last_base_rtt < ca->base_rtt) {
			ca->last_base_rtt = (ca->last_base_rtt >> 1) + (ca->base_rtt >> 1);
		} else {
			ca->last_base_rtt = ca->base_rtt;
		}
		ca->base_rtt = U32_MAX;
	}

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, ca->next_rtt_delivered)) {
		ca->next_rtt_delivered = tp->delivered;
		ca->lt_rtt_cnt++;
		ca->wwf_valid = false;
	}

	tcp_elegant_pkts_acked(sk, rs);

}

static void tcp_elegant_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	u8 prev_state = ca->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	tcp_elegant_update(sk, rs);

	if (!rs->acked_sacked)
		goto done;  /* no packet fully ACKed; just apply caps */

	if (state == TCP_CA_Open) /* Let cong_control adjustments run even if hybla_en is true */
		goto done;

	ca->prev_ca_state = state;
	
	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		ca->next_rtt_delivered = tp->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = max(cwnd, tcp_packets_in_flight(tp) + rs->acked_sacked);
		goto done;
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		cwnd = max(cwnd, ca->prior_cwnd);
	}

	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
}

static u32 tcp_elegant_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct elegant *ca = inet_csk_ca(sk);

	ca->lt_rtt_cnt = 0;
	
	return max(tp->snd_cwnd, tp->prior_cwnd);
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

