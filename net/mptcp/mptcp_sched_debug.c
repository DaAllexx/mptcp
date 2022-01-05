/* helpers for debugging and collecting stats from schedulers */

#include <net/mptcp.h>
#include <linux/log2.h>

#define __sdebug(fmt) "[sched] %s:%d::" fmt, __FUNCTION__, __LINE__
#define sdebug(fmt, args...) if (sysctl_mptcp_sched_print) printk(KERN_WARNING __sdebug(fmt), ## args)

/* TODO: create function for selecting flows based on port... */
static unsigned int tcp_unsent_pkts(const struct sock *sk)
{
	struct sk_buff *skb_it = tcp_send_head(sk);
	unsigned int pkts = 0;

	if (sk && skb_it) {
		tcp_for_write_queue_from(skb_it, sk) {
			/* Due to mptcp-specific stuff, nr of pkts in an
			 * skb is set to 0 before it's added to
			 * subsockets, TODO: why?/how to solve...
			 */
			//pkts += tcp_skb_pcount(skb_it);
			pkts = pkts + 1;
		}
	}

	return pkts;
}

static void inc_cwnd(u32* cwnd, u32 ssthresh )
{
	if ( *cwnd <= ssthresh ) {
		*cwnd = *cwnd * 2;
	} else {
		*cwnd = *cwnd + 1;
	}
}

static u32 ipow2(u32 n)
{
	if (!n)
		return 1;

	return 2 << (n - 1);
}

/**
 * Fast Square root algorithm
 *
 * Fractional parts of the answer are discarded. That is:
 *      - SquareRoot(3) --> 1
 *      - SquareRoot(4) --> 2
 *      - SquareRoot(5) --> 2
 *      - SquareRoot(8) --> 2
 *      - SquareRoot(9) --> 3
 */
static u32 isqrt_sttf(u32 a)
{
	u32 op  = a;
	u32 res = 0;
	u32 one = 1uL << 30;

	while (one > op)
		one >>= 2;

	while (one != 0) {
		if (op >= res + one) {
			op = op - (res + one);
			res = res + 2 * one;
		}

		res >>= 1;
		one >>= 2;
	}
	return res;
}

static u32 ilog2_sttf(u32 n)
{
	int l = 1;
	int i = 0;

	if (n == 0) {
		return 0;
	} else {
		while (l < n) {
			l *= 2;
			i++;
		}
		return i;
	}
}

static u32 compute_tt_2(u32 qsize, u32 f_cwnd, u32 cwnd, u32 ssthresh, u32 rtt)
{
	u32 cqsize = qsize; /* current qsize in packets */
	u32 ccwnd  = cwnd;  /* current cwnd in packets */
	u32 tt     = 0;     /* computed transfer time */
	u32 r_ss_max = 0xffffffff;
	u32 p_ss_max = 0xffffffff;
	u32 r_ss;
	u32 t;

	/* Nothing to send */
	if ( qsize == 0 )
		return 0;

	if (f_cwnd > 0) {
		/* Space left in cwnd during current round */
		cqsize = ( cqsize > f_cwnd )? cqsize - f_cwnd: 0;

		if ( cqsize > 0 )
			tt += rtt;
		else
			return rtt / 2;
	} else {
		tt += rtt;
	}

	if (2 * ccwnd <= ssthresh) {
		/* In slow start */
		ccwnd *= 2;
	} else if ((ccwnd < ssthresh) && (2 * ccwnd > ssthresh)) {
		/* Reaches sshresh during this round */
		ccwnd = ssthresh;
	} else {
		ccwnd += 1;
	}

	if (ssthresh != TCP_INFINITE_SSTHRESH) {
		r_ss_max = ilog2_sttf(ssthresh / ccwnd);
		p_ss_max = ccwnd * (ipow2(r_ss_max) - 1);
	}

	if (cqsize <= p_ss_max) {
		/* Remainder queued sent during slow start.
		 * Note that if ccwnd >= ssthresh then p_ss_max = 0
		 */
		r_ss = max_t(u32, ilog2_sttf( cqsize / ccwnd + 1), 1);
		t    = ccwnd * (ipow2( r_ss ) - 1);
		cqsize = (cqsize > t) ? cqsize - t: 0;
		tt += rtt * (r_ss - 1) + rtt / 2;
		if (cqsize > 0) {
			tt += rtt;
		}
		return tt;
	} else {
		u32 r_ca_max, p_ca_max;
		/* Remainder sent during slow start and congestion
		 * avoidance or only in congestion avoidance
		 */
		if (ccwnd < ssthresh) {
			/* Starts in slow start */
			u32 c_ss_max = ccwnd * ipow2(r_ss_max);
			cqsize -= p_ss_max;
			tt += r_ss_max * rtt;

			if (c_ss_max < ssthresh) {
				/* One round left in slow start */
				if (cqsize > c_ss_max) {
					/* Transfer continues beyond ssthresh */
					cqsize -= c_ss_max;
					tt += rtt;
				} else {
					/* Transfer ends before sshresh */
					tt += rtt / 2;
					return tt;
				}
			}
			ccwnd = ssthresh;
		}
		/* Remainder of transfer in congestion avoidance */
		r_ca_max = (-(2 * ccwnd - 1) + isqrt_sttf((2 * ccwnd + 1) * (2 * ccwnd + 1) + 8 * cqsize)) / 2;
		p_ca_max = (r_ca_max * (2 * ccwnd + (r_ca_max - 1))) / 2;
		cqsize = (cqsize > p_ca_max) ? cqsize - p_ca_max: 0;
		tt += rtt * (r_ca_max - 1) + rtt / 2;

		if (cqsize > 0) {
			tt += rtt;
		}
		return tt;
	}
}

void mptcp_calc_sched(struct sock *meta_sk, struct sock *subsk, int log)
{
	struct tcp_sock *subtp = tcp_sk(subsk);
	u32 qsize_meta = 1;
	u32 a, b, c, d, e, f, g;
	u32 qsize_curr_flow = a = tcp_unsent_pkts(subsk);
	u32 curr_in_flight = b = tcp_packets_in_flight(subtp);
	u32 f_cwnd = c = (subtp->snd_cwnd > curr_in_flight)? subtp->snd_cwnd - curr_in_flight: 0;
	u32 qsize = d = qsize_meta + qsize_curr_flow;
	u32 cwnd = e = subtp->snd_cwnd;
	u32 ssthresh = f = subtp->snd_ssthresh;
	u32 rtt = g = subtp->srtt_us;
	u32 tt = 0;
	u32 r = 0;
	int new_calc = 1;

	if (new_calc) {
		tt = compute_tt_2(qsize, f_cwnd, cwnd, ssthresh, rtt);
		goto end_calc;
	}

	if (qsize <= f_cwnd) {
		tt += rtt / 2;
		goto end_calc;
	}

	if (f_cwnd > 0) {
		qsize -= f_cwnd;
	}

	tt += rtt;

	/* Size of cwnd in second round. */
	inc_cwnd(&cwnd, ssthresh);

	if (ssthresh < TCP_INFINITE_SSTHRESH) {

		if (cwnd <= ssthresh) {
			unsigned int k = ilog2(ssthresh / cwnd);
			if (((ssthresh % cwnd) == 0) && (ssthresh == ipow2(k) * cwnd)) {
				unsigned int data_in_ss = 2 * ssthresh - cwnd;
				if ( qsize > data_in_ss ) {
					qsize -= data_in_ss;
					r = k + 1;
					cwnd = ssthresh + 1;
					while (qsize > 0) {
						qsize = (qsize > cwnd) ? qsize - cwnd : 0;
						inc_cwnd(&cwnd, ssthresh);
						r++;
					}
					tt += (r - 1) * rtt + rtt / 2;
				} else {
					if (qsize <= cwnd) {
						tt += rtt / 2;
					} else {
						r = order_base_2(((qsize % cwnd == 0)? qsize / cwnd: qsize / cwnd + 1) + 1) - 1;
						tt += r * rtt + rtt / 2;
					}
				}
			} else {
				if (qsize <= cwnd) {
					tt += rtt / 2;
				} else {
					unsigned int l = order_base_2((ssthresh % cwnd == 0)? ssthresh / cwnd: ssthresh / cwnd + 1) - 1;
					unsigned int m = ipow2(l) * cwnd;
					unsigned int data_in_ss_low = 2 * m - cwnd;
					if (qsize == data_in_ss_low) {
						tt += l * rtt + rtt / 2;
					} else if (qsize < data_in_ss_low) {
						if ((qsize % cwnd) == 0) {
							tt += (order_base_2(qsize / cwnd + 1) - 1) * rtt + rtt / 2;
						} else {
							tt += order_base_2(qsize / cwnd + 1) * rtt + rtt / 2;
						}
					} else {
						unsigned int d = ssthresh - m;
						unsigned int e = 2 * d;
						qsize -= data_in_ss_low;
						if (qsize <= e) {
							tt += (l + 1) * rtt + rtt / 2;
						} else {
							tt += (l + 1) * rtt;
							qsize -= e;
							r = 0;
							cwnd = ssthresh + 1;
							while (qsize > 0) {
								qsize = (qsize > cwnd) ? qsize - cwnd : 0;
								cwnd++;
								r++;
							}
							tt += (r - 1) * rtt + rtt / 2;
						}
					}
				}
			}
		} else {
			r = 0;
			while (qsize > 0) {
				qsize = (qsize > cwnd) ? qsize - cwnd : 0;
				cwnd++;
				r++;
			}
			tt += (r - 1) * rtt + rtt / 2;
		}
	} else {
		if (qsize <= cwnd) {
			tt += rtt / 2;
		} else {
			r = order_base_2(((qsize % cwnd == 0)? qsize / cwnd: qsize / cwnd + 1) + 1) - 1;
			tt += r * rtt + rtt / 2;
		}
	}
end_calc:
	if (mptcp_get_logmask(meta_sk)) {
		if (log == 1) {
			sdebug("%d# %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else if (log == 2) {
			sdebug("%d$ %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else if (log == 3) {
			sdebug("%d! %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else if (log == 4) {
			sdebug("%d& %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else if (log == 5) {
			sdebug("%dA %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else {
			sdebug("%d %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		}
	}
}
EXPORT_SYMBOL_GPL(mptcp_calc_sched);
