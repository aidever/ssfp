// SPDX-License-Identifier: MIT OR GPL-2.0
//
// TC egress：按 skb->mark 选模板，改写出站 SYN 的 TCP 窗口和选项布局。
//
// - 只处理 mark 高 16 位为 0x5f50 的包（ssfp 用 SO_MARK 标记），其余一律放行
// - 只处理本机内核发出的纯 SYN；内核的选项布局是固定的两种之一：
//     开时间戳: MSS,SACK_PERM,TS,NOP,WS            (20 字节)
//     关时间戳: MSS,NOP,NOP,SACK_PERM,NOP,WS       (12 字节)
//   不是这两种就原样放行
// - 新选项由用户态按模板预先拼好字节，并给出 MSS / WS / TS 值要填入的位置；
//   这里只做定长拷贝和填值，没有分支循环，验证器负担小
// - 选项长度变化时用 bpf_skb_change_tail 在包尾增删字节（SYN 不带数据，TCP 头起点不动，
//   skb->csum_start 仍然正确；adjust_room 会让 csum_start 错位，软件/网卡算校验和时写错位置）
// - TCP 校验和用增量方式（bpf_l4_csum_replace），兼容 CHECKSUM_PARTIAL 卸载
//
// 不依赖 libbpf 头文件，helper 按编号声明。

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define INLINE static __attribute__((always_inline)) inline

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 off, const void *from, __u32 len, __u64 flags) = (void *)9;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 off, __u64 from, __u64 to, __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 off, __u64 from, __u64 to, __u64 flags) = (void *)11;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 off, void *to, __u32 len) = (void *)26;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __u32 seed) = (void *)28;
static long (*bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)38;

#define MARK_MASK 0xffff0000u
#define MARK_BASE 0x5f500000u
#define MAX_TPL 8
#define NONE 0xff

// 与 src/ebpf.rs 的 Tpl 保持一致（48 字节）
struct tpl {
	__u16 window;  // 主机字节序；0 = 不改
	__u8 opt_len;  // 新选项总长（4 的倍数，≤40）；0 = 不改选项
	__u8 mss_off;  // 在 opts 里填 MSS 值（2 字节）的位置；NONE = 无
	__u8 ws_off;   // 填 WS 值（1 字节）的位置
	__u8 ts_off;   // 填 TSval+TSecr（8 字节）的位置
	__u8 pad[2];
	__u8 opts[40];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TPL);
	__type(key, __u32);
	__type(value, struct tpl);
} templates SEC(".maps");

// [0] = L3 头相对包首的偏移（以太网 14，无二层头的设备 0）
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

enum {
	ST_MARKED,
	ST_REWRITTEN,
	ST_NOT_SYN,
	ST_UNCHANGED,
	ST_PARSE_FAIL,
	ST_ADJUST_FAIL,
	ST_STORE_FAIL,
	ST_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

INLINE void count(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &k);
	if (v)
		*v += 1;
}

// 在寄存器里就地掩码，防止编译器复用溢出到栈上的值导致验证器丢失边界
#define BOUND(x, m) ({ __u64 __v = (x); asm volatile("%0 &= " #m : "+r"(__v)); __v; })

#define bswap16(x) ((__u16)(((x) >> 8) | ((x) << 8)))

SEC("classifier")
int syn_rewrite(struct __sk_buff *skb)
{
	__u32 mark = skb->mark;
	if ((mark & MARK_MASK) != MARK_BASE)
		return TC_ACT_OK;
	__u32 id = mark & 0xffff;
	if (id >= MAX_TPL)
		return TC_ACT_OK;
	struct tpl *t = bpf_map_lookup_elem(&templates, &id);
	if (!t)
		return TC_ACT_OK;
	count(ST_MARKED);
	if (t->window == 0 && t->opt_len == 0) {
		count(ST_UNCHANGED);
		return TC_ACT_OK;
	}

	__u32 zero = 0;
	__u32 *l3p = bpf_map_lookup_elem(&config, &zero);
	__u32 l3 = l3p ? *l3p : 14;
	if (l3 > 64)
		return TC_ACT_OK;

	__u32 l4, ip_len_off, tcp_len;
	int v6;
	__u16 proto = bswap16((__u16)skb->protocol);
	if (proto == ETH_P_IP) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, l3, &ip, sizeof(ip)))
			goto parse_fail;
		if (ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP || (ip.frag_off & bswap16(0x3fff)))
			goto parse_fail;
		l4 = l3 + 20;
		ip_len_off = l3 + 2;
		tcp_len = bswap16(ip.tot_len) - 20;
		v6 = 0;
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, l3, &ip6, sizeof(ip6)))
			goto parse_fail;
		if (ip6.nexthdr != IPPROTO_TCP)
			goto parse_fail;
		l4 = l3 + 40;
		ip_len_off = l3 + 4;
		tcp_len = bswap16(ip6.payload_len);
		v6 = 1;
	} else {
		return TC_ACT_OK;
	}

	__u8 old[60] = {};
	if (bpf_skb_load_bytes(skb, l4, old, 20))
		goto parse_fail;
	__u8 fl = old[13];
	if ((fl & 0x02) == 0 || (fl & 0x10) != 0) { // 要 SYN 且非 ACK
		count(ST_NOT_SYN);
		return TC_ACT_OK;
	}
	__u32 doff = (old[12] >> 4) * 4;
	if (tcp_len != doff || skb->len != l4 + doff) // 带数据（TFO）或有尾部填充的 SYN 不碰
		goto parse_fail;

	__u8 mss0, mss1, ws;
	__u8 ts[8] = {};
	int has_ts;
	if (doff == 40) {
		// MSS(2,4,m,m) SACK_PERM(4,2) TS(8,10,v*4,e*4) NOP WS(3,3,w)
		if (bpf_skb_load_bytes(skb, l4 + 20, old + 20, 20))
			goto parse_fail;
		if (old[20] != 2 || old[21] != 4 || old[24] != 4 || old[25] != 2 || old[26] != 8 || old[27] != 10 ||
		    old[36] != 1 || old[37] != 3 || old[38] != 3)
			goto parse_fail;
		mss0 = old[22];
		mss1 = old[23];
		ws = old[39];
#pragma clang loop unroll(full)
		for (int j = 0; j < 8; j++)
			ts[j] = old[28 + j];
		has_ts = 1;
	} else if (doff == 32) {
		// MSS NOP NOP SACK_PERM NOP WS
		if (bpf_skb_load_bytes(skb, l4 + 20, old + 20, 12))
			goto parse_fail;
		if (old[20] != 2 || old[21] != 4 || old[24] != 1 || old[25] != 1 || old[26] != 4 || old[27] != 2 ||
		    old[28] != 1 || old[29] != 3 || old[30] != 3)
			goto parse_fail;
		mss0 = old[22];
		mss1 = old[23];
		ws = old[31];
		has_ts = 0;
	} else {
		goto parse_fail;
	}

	// 新头：前 20 字节沿用，按模板改窗口、选项与 data offset
	__u8 nh[60] = {};
#pragma clang loop unroll(full)
	for (int k = 0; k < 20; k++)
		nh[k] = old[k];
	if (t->window) {
		nh[14] = t->window >> 8;
		nh[15] = t->window & 0xff;
	}
	__u32 ndoff;
	if (t->opt_len == 0) {
#pragma clang loop unroll(full)
		for (int k = 20; k < 60; k++)
			nh[k] = old[k];
		ndoff = doff;
	} else {
		__u32 ol = t->opt_len;
		if (ol > 40 || (ol & 3))
			goto parse_fail;
#pragma clang loop unroll(full)
		for (int k = 0; k < 40; k++)
			nh[20 + k] = t->opts[k];
		__u32 mo = t->mss_off, wo = t->ws_off, to = t->ts_off;
		if (mo != NONE) {
			nh[(20 + mo) & 63] = mss0;
			nh[(21 + mo) & 63] = mss1;
		}
		if (wo != NONE)
			nh[(20 + wo) & 63] = ws;
		if (to != NONE) {
			if (!has_ts) // 模板要 TS 但内核没发（net.ipv4.tcp_timestamps=0），不改
				goto parse_fail;
#pragma clang loop unroll(full)
			for (int j = 0; j < 8; j++)
				nh[(20 + to + j) & 63] = ts[j];
		}
		ndoff = 20 + ol;
	}
	nh[12] = (ndoff / 4) << 4 | (old[12] & 0x0f);

	// TCP 头内容的校验和差值（校验和字段两边相同，不参与）
	__s64 diff = bpf_csum_diff((__be32 *)old, BOUND(doff, 0x3c), (__be32 *)nh, BOUND(ndoff, 0x3c), 0);
	if (diff < 0)
		goto parse_fail;

	int delta = (int)ndoff - (int)doff;
	if (delta != 0 && bpf_skb_change_tail(skb, skb->len + delta, 0)) {
		count(ST_ADJUST_FAIL);
		return TC_ACT_OK; // 尚未改动，放行原包
	}
	__u64 wl = BOUND(ndoff, 0x3c);
	if (wl < 20)
		return TC_ACT_SHOT;
	if (bpf_skb_store_bytes(skb, l4, nh, wl, 0))
		goto store_fail;

	if (delta != 0) {
		__u16 old_len_be, new_len_be;
		if (v6) {
			old_len_be = bswap16((__u16)tcp_len);
			new_len_be = bswap16((__u16)ndoff);
		} else {
			old_len_be = bswap16((__u16)(tcp_len + 20));
			new_len_be = bswap16((__u16)(ndoff + 20));
			if (bpf_l3_csum_replace(skb, l3 + 10, old_len_be, new_len_be, 2))
				goto store_fail;
		}
		if (bpf_skb_store_bytes(skb, ip_len_off, &new_len_be, 2, 0))
			goto store_fail;
		// 伪头部里的 TCP 长度
		__u16 old_tl = bswap16((__u16)tcp_len), new_tl = bswap16((__u16)ndoff);
		if (bpf_l4_csum_replace(skb, l4 + 16, old_tl, new_tl, BPF_F_PSEUDO_HDR | 2))
			goto store_fail;
	}
	if (bpf_l4_csum_replace(skb, l4 + 16, 0, (__u32)diff, 0))
		goto store_fail;

	count(ST_REWRITTEN);
	return TC_ACT_OK;

parse_fail:
	count(ST_PARSE_FAIL);
	return TC_ACT_OK;
store_fail:
	count(ST_STORE_FAIL);
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "Dual MIT/GPL";
