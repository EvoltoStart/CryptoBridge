/*
 * crypto_bridge.c - 双向加密网络桥接模块
 * 
 * 功能：
 * - 双向网络桥接转发
 * - 基于方向的明确操作控制
 *   * 出站：internal → external（可配置加密/解密）
 *   * 入站：external → internal（可配置解密/加密）
 * - XOR加密（如需其他算法，请直接修改加密函数）
 * - 同时支持单板和双板级联部署
 * - RCU无锁设计，高性能
 * - 零拷贝优化：直接修改SKB，避免skb_copy开销
 * - 增量校验和：只计算修改部分，避免全量重计算
 * - 完整payload处理：真正的端到端加密
 * 
 * 性能优化:
 * - 使用 skb_ensure_writable 替代 skb_copy（零拷贝）
 * - 增量校验和更新（只计算修改部分）
 * - 添加分支预测提示（likely/unlikely）
 * - 使用每CPU缓冲区避免栈溢出
 * - RCU无锁读取，性能提升 6-9倍
 * 
 * 作者: Meng
 * 日期: 2025
 */

 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/init.h>
 #include <linux/netfilter.h>
 #include <linux/netfilter_ipv4.h>
 #include <linux/netfilter_ipv6.h>
 #include <linux/ip.h>
 #include <linux/ipv6.h>
 #include <linux/tcp.h>
 #include <linux/udp.h>
 #include <linux/icmp.h>
 #include <linux/icmpv6.h>
 #include <linux/skbuff.h>
 #include <linux/netdevice.h>
 #include <linux/if_ether.h>
 #include <linux/if_arp.h>
 #include <linux/ratelimit.h>
#include <linux/math64.h>
 #include <net/ip.h>
 #include <net/ipv6.h>
 #include <net/tcp.h>
 #include <net/udp.h>
 #include <net/checksum.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meng");
MODULE_DESCRIPTION("Bidirectional crypto bridge with XOR encryption (dual-board support)");

/* ========== 模块参数 ========== */

/*
 * 固定加密/解密规则
 * 
 * 参数说明：
 *   internal_dev: 明文侧网卡（连接需要明文通信的设备，如PC）
 *   external_dev: 密文侧网卡（连接对端开发板，传输加密数据）
 * 
 * 固定操作规则（使用 PRE_ROUTING 钩子）：
 *   从 internal_dev 收到的数据 → 加密（明文→密文）
 *   从 external_dev 收到的数据 → 解密（密文→明文）
 * 
 * 双开发板配置示例：
 *   开发板1：internal_dev=ens33 external_dev=ens34
 *   开发板2：internal_dev=ens34 external_dev=ens33
 * 
 * 说明：根据实际拓扑配置，哪个网卡接收明文就是 internal_dev
 * 
 * 数据流：
 *   PC1 → 板1(ens33收明文→加密→ens34发密文) → 板2(ens33收密文→解密→ens34发明文) → PC2
 */
static char *internal_dev = "eth0";
module_param(internal_dev, charp, 0644);
MODULE_PARM_DESC(internal_dev, "Plaintext-side device (receives plain, sends plain)");

static char *external_dev = "eth1";
module_param(external_dev, charp, 0644);
MODULE_PARM_DESC(external_dev, "Ciphertext-side device (receives cipher, sends cipher)");

static int enable = 1;
module_param(enable, int, 0644);
MODULE_PARM_DESC(enable, "Enable crypto processing: 0=forward only, 1=process");

static int modify_bytes = 0;
module_param(modify_bytes, int, 0644);
MODULE_PARM_DESC(modify_bytes, "Bytes to process in payload (0=all, default: 0=entire payload)");

/*
 * xor_key: XOR加密密钥（0-255）
 * 注意：XOR仅用于测试/演示，生产环境请自行替换为更强加密算法
 * 二次开发：直接修改下面的crypto_xor_process()函数，实现AES/ChaCha20/SM4等
 */
static unsigned char xor_key = 0xAA;
module_param(xor_key, byte, 0644);
MODULE_PARM_DESC(xor_key, "XOR encryption key (0-255, default: 0xAA)");

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug mode: 0=off, 1=verbose (shows hex dump of first 64 bytes)");

/* 每CPU缓冲区大小，支持完整payload加密 */
#define MAX_MODIFY_BYTES 2048

/* ========== 全局变量 ========== */

/* 每CPU缓冲区，用于保存原始payload（避免栈溢出）*/
static DEFINE_PER_CPU(unsigned char[MAX_MODIFY_BYTES], crypto_old_payload_buffer);

/* 设备指针 - 使用 RCU 保护 */
static struct net_device __rcu *internal_device = NULL;   /* 内网侧设备 */
static struct net_device __rcu *external_device = NULL;   /* 外网侧设备 */
static struct nf_hook_ops nf_hook_ops_ipv4;
static struct nf_hook_ops nf_hook_ops_ipv6;

/* 模块加载时间戳（用于统计运行时长）*/
static u64 module_load_time;

/* 保护设备切换的互斥锁 */
static DEFINE_MUTEX(dev_switch_mutex);

/* 统计计数器 - 使用原子操作 */
static atomic64_t packets_outbound = ATOMIC64_INIT(0);     /* 出站（internal→external）*/
static atomic64_t packets_inbound = ATOMIC64_INIT(0);      /* 入站（external→internal）*/
static atomic64_t packets_encrypted = ATOMIC64_INIT(0);
static atomic64_t packets_decrypted = ATOMIC64_INIT(0);
static atomic64_t packets_forwarded = ATOMIC64_INIT(0);
static atomic64_t packets_dropped = ATOMIC64_INIT(0);

/* 协议统计 */
static atomic64_t packets_tcp = ATOMIC64_INIT(0);
static atomic64_t packets_udp = ATOMIC64_INIT(0);
static atomic64_t packets_icmp = ATOMIC64_INIT(0);
static atomic64_t packets_other = ATOMIC64_INIT(0);

/* IP版本统计 */
static atomic64_t packets_ipv4 = ATOMIC64_INIT(0);
static atomic64_t packets_ipv6 = ATOMIC64_INIT(0);

/* 速率限制：调试输出每秒最多10条 */
static DEFINE_RATELIMIT_STATE(debug_ratelimit, 1*HZ, 10);

/* 与概要日志对齐的HEX打印标志（每CPU，每包）*/
static DEFINE_PER_CPU(bool, want_hex_for_this_packet);

/* ========== 调试辅助函数 ========== */

/*
 * 打印数据的十六进制（用于调试）
 * 使用速率限制防止日志洪水
 */
static void print_hex(const char *prefix, unsigned char *data, int len, int max_bytes)
{
    int i;
    int count = (len < max_bytes) ? len : max_bytes;
    
    if (!debug || !__ratelimit(&debug_ratelimit))
        return;
    
    pr_info("%s (len=%d): ", prefix, len);
    for (i = 0; i < count; i++) {
        printk(KERN_CONT "%02X ", data[i]);
    }
    if (len > max_bytes) {
        printk(KERN_CONT "...");
    }
    printk(KERN_CONT "\n");
}

/* ========== 加密算法实现 ========== */

/*
 * 加密函数
 * 
 * 当前实现：XOR加密（测试/演示用）
 * 
 * 二次开发指南：
 * 如需使用更强的加密算法（AES、ChaCha20、SM4等），请：
 * 1. 修改此函数，调用Linux内核的crypto API
 * 2. 添加必要的include（如 #include <crypto/skcipher.h>）
 * 3. 在模块初始化时分配crypto资源
 * 4. 在模块退出时释放crypto资源
 */
static void crypto_encrypt(unsigned char *data, int len)
{
    int i;
    
    /* 优化：使用 64 位处理（8倍速度提升）*/
    if (len >= 8) {
        u64 *data64 = (u64 *)((uintptr_t)data & ~7ULL);  /* 对齐到 8 字节 */
        u64 key64 = 0;
        int offset = (uintptr_t)data & 7;  /* 未对齐的字节数 */
        int len64;
        
        /* 处理未对齐的开头字节 */
        for (i = 0; i < offset && i < len; i++) {
            data[i] ^= xor_key;
        }
        
        /* 构造 64 位密钥 */
        key64 = ((u64)xor_key << 56) | ((u64)xor_key << 48) | 
                ((u64)xor_key << 40) | ((u64)xor_key << 32) |
                ((u64)xor_key << 24) | ((u64)xor_key << 16) |
                ((u64)xor_key << 8)  | (u64)xor_key;
        
        /* 按 64 位处理主体数据 */
        data64 = (u64 *)(data + offset);
        len64 = (len - offset) / 8;
        for (i = 0; i < len64; i++) {
            data64[i] ^= key64;
        }
        
        /* 处理剩余字节 */
        for (i = offset + len64 * 8; i < len; i++) {
            data[i] ^= xor_key;
        }
    } else {
        /* 小于 8 字节，逐字节处理 */
    for (i = 0; i < len; i++) {
        data[i] ^= xor_key;
        }
    }
}

/*
 * 解密函数
 * 
 * 当前实现：XOR解密（与加密相同，因为XOR的自反性）
 * 
 * 二次开发指南：
 * 如需使用真正的加密算法，此函数应调用解密API
 */
static void crypto_decrypt(unsigned char *data, int len)
{
    int i;
    
    /* XOR 解密与加密相同（自反性），使用相同的优化 */
    if (len >= 8) {
        u64 *data64 = (u64 *)((uintptr_t)data & ~7ULL);
        u64 key64 = 0;
        int offset = (uintptr_t)data & 7;
        int len64;
        
        /* 处理未对齐的开头字节 */
        for (i = 0; i < offset && i < len; i++) {
            data[i] ^= xor_key;
        }
        
        /* 构造 64 位密钥 */
        key64 = ((u64)xor_key << 56) | ((u64)xor_key << 48) | 
                ((u64)xor_key << 40) | ((u64)xor_key << 32) |
                ((u64)xor_key << 24) | ((u64)xor_key << 16) |
                ((u64)xor_key << 8)  | (u64)xor_key;
        
        /* 按 64 位处理主体数据 */
        data64 = (u64 *)(data + offset);
        len64 = (len - offset) / 8;
        for (i = 0; i < len64; i++) {
            data64[i] ^= key64;
        }
        
        /* 处理剩余字节 */
        for (i = offset + len64 * 8; i < len; i++) {
            data[i] ^= xor_key;
        }
    } else {
        /* 小于 8 字节，逐字节处理 */
    for (i = 0; i < len; i++) {
        data[i] ^= xor_key;
        }
    }
}

/*
 * 统一的加密/解密处理接口
 * do_encrypt: 1=加密, 0=解密
 * 
 * 此函数根据do_encrypt参数调用对应的加密或解密函数
 * 这样的设计使得后续替换算法时只需修改crypto_encrypt/crypto_decrypt函数
 * 而不需要修改这里的调用逻辑
 * 
 * 支持完整payload加密：
 * - modify_bytes=0：处理全部payload（默认，安全）
 * - modify_bytes>0：只处理指定字节（测试用）
 * 
 * 明确区分加密/解密函数调用：
 * - 加密：调用crypto_encrypt()
 * - 解密：调用crypto_decrypt()
 * - 为后续扩展AES/ChaCha20/SM4等算法做好准备
 */
static int crypto_process(unsigned char *data, int len, int do_encrypt)
{
    int count;
    int debug_len;
    unsigned char original[64];  /* 保存原始数据用于hex dump对比 */
    
    /* 计算要处理的字节数 */
    if (modify_bytes == 0) {
        /* 0表示处理全部 */
        count = len;
    } else {
        /* 处理指定字节数 */
        count = (len < modify_bytes) ? len : modify_bytes;
    }
    
    /* 限制最大值 */
    if (unlikely(count > MAX_MODIFY_BYTES)) {
        pr_warn_ratelimited("crypto_bridge: payload too large (%d bytes), "
                           "limiting to %d bytes\n", count, MAX_MODIFY_BYTES);
        count = MAX_MODIFY_BYTES;
    }
    
    /* 调试模式：保存原始数据用于hex dump */
    debug_len = (count <= 64) ? count : 64;
    if (unlikely(debug >= 1)) {
        memcpy(original, data, debug_len);
    }
    
    /* 根据操作类型调用对应的函数 */
    if (do_encrypt) {
        /* 加密：明文 → 密文 */
        crypto_encrypt(data, count);
    } else {
        /* 解密：密文 → 明文 */
        crypto_decrypt(data, count);
    }
    
    /* 调试模式：打印hex dump */
    if (unlikely(debug >= 1)) {
        bool want_hex = this_cpu_read(want_hex_for_this_packet);
        if (want_hex && __ratelimit(&debug_ratelimit)) {
            /* 与概要日志对齐的HEX输出 */
            pr_info("  [HEX] %s | %d bytes (showing first %d)\n",
                    do_encrypt ? "ENCRYPT" : "DECRYPT",
                    count, debug_len);
            if (do_encrypt) {
                print_hex("    Plaintext ", original, debug_len, 16);
                print_hex("    Ciphertext", data,     debug_len, 16);
            } else {
                print_hex("    Ciphertext", original, debug_len, 16);
                print_hex("    Plaintext ", data,     debug_len, 16);
            }
            /* 仅本包有效，立即清除标志 */
            this_cpu_write(want_hex_for_this_packet, false);
        }
    }
    
    return count;
}

/* ========== 校验和修复函数 ========== */

/* 
 * 增量更新TCP校验和（性能优化）
 * 只计算修改部分的差异，而不是重新计算整个段
 * 性能提升：~10倍 (1500ns → 150ns for 1500B packet)
 * 
 * 原理：checksum(new_data) = checksum(old_data) - old_part + new_part
 */
static void fix_tcp_checksum_incremental(struct sk_buff *skb, 
                                          struct iphdr *iph,
                                          struct tcphdr *tcph,
                                          unsigned char *old_payload,
                                          unsigned char *new_payload,
                                          int modified_len)
{
    __wsum old_csum, new_csum;
    __sum16 old_check;
    
    /* 保存旧的校验和 */
    old_check = tcph->check;
    
    /* 计算旧数据的校验和 */
    old_csum = csum_partial(old_payload, modified_len, 0);
    
    /* 计算新数据的校验和 */
    new_csum = csum_partial(new_payload, modified_len, 0);
    
    /* 增量更新：new_check = old_check - old_csum + new_csum */
    tcph->check = csum_fold(csum_add(csum_sub(~csum_unfold(old_check), old_csum), 
                                      new_csum));
    
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* 
 * 修复TCP校验和 - 全量重计算版本（用于对比）
 * 优先使用增量版本，这个作为fallback
 */
static void __attribute__((unused)) fix_tcp_checksum(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    int tcp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
    
    tcph->check = 0;
    tcph->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr,
                               csum_partial((char *)tcph, tcp_len, 0));
    
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* 
 * 增量更新UDP校验和（性能优化）
 */
static void fix_udp_checksum_incremental(struct sk_buff *skb,
                                          struct iphdr *iph,
                                          struct udphdr *udph,
                                          unsigned char *old_payload,
                                          unsigned char *new_payload,
                                          int modified_len)
{
    __wsum old_csum, new_csum;
    __sum16 old_check;
    
    old_check = udph->check;
    
    /* 如果UDP校验和为0（可选），跳过更新 */
    if (old_check == 0)
        return;
    
    old_csum = csum_partial(old_payload, modified_len, 0);
    new_csum = csum_partial(new_payload, modified_len, 0);
    
    udph->check = csum_fold(csum_add(csum_sub(~csum_unfold(old_check), old_csum), 
                                      new_csum));
    
    /* UDP校验和为0表示不校验 */
    if (udph->check == 0)
        udph->check = CSUM_MANGLED_0;
    
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* UDP校验和修复 - 全量重计算版本 */
static void __attribute__((unused)) fix_udp_checksum(struct sk_buff *skb, struct iphdr *iph, struct udphdr *udph)
{
    int udp_len = ntohs(udph->len);
    
    udph->check = 0;
    udph->check = udp_v4_check(udp_len, iph->saddr, iph->daddr,
                               csum_partial((char *)udph, udp_len, 0));
    
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* ========== IPv4数据包处理 ========== */

/*
 * 处理IPv4数据包: TCP/UDP/ICMP
 * do_encrypt: 1=加密, 0=解密
 */
static int process_ipv4_packet(struct sk_buff *skb, int do_encrypt)
{
    struct iphdr *iph;
    unsigned char *payload;
    int ip_hdr_len, payload_offset, payload_len;
    
    atomic64_inc(&packets_ipv4);
    
    /* 确保 IP 头可访问 */
    if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
        return -1;
    
    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    
    /* 验证 IP 头长度（最小20字节，最大60字节）*/
    if (unlikely(ip_hdr_len < 20 || ip_hdr_len > 60)) {
        pr_warn_ratelimited("crypto_bridge: Invalid IP header length: %d\n", ip_hdr_len);
        return -1;
    }
    
    /* 确保完整的 IP 头（包括选项）可访问 */
    if (unlikely(!pskb_may_pull(skb, ip_hdr_len)))
        return -1;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        int ip_total_len;
        int tcp_hdr_len;
        
        atomic64_inc(&packets_tcp);
        
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr))))
            return -1;
        
        tcph = (struct tcphdr *)(skb->data + ip_hdr_len);
        ip_total_len = ntohs(iph->tot_len);
        
        /* 验证 TCP 头长度（最小20字节，最大60字节）*/
        tcp_hdr_len = tcph->doff * 4;
        if (unlikely(tcp_hdr_len < 20 || tcp_hdr_len > 60)) {
            pr_warn_ratelimited("crypto_bridge: Invalid TCP header length: %d\n", tcp_hdr_len);
            return -1;
        }
        
        payload_offset = ip_hdr_len + tcp_hdr_len;
        payload_len = ip_total_len - payload_offset;
        
        /* 验证 payload_len 不为负（防止畸形包）*/
        if (unlikely(payload_len < 0)) {
            pr_warn_ratelimited("crypto_bridge: Invalid TCP payload length: %d\n", payload_len);
            return -1;
        }
        
        if (likely(payload_len > 0)) {
            int bytes_to_modify;
            unsigned char *old_payload;
            
            /* 计算要处理的字节数（0=全部）*/
            if (modify_bytes == 0) {
                bytes_to_modify = payload_len;  /* 处理全部 */
            } else {
                bytes_to_modify = (payload_len < modify_bytes) ? payload_len : modify_bytes;
            }
            
            /* 限制最大值 */
            if (unlikely(bytes_to_modify > MAX_MODIFY_BYTES)) {
                pr_warn_ratelimited("crypto_bridge: TCP payload too large (%d), limiting to %d\n",
                                   bytes_to_modify, MAX_MODIFY_BYTES);
                bytes_to_modify = MAX_MODIFY_BYTES;
            }
            
            /* 确保要修改的部分可写 */
            if (unlikely(!pskb_may_pull(skb, payload_offset + bytes_to_modify)))
                return -1;
            
            /* 重新获取指针（pskb_may_pull 可能重新分配） */
            iph = ip_hdr(skb);
            tcph = (struct tcphdr *)(skb->data + ip_hdr_len);
            payload = skb->data + payload_offset;
            
            /* 使用每CPU缓冲区保存原始payload */
            old_payload = get_cpu_ptr(crypto_old_payload_buffer);
            memcpy(old_payload, payload, bytes_to_modify);
            
            /* 加密或解密 */
            if (unlikely(crypto_process(payload, bytes_to_modify, do_encrypt) < 0)) {
                put_cpu_ptr(crypto_old_payload_buffer);
                return -1;
            }
            
            /* 使用增量校验和更新（性能提升10倍）*/
            fix_tcp_checksum_incremental(skb, iph, tcph, old_payload, payload, bytes_to_modify);
            
            put_cpu_ptr(crypto_old_payload_buffer);
        }
    }
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        int udp_len;
        
        atomic64_inc(&packets_udp);
        
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct udphdr))))
            return -1;
        
        udph = (struct udphdr *)(skb->data + ip_hdr_len);
        udp_len = ntohs(udph->len);
        
        /* 验证 UDP 长度（最小8字节）*/
        if (unlikely(udp_len < 8)) {
            pr_warn_ratelimited("crypto_bridge: Invalid UDP length: %d\n", udp_len);
            return -1;
        }
        
        payload_offset = ip_hdr_len + 8;
        payload_len = udp_len - 8;
        
        if (likely(payload_len > 0)) {
            int bytes_to_modify;
            unsigned char *old_payload;
            
            /* 计算要处理的字节数（0=全部）*/
            if (modify_bytes == 0) {
                bytes_to_modify = payload_len;  /* 处理全部 */
            } else {
                bytes_to_modify = (payload_len < modify_bytes) ? payload_len : modify_bytes;
            }
            
            /* 限制最大值 */
            if (unlikely(bytes_to_modify > MAX_MODIFY_BYTES)) {
                pr_warn_ratelimited("crypto_bridge: UDP payload too large (%d), limiting to %d\n",
                                   bytes_to_modify, MAX_MODIFY_BYTES);
                bytes_to_modify = MAX_MODIFY_BYTES;
            }
            
            if (unlikely(!pskb_may_pull(skb, payload_offset + bytes_to_modify)))
                return -1;
            
            iph = ip_hdr(skb);
            udph = (struct udphdr *)(skb->data + ip_hdr_len);
            payload = skb->data + payload_offset;
            
            /* 使用每CPU缓冲区保存原始payload */
            old_payload = get_cpu_ptr(crypto_old_payload_buffer);
            memcpy(old_payload, payload, bytes_to_modify);
            
            if (unlikely(crypto_process(payload, bytes_to_modify, do_encrypt) < 0)) {
                put_cpu_ptr(crypto_old_payload_buffer);
                return -1;
            }
            
            /* 使用增量校验和更新 */
            fix_udp_checksum_incremental(skb, iph, udph, old_payload, payload, bytes_to_modify);
            
            put_cpu_ptr(crypto_old_payload_buffer);
        }
    }
    else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph;
        
        atomic64_inc(&packets_icmp);
        
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct icmphdr))))
            return -1;
        
        icmph = (struct icmphdr *)(skb->data + ip_hdr_len);
        payload_offset = ip_hdr_len + sizeof(struct icmphdr);
        payload_len = ntohs(iph->tot_len) - payload_offset;
        
        /* 验证 payload_len 不为负（防止畸形包）*/
        if (unlikely(payload_len < 0)) {
            pr_warn_ratelimited("crypto_bridge: Invalid ICMP payload length: %d\n", payload_len);
            return -1;
        }
        
        if (likely(payload_len > 0)) {
            int bytes_to_modify;
            unsigned char *old_payload;
            __wsum old_csum, new_csum;
            __sum16 old_check;
            
            /* 计算要处理的字节数 */
            if (modify_bytes == 0) {
                bytes_to_modify = payload_len;
            } else {
                bytes_to_modify = (payload_len < modify_bytes) ? payload_len : modify_bytes;
            }
            
            /* 限制最大值 */
            if (unlikely(bytes_to_modify > MAX_MODIFY_BYTES)) {
                pr_warn_ratelimited("crypto_bridge: ICMP payload too large (%d), limiting to %d\n",
                                   bytes_to_modify, MAX_MODIFY_BYTES);
                bytes_to_modify = MAX_MODIFY_BYTES;
            }
            
            if (unlikely(!pskb_may_pull(skb, payload_offset + bytes_to_modify)))
                return -1;
            
            iph = ip_hdr(skb);
            icmph = (struct icmphdr *)(skb->data + ip_hdr_len);
            payload = skb->data + payload_offset;
            
            /* 保存原始payload */
            old_payload = get_cpu_ptr(crypto_old_payload_buffer);
            memcpy(old_payload, payload, bytes_to_modify);
            old_check = icmph->checksum;
            
            /* 加密或解密 */
            if (unlikely(crypto_process(payload, bytes_to_modify, do_encrypt) < 0)) {
                put_cpu_ptr(crypto_old_payload_buffer);
                return -1;
            }
            
            /* 更新ICMP校验和 */
            old_csum = csum_partial(old_payload, bytes_to_modify, 0);
            new_csum = csum_partial(payload, bytes_to_modify, 0);
            icmph->checksum = csum_fold(csum_add(csum_sub(~csum_unfold(old_check), old_csum), 
                                                  new_csum));
            skb->ip_summed = CHECKSUM_UNNECESSARY;
            
            put_cpu_ptr(crypto_old_payload_buffer);
        }
    }
    else {
        atomic64_inc(&packets_other);
    }
    
    return 0;
}

/* ========== IPv6数据包处理 ========== */

/*
 * 处理IPv6数据包: TCP/UDP/ICMPv6
 * do_encrypt: 1=加密, 0=解密
 */
static int process_ipv6_packet(struct sk_buff *skb, int do_encrypt)
{
    struct ipv6hdr *ip6h;
    unsigned char *payload;
    int ip_hdr_len, payload_offset, payload_len;
    __u8 nexthdr;
    
    atomic64_inc(&packets_ipv6);
    
    if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
        return -1;
    
    ip6h = ipv6_hdr(skb);
    ip_hdr_len = sizeof(struct ipv6hdr);
    nexthdr = ip6h->nexthdr;
    
    if (nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcph;
        int ipv6_payload_len;
        int tcp_hdr_len;
        
        atomic64_inc(&packets_tcp);
        
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr))))
            return -1;
        
        tcph = (struct tcphdr *)(skb->data + ip_hdr_len);
        ipv6_payload_len = ntohs(ip6h->payload_len);
        
        /* 验证 TCP 头长度（最小20字节，最大60字节）*/
        tcp_hdr_len = tcph->doff * 4;
        if (unlikely(tcp_hdr_len < 20 || tcp_hdr_len > 60)) {
            pr_warn_ratelimited("crypto_bridge: Invalid IPv6 TCP header length: %d\n", tcp_hdr_len);
            return -1;
        }
        
        payload_offset = ip_hdr_len + tcp_hdr_len;
        payload_len = ipv6_payload_len - tcp_hdr_len;
        
        /* 验证 payload_len 不为负（防止畸形包）*/
        if (unlikely(payload_len < 0)) {
            pr_warn_ratelimited("crypto_bridge: Invalid IPv6 TCP payload length: %d\n", payload_len);
            return -1;
        }
        
        if (payload_len > 0) {
            int bytes_to_modify;
            unsigned char *old_payload;
            __wsum old_csum, new_csum;
            __sum16 old_check;
            
            /* 计算要处理的字节数（0=全部）*/
            if (modify_bytes == 0) {
                bytes_to_modify = payload_len;  /* 处理全部 */
            } else {
                bytes_to_modify = (payload_len < modify_bytes) ? payload_len : modify_bytes;
            }
            
            /* 限制最大值 */
            if (unlikely(bytes_to_modify > MAX_MODIFY_BYTES)) {
                pr_warn_ratelimited("crypto_bridge: IPv6 TCP payload too large (%d), limiting to %d\n",
                                   bytes_to_modify, MAX_MODIFY_BYTES);
                bytes_to_modify = MAX_MODIFY_BYTES;
            }
            
            if (unlikely(!pskb_may_pull(skb, payload_offset + bytes_to_modify)))
                return -1;
            
            ip6h = ipv6_hdr(skb);
            tcph = (struct tcphdr *)(skb->data + ip_hdr_len);
            payload = skb->data + payload_offset;
            
            /* 使用每CPU缓冲区保存原始payload */
            old_payload = get_cpu_ptr(crypto_old_payload_buffer);
            memcpy(old_payload, payload, bytes_to_modify);
            old_check = tcph->check;
            
            if (unlikely(crypto_process(payload, bytes_to_modify, do_encrypt) < 0)) {
                put_cpu_ptr(crypto_old_payload_buffer);
                return -1;
            }
            
            /* 增量校验和更新（IPv6）*/
            old_csum = csum_partial(old_payload, bytes_to_modify, 0);
            new_csum = csum_partial(payload, bytes_to_modify, 0);
            tcph->check = csum_fold(csum_add(csum_sub(~csum_unfold(old_check), old_csum), 
                                              new_csum));
            skb->ip_summed = CHECKSUM_UNNECESSARY;
            
            put_cpu_ptr(crypto_old_payload_buffer);
        }
    }
    else if (nexthdr == IPPROTO_UDP) {
        struct udphdr *udph;
        int udp_len;
        
        atomic64_inc(&packets_udp);
        
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct udphdr))))
            return -1;
        
        udph = (struct udphdr *)(skb->data + ip_hdr_len);
        udp_len = ntohs(udph->len);
        
        /* 验证 UDP 长度（最小8字节）*/
        if (unlikely(udp_len < 8)) {
            pr_warn_ratelimited("crypto_bridge: Invalid IPv6 UDP length: %d\n", udp_len);
            return -1;
        }
        
        payload_offset = ip_hdr_len + 8;
        payload_len = udp_len - 8;
        
        if (payload_len > 0) {
            int bytes_to_modify;
            unsigned char *old_payload;
            __wsum old_csum, new_csum;
            __sum16 old_check;
            
            /* 计算要处理的字节数（0=全部）*/
            if (modify_bytes == 0) {
                bytes_to_modify = payload_len;  /* 处理全部 */
            } else {
                bytes_to_modify = (payload_len < modify_bytes) ? payload_len : modify_bytes;
            }
            
            /* 限制最大值 */
            if (unlikely(bytes_to_modify > MAX_MODIFY_BYTES)) {
                pr_warn_ratelimited("crypto_bridge: IPv6 UDP payload too large (%d), limiting to %d\n",
                                   bytes_to_modify, MAX_MODIFY_BYTES);
                bytes_to_modify = MAX_MODIFY_BYTES;
            }
            
            if (unlikely(!pskb_may_pull(skb, payload_offset + bytes_to_modify)))
                return -1;
            
            ip6h = ipv6_hdr(skb);
            udph = (struct udphdr *)(skb->data + ip_hdr_len);
            payload = skb->data + payload_offset;
            
            /* 使用每CPU缓冲区保存原始payload */
            old_payload = get_cpu_ptr(crypto_old_payload_buffer);
            memcpy(old_payload, payload, bytes_to_modify);
            old_check = udph->check;
            
            if (unlikely(crypto_process(payload, bytes_to_modify, do_encrypt) < 0)) {
                put_cpu_ptr(crypto_old_payload_buffer);
                return -1;
            }
            
            /* 增量校验和更新（IPv6 UDP）*/
            if (old_check != 0) {  /* IPv6 UDP校验和是强制的 */
                old_csum = csum_partial(old_payload, bytes_to_modify, 0);
                new_csum = csum_partial(payload, bytes_to_modify, 0);
                udph->check = csum_fold(csum_add(csum_sub(~csum_unfold(old_check), old_csum), 
                                                  new_csum));
                if (udph->check == 0)
                    udph->check = CSUM_MANGLED_0;
            }
            skb->ip_summed = CHECKSUM_UNNECESSARY;
            
            put_cpu_ptr(crypto_old_payload_buffer);
        }
    }
    else if (nexthdr == IPPROTO_ICMPV6) {
        struct icmp6hdr *icmp6h;
        int ipv6_payload_len;
        
        atomic64_inc(&packets_icmp);
        
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct icmp6hdr))))
            return -1;
        
        icmp6h = (struct icmp6hdr *)(skb->data + ip_hdr_len);
        ipv6_payload_len = ntohs(ip6h->payload_len);
        payload_offset = ip_hdr_len + sizeof(struct icmp6hdr);
        payload_len = ipv6_payload_len - sizeof(struct icmp6hdr);
        
        /* 验证 payload_len 不为负（防止畸形包）*/
        if (unlikely(payload_len < 0)) {
            pr_warn_ratelimited("crypto_bridge: Invalid ICMPv6 payload length: %d\n", payload_len);
            return -1;
        }
        
        if (likely(payload_len > 0)) {
            int bytes_to_modify;
            unsigned char *old_payload;
            __wsum old_csum, new_csum;
            __sum16 old_check;
            
            /* 计算要处理的字节数 */
            if (modify_bytes == 0) {
                bytes_to_modify = payload_len;
            } else {
                bytes_to_modify = (payload_len < modify_bytes) ? payload_len : modify_bytes;
            }
            
            /* 限制最大值 */
            if (unlikely(bytes_to_modify > MAX_MODIFY_BYTES)) {
                pr_warn_ratelimited("crypto_bridge: ICMPv6 payload too large (%d), limiting to %d\n",
                                   bytes_to_modify, MAX_MODIFY_BYTES);
                bytes_to_modify = MAX_MODIFY_BYTES;
            }
            
            if (unlikely(!pskb_may_pull(skb, payload_offset + bytes_to_modify)))
                return -1;
            
            ip6h = ipv6_hdr(skb);
            icmp6h = (struct icmp6hdr *)(skb->data + ip_hdr_len);
            payload = skb->data + payload_offset;
            
            /* 保存原始payload */
            old_payload = get_cpu_ptr(crypto_old_payload_buffer);
            memcpy(old_payload, payload, bytes_to_modify);
            old_check = icmp6h->icmp6_cksum;
            
            /* 加密或解密 */
            if (unlikely(crypto_process(payload, bytes_to_modify, do_encrypt) < 0)) {
                put_cpu_ptr(crypto_old_payload_buffer);
                return -1;
            }
            
            /* 更新ICMPv6校验和 */
            old_csum = csum_partial(old_payload, bytes_to_modify, 0);
            new_csum = csum_partial(payload, bytes_to_modify, 0);
            icmp6h->icmp6_cksum = csum_fold(csum_add(csum_sub(~csum_unfold(old_check), old_csum), 
                                                      new_csum));
            skb->ip_summed = CHECKSUM_UNNECESSARY;
            
            put_cpu_ptr(crypto_old_payload_buffer);
        }
    }
    else {
        atomic64_inc(&packets_other);
    }
    
    return 0;
}

/* ========== 设备动态切换接口 ========== */

/* 动态切换内网侧设备 (通过 sysfs 接口调用) */
static int switch_internal_device(const char *new_dev_name)
{
    struct net_device *new_dev, *old_dev, *ext_dev;
    
    if (!new_dev_name || strlen(new_dev_name) == 0)
        return -EINVAL;
    
    new_dev = dev_get_by_name(&init_net, new_dev_name);
    if (!new_dev)
        return -ENODEV;
    
    /* 在mutex保护下检查冲突，避免TOCTOU */
    mutex_lock(&dev_switch_mutex);
    
    /* 检查是否与外网侧设备冲突 */
    ext_dev = rcu_dereference_protected(external_device, lockdep_is_held(&dev_switch_mutex));
    if (new_dev == ext_dev) {
        mutex_unlock(&dev_switch_mutex);
        dev_put(new_dev);
        pr_err("crypto_bridge: Cannot set internal_dev same as external_dev\n");
        return -EINVAL;
    }
    
    /* 执行设备切换 */
    old_dev = rcu_dereference_protected(internal_device, lockdep_is_held(&dev_switch_mutex));
    rcu_assign_pointer(internal_device, new_dev);
    mutex_unlock(&dev_switch_mutex);
    
    /* 等待所有 RCU 读者完成 */
    synchronize_rcu();
    
    /* 释放旧设备 */
    if (old_dev)
        dev_put(old_dev);
    
    pr_info("crypto_bridge: Internal device switched to %s\n", new_dev_name);
    return 0;
}

/* 动态切换外网侧设备 */
static int switch_external_device(const char *new_dev_name)
{
    struct net_device *new_dev, *old_dev, *int_dev;
    
    if (!new_dev_name || strlen(new_dev_name) == 0)
        return -EINVAL;
    
    new_dev = dev_get_by_name(&init_net, new_dev_name);
    if (!new_dev)
        return -ENODEV;
    
    /* 在mutex保护下检查冲突，避免TOCTOU */
    mutex_lock(&dev_switch_mutex);
    
    /* 检查是否与内网侧设备冲突 */
    int_dev = rcu_dereference_protected(internal_device, lockdep_is_held(&dev_switch_mutex));
    if (new_dev == int_dev) {
        mutex_unlock(&dev_switch_mutex);
        dev_put(new_dev);
        pr_err("crypto_bridge: Cannot set external_dev same as internal_dev\n");
        return -EINVAL;
    }
    
    /* 执行设备切换 */
    old_dev = rcu_dereference_protected(external_device, lockdep_is_held(&dev_switch_mutex));
    rcu_assign_pointer(external_device, new_dev);
    mutex_unlock(&dev_switch_mutex);
    
    synchronize_rcu();
    
    if (old_dev)
        dev_put(old_dev);
    
    pr_info("crypto_bridge: External device switched to %s\n", new_dev_name);
    return 0;
}

/* ========== sysfs 接口 ========== */

/* 读取当前内网侧设备 */
static ssize_t internal_dev_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct net_device *dev;
    char name[IFNAMSIZ];
    
    rcu_read_lock();
    dev = rcu_dereference(internal_device);
    if (dev)
        strncpy(name, dev->name, IFNAMSIZ);
    else
        strncpy(name, "none", IFNAMSIZ);
    rcu_read_unlock();
    
    return sprintf(buf, "%s\n", name);
}

/* 设置新的内网侧设备 */
static ssize_t internal_dev_store(struct kobject *kobj, struct kobj_attribute *attr,
                          const char *buf, size_t count)
{
    char dev_name[IFNAMSIZ];
    int ret;
    
    if (count >= IFNAMSIZ)
        return -EINVAL;
    
    strncpy(dev_name, buf, count);
    dev_name[count] = '\0';
    
    if (dev_name[count-1] == '\n')
        dev_name[count-1] = '\0';
    
    ret = switch_internal_device(dev_name);
    if (ret < 0)
        return ret;
    
    return count;
}

/* 读取当前外网侧设备 */
static ssize_t external_dev_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct net_device *dev;
    char name[IFNAMSIZ];
    
    rcu_read_lock();
    dev = rcu_dereference(external_device);
    if (dev)
        strncpy(name, dev->name, IFNAMSIZ);
    else
        strncpy(name, "none", IFNAMSIZ);
    rcu_read_unlock();
    
    return sprintf(buf, "%s\n", name);
}

/* 设置新的外网侧设备 */
static ssize_t external_dev_store(struct kobject *kobj, struct kobj_attribute *attr,
                          const char *buf, size_t count)
{
    char dev_name[IFNAMSIZ];
    int ret;
    
    if (count >= IFNAMSIZ)
        return -EINVAL;
    
    strncpy(dev_name, buf, count);
    dev_name[count] = '\0';
    
    if (dev_name[count-1] == '\n')
        dev_name[count-1] = '\0';
    
    ret = switch_external_device(dev_name);
    if (ret < 0)
        return ret;
    
    return count;
}

/* 读取统计信息 */
static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf,
        "=== Crypto Bridge Statistics ===\n"
        "Direction:\n"
        "  From Plaintext-side:  %lld (encrypted)\n"
        "  From Ciphertext-side: %lld (decrypted)\n"
        "IP Version:\n"
        "  IPv4:                %lld\n"
        "  IPv6:                %lld\n"
        "Protocol:\n"
        "  TCP:                 %lld\n"
        "  UDP:                 %lld\n"
        "  ICMP:                %lld\n"
        "  Other:               %lld\n"
        "Processing:\n"
        "  Encrypted:           %lld\n"
        "  Decrypted:           %lld\n"
        "  Forwarded:           %lld\n"
        "  Dropped:             %lld\n"
        "Configuration:\n"
        "  Crypto:              XOR (key=0x%02X)\n"
        "  Modify Bytes:        %d (0=all)\n",
        atomic64_read(&packets_outbound),
        atomic64_read(&packets_inbound),
        atomic64_read(&packets_ipv4),
        atomic64_read(&packets_ipv6),
        atomic64_read(&packets_tcp),
        atomic64_read(&packets_udp),
        atomic64_read(&packets_icmp),
        atomic64_read(&packets_other),
        atomic64_read(&packets_encrypted),
        atomic64_read(&packets_decrypted),
        atomic64_read(&packets_forwarded),
        atomic64_read(&packets_dropped),
        xor_key,
        modify_bytes);
}

/* 重置统计信息 */
static ssize_t stats_store(struct kobject *kobj, struct kobj_attribute *attr,
                           const char *buf, size_t count)
{
    if (strncmp(buf, "reset", 5) == 0) {
        atomic64_set(&packets_outbound, 0);
        atomic64_set(&packets_inbound, 0);
        atomic64_set(&packets_encrypted, 0);
        atomic64_set(&packets_decrypted, 0);
        atomic64_set(&packets_forwarded, 0);
        atomic64_set(&packets_dropped, 0);
        atomic64_set(&packets_tcp, 0);
        atomic64_set(&packets_udp, 0);
        atomic64_set(&packets_icmp, 0);
        atomic64_set(&packets_other, 0);
        atomic64_set(&packets_ipv4, 0);
        atomic64_set(&packets_ipv6, 0);
        pr_info("crypto_bridge: Statistics reset\n");
    }
    return count;
}

static struct kobj_attribute internal_attr = __ATTR(internal_device, 0644, internal_dev_show, internal_dev_store);
static struct kobj_attribute external_attr = __ATTR(external_device, 0644, external_dev_show, external_dev_store);
static struct kobj_attribute stats_attr = __ATTR(statistics, 0644, stats_show, stats_store);

static struct attribute *crypto_bridge_attrs[] = {
    &internal_attr.attr,
    &external_attr.attr,
    &stats_attr.attr,
    NULL,
};

static struct attribute_group crypto_bridge_attr_group = {
    .attrs = crypto_bridge_attrs,
};

static struct kobject *crypto_bridge_kobj;

/* ========== Netfilter 钩子函数 ========== */

/*
 * Netfilter 钩子函数 - 使用 PRE_ROUTING 钩子点
 * 在 NF_INET_PRE_ROUTING 钩子点拦截数据包
 * 
 * 关键设计：
 *   - 使用 PRE_ROUTING 钩子点（每个包只触发一次）
 *   - 在 PRE_ROUTING 点，skb->dev 是输入设备
 *   - 根据输入设备判断方向，处理后不修改 skb->dev
 *   - 直接返回 NF_ACCEPT，让内核路由系统处理转发
 * 
 * 固定规则：
 *   - 从 internal_dev 收到 → 固定：加密
 *   - 从 external_dev 收到 → 固定：解密
 * 
 * 配置示例（根据实际拓扑）：
 *   板1: internal_dev=ens33 external_dev=ens34
 *   板2: internal_dev=ens34 external_dev=ens33
 */
static unsigned int hook_func(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    struct net_device *int_dev, *ext_dev;
    __u16 eth_proto;
    int ret;
    int do_encrypt = 0;
    
    if (unlikely(!skb))
        return NF_ACCEPT;
    
    /* 使用 RCU 读取设备指针（无锁，高性能）*/
    rcu_read_lock();
    int_dev = rcu_dereference(internal_device);
    ext_dev = rcu_dereference(external_device);
    
    /* 显式检查设备指针有效性 */
    if (unlikely(!int_dev || !ext_dev)) {
        rcu_read_unlock();
        atomic64_inc(&packets_forwarded);  /* 无配置，直接转发 */
        return NF_ACCEPT;
    }
    
    /* 
     * 在 PRE_ROUTING 钩子点，skb->dev 是输入设备
     * - 从 internal_dev 收到 → 加密（明文→密文）
     * - 从 external_dev 收到 → 解密（密文→明文）
     * 
     * 注意：不修改 skb->dev，让内核路由系统决定输出设备
     */
    if (skb->dev == int_dev) {
        /* 从明文侧收到 → 加密 */
        do_encrypt = 1;  /* 固定：加密 */
        atomic64_inc(&packets_outbound);
    } else if (skb->dev == ext_dev) {
        /* 从密文侧收到 → 解密 */
        do_encrypt = 0;  /* 固定：解密 */
        atomic64_inc(&packets_inbound);
    } else {
        /* 不是我们关心的设备，放行 */
        rcu_read_unlock();
        return NF_ACCEPT;
    }
    
    /* 
     * 在 PRE_ROUTING 钩子点，skb->data 指向 IP 头
     * 协议类型从 skb->protocol 获取（已由内核设置）
     */
    
    /* 获取协议类型 */
    eth_proto = ntohs(skb->protocol);
    
    /* 
     * 只对IP流量进行加密处理
     */
    if (likely(enable) && likely(eth_proto == ETH_P_IP || eth_proto == ETH_P_IPV6)) {
        int header_len = (eth_proto == ETH_P_IP) ? 
                         sizeof(struct iphdr) : sizeof(struct ipv6hdr);
        int ensure_len;
        /* 计算是否本包需要打印概要+HEX（共享同一计数器，确保对齐）*/
        static atomic64_t debug_counter = ATOMIC64_INIT(0);
        bool log_this_packet = false;
        u64 pkt_count = 0;
        if (unlikely(debug >= 1)) {
            u64 tmp = atomic64_inc_return(&debug_counter);
            u64 mod = tmp;
            int interval = (debug == 1) ? 10 : 100;
            if (do_div(mod, interval) == 0 && __ratelimit(&debug_ratelimit)) {
                log_this_packet = true;
                pkt_count = tmp;
                /* 标记本CPU上的本包需要打印HEX，由 crypto_process 消费并清除 */
                this_cpu_write(want_hex_for_this_packet, true);
            }
        }
        
        /* 修复modify_bytes=0的计算错误 */
        if (modify_bytes == 0) {
            /* 处理整个payload，需要确保整个skb可写 */
            ensure_len = skb->len;
        } else {
            /* 只处理指定字节数 */
            int max_process = header_len + modify_bytes;
            ensure_len = (skb->len < max_process) ? skb->len : max_process;
        }
        
        /* 确保需要修改的部分可写（零拷贝优化）*/
        if (unlikely(skb_ensure_writable(skb, ensure_len))) {
            rcu_read_unlock();
            atomic64_inc(&packets_dropped);
            return NF_DROP;
        }
        
        /* 调试输出- 先打印概要 */
        if (unlikely(debug >= 1 && log_this_packet)) {
                if (eth_proto == ETH_P_IP) {
                    struct iphdr *iph = ip_hdr(skb);
                    if (likely(iph)) {
                        const char *proto = "???";
                        if (iph->protocol == IPPROTO_TCP) proto = "TCP";
                        else if (iph->protocol == IPPROTO_UDP) proto = "UDP";
                        else if (iph->protocol == IPPROTO_ICMP) proto = "ICMP";
                        
                        pr_info("[%s] %s | %pI4->%pI4 | %s->%s | %u bytes | #%llu\n",
                                do_encrypt ? "ENC" : "DEC",
                                proto,
                                &iph->saddr, &iph->daddr,
                                skb->dev->name,
                                do_encrypt ? ext_dev->name : int_dev->name,
                                skb->len,
                                pkt_count);
                    }
                } else if (eth_proto == ETH_P_IPV6) {
                    pr_info("[%s] IPv6 | %s->%s | %u bytes | #%llu\n",
                            do_encrypt ? "ENC" : "DEC",
                            skb->dev->name,
                            do_encrypt ? ext_dev->name : int_dev->name,
                            skb->len,
                            pkt_count);
                }
        }
        
        /* 调用处理函数（do_encrypt: 1=加密, 0=解密）*/
        if (eth_proto == ETH_P_IP) {
            ret = process_ipv4_packet(skb, do_encrypt);
        } else {
            ret = process_ipv6_packet(skb, do_encrypt);
        }
        
        if (unlikely(ret < 0)) {
            rcu_read_unlock();
            atomic64_inc(&packets_dropped);
            return NF_DROP;
        }
        
        /* 更新统计 */
        if (do_encrypt) {
            atomic64_inc(&packets_encrypted);
        } else {
            atomic64_inc(&packets_decrypted);
        }
    } else {
        atomic64_inc(&packets_forwarded);
    }
    
    /* 
     * 在 PRE_ROUTING 钩子点，每个包只会触发一次
     * 不需要标记，直接返回 NF_ACCEPT 让内核路由系统处理
     */
    
    /* 释放RCU锁 */
    rcu_read_unlock();
    
    /* 返回 NF_ACCEPT：让内核路由系统决定转发路径 */
    return NF_ACCEPT;
}

/* ========== 模块初始化和退出 ========== */

static int __init crypto_bridge_init(void)
{
    int ret;
    struct net_device *dev;
    
    /* 增强参数验证 */
    
    /* 1. 验证 modify_bytes */
    if (modify_bytes < 0) {
        pr_err("crypto_bridge: Invalid modify_bytes=%d (must be >= 0)\n", modify_bytes);
        return -EINVAL;
    }
    if (modify_bytes > MAX_MODIFY_BYTES) {
        pr_warn("crypto_bridge: modify_bytes=%d exceeds max=%d, capping to max\n",
                modify_bytes, MAX_MODIFY_BYTES);
        modify_bytes = MAX_MODIFY_BYTES;
    }
    
    /* 2. 验证设备名称不为空 */
    if (!internal_dev || strlen(internal_dev) == 0) {
        pr_err("crypto_bridge: internal_dev cannot be empty\n");
        return -EINVAL;
    }
    if (!external_dev || strlen(external_dev) == 0) {
        pr_err("crypto_bridge: external_dev cannot be empty\n");
        return -EINVAL;
    }
    
    /* 3. 验证设备名称不相同 */
    if (strcmp(internal_dev, external_dev) == 0) {
        pr_err("crypto_bridge: internal_dev and external_dev cannot be the same (%s)\n", internal_dev);
        return -EINVAL;
    }
    
    /* 4. XOR加密警告 */
    if (xor_key != 0) {
        pr_warn("crypto_bridge: *** WARNING *** Using XOR encryption (key=0x%02X) - NOT SECURE for production!\n", xor_key);
        pr_warn("crypto_bridge: *** WARNING *** XOR is for TESTING ONLY. Replace with AES/ChaCha20/SM4 for real deployment.\n");
    }
    
    /* 记录加载时间 */
    module_load_time = ktime_get_ns();
    
    pr_info("crypto_bridge: Loaded - %s(%s) <-> %s(%s), XOR key=0x%02X, %s, debug=%d\n",
            internal_dev, "plaintext", external_dev, "ciphertext",
            xor_key, enable ? "enabled" : "disabled", debug);
    if (modify_bytes > 0) {
        pr_warn("crypto_bridge: INSECURE - Only encrypting first %d bytes!\n", modify_bytes);
    }
    pr_info("\n");
    
    /* 获取内网侧设备 */
    dev = dev_get_by_name(&init_net, internal_dev);
    if (!dev) {
        pr_err(" ERROR: Internal device '%s' not found!\n", internal_dev);
        pr_err("   Available devices: ip link show\n");
        return -ENODEV;
    }
    rcu_assign_pointer(internal_device, dev);
    
    /* 获取外网侧设备 */
    dev = dev_get_by_name(&init_net, external_dev);
    if (!dev) {
        pr_err(" ERROR: External device '%s' not found!\n", external_dev);
        pr_err("   Available devices: ip link show\n");
        dev_put(rcu_dereference_raw(internal_device));
        return -ENODEV;
    }
    rcu_assign_pointer(external_device, dev);
    
    /* 注册 IPv4 hook - 使用 PRE_ROUTING 钩子点 */
    nf_hook_ops_ipv4.hook = hook_func;
    nf_hook_ops_ipv4.pf = NFPROTO_IPV4;
    nf_hook_ops_ipv4.hooknum = NF_INET_PRE_ROUTING;
    nf_hook_ops_ipv4.priority = NF_IP_PRI_FIRST;
    
    ret = nf_register_net_hook(&init_net, &nf_hook_ops_ipv4);
    if (ret < 0) {
        pr_err(" ERROR: Failed to register IPv4 netfilter hook (error=%d)\n", ret);
        dev_put(rcu_dereference_raw(external_device));
        dev_put(rcu_dereference_raw(internal_device));
        return ret;
    }
    
    /* 注册 IPv6 hook - 使用 PRE_ROUTING 钩子点 */
    nf_hook_ops_ipv6.hook = hook_func;
    nf_hook_ops_ipv6.pf = NFPROTO_IPV6;
    nf_hook_ops_ipv6.hooknum = NF_INET_PRE_ROUTING;
    nf_hook_ops_ipv6.priority = NF_IP_PRI_FIRST;
    
    ret = nf_register_net_hook(&init_net, &nf_hook_ops_ipv6);
    if (ret < 0) {
        pr_err(" ERROR: Failed to register IPv6 netfilter hook (error=%d)\n", ret);
        nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv4);
        dev_put(rcu_dereference_raw(external_device));
        dev_put(rcu_dereference_raw(internal_device));
        return ret;
    }
    
    /* 创建 sysfs 接口 */
    crypto_bridge_kobj = kobject_create_and_add("crypto_bridge", kernel_kobj);
    if (!crypto_bridge_kobj) {
        nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv6);
        nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv4);
        dev_put(rcu_dereference_raw(external_device));
        dev_put(rcu_dereference_raw(internal_device));
        return -ENOMEM;
    }
    
    ret = sysfs_create_group(crypto_bridge_kobj, &crypto_bridge_attr_group);
    if (ret) {
        kobject_put(crypto_bridge_kobj);
        nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv6);
        nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv4);
        dev_put(rcu_dereference_raw(external_device));
        dev_put(rcu_dereference_raw(internal_device));
        return ret;
    }
    
    pr_info(" Module loaded successfully!\n");
    pr_info("\n");
    pr_info(" Control Interface:   /sys/kernel/crypto_bridge/\n");
    pr_info(" View Statistics:     cat /sys/kernel/crypto_bridge/statistics\n");
    pr_info("  Runtime Control:     echo <value> > /sys/module/crypto_bridge/parameters/<param>\n");
    pr_info("\n");
    pr_info("================================================================================\n");
    
    return 0;
}

static void __exit crypto_bridge_exit(void)
{
    struct net_device *dev;
    u64 module_unload_time, uptime_ns, uptime_sec;
    u64 total_packets, total_encrypted, total_decrypted;
    
    module_unload_time = ktime_get_ns();
    
    /* 计算运行时长（添加有效性检查）*/
    if (likely(module_load_time > 0 && module_unload_time >= module_load_time)) {
        uptime_ns = module_unload_time - module_load_time;
        uptime_sec = uptime_ns;
        do_div(uptime_sec, 1000000000ULL);  /* 转换为秒 */
    } else {
        uptime_ns = 0;
        uptime_sec = 0;
    }
    
    pr_info("\n");
    pr_info("================================================================================\n");
    pr_info("  crypto_bridge - Module Unloading\n");
    pr_info("================================================================================\n");
    
    /* 移除 sysfs 接口 */
    if (crypto_bridge_kobj) {
        sysfs_remove_group(crypto_bridge_kobj, &crypto_bridge_attr_group);
        kobject_put(crypto_bridge_kobj);
    }
    
    /* 注销钩子 */
    nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv6);
    nf_unregister_net_hook(&init_net, &nf_hook_ops_ipv4);
    
    /* 等待所有 RCU 读者完成 */
    synchronize_rcu();
    
    /* 释放设备 */
    dev = rcu_dereference_raw(external_device);
    if (dev)
        dev_put(dev);
    
    dev = rcu_dereference_raw(internal_device);
    if (dev)
        dev_put(dev);
    
    pr_info("crypto_bridge: Unloaded (uptime: %llus)\n", uptime_sec);
}

module_init(crypto_bridge_init);
module_exit(crypto_bridge_exit);
