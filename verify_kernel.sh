#!/bin/bash
# OK113i 内核功能验证脚本
# 在开发板上运行，验证裁减后的内核是否正常

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
section() { echo -e "\n${GREEN}=== $* ===${NC}"; }

FAILED_TESTS=0

# ============================================
section "1. 系统基本信息"
# ============================================

echo "内核版本:"
uname -a
echo ""
echo "启动时间:"
uptime
echo ""
echo "CPU 信息:"
cat /proc/cpuinfo | grep -E "model|Hardware|Revision" | head -3

# ============================================
section "2. 网络功能测试 (关键)"
# ============================================

# 检查网络接口
if ifconfig -a | grep -q "eth0"; then
    pass "网卡 eth0 存在"
else
    fail "网卡 eth0 不存在"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

if ifconfig -a | grep -q "eth1"; then
    pass "网卡 eth1 存在"
else
    warn "网卡 eth1 不存在（如果你的板子只有一个网口，这是正常的）"
fi

# 检查网络连接
echo ""
echo "当前 IP 配置:"
ifconfig | grep -E "inet|eth" | grep -v inet6

# Ping 测试（如果已配置网络）
if ifconfig eth0 | grep -q "inet"; then
    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
    if [ -n "$GATEWAY" ]; then
        if ping -c 3 -W 2 "$GATEWAY" > /dev/null 2>&1; then
            pass "网络连接正常 (ping $GATEWAY)"
        else
            warn "无法 ping 通网关 $GATEWAY"
        fi
    fi
else
    warn "eth0 未配置 IP，跳过网络连通性测试"
fi

# ============================================
section "3. 内核模块支持测试 (关键)"
# ============================================

# 检查模块支持
if [ -f /proc/modules ]; then
    pass "内核模块支持已启用"
    echo "已加载的模块数: $(lsmod | tail -n +2 | wc -l)"
else
    fail "内核模块支持未启用"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# 检查模块加载是否被禁用
if [ -f /proc/sys/kernel/modules_disabled ]; then
    DISABLED=$(cat /proc/sys/kernel/modules_disabled)
    if [ "$DISABLED" = "0" ]; then
        pass "模块加载功能正常"
    else
        fail "模块加载已被禁用"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
fi

# 尝试加载一个内核模块（测试）
echo ""
echo "已加载的模块 (前 10 个):"
lsmod | head -11

# ============================================
section "4. Netfilter 支持测试 (crypto_bridge 必需)"
# ============================================

echo "检查 Netfilter 框架和相关模块..."
echo ""

NETFILTER_OK=0
NETFILTER_TOTAL=0

# === 基础 Netfilter 支持 ===
NETFILTER_TOTAL=$((NETFILTER_TOTAL + 1))
if [ -d /proc/net/netfilter ]; then
    pass "Netfilter 框架 (CONFIG_NETFILTER) 已启用"
    NETFILTER_OK=$((NETFILTER_OK + 1))
    echo "  可用钩子: $(ls /proc/net/netfilter/ | wc -l) 个"
else
    fail "Netfilter 框架未启用"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# === 连接跟踪 ===
NETFILTER_TOTAL=$((NETFILTER_TOTAL + 1))
if [ -f /proc/net/nf_conntrack ]; then
    pass "连接跟踪 (CONFIG_NF_CONNTRACK) 可用"
    NETFILTER_OK=$((NETFILTER_OK + 1))
    echo "  当前连接数: $(cat /proc/net/nf_conntrack 2>/dev/null | wc -l)"
else
    warn "连接跟踪未加载（可能需要手动 modprobe nf_conntrack）"
fi

# === Netfilter Xtables (iptables 规则匹配) ===
NETFILTER_TOTAL=$((NETFILTER_TOTAL + 1))
if dmesg | grep -qi "xt_\|x_tables" || lsmod | grep -q "x_tables"; then
    pass "Netfilter Xtables (CONFIG_NETFILTER_XTABLES) 已加载"
    NETFILTER_OK=$((NETFILTER_OK + 1))
else
    warn "Netfilter Xtables 未检测到"
fi

# === IPv4 Netfilter (iptables) ===
NETFILTER_TOTAL=$((NETFILTER_TOTAL + 1))
if command -v iptables > /dev/null 2>&1; then
    if iptables -L -n > /dev/null 2>&1; then
        pass "IPv4 Netfilter (CONFIG_IP_NF_IPTABLES) 功能正常"
        NETFILTER_OK=$((NETFILTER_OK + 1))
        echo "  当前规则数: $(iptables -L | grep -c "Chain")"
    else
        warn "iptables 命令存在但无法执行"
    fi
else
    warn "iptables 命令未安装"
fi

# === IPv4 NAT 支持 ===
NETFILTER_TOTAL=$((NETFILTER_TOTAL + 1))
if iptables -t nat -L -n > /dev/null 2>&1; then
    pass "IPv4 NAT (CONFIG_IP_NF_NAT) 支持可用"
    NETFILTER_OK=$((NETFILTER_OK + 1))
else
    warn "IPv4 NAT 表不可用"
fi

# === IP 转发 ===
NETFILTER_TOTAL=$((NETFILTER_TOTAL + 1))
IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$IP_FORWARD" = "1" ]; then
    pass "IP 转发 (ip_forward) 已启用"
    NETFILTER_OK=$((NETFILTER_OK + 1))
else
    fail "IP 转发未启用（crypto_bridge 必需！）"
    echo "  修复: echo 1 > /proc/sys/net/ipv4/ip_forward"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""
echo "Netfilter 功能完整性: $NETFILTER_OK / $NETFILTER_TOTAL"
if [ $NETFILTER_OK -ge 5 ]; then
    pass "✅ Netfilter 配置完整，crypto_bridge 可正常工作"
elif [ $NETFILTER_OK -ge 3 ]; then
    warn "⚠️ Netfilter 部分功能缺失，可能影响 crypto_bridge"
else
    fail "❌ Netfilter 配置不完整，crypto_bridge 无法正常工作"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# ============================================
section "5. 文件系统测试"
# ============================================

# 检查关键挂载点
if mount | grep -q "proc"; then
    pass "procfs 已挂载"
else
    fail "procfs 未挂载"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

if mount | grep -q "sysfs"; then
    pass "sysfs 已挂载"
else
    fail "sysfs 未挂载"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# 检查根文件系统
ROOT_FS=$(mount | grep "on / " | awk '{print $5}')
pass "根文件系统类型: $ROOT_FS"

echo ""
echo "存储使用情况:"
df -h | grep -E "Filesystem|/dev/"

# ============================================
section "6. 串口支持测试"
# ============================================

if dmesg | grep -q "serial\|ttyS"; then
    pass "串口驱动已加载"
    echo "串口设备:"
    ls -l /dev/ttyS* 2>/dev/null || echo "  (未找到 /dev/ttyS* 设备)"
else
    warn "未检测到串口"
fi

# ============================================
section "7. 存储设备测试"
# ============================================

echo "分区信息:"
cat /proc/partitions

# 检测 Flash 类型
if [ -e /dev/mmcblk0 ]; then
    pass "检测到 eMMC 存储"
    echo "eMMC 分区:"
    ls -l /dev/mmcblk0* 2>/dev/null | grep -v "mmcblk0$"
elif [ -e /dev/mtd0 ]; then
    pass "检测到 NAND Flash 存储"
    echo "MTD 分区:"
    cat /proc/mtd
else
    warn "未检测到 eMMC 或 NAND"
fi

# ============================================
section "8. 系统资源状态"
# ============================================

echo "内存使用:"
free -h

echo ""
echo "CPU 频率:"
cat /proc/cpuinfo | grep "MHz" | head -2 || echo "  (频率信息不可用)"

echo ""
echo "负载:"
cat /proc/loadavg

# ============================================
section "9. 裁减配置验证 (应该被禁用的功能)"
# ============================================

echo "检查以下功能是否已成功裁减..."
echo ""

TRIMMED_OK=0
TRIMMED_TOTAL=0

# === 音频子系统 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! dmesg | grep -qi "ALSA\|snd_\|soundcore" && ! lsmod | grep -q "snd"; then
    pass "音频子系统 (SOUND/ALSA) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "音频子系统仍然存在"
    dmesg | grep -i "snd\|sound" | head -2
fi

# === 视频/媒体子系统 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! dmesg | grep -qi "video\|v4l\|camera" && ! ls /dev/video* 2>/dev/null; then
    pass "视频/媒体子系统 (VIDEO_DEV) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "视频/媒体子系统仍然存在"
fi

# === 图形显示系统 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! dmesg | grep -qi "drm\|framebuffer\|fb0" && ! ls /dev/fb* 2>/dev/null; then
    pass "图形显示系统 (DRM/FB) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "图形显示系统仍然存在"
    ls -l /dev/fb* 2>/dev/null || echo "  (framebuffer 设备)"
fi

# === 输入设备 (键盘/鼠标/触摸屏) ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
INPUT_COUNT=$(ls /dev/input/event* 2>/dev/null | wc -l)
if [ "$INPUT_COUNT" -eq 0 ] || [ "$INPUT_COUNT" -le 2 ]; then
    pass "输入设备驱动 (KEYBOARD/MOUSE/TOUCHSCREEN) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "输入设备仍然较多: $INPUT_COUNT 个 /dev/input/event* 设备"
fi

# === HID 设备 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! lsmod | grep -qi "hid\|usbhid" && ! dmesg | grep -qi "HID.*device"; then
    pass "HID 设备支持 (HID) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "HID 设备支持仍然存在"
fi

# === 蓝牙 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! lsmod | grep -qi "bluetooth\|btusb\|bnep" && ! dmesg | grep -qi "bluetooth"; then
    pass "蓝牙子系统 (BT) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "蓝牙子系统仍然存在"
fi

# === 无线网络 (WiFi) ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! lsmod | grep -qi "wifi\|wlan\|80211\|cfg80211" && ! ifconfig -a | grep -q "wlan"; then
    pass "无线网络 (WLAN) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "无线网络仍然存在"
    ifconfig -a | grep wlan || echo "  (WiFi 模块已加载)"
fi

# === 调试功能 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! cat /proc/config.gz 2>/dev/null | gunzip | grep -q "^CONFIG_DEBUG_KERNEL=y"; then
    pass "内核调试功能 (DEBUG_KERNEL) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "内核调试功能仍然启用（会增加体积和开销）"
fi

# === 调试文件系统 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! mount | grep -q debugfs && [ ! -d /sys/kernel/debug ]; then
    pass "调试文件系统 (DEBUG_FS) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "调试文件系统仍然存在"
fi

# === Staging 驱动（实验性）===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! dmesg | grep -qi "staging" && ! lsmod | grep -qi "staging"; then
    pass "Staging 驱动 (STAGING) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "Staging 驱动仍然存在"
fi

# === 工业 I/O 传感器 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! lsmod | grep -qi "iio\|industrialio" && [ ! -d /sys/bus/iio 2>/dev/null ]; then
    pass "工业 I/O 子系统 (IIO) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "工业 I/O 子系统仍然存在"
fi

# === NFC 近场通信 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! lsmod | grep -qi "nfc" && ! dmesg | grep -qi "NFC"; then
    pass "NFC 近场通信 (NFC) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "NFC 子系统仍然存在"
fi

# === CAN 总线 ===
TRIMMED_TOTAL=$((TRIMMED_TOTAL + 1))
if ! lsmod | grep -qi "can" && ! ifconfig -a | grep -q "can"; then
    pass "CAN 总线 (CAN) 已裁减"
    TRIMMED_OK=$((TRIMMED_OK + 1))
else
    warn "CAN 总线仍然存在"
fi

echo ""
echo "裁减效果: $TRIMMED_OK / $TRIMMED_TOTAL 项成功裁减"

# 计算裁减百分比
TRIM_PERCENT=$(( (TRIMMED_OK * 100) / TRIMMED_TOTAL ))

if [ $TRIMMED_OK -ge 12 ]; then
    pass "✅ 裁减配置正确，大部分不需要的功能已移除 ($TRIM_PERCENT%)"
elif [ $TRIMMED_OK -ge 8 ]; then
    warn "⚠️ 部分裁减成功，仍有一些功能未移除 ($TRIM_PERCENT%)"
else
    fail "❌ 裁减不完全，请检查内核配置 ($TRIM_PERCENT%)"
fi

# ============================================
section "10. crypto_bridge 模块测试"
# ============================================

# 检查模块文件是否存在
if [ -f /root/crypto_bridge.ko ]; then
    echo "尝试加载 crypto_bridge 模块..."
    
    # 卸载旧的（如果有）
    rmmod crypto_bridge 2>/dev/null
    
    # 加载模块
    if insmod /root/crypto_bridge.ko 2>&1; then
        pass "crypto_bridge 模块加载成功"
        
        # 检查是否真的加载了
        if lsmod | grep -q crypto_bridge; then
            pass "crypto_bridge 模块已激活"
            echo "模块信息:"
            lsmod | grep crypto_bridge
            echo ""
            echo "最后 10 行内核日志:"
            dmesg | tail -10
        else
            fail "模块加载命令成功但未在 lsmod 中看到"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        fail "crypto_bridge 模块加载失败"
        echo "错误信息:"
        dmesg | tail -5
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    warn "crypto_bridge.ko 不存在于 /root/ (请先编译并上传模块)"
    echo "上传方法: scp crypto_bridge.ko root@开发板IP:/root/"
fi

# ============================================
section "测试总结"
# ============================================

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              OK113i 内核验证报告                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# 计算总体得分
TOTAL_CHECKS=$((NETFILTER_TOTAL + TRIMMED_TOTAL + 4))  # 4 = 网络/模块/文件系统/存储
PASSED_CHECKS=$((NETFILTER_OK + TRIMMED_OK))

# 检查关键功能
CRITICAL_OK=true
if [ $FAILED_TESTS -gt 0 ]; then
    CRITICAL_OK=false
fi

echo "📊 验证统计:"
echo "  ├─ 关键测试失败: $FAILED_TESTS 项"
echo "  ├─ Netfilter 完整性: $NETFILTER_OK / $NETFILTER_TOTAL"
echo "  ├─ 裁减配置效果: $TRIMMED_OK / $TRIMMED_TOTAL"
echo "  └─ 总体通过率: $(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))%"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo "✅ 核心功能验证:"
    echo "  ├─ 网络接口: ✓"
    echo "  ├─ 模块加载: ✓"
    echo "  ├─ Netfilter: ✓"
    echo "  ├─ IP 转发: ✓"
    echo "  └─ 文件系统: ✓"
    echo ""
    
    if [ $TRIMMED_OK -ge 6 ]; then
        echo "✅ 裁减效果: 优秀"
        echo "  大部分不需要的功能已成功移除"
    elif [ $TRIMMED_OK -ge 4 ]; then
        echo "⚠️ 裁减效果: 良好"
        echo "  部分功能已裁减，仍有改进空间"
    else
        echo "⚠️ 裁减效果: 一般"
        echo "  裁减不完全，内核体积较大"
    fi
    echo ""
    
    pass "🎉 所有关键测试通过！内核可用于 crypto_bridge 开发"
    echo ""
    echo "📝 下一步建议："
    echo "  1. 编译 crypto_bridge 模块: ./build_module.sh"
    echo "  2. 上传模块到开发板: scp crypto_bridge.ko root@板卡IP:/root/"
    echo "  3. 加载模块: insmod /root/crypto_bridge.ko"
    echo "  4. 查看日志: dmesg | tail -20"
    echo ""
    exit 0
else
    echo "❌ 关键功能缺失:"
    echo ""
    
    # 列出具体问题
    if ! ifconfig -a | grep -q "eth0"; then
        echo "  ✗ 网卡 eth0 不存在"
    fi
    if [ ! -f /proc/modules ]; then
        echo "  ✗ 内核模块支持未启用"
    fi
    if [ ! -d /proc/net/netfilter ]; then
        echo "  ✗ Netfilter 框架未启用"
    fi
    if [ "$IP_FORWARD" != "1" ]; then
        echo "  ✗ IP 转发未启用"
    fi
    
    echo ""
    fail "有 $FAILED_TESTS 项关键测试失败"
    echo ""
    echo "🔧 修复建议："
    echo "  1. 如果是 Netfilter/模块支持问题:"
    echo "     → 重新运行 ./trim_kernel.sh"
    echo "     → 确保选择了正确的配置"
    echo "     → 重新编译并更新内核"
    echo ""
    echo "  2. 如果是 IP 转发问题:"
    echo "     → echo 1 > /proc/sys/net/ipv4/ip_forward"
    echo ""
    echo "  3. 如果是网络接口问题:"
    echo "     → 检查设备树配置"
    echo "     → 确保网卡驱动已编译进内核"
    echo ""
    echo "  4. 如果问题严重，考虑恢复原始内核:"
    echo "     → dd if=/root/kernel_backup.img of=/dev/mmcblk0p4 conv=fsync"
    echo "     → reboot"
    echo ""
    exit 1
fi

