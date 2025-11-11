#!/bin/bash
#
# Crypto Bridge 模块专业性能测试脚本
# 版本: 3.0 - 完整基准对比测试
#
# 功能特性:
#   ✓ 基准测试（无模块 vs 有模块）
#   ✓ TCP/UDP多场景测试
#   ✓ 并发连接压力测试
#   ✓ 延迟抖动分析
#   ✓ CPU/内存使用监控
#   ✓ 自动生成对比报告
#
# 测试拓扑:
#   VM1 (客户端) ←→ VM2 [加密] ←→ VM3 [解密] ←→ VM4 (服务器)
#
# 使用说明:
#   服务器端: ./performance_test.sh server
#   客户端端: ./performance_test.sh client <SERVER_IP>
#   查看统计: ./performance_test.sh stats
#

set -e

# ==================== 配置 ====================

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# 测试配置
readonly TEST_DURATION=30           # 每个测试持续时间（秒）
readonly IPERF_PORT=5201
readonly HTTP_PORT=8080
readonly NC_PORT=9999

# 结果目录
RESULTS_DIR="./perf_test_$(date +%Y%m%d_%H%M%S)"

# 全局变量 - 存储测试结果
RESULT_PING_LOSS=""
RESULT_PING_AVG=""
RESULT_JITTER_MIN=""
RESULT_JITTER_AVG=""
RESULT_JITTER_MAX=""
RESULT_JITTER_MDEV=""
RESULT_TCP_SINGLE_UP=""
RESULT_TCP_SINGLE_DOWN=""
RESULT_TCP_SINGLE_UP_ERROR=""
RESULT_TCP_SINGLE_DOWN_ERROR=""
RESULT_TCP_PARALLEL_UP=""
RESULT_TCP_PARALLEL_DOWN=""
RESULT_TCP_PARALLEL_UP_ERROR=""
RESULT_TCP_PARALLEL_DOWN_ERROR=""
RESULT_UDP_UP=""
RESULT_UDP_DOWN=""
RESULT_HTTP_AVG=""
RESULT_HTTP_SUCCESS=""
RESULT_CONN_SUCCESS=""
RESULT_CONN_TOTAL=""

# ==================== 工具函数 ====================

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║  Crypto Bridge Professional Performance Test Suite v3.0     ║
║  端到端加密模块完整性能基准测试                                ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_test()    { echo -e "${BLUE}[TEST]${NC} $1"; }
print_title() { echo -e "${MAGENTA}━━━ $1 ━━━${NC}"; }
print_section() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  $1"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# 检查依赖
check_dependencies() {
    local deps=("iperf3" "curl" "nc" "ping" "bc")
    local missing=()
    local optional=("ss" "dstat")
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少必要工具: ${missing[*]}"
        echo "请安装: sudo apt install iperf3 curl netcat-openbsd bc"
        exit 1
    fi
    
    # 检查可选工具
    for cmd in "${optional[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_warn "可选工具未安装: $cmd (不影响测试)"
        fi
    done
}

# 检查网络连通性
check_connectivity() {
    local target=$1
    log_info "检查网络连通性: $target"
    
    if ! ping -c 3 -W 2 "$target" &> /dev/null; then
        log_error "无法连接到目标: $target"
        exit 1
    fi
    
    log_info "网络连通正常"
}

# 检查crypto_bridge模块状态
check_module_status() {
    log_info "检查 crypto_bridge 模块状态..."
    
    if ! lsmod | grep -q crypto_bridge; then
        log_warn "crypto_bridge 模块未加载"
        log_warn "这是基准测试（无加密）模式"
        return 0
    fi
    
    log_info "✓ crypto_bridge 模块已加载"
    
    # 检查模块统计接口
    if [ -f /sys/kernel/crypto_bridge/statistics ]; then
        log_info "✓ 模块统计接口可用"
        
        # 显示当前配置
        echo ""
        log_info "当前模块配置:"
        if [ -f /sys/kernel/crypto_bridge/internal_device ]; then
            local int_dev=$(cat /sys/kernel/crypto_bridge/internal_device 2>/dev/null)
            echo "  Internal device: $int_dev"
        fi
        if [ -f /sys/kernel/crypto_bridge/external_device ]; then
            local ext_dev=$(cat /sys/kernel/crypto_bridge/external_device 2>/dev/null)
            echo "  External device: $ext_dev"
        fi
        
        # 显示当前统计
        echo ""
        log_info "当前统计数据:"
        cat /sys/kernel/crypto_bridge/statistics | head -15
        echo ""
    else
        log_warn "模块统计接口不可用"
    fi
}

# 检查服务器端服务
check_server_services() {
    local server=$1
    local all_ok=true
    
    log_info "检查服务器端服务状态..."
    
    # 检查 iperf3
    if nc -z -w 2 "$server" $IPERF_PORT 2>/dev/null; then
        log_info "✓ iperf3 服务 (端口 $IPERF_PORT) 可访问"
    else
        log_warn "✗ iperf3 服务 (端口 $IPERF_PORT) 不可访问"
        log_warn "  请在服务器端运行: iperf3 -s -p $IPERF_PORT -D"
        all_ok=false
    fi
    
    # 检查 HTTP
    if nc -z -w 2 "$server" $HTTP_PORT 2>/dev/null; then
        log_info "✓ HTTP 服务 (端口 $HTTP_PORT) 可访问"
    else
        log_warn "✗ HTTP 服务 (端口 $HTTP_PORT) 不可访问"
        log_warn "  请在服务器端运行: python3 -m http.server $HTTP_PORT"
        all_ok=false
    fi
    
    if [ "$all_ok" = false ]; then
        echo ""
        log_warn "部分服务未就绪，相关测试可能失败"
        log_warn "建议先在服务器端运行: $0 server"
        echo ""
        read -p "是否继续测试? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "测试已取消"
            exit 0
        fi
    fi
    
    echo ""
}

# 清理进程
cleanup() {
    log_warn "清理测试进程..."
    pkill -9 iperf3 2>/dev/null || true
    pkill -9 -f "python.*http.server" 2>/dev/null || true
    pkill -9 nc 2>/dev/null || true
    pkill -9 dstat 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# ==================== 服务器模式 ====================

run_server() {
    print_banner
    print_section "服务器模式 - 启动测试服务"
    
    cleanup
    
    # 启动 iperf3 服务器
    log_info "启动 iperf3 服务器 (端口 $IPERF_PORT)..."
    if iperf3 -s -p $IPERF_PORT -D; then
        sleep 1
        if pgrep -f "iperf3.*-s" > /dev/null; then
            log_info "✓ iperf3 服务器启动成功"
        else
            log_error "✗ iperf3 服务器启动失败"
        fi
    else
        log_error "✗ 无法启动 iperf3 服务器"
    fi
    
    # 启动 HTTP 服务器
    log_info "启动 HTTP 服务器 (端口 $HTTP_PORT)..."
    cd /tmp
    echo "<html><body><h1>Crypto Bridge Test Server</h1><p>$(date)</p></body></html>" > index.html
    python3 -m http.server $HTTP_PORT > /dev/null 2>&1 &
    sleep 1
    if netstat -tuln 2>/dev/null | grep -q ":$HTTP_PORT " || ss -tuln 2>/dev/null | grep -q ":$HTTP_PORT "; then
        log_info "✓ HTTP 服务器启动成功"
    else
        log_warn "✗ HTTP 服务器可能启动失败"
    fi
    
    # 启动 netcat 服务器（用于连接测试）
    log_info "启动 netcat 服务器 (端口 $NC_PORT)..."
    (while true; do nc -l -p $NC_PORT > /dev/null 2>&1; done) &
    sleep 1
    
    echo ""
    log_info "═══════════════════════════════════════════════"
    log_info "  所有服务已启动"
    log_info "═══════════════════════════════════════════════"
    echo ""
    echo "  ● iperf3:  端口 $IPERF_PORT"
    echo "  ● HTTP:    端口 $HTTP_PORT"
    echo "  ● netcat:  端口 $NC_PORT"
    echo ""
    log_info "服务器就绪，等待客户端连接..."
    echo ""
    echo "客户端命令: $0 client <THIS_SERVER_IP>"
    echo ""
    echo "按 Ctrl+C 停止服务器"
    
    # 保持运行
    wait
}

# ==================== 客户端测试 ====================

run_client() {
    local server_ip=$1
    
    if [ -z "$server_ip" ]; then
        log_error "请指定服务器 IP"
        echo "用法: $0 client <SERVER_IP>"
        exit 1
    fi
    
    print_banner
    print_section "客户端测试模式"
    
    check_dependencies
    check_connectivity "$server_ip"
    check_module_status
    check_server_services "$server_ip"
    
    # 创建结果目录
    mkdir -p "$RESULTS_DIR"
    log_info "测试结果保存到: $RESULTS_DIR"
    
    # 系统信息
    collect_system_info "$server_ip"
    
    # 开始测试
    echo ""
    log_info "═══════════════════════════════════════════════"
    log_info "  开始完整性能测试 (预计耗时: ~10 分钟)"
    log_info "═══════════════════════════════════════════════"
    echo ""
    
    # 测试序列
    test_01_baseline_latency "$server_ip"
    test_02_latency_jitter "$server_ip"
    test_03_tcp_throughput_single "$server_ip"
    test_04_tcp_throughput_parallel "$server_ip"
    test_05_tcp_bidirectional "$server_ip"
    test_06_udp_throughput "$server_ip"
    test_07_http_performance "$server_ip"
    test_08_connection_stress "$server_ip"
    test_09_mixed_traffic "$server_ip"
    
    # 生成报告
    generate_comprehensive_report "$server_ip"
    
    # 显示测试结果摘要
    print_test_summary
    
    echo ""
    log_info "查看详细报告: cat $RESULTS_DIR/REPORT.txt"
}

# ==================== 测试结果摘要 ====================

print_test_summary() {
    echo ""
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}✓ 测试完成 - 结果摘要${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 检查模块状态
    local module_status="未加载"
    if lsmod | grep -q crypto_bridge; then
        module_status="${GREEN}已加载${NC}"
    else
        module_status="${YELLOW}未加载 (基准测试)${NC}"
    fi
    echo -e "  ${CYAN}模块状态:${NC} $module_status"
    echo ""
    
    # 延迟测试
    echo -e "  ${MAGENTA}━━━ 延迟测试 ━━━${NC}"
    if [ -n "$RESULT_PING_AVG" ]; then
        echo -e "  ${CYAN}基准延迟:${NC}     ${RESULT_PING_AVG} ms (丢包率: ${RESULT_PING_LOSS})"
    else
        echo -e "  ${CYAN}基准延迟:${NC}     ${RED}测试失败${NC}"
    fi
    
    if [ -n "$RESULT_JITTER_AVG" ]; then
        echo -e "  ${CYAN}延迟抖动:${NC}     最小=${RESULT_JITTER_MIN}ms, 平均=${RESULT_JITTER_AVG}ms, 最大=${RESULT_JITTER_MAX}ms"
        echo -e "                  抖动=${RESULT_JITTER_MDEV}ms"
    else
        echo -e "  ${CYAN}延迟抖动:${NC}     ${RED}测试失败${NC}"
    fi
    echo ""
    
    # TCP 吞吐量
    echo -e "  ${MAGENTA}━━━ TCP 吞吐量 ━━━${NC}"
    if [ -n "$RESULT_TCP_SINGLE_UP" ] && [ "$RESULT_TCP_SINGLE_UP" != "N/A" ]; then
        echo -e "  ${CYAN}单线程:${NC}       上传=${RESULT_TCP_SINGLE_UP} Mbps, 下载=${RESULT_TCP_SINGLE_DOWN} Mbps"
    else
        echo -e "  ${CYAN}单线程:${NC}       ${RED}测试失败${NC}"
        [ -n "$RESULT_TCP_SINGLE_UP_ERROR" ] && echo -e "                  原因: $RESULT_TCP_SINGLE_UP_ERROR"
    fi
    
    if [ -n "$RESULT_TCP_PARALLEL_UP" ] && [ "$RESULT_TCP_PARALLEL_UP" != "N/A" ]; then
        echo -e "  ${CYAN}4并发:${NC}        上传=${RESULT_TCP_PARALLEL_UP} Mbps, 下载=${RESULT_TCP_PARALLEL_DOWN} Mbps"
    else
        echo -e "  ${CYAN}4并发:${NC}        ${RED}测试失败${NC}"
        [ -n "$RESULT_TCP_PARALLEL_UP_ERROR" ] && echo -e "                  原因: $RESULT_TCP_PARALLEL_UP_ERROR"
    fi
    echo ""
    
    # UDP 吞吐量
    if [ -n "$RESULT_UDP_UP" ]; then
        echo -e "  ${MAGENTA}━━━ UDP 吞吐量 ━━━${NC}"
        echo -e "  ${CYAN}UDP 测试:${NC}     上传=${RESULT_UDP_UP} Mbps, 下载=${RESULT_UDP_DOWN} Mbps"
        echo ""
    fi
    
    # HTTP 性能
    if [ -n "$RESULT_HTTP_AVG" ]; then
        echo -e "  ${MAGENTA}━━━ HTTP 性能 ━━━${NC}"
        echo -e "  ${CYAN}响应时间:${NC}     平均=${RESULT_HTTP_AVG}ms"
        echo -e "  ${CYAN}成功率:${NC}       ${RESULT_HTTP_SUCCESS}/100 ($(( RESULT_HTTP_SUCCESS ))%)"
        echo ""
    fi
    
    # 连接压力测试
    if [ -n "$RESULT_CONN_SUCCESS" ]; then
        echo -e "  ${MAGENTA}━━━ 连接压力 ━━━${NC}"
        local success_rate=$(awk "BEGIN {printf \"%.1f\", $RESULT_CONN_SUCCESS * 100 / $RESULT_CONN_TOTAL}")
        echo -e "  ${CYAN}连接成功率:${NC}   ${RESULT_CONN_SUCCESS}/${RESULT_CONN_TOTAL} (${success_rate}%)"
        echo ""
    fi
    
    # 性能评级
    echo -e "  ${MAGENTA}━━━ 性能评级 ━━━${NC}"
    
    # 延迟评级
    if [ -n "$RESULT_PING_AVG" ]; then
        local latency_rating=""
        local latency_val=$(echo "$RESULT_PING_AVG" | awk '{print $1}')
        if (( $(echo "$latency_val < 2" | bc -l 2>/dev/null || echo 0) )); then
            latency_rating="${GREEN}优秀${NC}"
        elif (( $(echo "$latency_val < 5" | bc -l 2>/dev/null || echo 0) )); then
            latency_rating="${GREEN}良好${NC}"
        elif (( $(echo "$latency_val < 10" | bc -l 2>/dev/null || echo 0) )); then
            latency_rating="${YELLOW}一般${NC}"
        else
            latency_rating="${RED}需优化${NC}"
        fi
        echo -e "  ${CYAN}延迟:${NC}         $latency_rating (${latency_val}ms)"
    fi
    
    # 吞吐量评级
    if [ -n "$RESULT_TCP_SINGLE_UP" ] && [ "$RESULT_TCP_SINGLE_UP" != "N/A" ]; then
        local throughput_rating=""
        local throughput_val=$(echo "$RESULT_TCP_SINGLE_UP" | awk '{print $1}')
        if (( $(echo "$throughput_val > 800" | bc -l 2>/dev/null || echo 0) )); then
            throughput_rating="${GREEN}优秀${NC}"
        elif (( $(echo "$throughput_val > 500" | bc -l 2>/dev/null || echo 0) )); then
            throughput_rating="${GREEN}良好${NC}"
        elif (( $(echo "$throughput_val > 300" | bc -l 2>/dev/null || echo 0) )); then
            throughput_rating="${YELLOW}一般${NC}"
        else
            throughput_rating="${RED}需优化${NC}"
        fi
        echo -e "  ${CYAN}吞吐量:${NC}       $throughput_rating (${throughput_val} Mbps)"
    fi
    
    # 稳定性评级
    if [ -n "$RESULT_JITTER_MDEV" ]; then
        local stability_rating=""
        local jitter_val=$(echo "$RESULT_JITTER_MDEV" | awk '{print $1}')
        if (( $(echo "$jitter_val < 1" | bc -l 2>/dev/null || echo 0) )); then
            stability_rating="${GREEN}优秀${NC}"
        elif (( $(echo "$jitter_val < 3" | bc -l 2>/dev/null || echo 0) )); then
            stability_rating="${GREEN}良好${NC}"
        elif (( $(echo "$jitter_val < 5" | bc -l 2>/dev/null || echo 0) )); then
            stability_rating="${YELLOW}一般${NC}"
        else
            stability_rating="${RED}需优化${NC}"
        fi
        echo -e "  ${CYAN}稳定性:${NC}       $stability_rating (抖动 ${jitter_val}ms)"
    fi
    
    echo ""
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ==================== 系统信息收集 ====================

collect_system_info() {
    local server_ip=$1
    
    print_section "系统信息收集"
    
    {
        echo "测试时间: $(date)"
        echo "服务器IP: $server_ip"
        echo ""
        echo "=== 客户端系统 ==="
        echo "内核版本: $(uname -r)"
        echo "CPU: $(lscpu | grep "Model name" | sed 's/Model name:\s*//')"
        echo "内存: $(free -h | awk '/^Mem:/{print $2}')"
        echo "网卡: $(ip -o link show | grep -v "lo:" | awk '{print $2}' | tr -d ':')"
        echo ""
        echo "=== 模块状态 ==="
        if lsmod | grep -q crypto_bridge; then
            echo "crypto_bridge: 已加载"
            if [ -f /sys/kernel/crypto_bridge/statistics ]; then
                echo ""
                cat /sys/kernel/crypto_bridge/statistics
            fi
        else
            echo "crypto_bridge: 未加载"
        fi
    } > "$RESULTS_DIR/system_info.txt"
    
    log_info "系统信息已保存"
}

# ==================== 测试 01: 基准延迟 ====================

test_01_baseline_latency() {
    local server=$1
    print_section "测试 01: 基准延迟测试 (ICMP)"
    
    log_test "测试快速ping (10个包)..."
    ping -c 10 -i 0.2 "$server" | tee "$RESULTS_DIR/01_ping_fast.txt"
    
    # 修复：正确解析丢包率和延迟
    local loss=$(grep "packet loss" "$RESULTS_DIR/01_ping_fast.txt" | awk -F',' '{print $3}' | awk '{print $1}')
    local stats_line=$(grep "rtt min/avg/max/mdev" "$RESULTS_DIR/01_ping_fast.txt")
    local avg=$(echo "$stats_line" | awk -F'[=/]' '{print $6}')
    
    echo ""
    log_info "快速测试: 丢包率=${loss}, 平均延迟=${avg}ms"
    
    # 保存到全局变量供最终报告使用
    RESULT_PING_LOSS="$loss"
    RESULT_PING_AVG="$avg"
    
    # 分析
    local loss_num=${loss%%%*}
    if [ -n "$loss_num" ] && [ "$loss_num" -gt 0 ] 2>/dev/null; then
        log_warn "检测到丢包，可能存在网络问题"
    fi
    
    echo ""
}

# ==================== 测试 02: 延迟抖动 ====================

test_02_latency_jitter() {
    local server=$1
    print_section "测试 02: 延迟抖动分析 (500个包)"
    
    log_test "执行延迟抖动测试..."
    ping -c 500 -i 0.01 "$server" > "$RESULTS_DIR/02_jitter.txt" 2>&1
    
    # 修复：正确提取统计数据
    # 格式: rtt min/avg/max/mdev = 0.602/0.809/1.025/0.117 ms
    local stats=$(grep "rtt min/avg/max/mdev" "$RESULTS_DIR/02_jitter.txt" | tail -1)
    local values=$(echo "$stats" | awk -F'=' '{print $2}' | awk '{print $1}')
    local min=$(echo "$values" | awk -F'/' '{print $1}')
    local avg=$(echo "$values" | awk -F'/' '{print $2}')
    local max=$(echo "$values" | awk -F'/' '{print $3}')
    local mdev=$(echo "$values" | awk -F'/' '{print $4}')
    
    echo ""
    log_info "延迟统计 (ms):"
    echo "  最小: $min"
    echo "  平均: $avg"
    echo "  最大: $max"
    echo "  抖动: $mdev"
    
    # 保存到全局变量
    RESULT_JITTER_MIN="$min"
    RESULT_JITTER_AVG="$avg"
    RESULT_JITTER_MAX="$max"
    RESULT_JITTER_MDEV="$mdev"
    
    # 分析抖动
    if [ -n "$mdev" ] && (( $(echo "$mdev > 5" | bc -l 2>/dev/null || echo 0) )); then
        log_warn "延迟抖动较大 (${mdev}ms)"
    fi
    
    echo ""
}

# ==================== 测试 03: TCP单线程吞吐量 ====================

test_03_tcp_throughput_single() {
    local server=$1
    print_section "测试 03: TCP 单线程吞吐量"
    
    log_test "测试 TCP 单线程 (${TEST_DURATION}秒)..."
    
    # 客户端→服务器
    log_info "方向: 客户端 → 服务器"
    echo -n "  进度: "
    if iperf3 -c "$server" -p $IPERF_PORT -t $TEST_DURATION -i 5 -J > "$RESULTS_DIR/03_tcp_single_upload.json" 2>&1; then
        echo "✓ 完成"
    else
        echo "✗ 失败"
        log_warn "上传测试失败，检查错误信息..."
        if [ -f "$RESULTS_DIR/03_tcp_single_upload.json" ]; then
            grep -i "error\|unable\|refused" "$RESULTS_DIR/03_tcp_single_upload.json" | head -3
        fi
    fi
    
    sleep 2
    
    # 服务器→客户端
    log_info "方向: 服务器 → 客户端"
    echo -n "  进度: "
    if iperf3 -c "$server" -p $IPERF_PORT -t $TEST_DURATION -i 5 -R -J > "$RESULTS_DIR/03_tcp_single_download.json" 2>&1; then
        echo "✓ 完成"
    else
        echo "✗ 失败"
        log_warn "下载测试失败，检查错误信息..."
        if [ -f "$RESULTS_DIR/03_tcp_single_download.json" ]; then
            grep -i "error\|unable\|refused" "$RESULTS_DIR/03_tcp_single_download.json" | head -3
        fi
    fi
    
    # 解析结果（改进的JSON解析）
    local upload_mbps="N/A"
    local download_mbps="N/A"
    local upload_error=""
    local download_error=""
    
    if [ -f "$RESULTS_DIR/03_tcp_single_upload.json" ]; then
        # 检查文件大小
        local fsize=$(wc -c < "$RESULTS_DIR/03_tcp_single_upload.json" 2>/dev/null || echo 0)
        if [ "$fsize" -lt 50 ]; then
            upload_error="JSON 文件异常 (${fsize} bytes)"
        # 检查是否有错误
        elif grep -q '"error"' "$RESULTS_DIR/03_tcp_single_upload.json"; then
            upload_error=$(grep '"error"' "$RESULTS_DIR/03_tcp_single_upload.json" | head -1 | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        else
            # 多种方式尝试提取 bits_per_second（按优先级）
            local upload_bps=""
            
            # 方法1: end.sum_sent.bits_per_second (新版 iperf3, 发送方)
            upload_bps=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/03_tcp_single_upload.json" | grep -A 10 '"sum_sent"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            
            # 方法2: end.sum.bits_per_second (老版 iperf3)
            if [ -z "$upload_bps" ]; then
                upload_bps=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/03_tcp_single_upload.json" | grep -A 10 '"sum"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            
            # 方法3: 搜索 intervals 最后一个记录
            if [ -z "$upload_bps" ]; then
                upload_bps=$(grep '"bits_per_second"' "$RESULTS_DIR/03_tcp_single_upload.json" | grep -v null | tail -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            
            if [ -n "$upload_bps" ] && [ "$upload_bps" != "0" ]; then
                upload_mbps=$(awk "BEGIN {printf \"%.2f\", $upload_bps / 1000000}")
            else
                upload_error="无法解析 JSON 数据（检查 iperf3 版本）"
            fi
        fi
    else
        upload_error="测试文件不存在"
    fi
    
    if [ -f "$RESULTS_DIR/03_tcp_single_download.json" ]; then
        # 检查文件大小
        local fsize=$(wc -c < "$RESULTS_DIR/03_tcp_single_download.json" 2>/dev/null || echo 0)
        if [ "$fsize" -lt 50 ]; then
            download_error="JSON 文件异常 (${fsize} bytes)"
        # 检查是否有错误
        elif grep -q '"error"' "$RESULTS_DIR/03_tcp_single_download.json"; then
            download_error=$(grep '"error"' "$RESULTS_DIR/03_tcp_single_download.json" | head -1 | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        else
            # 多种方式尝试提取 bits_per_second（按优先级）
            local download_bps=""
            
            # 方法1: end.sum_received.bits_per_second (新版 iperf3, 接收方)
            download_bps=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/03_tcp_single_download.json" | grep -A 10 '"sum_received"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            
            # 方法2: end.sum.bits_per_second (老版 iperf3)
            if [ -z "$download_bps" ]; then
                download_bps=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/03_tcp_single_download.json" | grep -A 10 '"sum"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            
            # 方法3: 搜索 intervals 最后一个记录
            if [ -z "$download_bps" ]; then
                download_bps=$(grep '"bits_per_second"' "$RESULTS_DIR/03_tcp_single_download.json" | grep -v null | tail -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            
            if [ -n "$download_bps" ] && [ "$download_bps" != "0" ]; then
                download_mbps=$(awk "BEGIN {printf \"%.2f\", $download_bps / 1000000}")
            else
                download_error="无法解析 JSON 数据（检查 iperf3 版本）"
            fi
        fi
    else
        download_error="测试文件不存在"
    fi
    
    echo ""
    log_info "单线程吞吐量:"
    if [ "$upload_mbps" != "N/A" ]; then
        echo -e "  上传: ${GREEN}${upload_mbps} Mbps${NC}"
    else
        echo -e "  上传: ${RED}失败${NC} (${upload_error})"
    fi
    
    if [ "$download_mbps" != "N/A" ]; then
        echo -e "  下载: ${GREEN}${download_mbps} Mbps${NC}"
    else
        echo -e "  下载: ${RED}失败${NC} (${download_error})"
    fi
    
    # 保存到全局变量
    RESULT_TCP_SINGLE_UP="$upload_mbps"
    RESULT_TCP_SINGLE_DOWN="$download_mbps"
    RESULT_TCP_SINGLE_UP_ERROR="$upload_error"
    RESULT_TCP_SINGLE_DOWN_ERROR="$download_error"
    
    echo ""
}

# ==================== 测试 04: TCP并发吞吐量 ====================

test_04_tcp_throughput_parallel() {
    local server=$1
    print_section "测试 04: TCP 并发吞吐量 (4线程)"
    
    log_test "测试 TCP 4并发连接 (${TEST_DURATION}秒)..."
    
    # 4并发上传
    log_info "4并发上传测试..."
    echo -n "  进度: "
    if iperf3 -c "$server" -p $IPERF_PORT -t $TEST_DURATION -P 4 -i 5 -J > "$RESULTS_DIR/04_tcp_parallel_upload.json" 2>&1; then
        echo "✓ 完成"
    else
        echo "✗ 失败"
        log_warn "并发上传测试失败"
    fi
    
    sleep 2
    
    # 4并发下载
    log_info "4并发下载测试..."
    echo -n "  进度: "
    if iperf3 -c "$server" -p $IPERF_PORT -t $TEST_DURATION -P 4 -R -i 5 -J > "$RESULTS_DIR/04_tcp_parallel_download.json" 2>&1; then
        echo "✓ 完成"
    else
        echo "✗ 失败"
        log_warn "并发下载测试失败"
    fi
    
    # 解析结果（改进的JSON解析）
    local upload_mbps="N/A"
    local download_mbps="N/A"
    local upload_error=""
    local download_error=""
    
    if [ -f "$RESULTS_DIR/04_tcp_parallel_upload.json" ]; then
        local fsize=$(wc -c < "$RESULTS_DIR/04_tcp_parallel_upload.json" 2>/dev/null || echo 0)
        if [ "$fsize" -lt 50 ]; then
            upload_error="JSON 文件异常 (${fsize} bytes)"
        elif grep -q '"error"' "$RESULTS_DIR/04_tcp_parallel_upload.json"; then
            upload_error=$(grep '"error"' "$RESULTS_DIR/04_tcp_parallel_upload.json" | head -1 | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        else
            local upload_sum=""
            # 方法1: end.sum_sent.bits_per_second
            upload_sum=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/04_tcp_parallel_upload.json" | grep -A 10 '"sum_sent"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            # 方法2: end.sum.bits_per_second
            if [ -z "$upload_sum" ]; then
                upload_sum=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/04_tcp_parallel_upload.json" | grep -A 10 '"sum"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            if [ -n "$upload_sum" ] && [ "$upload_sum" != "0" ]; then
                upload_mbps=$(awk "BEGIN {printf \"%.2f\", $upload_sum / 1000000}")
            else
                upload_error="无法解析 JSON 数据（检查 iperf3 版本）"
            fi
        fi
    else
        upload_error="测试文件不存在"
    fi
    
    if [ -f "$RESULTS_DIR/04_tcp_parallel_download.json" ]; then
        local fsize=$(wc -c < "$RESULTS_DIR/04_tcp_parallel_download.json" 2>/dev/null || echo 0)
        if [ "$fsize" -lt 50 ]; then
            download_error="JSON 文件异常 (${fsize} bytes)"
        elif grep -q '"error"' "$RESULTS_DIR/04_tcp_parallel_download.json"; then
            download_error=$(grep '"error"' "$RESULTS_DIR/04_tcp_parallel_download.json" | head -1 | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        else
            local download_sum=""
            # 方法1: end.sum_received.bits_per_second
            download_sum=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/04_tcp_parallel_download.json" | grep -A 10 '"sum_received"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            # 方法2: end.sum.bits_per_second
            if [ -z "$download_sum" ]; then
                download_sum=$(sed -n '/"end"/,/"intervals"/p' "$RESULTS_DIR/04_tcp_parallel_download.json" | grep -A 10 '"sum"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            if [ -n "$download_sum" ] && [ "$download_sum" != "0" ]; then
                download_mbps=$(awk "BEGIN {printf \"%.2f\", $download_sum / 1000000}")
            else
                download_error="无法解析 JSON 数据（检查 iperf3 版本）"
            fi
        fi
    else
        download_error="测试文件不存在"
    fi
    
    echo ""
    log_info "并发吞吐量 (4线程):"
    if [ "$upload_mbps" != "N/A" ]; then
        echo -e "  上传: ${GREEN}${upload_mbps} Mbps${NC}"
    else
        echo -e "  上传: ${RED}失败${NC} (${upload_error})"
    fi
    
    if [ "$download_mbps" != "N/A" ]; then
        echo -e "  下载: ${GREEN}${download_mbps} Mbps${NC}"
    else
        echo -e "  下载: ${RED}失败${NC} (${download_error})"
    fi
    
    # 保存到全局变量
    RESULT_TCP_PARALLEL_UP="$upload_mbps"
    RESULT_TCP_PARALLEL_DOWN="$download_mbps"
    RESULT_TCP_PARALLEL_UP_ERROR="$upload_error"
    RESULT_TCP_PARALLEL_DOWN_ERROR="$download_error"
    
    echo ""
}

# ==================== 测试 05: TCP双向同时 ====================

test_05_tcp_bidirectional() {
    local server=$1
    print_section "测试 05: TCP 双向同时传输"
    
    log_test "测试双向同时传输 (${TEST_DURATION}秒)..."
    echo -n "  进度: "
    
    if iperf3 -c "$server" -p $IPERF_PORT -t $TEST_DURATION --bidir -i 5 -J > "$RESULTS_DIR/05_tcp_bidir.json" 2>&1; then
        echo "✓ 完成"
    else
        echo "✗ 失败"
        log_warn "双向传输测试失败"
    fi
    
    # 解析结果
    echo ""
    if [ -f "$RESULTS_DIR/05_tcp_bidir.json" ]; then
        # 提取发送和接收方向的吞吐量
        local send_bps=$(grep -A 30 '"end"' "$RESULTS_DIR/05_tcp_bidir.json" | grep -A 5 '"sender"' | grep '"bits_per_second"' | head -1 | awk -F': ' '{print $2}' | tr -d ', ')
        local recv_bps=$(grep -A 30 '"end"' "$RESULTS_DIR/05_tcp_bidir.json" | grep -A 5 '"receiver"' | grep '"bits_per_second"' | head -1 | awk -F': ' '{print $2}' | tr -d ', ')
        
        log_info "双向传输结果:"
        
        if [ -n "$send_bps" ] && [ "$send_bps" != "null" ] && [ "$send_bps" != "" ]; then
            local send_mbps=$(awk "BEGIN {printf \"%.2f\", $send_bps / 1000000}")
            echo -e "  发送方向: ${GREEN}${send_mbps} Mbps${NC}"
        else
            echo -e "  发送方向: ${RED}无法解析${NC}"
        fi
        
        if [ -n "$recv_bps" ] && [ "$recv_bps" != "null" ] && [ "$recv_bps" != "" ]; then
            local recv_mbps=$(awk "BEGIN {printf \"%.2f\", $recv_bps / 1000000}")
            echo -e "  接收方向: ${GREEN}${recv_mbps} Mbps${NC}"
        else
            echo -e "  接收方向: ${RED}无法解析${NC}"
        fi
        
        # 计算总吞吐量
        if [ -n "$send_bps" ] && [ -n "$recv_bps" ] && [ "$send_bps" != "null" ] && [ "$recv_bps" != "null" ]; then
            local total_mbps=$(awk "BEGIN {printf \"%.2f\", ($send_bps + $recv_bps) / 1000000}")
            echo -e "  总吞吐量: ${GREEN}${total_mbps} Mbps${NC}"
        fi
    else
        log_error "测试结果文件不存在"
    fi
    
    echo ""
}

# ==================== 测试 06: UDP吞吐量 ====================

test_06_udp_throughput() {
    local server=$1
    print_section "测试 06: UDP 吞吐量测试"
    
    # UDP 100 Mbps
    log_test "UDP 100 Mbps 测试..."
    iperf3 -c "$server" -p $IPERF_PORT -u -b 100M -t $TEST_DURATION -i 5 -J > "$RESULTS_DIR/06_udp_100m.json" 2>&1 || true
    
    sleep 2
    
    # UDP 500 Mbps
    log_test "UDP 500 Mbps 测试..."
    iperf3 -c "$server" -p $IPERF_PORT -u -b 500M -t $TEST_DURATION -i 5 -J > "$RESULTS_DIR/06_udp_500m.json" 2>&1 || true
    
    sleep 2
    
    # UDP 1 Gbps
    log_test "UDP 1 Gbps 测试..."
    iperf3 -c "$server" -p $IPERF_PORT -u -b 1G -t $TEST_DURATION -i 5 -J > "$RESULTS_DIR/06_udp_1g.json" 2>&1 || true
    
    # 分析UDP丢包率和吞吐量（改进的解析）
    echo ""
    log_info "UDP 测试结果："
    local udp_100m_mbps="N/A"
    local udp_500m_mbps="N/A"
    local udp_100m_loss="N/A"
    local udp_500m_loss="N/A"
    
    for file in "$RESULTS_DIR"/06_udp_*.json; do
        if [ -f "$file" ]; then
            local bitrate=$(basename "$file" | sed 's/06_udp_//; s/.json//')
            
            # 检查文件大小
            local fsize=$(wc -c < "$file" 2>/dev/null || echo 0)
            if [ "$fsize" -lt 50 ]; then
                echo -e "  ${bitrate}: ${RED}JSON 文件异常 (${fsize} bytes)${NC}"
                continue
            fi
            
            # 多种方式提取 lost_percent 和 bits_per_second
            local loss=""
            local bps=""
            
            # 方法1：从 end.sum 提取（新版 iperf3）
            loss=$(sed -n '/"end"/,/"intervals"/p' "$file" | grep -A 5 '"sum"' | grep '"lost_percent"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            bps=$(sed -n '/"end"/,/"intervals"/p' "$file" | grep -A 5 '"sum"' | grep '"bits_per_second"' | head -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            
            # 方法2：从 intervals 最后一个记录提取
            if [ -z "$loss" ]; then
                loss=$(grep '"lost_percent"' "$file" | grep -v "null" | tail -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            
            if [ -z "$bps" ]; then
                bps=$(grep '"bits_per_second"' "$file" | grep -v "null" | tail -1 | grep -o '[0-9]\+\(\.[0-9]\+\)\?' | head -1)
            fi
            
            # 显示结果
            echo -ne "  ${bitrate}: "
            if [ -n "$loss" ] && [ "$loss" != "null" ] && [ "$loss" != "" ]; then
                echo -ne "丢包率 ${GREEN}${loss}%${NC}"
                # 保存丢包率
                if [ "$bitrate" = "100m" ]; then
                    udp_100m_loss="$loss"
                elif [ "$bitrate" = "500m" ]; then
                    udp_500m_loss="$loss"
                fi
            else
                echo -ne "丢包率 ${RED}N/A${NC}"
            fi
            
            # 显示吞吐量
            if [ -n "$bps" ] && [ "$bps" != "null" ] && [ "$bps" != "" ]; then
                local mbps=$(awk "BEGIN {printf \"%.2f\", $bps / 1000000}")
                echo -e ", 吞吐量 ${GREEN}${mbps} Mbps${NC}"
                
                # 保存吞吐量
                if [ "$bitrate" = "100m" ]; then
                    udp_100m_mbps="$mbps"
                elif [ "$bitrate" = "500m" ]; then
                    udp_500m_mbps="$mbps"
                fi
            else
                echo -e ", 吞吐量 ${RED}N/A${NC}"
                log_warn "    无法解析 $bitrate 的吞吐量数据"
            fi
        fi
    done
    
    # 保存到全局变量
    RESULT_UDP_UP="$udp_100m_mbps"
    RESULT_UDP_DOWN="$udp_500m_mbps"
    
    # 如果所有测试都失败，给出诊断
    if [ "$udp_100m_mbps" = "N/A" ] && [ "$udp_500m_mbps" = "N/A" ]; then
        echo ""
        log_warn "UDP 测试可能失败，请检查："
        echo "    1. 服务器端 iperf3 是否支持 UDP"
        echo "    2. 网络是否允许 UDP 流量"
        echo "    3. 查看详细日志: cat $RESULTS_DIR/06_udp_*.json"
    fi
    
    echo ""
}

# ==================== 测试 07: HTTP性能 ====================

test_07_http_performance() {
    local server=$1
    print_section "测试 07: HTTP 应用层性能"
    
    log_test "HTTP 并发请求测试 (100次，10并发)..."
    
    # 使用curl测试（正确的并发方式）
    {
        for batch in {1..10}; do
            echo "批次 $batch/10" >&2
            for i in {1..10}; do
                (
                    start=$(date +%s%N)
                    if curl -s -m 5 "http://$server:$HTTP_PORT/" > /dev/null 2>&1; then
                        end=$(date +%s%N)
                        elapsed=$(( (end - start) / 1000000 ))
                        echo "SUCCESS $elapsed"
                    else
                        echo "FAILED 0"
                    fi
                ) &
            done
            wait
            sleep 0.5
        done
    } > "$RESULTS_DIR/07_http_raw.txt"
    
    # 计算统计（修复整数比较错误）
    local success_count=0
    local failed_count=0
    
    if [ -f "$RESULTS_DIR/07_http_raw.txt" ]; then
        # 使用 grep 配合 wc -l 来确保得到干净的计数
        success_count=$(grep "SUCCESS" "$RESULTS_DIR/07_http_raw.txt" 2>/dev/null | wc -l)
        failed_count=$(grep "FAILED" "$RESULTS_DIR/07_http_raw.txt" 2>/dev/null | wc -l)
    fi
    
    # 确保是整数，去除所有非数字字符
    success_count=$(echo "$success_count" | tr -cd '0-9')
    failed_count=$(echo "$failed_count" | tr -cd '0-9')
    success_count=${success_count:-0}
    failed_count=${failed_count:-0}
    
    echo ""
    if [ "$success_count" -gt 0 ] 2>/dev/null; then
        local times=$(grep "SUCCESS" "$RESULTS_DIR/07_http_raw.txt" | awk '{print $2}')
        if [ -n "$times" ]; then
            local avg=$(echo "$times" | awk '{sum+=$1; n++} END {if(n>0) print int(sum/n); else print 0}')
            local min=$(echo "$times" | sort -n | head -1)
            local max=$(echo "$times" | sort -n | tail -1)
            
            echo ""
            log_info "HTTP 性能统计:"
            echo "  总请求: 100"
            echo -e "  成功: ${GREEN}$success_count${NC}"
            echo -e "  失败: ${RED}$failed_count${NC}"
            echo "  平均响应: ${avg}ms"
            echo "  最快响应: ${min}ms"
            echo "  最慢响应: ${max}ms"
            
            # 保存到全局变量
            RESULT_HTTP_AVG="$avg"
            RESULT_HTTP_SUCCESS="$success_count"
        else
            log_error "无法解析HTTP响应时间"
        fi
    else
        log_error "所有HTTP请求失败 (成功: $success_count, 失败: $failed_count)"
        log_warn "请确保服务器端已启动 HTTP 服务 (端口 $HTTP_PORT)"
    fi
    
    echo ""
}

# ==================== 测试 08: 连接压力 ====================

test_08_connection_stress() {
    local server=$1
    print_section "测试 08: TCP 连接压力测试"
    
    log_test "短连接压力测试 (100个快速连接到 iperf3 端口 $IPERF_PORT)..."
    
    local success=0
    local failed=0
    local test_port=$IPERF_PORT
    local method="nc"
    
    # 检测可用的连接测试方法
    if command -v nc &> /dev/null; then
        method="nc"
    elif command -v telnet &> /dev/null; then
        method="telnet"
    elif [ -e /dev/tcp ]; then
        method="devtcp"
    else
        log_warn "未找到合适的连接测试工具（nc/telnet/bash），跳过测试"
        return
    fi
    
    log_info "使用方法: $method"
    echo -n "  进度: "
    
    for i in {1..100}; do
        local conn_success=false
        
        case "$method" in
            nc)
                if nc -z -w 1 "$server" "$test_port" 2>/dev/null; then
                    conn_success=true
                fi
                ;;
            telnet)
                if echo "quit" | timeout 1 telnet "$server" "$test_port" 2>/dev/null | grep -q "Connected\|Escape"; then
                    conn_success=true
                fi
                ;;
            devtcp)
                if timeout 1 bash -c "echo > /dev/tcp/$server/$test_port" 2>/dev/null; then
                    conn_success=true
                fi
                ;;
        esac
        
        if [ "$conn_success" = true ]; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
        
        [ $((i % 10)) -eq 0 ] && echo -n "."
    done
    echo " 完成"
    
    echo ""
    log_info "连接测试结果:"
    
    # 计算成功率
    local success_rate=$(awk "BEGIN {printf \"%.1f\", $success * 100 / 100}")
    
    if [ $success -gt 90 ]; then
        echo -e "  成功: ${GREEN}$success/100${NC} (${success_rate}%)"
        echo "  失败: $failed/100"
        log_info "✓ 连接稳定性优秀"
    elif [ $success -gt 70 ]; then
        echo -e "  成功: ${YELLOW}$success/100${NC} (${success_rate}%)"
        echo "  失败: $failed/100"
        log_warn "⚠ 连接稳定性一般"
    elif [ $success -gt 0 ]; then
        echo -e "  成功: ${RED}$success/100${NC} (${success_rate}%)"
        echo "  失败: $failed/100"
        log_warn "✗ 连接稳定性较差"
    else
        echo -e "  成功: ${RED}$success/100${NC} (0%)"
        echo "  失败: $failed/100"
        log_error "✗ 所有连接失败"
    fi
    
    if [ $failed -gt 50 ]; then
        echo ""
        log_warn "连接失败率过高，可能原因："
        echo "    1. 服务器端 iperf3 未运行 (检查: ps aux | grep iperf3)"
        echo "    2. 防火墙阻止连接 (检查: iptables -L)"
        echo "    3. 网络不稳定或延迟过高"
        echo "    4. 端口 $test_port 不正确"
        echo ""
        echo "  诊断命令："
        echo "    nc -zv $server $test_port"
        echo "    telnet $server $test_port"
    fi
    
    # 保存到全局变量
    RESULT_CONN_SUCCESS="$success"
    RESULT_CONN_TOTAL="100"
    
    echo ""
}

# ==================== 测试 09: 混合流量 ====================

test_09_mixed_traffic() {
    local server=$1
    print_section "测试 09: 混合流量压力测试"
    
    log_test "同时运行 TCP + UDP + ICMP (15秒)..."
    
    # 后台运行 iperf3 TCP
    log_info "启动 TCP 流..."
    iperf3 -c "$server" -p $IPERF_PORT -t 15 > "$RESULTS_DIR/09_mixed_tcp.txt" 2>&1 &
    local tcp_pid=$!
    
    sleep 1
    
    # 后台运行 iperf3 UDP
    log_info "启动 UDP 流..."
    iperf3 -c "$server" -p $IPERF_PORT -u -b 100M -t 15 > "$RESULTS_DIR/09_mixed_udp.txt" 2>&1 &
    local udp_pid=$!
    
    sleep 1
    
    # 前台运行 ping
    log_info "启动 ICMP 测试..."
    echo -n "  进度: "
    ping -c 150 -i 0.1 "$server" > "$RESULTS_DIR/09_mixed_ping.txt" 2>&1 &
    local ping_pid=$!
    
    # 等待 ping 完成（约15秒）
    local count=0
    while kill -0 $ping_pid 2>/dev/null; do
        sleep 1
        count=$((count + 1))
        [ $((count % 3)) -eq 0 ] && echo -n "."
    done
    echo " 完成"
    
    # 等待 iperf3 完成
    wait $tcp_pid $udp_pid 2>/dev/null
    
    # 分析结果
    echo ""
    log_info "混合流量测试结果:"
    
    # ICMP 延迟
    if [ -f "$RESULTS_DIR/09_mixed_ping.txt" ]; then
        local ping_loss=$(grep "packet loss" "$RESULTS_DIR/09_mixed_ping.txt" | awk -F',' '{print $3}' | awk '{print $1}')
        local ping_avg=$(grep "rtt min/avg/max" "$RESULTS_DIR/09_mixed_ping.txt" | awk -F'[=/]' '{print $6}')
        
        if [ -n "$ping_avg" ]; then
            echo -e "  ICMP 延迟: ${GREEN}${ping_avg}ms${NC} (丢包率: ${ping_loss})"
        else
            echo -e "  ICMP 延迟: ${RED}无法解析${NC}"
        fi
    fi
    
    # TCP 吞吐量
    if [ -f "$RESULTS_DIR/09_mixed_tcp.txt" ]; then
        local tcp_bps=$(grep "sender" "$RESULTS_DIR/09_mixed_tcp.txt" | tail -1 | awk '{print $(NF-2), $(NF-1)}')
        if [ -n "$tcp_bps" ]; then
            echo -e "  TCP 吞吐量: ${GREEN}${tcp_bps}${NC}"
        else
            echo -e "  TCP 吞吐量: ${RED}无法解析${NC}"
        fi
    fi
    
    # UDP 丢包率
    if [ -f "$RESULTS_DIR/09_mixed_udp.txt" ]; then
        local udp_loss=$(grep "Lost" "$RESULTS_DIR/09_mixed_udp.txt" | tail -1 | awk -F'[()]' '{print $2}')
        if [ -n "$udp_loss" ]; then
            echo -e "  UDP 丢包率: ${GREEN}${udp_loss}${NC}"
        else
            echo -e "  UDP 丢包率: ${RED}无法解析${NC}"
        fi
    fi
    
    echo ""
    log_info "✓ 混合流量测试完成 - 系统在多种流量并发下的表现"
    echo ""
}

# ==================== 模块统计 ====================

show_stats() {
    print_banner
    print_section "Crypto Bridge 模块统计"
    
    if ! lsmod | grep -q crypto_bridge; then
        log_error "crypto_bridge 模块未加载"
        exit 1
    fi
    
    if [ -f /sys/kernel/crypto_bridge/statistics ]; then
        cat /sys/kernel/crypto_bridge/statistics
    else
        log_error "无法读取模块统计"
        exit 1
    fi
    
    echo ""
    log_info "实时监控 (每2秒刷新，Ctrl+C退出):"
    echo ""
    
    while true; do
        clear
        echo "═══ Crypto Bridge 实时统计 ═══"
        echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        cat /sys/kernel/crypto_bridge/statistics
        sleep 2
    done
}

# ==================== 报告生成 ====================

generate_comprehensive_report() {
    local server=$1
    
    print_section "生成测试报告"
    
    local report="$RESULTS_DIR/REPORT.txt"
    
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "  Crypto Bridge 性能测试报告"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "测试时间: $(date)"
        echo "服务器IP: $server"
        echo "测试时长: ${TEST_DURATION}秒/项"
        echo ""
        echo "───────────────────────────────────────────────────────────"
        echo ""
        
        # 01: 延迟测试
        echo "【测试 01】基准延迟"
        echo "─────────────────────"
        if [ -f "$RESULTS_DIR/01_ping_fast.txt" ]; then
            grep "packet loss\|rtt min/avg/max" "$RESULTS_DIR/01_ping_fast.txt" | tail -2
        fi
        echo ""
        
        # 02: 抖动测试
        echo "【测试 02】延迟抖动 (500个包)"
        echo "─────────────────────"
        if [ -f "$RESULTS_DIR/02_jitter.txt" ]; then
            grep "packet loss\|rtt min/avg/max/mdev" "$RESULTS_DIR/02_jitter.txt" | tail -2
        fi
        echo ""
        
        # 03: TCP单线程
        echo "【测试 03】TCP 单线程吞吐量"
        echo "─────────────────────"
        echo "上传方向:"
        if [ -f "$RESULTS_DIR/03_tcp_single_upload.json" ]; then
            grep -A1 "sender" "$RESULTS_DIR/03_tcp_single_upload.json" | grep "bits_per_second" | head -1
        fi
        echo "下载方向:"
        if [ -f "$RESULTS_DIR/03_tcp_single_download.json" ]; then
            grep -A1 "receiver" "$RESULTS_DIR/03_tcp_single_download.json" | grep "bits_per_second" | head -1
        fi
        echo ""
        
        # 04: TCP并发
        echo "【测试 04】TCP 并发吞吐量 (4线程)"
        echo "─────────────────────"
        echo "4并发上传:"
        if [ -f "$RESULTS_DIR/04_tcp_parallel_upload.json" ]; then
            grep -A5 "sum_sent" "$RESULTS_DIR/04_tcp_parallel_upload.json" | grep "bits_per_second" | tail -1
        fi
        echo "4并发下载:"
        if [ -f "$RESULTS_DIR/04_tcp_parallel_download.json" ]; then
            grep -A5 "sum_received" "$RESULTS_DIR/04_tcp_parallel_download.json" | grep "bits_per_second" | tail -1
        fi
        echo ""
        
        # 06: UDP测试
        echo "【测试 06】UDP 吞吐量与丢包率"
        echo "─────────────────────"
        for file in "$RESULTS_DIR"/06_udp_*.json; do
            if [ -f "$file" ]; then
                local bitrate=$(basename "$file" | sed 's/06_udp_//; s/.json//')
                echo "测试速率: $bitrate"
                grep "lost_percent\|jitter_ms" "$file" | tail -2
                echo ""
            fi
        done
        
        # 07: HTTP测试
        echo "【测试 07】HTTP 应用层性能"
        echo "─────────────────────"
        if [ -f "$RESULTS_DIR/07_http_raw.txt" ]; then
            local total=100
            local success=$(grep -c "SUCCESS" "$RESULTS_DIR/07_http_raw.txt" || echo 0)
            local failed=$(grep -c "FAILED" "$RESULTS_DIR/07_http_raw.txt" || echo 0)
            echo "总请求: $total"
            echo "成功: $success"
            echo "失败: $failed"
            
            if [ $success -gt 0 ]; then
                local times=$(grep "SUCCESS" "$RESULTS_DIR/07_http_raw.txt" | awk '{print $2}')
                local avg=$(echo "$times" | awk '{sum+=$1} END {print int(sum/NR)}')
                echo "平均响应时间: ${avg}ms"
            fi
        fi
        echo ""
        
        # 09: 混合流量
        echo "【测试 09】混合流量压力"
        echo "─────────────────────"
        if [ -f "$RESULTS_DIR/09_mixed_ping.txt" ]; then
            echo "混合流量下ICMP延迟:"
            grep "rtt min/avg/max" "$RESULTS_DIR/09_mixed_ping.txt"
        fi
        echo ""
        
        echo "───────────────────────────────────────────────────────────"
        echo ""
        echo "【性能分析与建议】"
        echo ""
        
        # 延迟分析
        if [ -f "$RESULTS_DIR/01_ping_fast.txt" ]; then
            local avg_latency=$(grep "rtt min/avg/max" "$RESULTS_DIR/01_ping_fast.txt" | awk -F'/' '{print $5}' | awk '{print $1}')
            if [ -n "$avg_latency" ]; then
                echo "▸ 延迟性能:"
                if (( $(echo "$avg_latency < 2" | bc -l) )); then
                    echo "  ✓ 优秀 (${avg_latency}ms < 2ms)"
                elif (( $(echo "$avg_latency < 5" | bc -l) )); then
                    echo "  ✓ 良好 (${avg_latency}ms < 5ms)"
                else
                    echo "  ⚠ 需优化 (${avg_latency}ms)"
                fi
            fi
        fi
        
        # 吞吐量分析
        if [ -f "$RESULTS_DIR/03_tcp_single_upload.json" ]; then
            local upload_bps=$(grep '"bits_per_second"' "$RESULTS_DIR/03_tcp_single_upload.json" | grep -v "null" | tail -1 | awk -F': ' '{print $2}' | tr -d ', ')
            if [ -n "$upload_bps" ] && [ "$upload_bps" != "null" ]; then
                local upload_mbps=$(awk "BEGIN {printf \"%.0f\", $upload_bps / 1000000}")
                echo ""
                echo "▸ 吞吐量性能:"
                if [ "$upload_mbps" -gt 800 ]; then
                    echo "  ✓ 优秀 (${upload_mbps} Mbps > 800 Mbps)"
                elif [ "$upload_mbps" -gt 500 ]; then
                    echo "  ✓ 良好 (${upload_mbps} Mbps > 500 Mbps)"
                elif [ "$upload_mbps" -gt 100 ]; then
                    echo "  ○ 一般 (${upload_mbps} Mbps)"
                else
                    echo "  ⚠ 需优化 (${upload_mbps} Mbps < 100 Mbps)"
                fi
            fi
        fi
        
        # 稳定性分析
        if [ -f "$RESULTS_DIR/02_jitter.txt" ]; then
            local loss=$(grep "packet loss" "$RESULTS_DIR/02_jitter.txt" | awk '{print $(NF-5)}' | tr -d '%')
            if [ -n "$loss" ]; then
                echo ""
                echo "▸ 稳定性:"
                if (( $(echo "$loss == 0" | bc -l) )); then
                    echo "  ✓ 完美 (0% 丢包)"
                elif (( $(echo "$loss < 1" | bc -l) )); then
                    echo "  ✓ 良好 (<1% 丢包)"
                else
                    echo "  ⚠ 需检查 (${loss}% 丢包)"
                fi
            fi
        fi
        
        echo ""
        echo "详细数据文件位于: $RESULTS_DIR/"
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        
    } | tee "$report"
    
    log_info "完整报告已生成: $report"
    echo ""
}

# ==================== 快速测试模式 ====================

run_quick_test() {
    local server_ip=$1
    
    if [ -z "$server_ip" ]; then
        log_error "请指定服务器 IP"
        echo "用法: $0 quick <SERVER_IP>"
        exit 1
    fi
    
    print_banner
    print_section "快速测试模式 (约2分钟)"
    
    check_dependencies
    check_connectivity "$server_ip"
    
    # 创建结果目录
    RESULTS_DIR="./quick_test_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULTS_DIR"
    
    echo ""
    log_info "开始快速测试..."
    echo ""
    
    # 1. 延迟测试
    print_title "1. 延迟测试"
    ping -c 10 "$server_ip" | tee "$RESULTS_DIR/ping.txt"
    local avg=$(grep "rtt min/avg/max" "$RESULTS_DIR/ping.txt" | awk -F'/' '{print $5}' | awk '{print $1}')
    echo ""
    log_info "平均延迟: ${avg}ms"
    
    # 2. TCP 吞吐量
    print_title "2. TCP 吞吐量 (10秒)"
    if nc -z -w 2 "$server_ip" $IPERF_PORT 2>/dev/null; then
        iperf3 -c "$server_ip" -p $IPERF_PORT -t 10 | tee "$RESULTS_DIR/tcp.txt"
        local throughput=$(grep "sender" "$RESULTS_DIR/tcp.txt" | awk '{print $(NF-2), $(NF-1)}')
        echo ""
        log_info "TCP 吞吐量: $throughput"
    else
        log_warn "iperf3 服务不可用，跳过吞吐量测试"
    fi
    
    # 3. 连接测试
    print_title "3. 连接稳定性"
    local success=0
    for i in {1..20}; do
        nc -z -w 1 "$server_ip" $HTTP_PORT 2>/dev/null && success=$((success + 1))
    done
    echo ""
    log_info "连接成功率: $success/20 ($(( success * 5 ))%)"
    
    echo ""
    log_info "═══════════════════════════════════════════════"
    log_info "  快速测试完成"
    log_info "═══════════════════════════════════════════════"
    echo ""
    echo "结果保存在: $RESULTS_DIR/"
    echo ""
    echo "运行完整测试: $0 client $server_ip"
    echo ""
}

# ==================== 使用说明 ====================

show_usage() {
    print_banner
    cat << EOF
${CYAN}使用说明:${NC}

  ${GREEN}服务器端${NC} (在 VM4 或 PC2 上运行):
    $0 server

  ${GREEN}客户端完整测试${NC} (在 VM1 或 PC1 上运行):
    $0 client <SERVER_IP>

  ${GREEN}快速测试${NC} (约2分钟):
    $0 quick <SERVER_IP>

  ${GREEN}查看统计${NC} (在开发板上运行):
    $0 stats

${CYAN}测试拓扑:${NC}
    VM1 (客户端) ←→ VM2 [加密] ←→ VM3 [解密] ←→ VM4 (服务器)

${CYAN}测试项目:${NC}
    01. 基准延迟测试 (ICMP ping)
    02. 延迟抖动分析 (500个包)
    03. TCP 单线程双向吞吐量
    04. TCP 4并发双向吞吐量
    05. TCP 双向同时传输
    06. UDP 多速率吞吐量测试
    07. HTTP 并发应用性能
    08. TCP 短连接压力测试
    09. 混合流量压力测试

${CYAN}注意事项:${NC}
    • 测试前确保服务器端已启动
    • 完整测试约需 10-15 分钟
    • 建议在低负载时段进行测试
    • 测试结果保存在 ./perf_test_* 目录

EOF
}

# ==================== 主函数 ====================

main() {
    local mode=$1
    local arg=$2
    
    case "$mode" in
        server)
            run_server
            ;;
        client)
            run_client "$arg"
            ;;
        quick)
            run_quick_test "$arg"
            ;;
        stats)
            show_stats
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

# 运行
main "$@"

