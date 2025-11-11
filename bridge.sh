#!/bin/bash

#####################################################################
# crypto_bridge 统一管理脚本 (虚拟机版本 V3.8.0)
# 
# 功能: 编译、加载、配置、测试、监控 - 一个脚本搞定所有事情
# 适用: 虚拟机环境 (VMware/VirtualBox)
# 作者: Meng
# 版本: 3.8.0 (重大简化：固定加密/解密规则，移除复杂参数)
#####################################################################

set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m'

# 配置文件（优先级：当前目录 > 用户主目录）
if [ -w "$SCRIPT_DIR" ]; then
    CONFIG_FILE="$SCRIPT_DIR/.crypto_bridge_v3.8.conf"
else
    CONFIG_FILE="$HOME/.crypto_bridge_v3.8.conf"
fi
SYSFS_PATH="/sys/kernel/crypto_bridge"

# 默认配置（V3.8参数 - 简化版）
DEFAULT_INTERNAL_DEV="ens33"  # 明文侧网卡
DEFAULT_EXTERNAL_DEV="ens34"  # 密文侧网卡
DEFAULT_ENABLE=1
DEFAULT_XOR_KEY=170
DEFAULT_DEBUG=0
DEFAULT_MODIFY_BYTES=0  # 0=完整payload加密

#####################################################################
# 辅助函数
#####################################################################

print_banner() {
    echo -e "${BLUE}"
    echo "=============================================================="
    echo "  crypto_bridge V3.8.0 管理工具 (虚拟机版本)"
    echo "  双开发板级联支持 - 完整payload加密"
    echo "  V3.8.0: 重大简化 - 固定加密/解密规则"
    echo "  配置更简单：只需指定明文侧和密文侧网卡！"
    echo "=============================================================="
    echo -e "${NC}"
}

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ $1${NC}"; }
print_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 sudo 运行"
        exit 1
    fi
}

#####################################################################
# 配置管理
#####################################################################

save_config() {
    cat > "$CONFIG_FILE" <<EOF
# crypto_bridge V3.8 配置文件
INTERNAL_DEV="$1"
EXTERNAL_DEV="$2"
ENABLE="$3"
XOR_KEY="$4"
MODIFY_BYTES="$5"
DEBUG="$6"
EOF
    print_success "配置已保存"
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        return 0
    fi
    return 1
}

#####################################################################
# 模块操作
#####################################################################

compile_module() {
    echo "编译模块..."
    
    # 进入脚本目录编译
    cd "$SCRIPT_DIR"
    
    if [ ! -f "crypto_bridge.c" ]; then
        print_error "找不到 crypto_bridge.c"
        exit 1
    fi

    make -C /lib/modules/$(uname -r)/build M="$SCRIPT_DIR" clean > /dev/null 2>&1 || true
    
    if make -C /lib/modules/$(uname -r)/build M="$SCRIPT_DIR" modules 2>&1 | grep -q "error:"; then
        print_error "编译失败"
        exit 1
    fi
    
    print_success "编译完成"
}

load_module() {
    local internal_dev="${1:-$DEFAULT_INTERNAL_DEV}"
    local external_dev="${2:-$DEFAULT_EXTERNAL_DEV}"
    local enable="${3:-$DEFAULT_ENABLE}"
    local xor_key="${4:-$DEFAULT_XOR_KEY}"
    local modify_bytes="${5:-$DEFAULT_MODIFY_BYTES}"
    local debug="${6:-$DEFAULT_DEBUG}"
    
    # 卸载旧模块
    if lsmod | grep -q crypto_bridge; then
        echo "卸载旧模块..."
        rmmod crypto_bridge 2>/dev/null || true
        sleep 1
    fi
    
    # 检查.ko文件
    if [ ! -f "$SCRIPT_DIR/crypto_bridge.ko" ]; then
        print_warn "模块未编译，正在编译..."
        compile_module
    fi
    
    # 加载模块 (V3.8: 移除了 mode 参数)
    echo "加载模块..."
    local params="internal_dev=$internal_dev external_dev=$external_dev enable=$enable xor_key=$xor_key modify_bytes=$modify_bytes debug=$debug"
    
    if insmod "$SCRIPT_DIR/crypto_bridge.ko" $params; then
        if [ "$debug" = "0" ]; then
            local debug_str="关闭"
        elif [ "$debug" = "1" ]; then
            local debug_str="Level 1 (每10包)"
        else
            local debug_str="Level 2 (每100包)"
        fi
        print_success "模块已加载 (V3.8.0)"
        echo "  明文侧网卡: $internal_dev"
        echo "  密文侧网卡: $external_dev"
        echo "  固定规则:"
        echo "    $internal_dev 收到 → 加密 → $external_dev 发出"
        echo "    $external_dev 收到 → 解密 → $internal_dev 发出"
        echo "  XOR密钥: 0x$(printf '%02X' $xor_key) (十进制: $xor_key)"
        echo "  处理字节: $modify_bytes (0=全部)"
        echo "  调试模式: $debug_str (debug=$debug)"
        save_config "$internal_dev" "$external_dev" "$enable" "$xor_key" "$modify_bytes" "$debug"
    sleep 1
        dmesg | grep crypto_bridge | tail -5 | sed 's/^/  /'
    else
        print_error "加载失败"
        dmesg | grep crypto_bridge | tail -5
        exit 1
    fi
}
    
unload_module() {
    print_banner
    
    # 1. 卸载模块
    if lsmod | grep -q crypto_bridge; then
        echo "1. 卸载模块..."
        rmmod crypto_bridge
        print_success "模块已卸载"
    echo ""
        dmesg | grep crypto_bridge | tail -10 | sed 's/^/  /'
    else
        print_info "1. 模块未加载"
    fi
    echo ""
    
    # 2. 清理编译文件
    echo "2. 清理编译文件..."
    cd "$SCRIPT_DIR"
    make -C /lib/modules/$(uname -r)/build M="$SCRIPT_DIR" clean > /dev/null 2>&1 || true
    rm -f *.o *.ko *.mod *.mod.c *.mod.o *.symvers *.order 2>/dev/null || true
    rm -rf .tmp_versions .*.cmd 2>/dev/null || true
    
    local ko_count=$(ls -1 *.ko 2>/dev/null | wc -l)
    if [ "$ko_count" -eq 0 ]; then
        print_success "编译文件已清理"
    else
        print_warn "还有 $ko_count 个 .ko 文件"
    fi
    echo ""
    
    # 3. 清理内核日志
    echo "3. 清理内核日志..."
    local log_count=$(dmesg | grep crypto_bridge | wc -l)
    echo "  当前日志条目: $log_count"
    
    if [ "$log_count" -gt 0 ]; then
            if dmesg -C 2>/dev/null; then
                print_success "内核日志已清空"
            else
            print_warn "无法清空日志 (权限不足)"
            fi
        else
        print_info "无日志需要清理"
    fi
    echo ""
    
    # 4. 显示最终状态
    print_success "清理完成!"
    echo ""
    echo "最终状态:"
    echo "  模块: $(lsmod | grep crypto_bridge > /dev/null && echo '已加载 ⚠' || echo '未加载 ✓')"
    echo "  .ko文件: $(ls -1 *.ko 2>/dev/null | wc -l) 个"
    echo "  日志: $(dmesg | grep crypto_bridge 2>/dev/null | wc -l) 条"
    echo "  配置: $([ -f "$CONFIG_FILE" ] && echo '保留' || echo '无')"
}

#####################################################################
# 状态查看
#####################################################################

show_status() {
    if ! lsmod | grep -q crypto_bridge; then
        print_warn "模块未加载"
        return
    fi
    
    echo -e "${GREEN}模块状态:${NC}"
    echo "  状态: 运行中 (V3.8.0 - 固定加密/解密规则)"
    
    if [ -d "$SYSFS_PATH" ]; then
        local internal=$(cat $SYSFS_PATH/internal_device 2>/dev/null || echo 'N/A')
        local external=$(cat $SYSFS_PATH/external_device 2>/dev/null || echo 'N/A')
        echo "  明文侧网卡: $internal"
        echo "  密文侧网卡: $external"
    echo ""
        echo "  固定规则:"
        echo "    $internal 收到 → 加密 → $external 发出"
        echo "    $external 收到 → 解密 → $internal 发出"
    fi
    
    if [ -d "/sys/module/crypto_bridge/parameters" ]; then
        local enable=$(cat /sys/module/crypto_bridge/parameters/enable 2>/dev/null || echo 'N/A')
        local xor_key=$(cat /sys/module/crypto_bridge/parameters/xor_key 2>/dev/null || echo 'N/A')
        local modify_bytes=$(cat /sys/module/crypto_bridge/parameters/modify_bytes 2>/dev/null || echo 'N/A')
        local debug=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null || echo 'N/A')
    
    echo ""
        echo "  启用处理: $enable"
        
        if [ "$xor_key" != "N/A" ]; then
            echo "  XOR密钥: 0x$(printf '%02X' $xor_key) (十进制: $xor_key)"
        else
            echo "  XOR密钥: N/A"
        fi
        
        echo "  处理字节: $modify_bytes (0=全部)"
        
        if [ "$debug" != "N/A" ]; then
            if [ "$debug" = "0" ]; then
                local debug_str="关闭"
            elif [ "$debug" = "1" ]; then
                local debug_str="Level 1 (每10包)"
            else
                local debug_str="Level 2 (每100包)"
            fi
            echo "  调试模式: $debug_str (debug=$debug)"
        fi
    fi
    
    echo ""
    echo -e "${GREEN}统计信息:${NC}"
    if [ -f "$SYSFS_PATH/statistics" ]; then
        cat $SYSFS_PATH/statistics | sed 's/^/  /'
    else
        print_warn "统计不可用"
    fi
}

#####################################################################
# 动态配置
#####################################################################

set_device() {
    local type=$1
    local device=$2
    
    if [ -z "$device" ]; then
        print_error "请指定网卡名称"
        exit 1
    fi
    
    if ! ip link show "$device" &>/dev/null; then
        print_error "网卡 $device 不存在"
        exit 1
    fi
    
    if [ "$type" == "internal" ]; then
    echo "$device" > $SYSFS_PATH/internal_device
        print_success "明文侧网卡已切换到 $device"
    else
        echo "$device" > $SYSFS_PATH/external_device
        print_success "密文侧网卡已切换到 $device"
    fi
    
    dmesg | grep crypto_bridge | tail -1
}

reset_stats() {
    if [ -f "$SYSFS_PATH/statistics" ]; then
        echo "reset" > $SYSFS_PATH/statistics
        print_success "统计已重置"
    else
        print_error "统计功能不可用"
    fi
}


#####################################################################
# 智能启动 (自动判断配置或交互)
#####################################################################

smart_start() {
    print_banner
    
    # 如果有配置文件,直接使用
    if load_config; then
        if [ "${DEBUG:-0}" = "0" ]; then
            local debug_str="关闭"
        elif [ "${DEBUG:-0}" = "1" ]; then
            local debug_str="Level 1 (每10包)"
        else
            local debug_str="Level 2 (每100包)"
        fi
        print_info "找到已保存的配置 (V3.8)"
        echo "  明文侧网卡: $INTERNAL_DEV"
        echo "  密文侧网卡: $EXTERNAL_DEV"
        echo "  固定规则:"
        echo "    $INTERNAL_DEV 收到 → 加密 → $EXTERNAL_DEV 发出"
        echo "    $EXTERNAL_DEV 收到 → 解密 → $INTERNAL_DEV 发出"
        echo "  启用处理: $ENABLE"
        echo "  XOR密钥: ${XOR_KEY:-$DEFAULT_XOR_KEY}"
        echo "  处理字节: $MODIFY_BYTES (0=全部)"
        echo "  调试模式: $debug_str (debug=${DEBUG:-$DEFAULT_DEBUG})"
    echo ""
        
        read -p "使用此配置? [Y/n/r(重新配置)]: " use_config
        
        if [[ "$use_config" =~ ^[Rr]$ ]]; then
            # 重新配置
            interactive_config
        elif [[ "$use_config" =~ ^[Nn]$ ]]; then
            print_info "已取消"
            exit 0
        else
            # 使用已保存配置
            compile_module
            load_module "$INTERNAL_DEV" "$EXTERNAL_DEV" "$ENABLE" "${XOR_KEY:-$DEFAULT_XOR_KEY}" "$MODIFY_BYTES" "${DEBUG:-$DEFAULT_DEBUG}"
        fi
    else
        # 没有配置,进行交互式配置
        print_info "首次使用,开始配置..."
        echo ""
        interactive_config
    fi
    
    echo ""
    show_status
}

# 交互式配置函数
interactive_config() {
    # 检测网卡
    echo "检测可用网卡..."
    local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')
    local iface_array=($interfaces)
    
    echo ""
    echo -e "${BLUE}可用网卡:${NC}"
    local i=1
    for iface in $interfaces; do
        local status=$(ip link show $iface | grep -o 'state [A-Z]*' | awk '{print $2}')
        local ip=$(ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        
        if [ -n "$ip" ]; then
            echo -e "  ${GREEN}[$i]${NC} $iface (${status}) - ${ip}"
        else
            echo -e "  ${YELLOW}[$i]${NC} $iface (${status}) - 无IP"
        fi
        i=$((i+1))
    done
    echo ""
    
    # 选择明文侧网卡
    echo ""
    echo -e "${BLUE}明文侧网卡${NC} (连接PC/VM，处理明文数据)"
    read -p "选择 [1-${#iface_array[@]}] 或网卡名 [默认: $DEFAULT_INTERNAL_DEV]: " internal_choice
    if [ -z "$internal_choice" ]; then
        INTERNAL_DEV="$DEFAULT_INTERNAL_DEV"
    elif [[ "$internal_choice" =~ ^[0-9]+$ ]] && [ "$internal_choice" -ge 1 ] && [ "$internal_choice" -le "${#iface_array[@]}" ]; then
        INTERNAL_DEV="${iface_array[$((internal_choice-1))]}"
    else
        INTERNAL_DEV="$internal_choice"
    fi
    
    # 验证明文侧网卡
    if [ -z "$INTERNAL_DEV" ]; then
        print_error "明文侧网卡不能为空"
        exit 1
    fi
    
    # 选择密文侧网卡
    echo ""
    echo -e "${BLUE}密文侧网卡${NC} (连接对端板，传输加密数据)"
    read -p "选择 [1-${#iface_array[@]}] 或网卡名 [默认: $DEFAULT_EXTERNAL_DEV]: " external_choice
    if [ -z "$external_choice" ]; then
        EXTERNAL_DEV="$DEFAULT_EXTERNAL_DEV"
    elif [[ "$external_choice" =~ ^[0-9]+$ ]] && [ "$external_choice" -ge 1 ] && [ "$external_choice" -le "${#iface_array[@]}" ]; then
        EXTERNAL_DEV="${iface_array[$((external_choice-1))]}"
    else
        EXTERNAL_DEV="$external_choice"
    fi
    
    # 验证密文侧网卡
    if [ -z "$EXTERNAL_DEV" ]; then
        print_error "密文侧网卡不能为空"
        exit 1
    fi
    
    # 高级选项
    echo ""
    read -p "启用payload处理? [Y/n]: " enable_choice
    ENABLE=$([[ "$enable_choice" =~ ^[Nn]$ ]] && echo 0 || echo 1)
    
    read -p "XOR密钥 (0-255) [默认: $DEFAULT_XOR_KEY]: " key_choice
    XOR_KEY="${key_choice:-$DEFAULT_XOR_KEY}"
    
    read -p "处理字节数 (0=全部) [默认: $DEFAULT_MODIFY_BYTES]: " bytes_choice
    MODIFY_BYTES="${bytes_choice:-$DEFAULT_MODIFY_BYTES}"
    
    read -p "开启调试模式? (0=关闭, 1=每10包, 2=每100包) [默认: 0]: " debug_choice
    DEBUG="${debug_choice:-0}"
    
    echo ""
    if [ "$DEBUG" = "0" ]; then
        local debug_str="关闭"
    elif [ "$DEBUG" = "1" ]; then
        local debug_str="Level 1 (每10包: 协议+IP+hex)"
    else
        local debug_str="Level 2 (每100包: 协议+IP+hex)"
    fi
    echo -e "${BLUE}配置摘要 (V3.8):${NC}"
    echo "  明文侧网卡: $INTERNAL_DEV"
    echo "  密文侧网卡: $EXTERNAL_DEV"
    echo ""
    echo "  固定规则:"
    echo "    $INTERNAL_DEV 收到 → 加密 → $EXTERNAL_DEV 发出"
    echo "    $EXTERNAL_DEV 收到 → 解密 → $INTERNAL_DEV 发出"
    echo ""
    echo "  启用处理: $ENABLE"
    echo "  XOR密钥: 0x$(printf '%02X' $XOR_KEY) (十进制: $XOR_KEY)"
    echo "  处理字节: $MODIFY_BYTES (0=全部)"
    echo "  调试模式: $debug_str (debug=$DEBUG)"
    echo ""
    
    read -p "继续? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        print_info "已取消"
        exit 0
    fi
    
    compile_module
    load_module "$INTERNAL_DEV" "$EXTERNAL_DEV" "$ENABLE" "$XOR_KEY" "$MODIFY_BYTES" "$DEBUG"
}


#####################################################################
# 监控功能
#####################################################################

monitor() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    print_info "实时监控 (Ctrl+C 退出)"
    echo ""
    
    watch -n 1 "cat $SYSFS_PATH/statistics 2>/dev/null"
}

debug_on() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    local debug_status=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null)
    if [ "$debug_status" != "0" ]; then
        print_info "调试模式已经开启 (level=$debug_status)"
    else
    echo ""
        read -p "设置调试级别 (1=每10包, 2=每100包) [默认: 1]: " level
        level=${level:-1}
        
        echo $level > /sys/module/crypto_bridge/parameters/debug
        print_success "调试模式已开启 (Level $level)"
    echo ""
        echo "现在可以运行以下命令查看日志："
        echo "  sudo $0 debug-log    # 实时查看日志"
        echo "  sudo dmesg | grep -E 'ENC|DEC|HEX' | tail -20    # 查看最近20条"
    fi
}

debug_off() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    local debug_status=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null)
    if [ "$debug_status" = "0" ]; then
        print_info "调试模式已经关闭"
    else
    echo 0 > /sys/module/crypto_bridge/parameters/debug
    print_success "调试模式已关闭"
        echo ""
        echo "提示："
        echo "  - 关闭调试后不再记录加密/解密详细日志"
        echo "  - 可以减少系统日志负担，提高性能"
        echo "  - 需要时可运行: sudo $0 debug-on 重新开启"
    fi
}

debug_log() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    # 检查调试是否开启
    local debug_status=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null)
    if [ "$debug_status" = "0" ]; then
        print_warn "调试模式未开启"
    echo ""
        read -p "是否开启调试模式? [Y/n]: " enable_debug
        if [[ "$enable_debug" =~ ^[Nn]$ ]]; then
            print_info "已取消"
            exit 0
        else
            read -p "设置调试级别 (1=每10包, 2=每100包) [默认: 1]: " level
            level=${level:-1}
            echo $level > /sys/module/crypto_bridge/parameters/debug
            print_success "调试模式已开启 (Level $level)"
    echo ""
        fi
    else
        print_info "调试模式已开启 (level=$debug_status)"
        echo ""
        if [ "$debug_status" = "1" ]; then
            echo "当前级别: Level 1 (每10包打印协议+IP+hex dump)"
        else
            echo "当前级别: Level 2 (每100包打印协议+IP+hex dump)"
        fi
        echo ""
        echo "提示: 按 Ctrl+C 退出后，可运行 'sudo $0 debug-off' 关闭调试"
        echo ""
    fi
    
    print_info "实时查看调试日志 (按 Ctrl+C 退出)"
    echo "=============================================================="
    echo ""
    
    # 清空旧日志（可选）
    read -p "是否清空旧日志? [y/N]: " clear_log
    if [[ "$clear_log" =~ ^[Yy]$ ]]; then
        dmesg -C 2>/dev/null && print_info "日志已清空" || print_warn "无法清空日志"
        echo ""
    fi
    
    print_info "等待新日志... (发送测试数据以查看加密/解密过程)"
    echo "提示: 运行测试 → python3 test_tcp.py client 192.168.1.200 8888"
    echo "=============================================================="
    echo ""
    
    # 使用 dmesg -w 实时跟踪（如果支持）
    if dmesg -w 2>&1 | head -1 | grep -q "invalid option"; then
        # dmesg 不支持 -w，使用轮询
        local last_line=$(dmesg | wc -l)
        echo "开始监控... (每秒刷新)"
        echo ""
        
        while true; do
            sleep 1
            local current_line=$(dmesg | wc -l)
            
            if [ "$current_line" -gt "$last_line" ]; then
                # 只显示新增的行，并过滤加密/解密相关
                local new_logs=$(dmesg | tail -n +$((last_line + 1)) | grep -E "ENCRYPT|DECRYPT")
                if [ -n "$new_logs" ]; then
                    echo "$new_logs"
                fi
                last_line=$current_line
        fi
    done
    else
        # 支持 -w，直接使用
        dmesg -w | grep --line-buffered -E "ENCRYPT|DECRYPT"
    fi
}



install_autoload() {
    print_banner
    echo "配置开机自动加载..."
    echo ""
    
    MODULE_PATH="$SCRIPT_DIR"
    MODULE_FILE="${MODULE_PATH}/crypto_bridge.ko"
    
    # 检查模块文件
    if [ ! -f "$MODULE_FILE" ]; then
        print_error "找不到 crypto_bridge.ko，请先编译模块"
        echo "运行: sudo $0 compile"
        exit 1
    fi
    
    # 加载配置
    if ! load_config; then
        print_error "未找到配置文件，请先运行 start 配置模块"
        exit 1
    fi
    
    local xor_key=${XOR_KEY:-$DEFAULT_XOR_KEY}
    
    echo "使用配置 (V3.8):"
    echo "  明文侧网卡: $INTERNAL_DEV"
    echo "  密文侧网卡: $EXTERNAL_DEV"
    echo "  固定规则: $INTERNAL_DEV收到→加密, $EXTERNAL_DEV收到→解密"
    echo "  启用: $ENABLE"
    echo "  XOR密钥: 0x$(printf '%02X' $xor_key)"
    echo "  处理字节: $MODIFY_BYTES"
        echo ""
    
    echo "选择安装方法:"
    echo "  [1] systemd 服务 (推荐)"
    echo "  [2] /etc/modules + modprobe.d"
    echo ""
    read -p "选择 [1-2, 默认1]: " method
    method=${method:-1}
    
    if [ "$method" == "1" ]; then
        # systemd 方法
        print_info "创建 systemd 服务..."
        
        cat > /tmp/crypto-bridge.service << SVCEOF
[Unit]
Description=Crypto Bridge Network Packet Processing Module
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# 启动前检查
ExecStartPre=/bin/sh -c 'test -f ${MODULE_FILE} || exit 1'
ExecStartPre=/bin/sh -c 'ip link show ${INTERNAL_DEV} > /dev/null 2>&1 || exit 1'
ExecStartPre=/bin/sh -c 'ip link show ${EXTERNAL_DEV} > /dev/null 2>&1 || exit 1'

# 开启IP转发
ExecStartPre=/sbin/sysctl -w net.ipv4.ip_forward=1

# 卸载旧模块
ExecStartPre=-/sbin/rmmod crypto_bridge

# 加载模块 (V3.8)
ExecStart=/sbin/insmod ${MODULE_FILE} internal_dev=${INTERNAL_DEV} external_dev=${EXTERNAL_DEV} enable=${ENABLE} xor_key=${xor_key} modify_bytes=${MODIFY_BYTES} debug=${DEBUG:-0}

# 验证
ExecStartPost=/bin/sh -c 'lsmod | grep -q crypto_bridge && echo "Module loaded"'

# 停止
ExecStop=/sbin/rmmod crypto_bridge

# 重启
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
SVCEOF
        
        # 安装服务
        sudo mv /tmp/crypto-bridge.service /etc/systemd/system/
        sudo systemctl daemon-reload
        sudo systemctl enable crypto-bridge.service
        
        print_success "systemd 服务已安装并启用"
    echo ""
        echo "管理命令:"
        echo "  启动: sudo systemctl start crypto-bridge"
        echo "  停止: sudo systemctl stop crypto-bridge"
        echo "  状态: sudo systemctl status crypto-bridge"
        echo "  日志: sudo journalctl -u crypto-bridge"
        echo "  禁用: sudo systemctl disable crypto-bridge"
        
        echo ""
        read -p "是否现在启动服务测试? [Y/n]: " test_now
        if [[ ! "$test_now" =~ ^[Nn]$ ]]; then
            sudo systemctl start crypto-bridge.service
    sleep 1
            sudo systemctl status crypto-bridge.service
        fi
        
    elif [ "$method" == "2" ]; then
        # /etc/modules 方法
        print_info "安装到系统模块目录..."
        
        KERNEL_VERSION=$(uname -r)
        MODULES_DIR="/lib/modules/$KERNEL_VERSION/extra"
        
        sudo mkdir -p "$MODULES_DIR"
        sudo cp "$MODULE_FILE" "$MODULES_DIR/"
        sudo depmod -a
        
        print_success "模块已复制到 $MODULES_DIR/"
        
        # 配置自动加载
        if ! grep -q "crypto_bridge" /etc/modules 2>/dev/null; then
            echo "crypto_bridge" | sudo tee -a /etc/modules > /dev/null
            print_success "已添加到 /etc/modules"
        else
            print_warn "/etc/modules 中已存在"
        fi
        
        # 配置参数
        sudo tee /etc/modprobe.d/crypto-bridge.conf > /dev/null << MODEOF
# Crypto Bridge 模块参数 (V3.8)
options crypto_bridge internal_dev=${INTERNAL_DEV} external_dev=${EXTERNAL_DEV} enable=${ENABLE} xor_key=${xor_key} modify_bytes=${MODIFY_BYTES} debug=${DEBUG:-0}
MODEOF
        
        print_success "参数已配置到 /etc/modprobe.d/crypto-bridge.conf"
        
        # 配置IP转发
        if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
            echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf > /dev/null
            print_success "IP转发已配置"
        fi
        
        echo ""
        read -p "是否现在加载模块测试? [Y/n]: " test_now
        if [[ ! "$test_now" =~ ^[Nn]$ ]]; then
            sudo modprobe crypto_bridge
            if lsmod | grep -q crypto_bridge; then
                print_success "模块已加载"
                show_status
            fi
        fi
    fi
    
    echo ""
    print_success "开机自动加载已配置！"
    echo ""
    echo "验证方法:"
    echo "  1. 重启系统: sudo reboot"
    echo "  2. 重启后检查: lsmod | grep crypto_bridge"
    echo "  3. 查看状态: $0 status"
}

uninstall_autoload() {
    print_banner
    echo "卸载开机自动加载..."
        echo ""
    
    # 检查 systemd 服务
    if systemctl list-unit-files | grep -q crypto-bridge.service; then
        print_info "发现 systemd 服务，正在卸载..."
        sudo systemctl stop crypto-bridge.service 2>/dev/null || true
        sudo systemctl disable crypto-bridge.service 2>/dev/null || true
        sudo rm -f /etc/systemd/system/crypto-bridge.service
        sudo systemctl daemon-reload
        print_success "systemd 服务已卸载"
    fi
    
    # 检查 /etc/modules
    if grep -q "crypto_bridge" /etc/modules 2>/dev/null; then
        print_info "从 /etc/modules 移除..."
        sudo sed -i '/crypto_bridge/d' /etc/modules
        print_success "已从 /etc/modules 移除"
    fi
    
    # 检查 modprobe.d
    if [ -f /etc/modprobe.d/crypto-bridge.conf ]; then
        print_info "删除 modprobe 配置..."
        sudo rm -f /etc/modprobe.d/crypto-bridge.conf
        print_success "modprobe 配置已删除"
    fi
    
    # 检查系统模块目录
    KERNEL_VERSION=$(uname -r)
    if [ -f "/lib/modules/$KERNEL_VERSION/extra/crypto_bridge.ko" ]; then
        print_info "从系统模块目录删除..."
        sudo rm -f "/lib/modules/$KERNEL_VERSION/extra/crypto_bridge.ko"
        sudo depmod -a
        print_success "系统模块已删除"
    fi
    
        echo ""
    print_success "自动加载配置已全部移除"
        echo ""
    echo "模块本身仍保留在项目目录中"
    echo "如需重新配置: sudo $0 install-autoload"
}

#####################################################################
# 帮助信息
#####################################################################
show_help() {
    cat <<EOF
crypto_bridge 管理工具 (V3.8.0 - 固定加密/解密规则)

用法: sudo $0 <命令> [选项]

命令:
  start              启动模块 (智能判断: 有配置直接用,无配置则交互)
  stop               停止模块 (自动清理: 卸载+清理编译文件+清理日志)
  restart            重启模块
  
  status             查看状态和统计
  monitor            实时监控统计信息
  reset-stats        重置统计计数器
  
  debug-on           开启调试模式
  debug-off          关闭调试模式
  debug-log          实时查看加密/解密日志
  
  set-internal <网卡>  动态切换明文侧网卡
  set-external <网卡>  动态切换密文侧网卡
  
  install-autoload   配置开机自动加载 
  uninstall-autoload 移除开机自动加载
  
  compile            仅编译模块
  config             显示当前配置文件
  log                查看内核日志
  
  help               显示帮助

V3.8 固定规则说明:
  - 从明文侧网卡收到数据 → 自动加密 → 发送到密文侧网卡
  - 从密文侧网卡收到数据 → 自动解密 → 发送到明文侧网卡
  - 双开发板配置相同！只需指定哪个是明文侧，哪个是密文侧

示例:
  # 启动模块 (首次会交互配置,之后直接使用已保存配置)
  sudo $0 start
  
  # 查看状态 (显示加密/解密统计)
  sudo $0 status
  
  # 调试功能
  sudo $0 debug-on               # 开启调试模式 (可选level 1或2)
  sudo $0 debug-log              # 实时查看加密/解密日志
  sudo $0 debug-off              # 关闭调试模式
  
  调试级别说明:
    Level 1: 每10包打印 (协议+IP+方向+hex dump)
    Level 2: 每100包打印 (协议+IP+方向+hex dump)
  
  # 配置开机自动加载 
  sudo $0 install-autoload
  
  # 动态切换网卡 (无需重启)
  sudo $0 set-internal ens33     # 切换明文侧网卡
  sudo $0 set-external ens34     # 切换密文侧网卡
  
  # 实时监控流量
  sudo $0 monitor
  
  # 查看内核日志
  sudo $0 log
  
  # 移除开机自动加载
  sudo $0 uninstall-autoload
  
  # 停止服务 (自动清理所有编译文件和日志)
  sudo $0 stop

配置文件: $CONFIG_FILE
sysfs接口: $SYSFS_PATH
  - internal_device: 明文侧网卡
  - external_device: 密文侧网卡
  - statistics: 统计信息

提示:
  - 首次运行 start 会交互式配置
  - 之后运行 start 会提示使用已保存配置
  - 按 'r' 可以重新配置
  - VM2和VM3配置相同：都是明文侧=ens33，密文侧=ens34

EOF
}

#####################################################################
# 主程序
#####################################################################

main() {
    case "${1:-help}" in
        start|s)
            check_root
            smart_start
            ;;
        stop)
            check_root
            unload_module
            ;;
        restart|r)
            check_root
            unload_module
            echo ""
            smart_start
            ;;
        status|st)
            show_status
            ;;
        monitor|m)
            monitor
            ;;
        reset-stats|rs)
            check_root
            reset_stats
            ;;
        debug-on)
            check_root
            debug_on
            ;;
        debug-off)
            check_root
            debug_off
            ;;
        debug-log)
            check_root
            debug_log
            ;;
        set-internal|si)
            check_root
            set_device "internal" "$2"
            ;;
        set-external|se)
            check_root
            set_device "external" "$2"
            ;;
        install-autoload|ia)
            check_root
            install_autoload
            ;;
        uninstall-autoload|ua)
            check_root
            uninstall_autoload
            ;;
        compile|c)
            check_root
            compile_module
            ;;
        config)
            if [ -f "$CONFIG_FILE" ]; then
                cat "$CONFIG_FILE"
            else
                print_info "配置文件不存在"
            fi
            ;;
        log|l)
            dmesg | grep crypto_bridge | tail -20
            ;;
        help|h|--help|-h|"")
            show_help
            ;;
        *)
            print_error "未知命令: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"

