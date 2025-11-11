#!/bin/sh
# crypto_bridge 开发板管理脚本
# 功能: 动态检测网卡、交互式配置、智能启动
# 兼容: busybox sh
# 作者: Meng

#####################################################################
# 配置
#####################################################################

# 脚本所在目录
SCRIPT_DIR=$(cd $(dirname $0) && pwd)
MODULE_PATH="$SCRIPT_DIR/crypto_bridge.ko"
SYSFS_PATH="/sys/kernel/crypto_bridge"
# 配置文件优先级：当前目录 > 用户主目录 > /tmp
if [ -w "$SCRIPT_DIR" ]; then
    CONFIG_FILE="$SCRIPT_DIR/.crypto_bridge.conf"
elif [ -w "$HOME" ]; then
    CONFIG_FILE="$HOME/.crypto_bridge.conf"
else
    CONFIG_FILE="/tmp/.crypto_bridge.conf"
fi

# 默认配置（简化版：固定加密/解密规则）
DEFAULT_INTERNAL_DEV="eth0"
DEFAULT_EXTERNAL_DEV="eth1"
DEFAULT_ENABLE=1
DEFAULT_XOR_KEY=170
DEFAULT_DEBUG=0
DEFAULT_MODIFY_BYTES=0  # 0=完整加密

#####################################################################
# 辅助函数
#####################################################################

print_banner() {
    echo "=============================================================="
    echo "  crypto_bridge 开发板管理工具"
    echo "  双开发板级联支持 - 完整payload加密"
    echo "  固定加密规则 + PRE_ROUTING钩子"
    echo "=============================================================="
    echo ""
}

print_success() { echo "[OK] $1"; }
print_error() { echo "[ERROR] $1"; }
print_info() { echo "[INFO] $1"; }
print_warn() { echo "[WARN] $1"; }

#####################################################################
# 配置管理
#####################################################################

save_config() {
    cat > "$CONFIG_FILE" <<EOF
# crypto_bridge 配置文件
# 简化版: 移除outbound_encrypt/inbound_decrypt参数
# 固定规则: internal收到→加密, external收到→解密
INTERNAL_DEV=$1
EXTERNAL_DEV=$2
ENABLE=$3
XOR_KEY=$4
MODIFY_BYTES=$5
DEBUG=$6
EOF
    print_success "配置已保存到 $CONFIG_FILE"
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        . "$CONFIG_FILE"
        return 0
    fi
    return 1
}

#####################################################################
# 模块操作
#####################################################################

load_module() {
    internal_dev="${1:-$DEFAULT_INTERNAL_DEV}"
    external_dev="${2:-$DEFAULT_EXTERNAL_DEV}"
    enable="${3:-$DEFAULT_ENABLE}"
    xor_key="${4:-$DEFAULT_XOR_KEY}"
    modify_bytes="${5:-$DEFAULT_MODIFY_BYTES}"
    debug="${6:-$DEFAULT_DEBUG}"
    
    # 检查模块文件
    if [ ! -f "$MODULE_PATH" ]; then
        print_error "模块文件不存在: $MODULE_PATH"
        echo ""
        echo "请确保 crypto_bridge.ko 与脚本在同一目录："
        echo "  当前脚本目录: $SCRIPT_DIR"
        echo "  需要的文件: $MODULE_PATH"
        echo ""
        echo "上传方法："
        echo "  scp crypto_bridge.ko root@<IP>:$SCRIPT_DIR/"
        exit 1
    fi
    
    # 卸载旧模块
    if lsmod | grep -q crypto_bridge; then
        print_info "卸载旧模块..."
        rmmod crypto_bridge 2>/dev/null || true
        sleep 1
    fi
    
    # 检查网卡
    if ! ip link show "$internal_dev" >/dev/null 2>&1; then
        print_error "内网侧网卡 $internal_dev 不存在"
        echo "可用网卡:"
        ip link show | grep -E "^[0-9]+:" | awk '{print "  " $2}' | sed 's/:$//'
        exit 1
    fi
    
    if ! ip link show "$external_dev" >/dev/null 2>&1; then
        print_error "外网侧网卡 $external_dev 不存在"
        echo "可用网卡:"
        ip link show | grep -E "^[0-9]+:" | awk '{print "  " $2}' | sed 's/:$//'
        exit 1
    fi
    
    # 启用 IP 转发
    print_info "启用 IP 转发..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
    
    # 加载模块（简化版：移除outbound_encrypt/inbound_decrypt）
    echo "加载模块..."
    params="internal_dev=$internal_dev external_dev=$external_dev enable=$enable xor_key=$xor_key modify_bytes=$modify_bytes debug=$debug"
    
    if insmod "$MODULE_PATH" $params; then
        if [ "$debug" = "0" ]; then
            debug_str="关闭"
        elif [ "$debug" = "1" ]; then
            debug_str="Level 1 (每10包)"
        else
            debug_str="Level 2 (每100包)"
        fi
        modify_str=$([ "$modify_bytes" = "0" ] && echo "完整payload" || echo "${modify_bytes}字节")
        
        print_success "模块已加载 (PRE_ROUTING钩子)"
        echo "  内网侧设备: $internal_dev (明文侧，连接PC/LAN)"
        echo "  外网侧设备: $external_dev (密文侧，连接对端板/WAN)"
        echo "  固定规则:"
        echo "    从 $internal_dev 收到 → 加密 (明文→密文)"
        echo "    从 $external_dev 收到 → 解密 (密文→明文)"
        echo "  XOR密钥: 0x$(printf '%02X' $xor_key) (十进制: $xor_key)"
        echo "  处理范围: $modify_str"
        echo "  调试模式: $debug_str (debug=$debug)"
        
        save_config "$internal_dev" "$external_dev" "$enable" "$xor_key" "$modify_bytes" "$debug"
        sleep 1
        echo ""
        echo "加载日志:"
        dmesg | grep crypto_bridge | tail -10 | sed 's/^/  /'
    else
        print_error "加载失败"
        dmesg | tail -15
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
        dmesg | grep crypto_bridge | tail -15 | sed 's/^/  /'
    else
        print_info "1. 模块未加载"
    fi
    echo ""
    
    # 2. 显示最终状态
    print_success "清理完成!"
    echo ""
    echo "最终状态:"
    if lsmod | grep -q crypto_bridge; then
        echo "  模块: 已加载 [WARN]"
    else
        echo "  模块: 未加载 [OK]"
    fi
    if [ -f "$CONFIG_FILE" ]; then
        echo "  配置: 保留 ($CONFIG_FILE)"
    else
        echo "  配置: 无"
    fi
}

#####################################################################
# 状态查看
#####################################################################

show_status() {
    if ! lsmod | grep -q crypto_bridge; then
        print_warn "模块未加载"
        return
    fi
    
    echo "模块状态: 运行中 (PRE_ROUTING钩子)"
    echo ""
    
    if [ -d "$SYSFS_PATH" ]; then
        int_dev=$(cat $SYSFS_PATH/internal_device 2>/dev/null || echo 'N/A')
        ext_dev=$(cat $SYSFS_PATH/external_device 2>/dev/null || echo 'N/A')
        echo "  内网侧设备: $int_dev (明文侧，连接PC/LAN)"
        echo "  外网侧设备: $ext_dev (密文侧，连接对端板/WAN)"
        echo ""
        echo "  固定规则:"
        echo "    从 $int_dev 收到 → 加密 (明文→密文)"
        echo "    从 $ext_dev 收到 → 解密 (密文→明文)"
        echo ""
    fi
    
    if [ -d "/sys/module/crypto_bridge/parameters" ]; then
        enable=$(cat /sys/module/crypto_bridge/parameters/enable 2>/dev/null || echo 'N/A')
        xor_key=$(cat /sys/module/crypto_bridge/parameters/xor_key 2>/dev/null || echo 'N/A')
        modify_bytes=$(cat /sys/module/crypto_bridge/parameters/modify_bytes 2>/dev/null || echo 'N/A')
        debug=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null || echo 'N/A')
        
        echo "  启用处理: $enable"
        
        if [ "$xor_key" != "N/A" ]; then
            echo "  XOR密钥: 0x$(printf '%02X' $xor_key) (十进制: $xor_key)"
        fi
        
        if [ "$modify_bytes" != "N/A" ]; then
            if [ "$modify_bytes" = "0" ]; then
                echo "  处理范围: 完整payload (安全)"
            else
                echo "  处理范围: 前${modify_bytes}字节 (⚠️不安全)"
            fi
        fi
        
        if [ "$debug" != "N/A" ]; then
            if [ "$debug" = "0" ]; then
                debug_str="关闭"
            elif [ "$debug" = "1" ]; then
                debug_str="Level 1 (每10包)"
            else
                debug_str="Level 2 (每100包)"
            fi
            echo "  调试模式: $debug_str (debug=$debug)"
        fi
    fi
    echo ""
    
    echo "统计信息:"
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
    type=$1
    device=$2
    
    if [ -z "$device" ]; then
        print_error "请指定网卡名称"
        exit 1
    fi
    
    if ! ip link show "$device" >/dev/null 2>&1; then
        print_error "网卡 $device 不存在"
        exit 1
    fi
    
    if [ "$type" = "internal" ]; then
        echo "$device" > $SYSFS_PATH/internal_device
        print_success "内网侧设备已切换到 $device"
    else
        echo "$device" > $SYSFS_PATH/external_device
        print_success "外网侧设备已切换到 $device"
    fi
    
    dmesg | tail -1
}

reset_stats() {
    if [ ! -f "$SYSFS_PATH/statistics" ]; then
        print_error "统计功能不可用"
        exit 1
    fi
    
    echo "reset" > $SYSFS_PATH/statistics
    print_success "统计已重置"
}

#####################################################################
# 监控功能
#####################################################################

monitor() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    print_info "实时监控 (按 Ctrl+C 退出)"
    echo ""
    
    # 检查是否有 watch 命令
    if command -v watch >/dev/null 2>&1; then
        watch -n 1 "cat $SYSFS_PATH/statistics 2>/dev/null"
    else
        # busybox 可能没有 watch，使用循环
            while true; do
            clear
            echo "crypto_bridge 统计 ($(date '+%Y-%m-%d %H:%M:%S'))"
            echo "=================================================="
            cat $SYSFS_PATH/statistics 2>/dev/null
            sleep 1
        done
    fi
}

debug_on() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    debug_status=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null)
    if [ "$debug_status" != "0" ]; then
        print_info "调试模式已经开启 (level=$debug_status)"
    else
        echo ""
        printf "设置调试级别 (1=每10包, 2=每100包) [默认: 1]: "
        read level
        level=${level:-1}
        
        echo $level > /sys/module/crypto_bridge/parameters/debug
        print_success "调试模式已开启 (Level $level)"
        echo ""
        echo "现在可以运行以下命令查看日志："
        echo "  $0 debug-log    # 实时查看日志"
        echo "  dmesg | grep -E 'ENC|DEC|HEX' | tail -20"
    fi
}

debug_off() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    debug_status=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null)
    if [ "$debug_status" = "0" ]; then
        print_info "调试模式已经关闭"
    else
        echo 0 > /sys/module/crypto_bridge/parameters/debug
        print_success "调试模式已关闭"
        echo ""
        echo "提示："
        echo "  - 关闭调试后不再记录详细日志"
        echo "  - 可以减少系统日志负担，提高性能"
        echo "  - 需要时可运行: $0 debug-on 重新开启"
    fi
}

debug_log() {
    if ! lsmod | grep -q crypto_bridge; then
        print_error "模块未加载"
        exit 1
    fi
    
    # 检查调试是否开启
    debug_status=$(cat /sys/module/crypto_bridge/parameters/debug 2>/dev/null)
    if [ "$debug_status" = "0" ]; then
        print_warn "调试模式未开启"
        echo ""
        printf "是否开启调试模式? [Y/n]: "
        read enable_debug
        case "$enable_debug" in
            [Nn]*)
                print_info "已取消"
                exit 0
                ;;
            *)
                printf "设置调试级别 (1=每10包, 2=每100包) [默认: 1]: "
                read level
                level=${level:-1}
                echo $level > /sys/module/crypto_bridge/parameters/debug
                print_success "调试模式已开启 (Level $level)"
                echo ""
                ;;
        esac
    else
        print_info "调试模式已开启 (level=$debug_status)"
        echo ""
        if [ "$debug_status" = "1" ]; then
            echo "当前级别: Level 1 (每10包打印协议+IP+hex dump)"
        else
            echo "当前级别: Level 2 (每100包打印协议+IP+hex dump)"
        fi
        echo ""
        echo "提示: 按 Ctrl+C 退出后，可运行 '$0 debug-off' 关闭调试"
        echo ""
    fi
    
    print_info "实时查看调试日志 (按 Ctrl+C 退出)"
    echo "=============================================================="
    echo ""
    
    # 清空旧日志（可选）
    printf "是否清空旧日志? [y/N]: "
    read clear_log
    case "$clear_log" in
        [Yy]*)
            dmesg -c > /dev/null
            print_info "日志已清空"
            echo ""
            ;;
    esac
    
    print_info "等待新日志... (发送测试数据以查看加密/解密过程)"
    echo "=============================================================="
    echo ""
    
    # BusyBox 兼容的实时日志查看
    last_line=$(dmesg | wc -l)
    
    echo "开始监控... (每秒刷新)"
    echo ""
    
    while true; do
        sleep 1
        current_line=$(dmesg | wc -l)
        
        if [ "$current_line" -gt "$last_line" ]; then
            new_logs=$(dmesg | tail -n +$((last_line + 1)) | grep -E "crypto_bridge|\[ENC\]|\[DEC\]|\[HEX")
            if [ -n "$new_logs" ]; then
                echo "$new_logs"
            fi
            last_line=$current_line
        fi
    done
}

#####################################################################
# 智能启动
#####################################################################

smart_start() {
    print_banner
    
    # 如果有配置文件,直接使用
    if load_config; then
        if [ "${DEBUG:-0}" = "0" ]; then
            debug_str="关闭"
        elif [ "${DEBUG:-0}" = "1" ]; then
            debug_str="Level 1 (每10包)"
        else
            debug_str="Level 2 (每100包)"
        fi
        modify_str=$([ "${MODIFY_BYTES:-0}" = "0" ] && echo "完整payload" || echo "${MODIFY_BYTES}字节")
        
        print_info "找到已保存的配置"
        echo "  内网侧设备: $INTERNAL_DEV (明文侧，连接PC/LAN)"
        echo "  外网侧设备: $EXTERNAL_DEV (密文侧，连接对端板/WAN)"
        echo "  固定规则:"
        echo "    从 $INTERNAL_DEV 收到 → 加密 (明文→密文)"
        echo "    从 $EXTERNAL_DEV 收到 → 解密 (密文→明文)"
        echo "  启用处理: ${ENABLE:-$DEFAULT_ENABLE}"
        echo "  XOR密钥: 0x$(printf '%02X' ${XOR_KEY:-$DEFAULT_XOR_KEY})"
        echo "  处理范围: $modify_str"
        echo "  调试模式: $debug_str"
        echo ""
        
        printf "使用此配置? [Y/n/r(重新配置)]: "
        read use_config
        
        case "$use_config" in
            [Rr]*)
                interactive_config
                ;;
            [Nn]*)
                print_info "已取消"
                exit 0
                ;;
            *)
                load_module "$INTERNAL_DEV" "$EXTERNAL_DEV" \
                    "${ENABLE:-$DEFAULT_ENABLE}" \
                    "${XOR_KEY:-$DEFAULT_XOR_KEY}" \
                    "${MODIFY_BYTES:-$DEFAULT_MODIFY_BYTES}" \
                    "${DEBUG:-$DEFAULT_DEBUG}"
                ;;
        esac
    else
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
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')
    
    echo ""
    echo "可用网卡:"
    i=1
    for iface in $interfaces; do
        state=$(ip link show "$iface" | grep -o 'state [A-Z]*' | awk '{print $2}')
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -o 'inet [0-9\.]*' | awk '{print $2}')
        
        if [ -n "$ip_addr" ]; then
            echo "  [$i] $iface ($state) - $ip_addr"
        else
            echo "  [$i] $iface ($state) - 无IP"
        fi
        i=$((i+1))
    done
    echo ""
    
    echo "配置说明："
    echo "  - internal_dev: 明文侧网卡（连接PC/内网）"
    echo "  - external_dev: 密文侧网卡（连接对端开发板/外网）"
    echo "  - 固定规则: internal收到→加密, external收到→解密"
    echo ""
    
    # 选择内网侧设备
    printf "选择内网侧设备 (连接PC) [1-$((i-1))] 或网卡名 [默认: $DEFAULT_INTERNAL_DEV]: "
    read int_choice
    
    if [ -z "$int_choice" ]; then
        INTERNAL_DEV="$DEFAULT_INTERNAL_DEV"
    elif echo "$int_choice" | grep -qE '^[0-9]+$'; then
        j=1
        for iface in $interfaces; do
            if [ "$j" -eq "$int_choice" ]; then
                INTERNAL_DEV="$iface"
                break
            fi
            j=$((j+1))
        done
        if [ -z "$INTERNAL_DEV" ]; then
            INTERNAL_DEV="$int_choice"
        fi
    else
        INTERNAL_DEV="$int_choice"
    fi
    
    if [ -z "$INTERNAL_DEV" ]; then
        print_error "内网侧设备不能为空"
        exit 1
    fi
    
    # 选择外网侧设备
    printf "选择外网侧设备 (连接对端板) [1-$((i-1))] 或网卡名 [默认: $DEFAULT_EXTERNAL_DEV]: "
    read ext_choice
    
    if [ -z "$ext_choice" ]; then
        EXTERNAL_DEV="$DEFAULT_EXTERNAL_DEV"
    elif echo "$ext_choice" | grep -qE '^[0-9]+$'; then
        j=1
        for iface in $interfaces; do
            if [ "$j" -eq "$ext_choice" ]; then
                EXTERNAL_DEV="$iface"
                break
            fi
            j=$((j+1))
        done
        if [ -z "$EXTERNAL_DEV" ]; then
            EXTERNAL_DEV="$ext_choice"
        fi
    else
        EXTERNAL_DEV="$ext_choice"
    fi
    
    if [ -z "$EXTERNAL_DEV" ]; then
        print_error "外网侧设备不能为空"
        exit 1
    fi
    
    # 参数配置（简化版：移除outbound_encrypt/inbound_decrypt）
    echo ""
    printf "启用payload处理? [Y/n]: "
    read enable_choice
    case "$enable_choice" in
        [Nn]*)
            ENABLE=0
            ;;
        *)
            ENABLE=1
            ;;
    esac
    
    echo ""
    echo "固定规则说明:"
    echo "  - 从 internal_dev 收到的数据 → 自动加密 (明文→密文)"
    echo "  - 从 external_dev 收到的数据 → 自动解密 (密文→明文)"
    echo "  - 两块开发板配置完全相同，只需指定网卡名称"
    echo ""
    
    printf "XOR密钥 (0-255) [默认: $DEFAULT_XOR_KEY]: "
    read key_choice
    XOR_KEY="${key_choice:-$DEFAULT_XOR_KEY}"
    
    printf "处理字节数 (0=完整payload,推荐) [默认: $DEFAULT_MODIFY_BYTES]: "
    read bytes_choice
    MODIFY_BYTES="${bytes_choice:-$DEFAULT_MODIFY_BYTES}"
    
    printf "启用调试模式? (0=关闭, 1=每10包, 2=每100包) [默认: $DEFAULT_DEBUG]: "
    read debug_choice
    DEBUG="${debug_choice:-$DEFAULT_DEBUG}"
    
    echo ""
    if [ "$DEBUG" = "0" ]; then
        debug_str="关闭"
    elif [ "$DEBUG" = "1" ]; then
        debug_str="Level 1 (每10包: 协议+IP+hex)"
    else
        debug_str="Level 2 (每100包: 协议+IP+hex)"
    fi
    modify_str=$([ "$MODIFY_BYTES" = "0" ] && echo "完整payload (安全)" || echo "${MODIFY_BYTES}字节 (⚠️不安全)")
    
    echo "配置摘要:"
    echo "  内网侧设备: $INTERNAL_DEV (明文侧，连接PC/LAN)"
    echo "  外网侧设备: $EXTERNAL_DEV (密文侧，连接对端板/WAN)"
    echo "  固定规则:"
    echo "    从 $INTERNAL_DEV 收到 → 加密 (明文→密文)"
    echo "    从 $EXTERNAL_DEV 收到 → 解密 (密文→明文)"
    echo "  启用处理: $ENABLE"
    echo "  XOR密钥: 0x$(printf '%02X' $XOR_KEY) (十进制: $XOR_KEY)"
    echo "  处理范围: $modify_str"
    echo "  调试模式: $debug_str"
    echo ""
    
    printf "继续? [Y/n]: "
    read confirm
    case "$confirm" in
        [Nn]*)
            print_info "已取消"
            exit 0
            ;;
    esac
    
    load_module "$INTERNAL_DEV" "$EXTERNAL_DEV" "$ENABLE" "$XOR_KEY" "$MODIFY_BYTES" "$DEBUG"
}

#####################################################################
# 开机自动加载
#####################################################################

install_autoload() {
    print_banner
    print_info "配置开机自动加载..."
    echo ""
    
    if [ ! -f "$MODULE_PATH" ]; then
        print_error "找不到模块文件: $MODULE_PATH"
        exit 1
    fi
    
    # 加载配置
    if load_config; then
        internal_dev=$INTERNAL_DEV
        external_dev=$EXTERNAL_DEV
        enable=${ENABLE:-$DEFAULT_ENABLE}
        xor_key=${XOR_KEY:-$DEFAULT_XOR_KEY}
        modify_bytes=${MODIFY_BYTES:-$DEFAULT_MODIFY_BYTES}
        debug=${DEBUG:-$DEFAULT_DEBUG}
    else
        internal_dev=$DEFAULT_INTERNAL_DEV
        external_dev=$DEFAULT_EXTERNAL_DEV
        enable=$DEFAULT_ENABLE
        xor_key=$DEFAULT_XOR_KEY
        modify_bytes=$DEFAULT_MODIFY_BYTES
        debug=$DEFAULT_DEBUG
    fi
    
    echo "使用配置:"
    echo "  内网侧: $internal_dev (明文侧)"
    echo "  外网侧: $external_dev (密文侧)"
    echo "  固定规则: internal收到→加密, external收到→解密"
    echo "  XOR密钥: 0x$(printf '%02X' $xor_key)"
    echo ""
    
    # 创建启动脚本
    cat > /etc/init.d/S99crypto-bridge <<EOF
#!/bin/sh

case "\$1" in
  start)
    echo "Starting crypto_bridge..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
    insmod $MODULE_PATH internal_dev=$internal_dev external_dev=$external_dev enable=$enable xor_key=$xor_key modify_bytes=$modify_bytes debug=$debug
    ;;
  stop)
    echo "Stopping crypto_bridge..."
    rmmod crypto_bridge 2>/dev/null || true
    ;;
  restart)
    \$0 stop
    sleep 1
    \$0 start
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart}"
    exit 1
    ;;
esac
EOF
    
    chmod +x /etc/init.d/S99crypto-bridge
    
    print_success "开机自动加载已配置"
    echo "启动脚本: /etc/init.d/S99crypto-bridge"
    echo ""
    echo "管理命令:"
    echo "  /etc/init.d/S99crypto-bridge start"
    echo "  /etc/init.d/S99crypto-bridge stop"
    echo "  /etc/init.d/S99crypto-bridge restart"
}

uninstall_autoload() {
    if [ -f /etc/init.d/S99crypto-bridge ]; then
        print_info "移除开机自动加载..."
        rm -f /etc/init.d/S99crypto-bridge
        print_success "已移除"
    else
        print_info "未配置开机自动加载"
    fi
}

#####################################################################
# 帮助信息
#####################################################################

show_help() {
    cat <<EOF
crypto_bridge 开发板管理工具
双开发板级联支持 - 完整payload加密

用法: $0 <命令> [选项]

命令:
  start              启动模块 (智能判断: 有配置直接用,无配置则交互)
  stop               停止模块 (自动清理)
  restart            重启模块
  
  status             查看状态和统计
  monitor            实时监控统计信息
  debug-on           开启调试模式
  debug-off          关闭调试模式
  debug-log          实时查看加密/解密日志 (自动开启调试)
  reset-stats        重置统计计数器
  
  set-internal <网卡>   动态切换内网侧设备
  set-external <网卡>   动态切换外网侧设备
  
  install-autoload   配置开机自动加载
  uninstall-autoload 移除开机自动加载
  
  config             显示当前配置文件
  log                查看内核日志
  
  help               显示帮助

主要特性:
  🎯 重大简化: 移除outbound_encrypt/inbound_decrypt参数
  🎯 固定规则: internal收到→加密, external收到→解密
  🔧 使用PRE_ROUTING钩子点 (每个包只触发一次)
  ✅ 双开发板配置完全相同 (大幅简化配置)
  ✅ 完整payload加密 (modify_bytes=0默认)
  ✅ ICMP/ICMPv6完整支持

双开发板配置说明 (超简化版):
  - 两块板配置完全相同，只需指定网卡名称
  - internal_dev: 明文侧网卡（连接PC/LAN）
  - external_dev: 密文侧网卡（连接对端板/WAN）
  - 固定规则: 从internal收到→加密, 从external收到→解密

拓扑示例:
  PC1 ----[ens33 板1 ens34]----[ens33 板2 ens34]---- PC2
  
  板1配置: internal_dev=ens33 external_dev=ens34
  板2配置: internal_dev=ens34 external_dev=ens33
  (两板配置相同，只需选择正确的网卡名称！)

示例:

  1. 首次启动 (会进入交互式配置):
     $0 start

  2. 再次启动 (使用已保存配置):
     $0 start
     # 按 Y 使用配置，按 R 重新配置

  3. 查看状态:
     $0 status

  4. 动态切换设备 (无需重启):
     $0 set-internal eth2
     $0 set-external wlan0

  5. 实时监控:
     $0 monitor

  6. 查看加密/解密日志 (调试):
     $0 debug-on               # 开启调试模式 (可选level 1或2)
     $0 debug-log              # 实时查看数据加密/解密过程
     $0 debug-off              # 关闭调试模式
     
     调试级别说明:
       Level 1: 每10包打印 (协议+IP+方向+hex dump)
       Level 2: 每100包打印 (协议+IP+方向+hex dump)

  7. 配置开机自动加载:
     $0 install-autoload

配置文件: $CONFIG_FILE
模块文件: $MODULE_PATH
sysfs接口: $SYSFS_PATH

提示:
  - 首次运行 start 会交互式配置 (检测网卡)
  - 之后运行 start 会提示使用已保存配置
  - 按 'r' 可以重新配置
  - 确保 crypto_bridge.ko 与脚本在同一目录
  - 大幅简化配置，双板配置完全相同！
  - 使用PRE_ROUTING钩子，每个包只处理一次
  - 默认完整加密payload (modify_bytes=0)

EOF
}

#####################################################################
# 主程序
#####################################################################

main() {
    case "${1:-help}" in
        start|s)
            smart_start
            ;;
        stop)
            unload_module
            ;;
        restart|r)
            unload_module
            echo ""
            smart_start
            ;;
        status|st)
            show_status
            ;;
        set-internal|si)
            set_device "internal" "$2"
            ;;
        set-external|se)
            set_device "external" "$2"
            ;;
        reset-stats|rs)
            reset_stats
            ;;
        monitor|m)
            monitor
            ;;
        debug-on)
            debug_on
            ;;
        debug-off)
            debug_off
            ;;
        debug-log|dl|d)
            debug_log
            ;;
        log|l)
            dmesg | grep crypto_bridge | tail -30
            ;;
        install-autoload|ia)
            install_autoload
            ;;
        uninstall-autoload|ua)
            uninstall_autoload
            ;;
        config)
            if [ -f "$CONFIG_FILE" ]; then
                cat "$CONFIG_FILE"
            else
                print_info "配置文件不存在"
            fi
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

