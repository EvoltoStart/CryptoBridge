#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP 测试脚本 - 用于测试加密/解密系统
拓扑: PC1(client) → 开发板1(加密) → 开发板2(解密) → PC2(server)
用法:
    服务端: python3 test_udp.py server [port]
    客户端: python3 test_udp.py client <server_ip> [port] [count]
"""
import socket
import sys
import time

def show_help():
    print("=" * 70)
    print("UDP 加密/解密测试脚本")
    print("=" * 70)
    print()
    print("拓扑结构:")
    print("  PC1(Client) → 开发板1(加密) → 开发板2(解密) → PC2(Server)")
    print()
    print("用法:")
    print("  Server mode: python3 test_udp.py server [port]")
    print("  Client mode: python3 test_udp.py client <server_ip> [port] [count]")
    print()
    print("示例:")
    print("  # 在 PC2 上启动服务器")
    print("  python3 test_udp.py server 8888")
    print()
    print("  # 在 PC1 上发送 10 个数据包")
    print("  python3 test_udp.py client 192.168.1.200 8888 10")
    print()
    print("  # 发送 50 个数据包")
    print("  python3 test_udp.py client 192.168.1.200 8888 50")
    print()
    print("功能:")
    print("  - 多数据包传输测试")
    print("  - 显示每个数据包的原始内容和接收内容")
    print("  - 验证加密/解密是否正常工作")
    print()
    sys.exit(0)

def hex_dump(data, max_bytes=32):
    """将数据转换为十六进制字符串"""
    bytes_to_show = min(len(data), max_bytes)
    hex_str = ' '.join('%02X' % b for b in data[:bytes_to_show])
    if len(data) > max_bytes:
        hex_str += ' ...'
    return hex_str

def safe_decode(data):
    """安全地解码数据为文本"""
    try:
        return data.decode('utf-8', errors='replace')
    except:
        return repr(data)

def server(port=8888):
    """UDP 服务器模式 (PC2)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        
        print()
        print("=" * 70)
        print(" UDP 服务器 (PC2) - 接收解密后的数据")
        print("=" * 70)
        print()
        print("  监听地址: 0.0.0.0:%d" % port)
        print("  数据流向: PC1 → 开发板1(加密) → 开发板2(解密) → 本服务器")
        print()
        print("  按 Ctrl+C 停止")
        print("=" * 70)
        print()
        
        packet_count = 0
        first_packet_hex = None
        
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                packet_count += 1
                
                # 保存第一个数据包用于对比
                if packet_count == 1:
                    first_packet_hex = hex_dump(data, 16)
                
                # 每10个数据包显示一次详细信息，否则只显示摘要
                if packet_count % 10 == 1 or packet_count <= 3:
                    print("\n" + "─" * 70)
                    print("📥 [数据包 #%d] 来自 %s:%d" % (packet_count, addr[0], addr[1]))
                    print("─" * 70)
                    print()
                    print("  接收到的数据 (已解密):")
                    print("    · 长度:   %d 字节" % len(data))
                    print("    · 十六进制: %s" % hex_dump(data, 64))
                    print("    · 文本:   %s" % safe_decode(data).strip())
                    print()
                else:
                    # 简洁输出
                    print("  [#%03d] %d 字节 - %s" % (packet_count, len(data), safe_decode(data).strip()[:50]))
                
            except Exception as e:
                print("  ❌ 错误: %s" % str(e))
                
    except KeyboardInterrupt:
        print("\n\n" + "=" * 70)
        print(" 服务器已停止")
        print("=" * 70)
        print()
        print("  统计信息:")
        print("    · 总接收数据包: %d" % packet_count)
        if first_packet_hex:
            print("    · 第一个数据包十六进制: %s" % first_packet_hex)
        print()
        print("  提示: 对比 PC1 发送的原始数据，验证解密是否正确")
        print()
    except Exception as e:
        print("\n❌ 服务器错误: %s" % str(e))
    finally:
        sock.close()

def client(server_ip, port=8888, count=10):
    """UDP 客户端模式 (PC1)"""
    try:
        print()
        print("=" * 70)
        print(" UDP 客户端 (PC1) - 发送待加密的数据")
        print("=" * 70)
        print()
        print("  目标服务器: %s:%d" % (server_ip, port))
        print("  数据包数量: %d" % count)
        print("  数据流向: 本客户端 → 开发板1(加密) → 开发板2(解密) → PC2")
        print()
        print("=" * 70)
        print()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        success = 0
        first_packet_hex = None
        
        for i in range(1, count + 1):
            try:
                # 构造测试数据
                msg = "UDP-PACKET-%03d: Test data for encryption from PC1" % i
                
                # 显示详细信息（前3个和每10个）
                if i <= 3 or i % 10 == 1:
                    print("\n📤 [数据包 #%d/%d]" % (i, count))
                    print("   原始数据 (将被加密):")
                    print("     · 长度:   %d 字节" % len(msg))
                    print("     · 十六进制: %s" % hex_dump(msg.encode(), 64))
                    print("     · 文本:   %s" % msg)
                    if i == 1:
                        first_packet_hex = hex_dump(msg.encode(), 16)
                        print()
                        print("   ⚠️  前8字节将被 XOR 加密 (key=0xAA)")
                    print()
                    print("   发送中...", end=' ')
                else:
                    print("  [#%03d/%03d] 发送..." % (i, count), end=' ')
                
                sock.sendto(msg.encode(), (server_ip, port))
                print("✓")
                
                success += 1
                
                # 短暂延迟，避免丢包
                if i < count:
                    time.sleep(0.05)
                
            except Exception as e:
                print("❌ 失败 - %s" % str(e))
        
        print()
        print("=" * 70)
        print(" 发送完成!")
        print("=" * 70)
        print()
        print("  统计信息:")
        print("    · 已发送: %d/%d 数据包" % (success, count))
        print("    · 成功率: %.1f%%" % (success * 100.0 / count))
        if first_packet_hex:
            print("    · 第一个数据包十六进制: %s" % first_packet_hex)
        print()
        print("  提示:")
        print("    · UDP 是无连接协议，无响应确认")
        print("    · 查看 PC2 服务器输出以验证接收")
        print("    · 对比十六进制数据，验证加密/解密")
        print()
        print("  检查开发板统计:")
        print("    开发板1: cat /sys/kernel/crypto_bridge/stats")
        print("    开发板2: cat /sys/kernel/crypto_bridge/stats")
        print()
        
    except Exception as e:
        print("\n❌ 错误: %s" % str(e))
    finally:
        sock.close()

if __name__ == '__main__':
    # 参数解析
    if len(sys.argv) < 2:
        show_help()
    
    mode = sys.argv[1].lower()
    
    if mode in ['-h', '--help', 'help']:
        show_help()
    
    elif mode == 'server':
        # 服务器模式
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
        server(port)
    
    elif mode == 'client':
        # 客户端模式
        if len(sys.argv) < 3:
            print("[ERROR] Missing server IP address")
            print()
            show_help()
        
        server_ip = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 8888
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 10
        client(server_ip, port, count)
    
    else:
        print("[ERROR] Invalid mode: %s" % mode)
        print()
        show_help()

