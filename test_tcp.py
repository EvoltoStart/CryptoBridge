#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP 测试脚本 - 用于测试加密/解密系统
拓扑: PC1(client) → 开发板1(加密) → 开发板2(解密) → PC2(server)
用法:
    服务端: python3 test_tcp.py server [port]
    客户端: python3 test_tcp.py client <server_ip> [port]
"""
import socket
import sys
import time

def show_help():
    print("=" * 70)
    print("TCP 加密/解密测试脚本")
    print("=" * 70)
    print()
    print("拓扑结构:")
    print("  PC1(Client) → 开发板1(加密) → 开发板2(解密) → PC2(Server)")
    print()
    print("用法:")
    print("  Server mode: python3 test_tcp.py server [port]")
    print("  Client mode: python3 test_tcp.py client <server_ip> [port]")
    print()
    print("示例:")
    print("  # 在 PC2 上启动服务器")
    print("  python3 test_tcp.py server 8888")
    print()
    print("  # 在 PC1 上启动客户端（连接到 PC2）")
    print("  python3 test_tcp.py client 192.168.1.200 8888")
    print()
    print("功能:")
    print("  - 双向数据传输测试")
    print("  - 显示原始数据和传输后的数据对比")
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
    """TCP 服务器模式 (PC2)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        
        print()
        print("=" * 70)
        print(" TCP 服务器 (PC2) - 接收解密后的数据")
        print("=" * 70)
        print()
        print("  监听地址: 0.0.0.0:%d" % port)
        print("  数据流向: PC1 → 开发板1(加密) → 开发板2(解密) → 本服务器")
        print()
        print("  按 Ctrl+C 停止")
        print("=" * 70)
        print()
        
        connection_count = 0
        
        while True:
            client, addr = sock.accept()
            connection_count += 1
            
            print("\n" + "─" * 70)
            print("📥 [连接 #%d] 来自 %s:%d" % (connection_count, addr[0], addr[1]))
            print("─" * 70)
            
            try:
                # 接收客户端发来的数据（应该已被解密）
                data = client.recv(4096)
                if data:
                    print()
                    print("✓ 接收到数据:")
                    print("  · 长度:   %d 字节" % len(data))
                    print("  · 十六进制: %s" % hex_dump(data, 64))
                    print("  · 文本:   %s" % safe_decode(data).strip())
                    print()
                    
                    # 准备回复数据（这将被加密后发送给客户端）
                    response = "SERVER-RESPONSE: Hello from PC2! Data received successfully.\n"
                    
                    print("📤 发送响应数据:")
                    print("  · 长度:   %d 字节" % len(response))
                    print("  · 十六进制: %s" % hex_dump(response.encode(), 64))
                    print("  · 文本:   %s" % response.strip())
                    print()
                    print("  ⚠️  注意: 此数据将经过 开发板2(加密) → 开发板1(解密) → PC1")
                    print()
                    
                    client.send(response.encode())
                    
                    print("✓ 响应已发送")
                    
                else:
                    print("  ⚠️  未收到数据")
                    
            except Exception as e:
                print("  ❌ 错误: %s" % str(e))
            finally:
                client.close()
                print()
                
    except KeyboardInterrupt:
        print("\n\n" + "=" * 70)
        print(" 服务器已停止")
        print("=" * 70)
        print("  总连接数: %d" % connection_count)
        print()
    except Exception as e:
        print("\n❌ 服务器错误: %s" % str(e))
    finally:
        sock.close()

def client(server_ip, port=8888):
    """TCP 客户端模式 (PC1)"""
    try:
        print()
        print("=" * 70)
        print(" TCP 客户端 (PC1) - 发送待加密的数据")
        print("=" * 70)
        print()
        print("  目标服务器: %s:%d" % (server_ip, port))
        print("  数据流向: 本客户端 → 开发板1(加密) → 开发板2(解密) → PC2")
        print()
        print("=" * 70)
        print()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10秒超时
        
        # 步骤1: 连接
        print("[步骤 1/3] 连接到服务器...")
        sock.connect((server_ip, port))
        print("           ✓ 已连接!")
        print()
        time.sleep(0.5)
        
        # 步骤2: 发送测试数据
        msg = "CLIENT-REQUEST: Hello from PC1! This is a test message for encryption.\n"
        
        print("[步骤 2/3] 发送测试数据...")
        print()
        print("  📤 原始数据 (将被加密):")
        print("     · 长度:   %d 字节" % len(msg))
        print("     · 十六进制: %s" % hex_dump(msg.encode(), 64))
        print("     · 文本:   %s" % msg.strip())
        print()
        print("  ⚠️  注意: 此数据将经过 开发板1 加密后发送")
        print()
        
        sock.send(msg.encode())
        print("           ✓ 数据已发送!")
        print()
        time.sleep(0.5)
        
        # 步骤3: 接收响应
        print("[步骤 3/3] 等待服务器响应...")
        print()
        
        try:
            response = sock.recv(4096)
            if response:
                print("  📥 接收到响应 (已解密):")
                print("     · 长度:   %d 字节" % len(response))
                print("     · 十六进制: %s" % hex_dump(response, 64))
                print("     · 文本:   %s" % safe_decode(response).strip())
                print()
                print("  ⚠️  注意: 此数据经过了 开发板2(加密) → 开发板1(解密)")
                print()
            else:
                print("  ⚠️  未收到响应")
                
        except socket.timeout:
            print("  ⏱️  超时 (未收到响应)")
            print()
        
        print("=" * 70)
        print(" 测试完成!")
        print("=" * 70)
        print()
        print("检查要点:")
        print("  1. PC2 服务器应该收到解密后的原始数据")
        print("  2. 开发板1 统计应该显示加密操作")
        print("  3. 开发板2 统计应该显示解密操作")
        print()
        print("查看统计命令:")
        print("  开发板1: cat /sys/kernel/crypto_bridge/stats")
        print("  开发板2: cat /sys/kernel/crypto_bridge/stats")
        print()
        
    except socket.timeout:
        print()
        print("❌ 连接超时")
        print()
        print("  请检查:")
        print("  · 服务器是否运行: %s:%d" % (server_ip, port))
        print("  · 网络连通性: ping %s" % server_ip)
        print("  · 路由配置")
        print("  · 开发板模块是否加载")
        print()
    except ConnectionRefusedError:
        print()
        print("❌ 连接被拒绝")
        print()
        print("  服务器未在 %s:%d 监听" % (server_ip, port))
        print("  请在 PC2 上运行: python3 test_tcp.py server %d" % port)
        print()
    except Exception as e:
        print()
        print("❌ 错误: %s" % str(e))
        print()
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
        client(server_ip, port)
    
    else:
        print("[ERROR] Invalid mode: %s" % mode)
        print()
        show_help()

