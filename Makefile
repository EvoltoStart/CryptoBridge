# Makefile for crypto_bridge kernel module
# 支持本地编译和交叉编译

# ========== 配置区域 ==========

# 内核源码目录
# 本地编译: 使用当前系统内核
# 交叉编译: 指定目标板内核源码路径
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# 交叉编译工具链
# 本地编译: 留空
# 交叉编译: 设置为目标架构的工具链前缀
ARCH ?=
CROSS_COMPILE ?=

# 当前目录
PWD := $(shell pwd)

# 模块名称
obj-m := crypto_bridge.o

# ========== 编译参数 ==========

# 构建基础命令
MAKE_OPTS := -C $(KERNELDIR) M=$(PWD)

# 如果指定了ARCH，添加到编译参数
ifneq ($(ARCH),)
    MAKE_OPTS += ARCH=$(ARCH)
endif

# 如果指定了CROSS_COMPILE，添加到编译参数
ifneq ($(CROSS_COMPILE),)
    MAKE_OPTS += CROSS_COMPILE=$(CROSS_COMPILE)
endif

# ========== 编译目标 ==========

# 默认目标（本地编译）
all:
	@echo "=========================================="
	@echo "  编译 crypto_bridge 内核模块"
	@echo "=========================================="
	@echo "编译模式: $(if $(ARCH),交叉编译,本地编译)"
ifneq ($(ARCH),)
	@echo "目标架构: $(ARCH)"
endif
ifneq ($(CROSS_COMPILE),)
	@echo "工具链: $(CROSS_COMPILE)gcc"
endif
	@echo "内核目录: $(KERNELDIR)"
	@echo "=========================================="
	@echo ""
	$(MAKE) $(MAKE_OPTS) modules
	@echo ""
	@echo "✓ 编译完成"
	@ls -lh *.ko 2>/dev/null || true

# 清理
clean:
	@echo "清理编译文件..."
	@$(MAKE) $(MAKE_OPTS) clean 2>/dev/null || true
	@rm -f *.ko *.o *.mod.* *.symvers *.order .*.cmd
	@rm -rf .tmp_versions/
	@echo "✓ 清理完成"

# 安装
install:
	$(MAKE) $(MAKE_OPTS) modules_install

# 查看模块信息
info:
	@if [ -f crypto_bridge.ko ]; then \
		echo "==========  模块信息  =========="; \
		modinfo crypto_bridge.ko; \
		echo ""; \
		echo "==========  文件信息  =========="; \
		file crypto_bridge.ko; \
		ls -lh crypto_bridge.ko; \
	else \
		echo "错误: crypto_bridge.ko 不存在，请先编译"; \
		exit 1; \
	fi

# 交叉编译快捷方式
cross:
	@echo "交叉编译模式（需要指定参数）"
	@echo ""
	@echo "示例:"
	@echo "  make cross ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KERNELDIR=~/kernel"
	@echo ""
	@echo "或者直接使用:"
	@echo "  make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KERNELDIR=~/kernel"

# 帮助信息
help:
	@echo "crypto_bridge 内核模块编译系统"
	@echo ""
	@echo "========== 本地编译 =========="
	@echo "  make                    编译模块（使用当前系统内核）"
	@echo "  make clean              清理编译文件"
	@echo "  make install            安装模块到系统"
	@echo "  make info               查看编译后的模块信息"
	@echo ""
	@echo "========== 交叉编译 =========="
	@echo "  make ARCH=<arch> CROSS_COMPILE=<prefix> KERNELDIR=<path>"
	@echo ""
	@echo "  参数说明:"
	@echo "    ARCH           - 目标架构 (arm, arm64, mips, x86 等)"
	@echo "    CROSS_COMPILE  - 交叉编译工具链前缀"
	@echo "    KERNELDIR      - 目标板内核源码路径"
	@echo ""
	@echo "  示例1: ARM 32位 (飞凌T113i)"
	@echo "    make ARCH=arm \\"
	@echo "         CROSS_COMPILE=arm-linux-gnueabihf- \\"
	@echo "         KERNELDIR=~/t113i_workspace/kernel"
	@echo ""
	@echo "  示例2: ARM 64位"
	@echo "    make ARCH=arm64 \\"
	@echo "         CROSS_COMPILE=aarch64-linux-gnu- \\"
	@echo "         KERNELDIR=~/kernel-aarch64"
	@echo ""
	@echo "  示例3: MIPS"
	@echo "    make ARCH=mips \\"
	@echo "         CROSS_COMPILE=mips-linux-gnu- \\"
	@echo "         KERNELDIR=~/kernel-mips"
	@echo ""
	@echo "========== 清理 =========="
	@echo "  make clean              清理编译文件"
	@echo ""
	@echo "========== 其他 =========="
	@echo "  make help               显示本帮助信息"
	@echo ""
	@echo "提示: 推荐使用脚本进行交叉编译"
	@echo "  ./build_cross.sh        自动化交叉编译脚本"
	@echo "  ./deploy_cross.sh       自动化部署脚本"
	@echo ""

.PHONY: all clean install info cross help

