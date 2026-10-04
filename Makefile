# minifrpc —— 纯 C 极简 frpc 客户端（兼容 Go frp 0.71.0）
#
# 用法：
#   make                                   # gcc 编译（先自动清理上次产物与依赖）
#   make static                            # musl-gcc 静态编译
#   make STRIP=aarch64-linux-musl-strip    # 用独立 strip 工具（替代链接器 -s）
#   make CC=aarch64-linux-musl-gcc STRIP=aarch64-linux-musl-strip   # 交叉编译
#   make clean                             # 清理产物与依赖编译目录
#   make distclean                         # 彻底清理（含依赖库）
#
# 说明：
#   - make 会先自动删除上次的编译产物与依赖库（不同架构产物不复用），再编译
#   - 依赖（json-c / libevent）源码位于 vendor/，本地编译，不联网
#   - strip：默认用链接器 -s 完成；若指定 STRIP=xxx 则改用独立 strip 工具
#   - 版本号 = 日期 + git 短哈希（无 git 则仅日期）

CC    ?= gcc
STRIP ?=

# 版本号生成
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null)
DATE     := $(shell date +%Y%m%d)
ifeq ($(GIT_HASH),)
VERSION  := $(DATE)
else
VERSION  := $(DATE)-$(GIT_HASH)
endif

# 目录
SRC_DIR    := src
CRYPTO_DIR := src/crypto
VENDOR_DIR := vendor/tomlc17
BUILD_DIR  := build

# 依赖库目录：musl 编译器用 deps-musl，否则用 deps
ifneq ($(findstring musl,$(CC)),)
DEPS_DIR := deps-musl
else
DEPS_DIR := deps
endif

DEPS_ROOT    := $(abspath $(DEPS_DIR))
JSONC_STATIC := $(DEPS_DIR)/lib/libjson-c.a
EVENT_STATIC := $(DEPS_DIR)/lib/libevent_core.a

# 依赖统一最小体积编译选项
DEPS_CFLAGS := -Os -ffunction-sections -fdata-sections
CMAKE_MIN   := -DCMAKE_POLICY_VERSION_MINIMUM=3.5
# 交叉编译时避免 cmake try_compile 运行目标二进制
CMAKE_CROSS := -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY

# 源文件
SRCS := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/log.c \
	$(SRC_DIR)/config.c \
	$(SRC_DIR)/base64.c \
	$(SRC_DIR)/frp_msg.c \
	$(SRC_DIR)/client.c \
	$(SRC_DIR)/yamux.c \
	$(SRC_DIR)/proxyproto.c \
	$(CRYPTO_DIR)/md5.c \
	$(CRYPTO_DIR)/sha1.c \
	$(CRYPTO_DIR)/kdf.c \
	$(CRYPTO_DIR)/aes.c \
	$(VENDOR_DIR)/tomlc17.c

OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

TARGET := $(BUILD_DIR)/minifrpc

# 编译选项（本体同样最小体积）
CFLAGS  += -Os -ffunction-sections -fdata-sections -fno-stack-protector -Wall
CFLAGS  += -DVERSION=\"$(VERSION)\"
CFLAGS  += -I$(SRC_DIR) -I$(CRYPTO_DIR) -I$(VENDOR_DIR)
CFLAGS  += -I$(DEPS_DIR)/include

# 链接（strip：STRIP 为空时用链接器 -s；否则交给 $(STRIP)）
ifeq ($(findstring musl,$(CC)),)
LDFLAGS += -Wl,--gc-sections -L$(DEPS_DIR)/lib -ljson-c -levent_core
else
LDFLAGS += -static -Wl,--gc-sections -L$(DEPS_DIR)/lib -ljson-c -levent_core
endif

ifeq ($(STRIP),)
LDFLAGS += -s
endif

.PHONY: all static build clean distclean preclean

# ---- 顶层目标：先清理（不同架构不复用），再编译 ----

all: preclean
	@$(MAKE) build CC=$(CC) STRIP=$(STRIP)

static: preclean
	@$(MAKE) build CC=musl-gcc STRIP=$(STRIP)

# 仅编译，不清理（内部使用）
build: $(TARGET)

preclean:
	@echo "==> 清理上次编译产物与依赖库（不同架构不复用）"
	@rm -rf $(BUILD_DIR) deps deps-musl vendor/json-c/build vendor/libevent/build

# ---- 依赖库（本地 vendor 源码编译，不联网） ----

$(JSONC_STATIC): vendor/json-c/CMakeLists.txt
	@echo "==> 编译 json-c（$(CC)，最小体积）"
	cd vendor/json-c && rm -rf build && \
	cmake -B build -DCMAKE_C_COMPILER=$(CC) -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS="$(DEPS_CFLAGS)" \
		-DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF \
		-DBUILD_APPS=OFF -DDISABLE_BSYMBOLIC=ON \
		$(CMAKE_MIN) $(CMAKE_CROSS) -DCMAKE_INSTALL_PREFIX=$(DEPS_ROOT) >/dev/null && \
	cmake --build build -j4 >/dev/null && \
	cmake --install build >/dev/null

$(EVENT_STATIC): vendor/libevent/CMakeLists.txt
	@echo "==> 编译 libevent（$(CC)，最小体积）"
	cd vendor/libevent && rm -rf build && \
	cmake -B build -DCMAKE_C_COMPILER=$(CC) -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS="$(DEPS_CFLAGS)" \
		-DBUILD_SHARED_LIBS=OFF -DEVENT__LIBRARY_TYPE=STATIC \
		-DEVENT__DISABLE_TESTS=ON -DEVENT__DISABLE_SAMPLES=ON \
		-DEVENT__DISABLE_REGRESS=ON -DEVENT__DISABLE_BENCHMARK=ON \
		-DEVENT__DISABLE_OPENSSL=ON \
		$(CMAKE_MIN) $(CMAKE_CROSS) -DCMAKE_INSTALL_PREFIX=$(DEPS_ROOT) >/dev/null && \
	cmake --build build -j4 >/dev/null && \
	cmake --install build >/dev/null

# ---- 本体 ----

$(TARGET): $(OBJS) $(JSONC_STATIC) $(EVENT_STATIC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
ifneq ($(STRIP),)
	@echo "==> strip: $(STRIP)"
	@$(STRIP) $@
endif
	@echo "构建完成: $@ (版本 $(VERSION))"
	@ls -lh $@
	@file $@ | grep -q "statically linked" && echo "静态链接: 是" || true
# 依赖库需在源文件编译前就绪（order-only）
$(OBJS): | $(JSONC_STATIC) $(EVENT_STATIC)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) deps deps-musl
	rm -rf vendor/json-c/build vendor/libevent/build

distclean: clean
	rm -rf deps deps-musl
