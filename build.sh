#!/usr/bin/env bash
#
# build.sh — 在 Ubuntu x86_64 本地编译 xfrpc
# 参照 .github/workflows/linux.yml 中 x86_64-linux-musl 矩阵项的流程：
#   1. 下载 musl-gcc 工具链到 x86_64-linux-musl-cross（等价 lmq8267/dl-musl）
#   2. 交叉编译依赖库 zlib + mbedTLS + json-c + libevent → sysroot（带缓存）
#   3. 编译 xfrpc → bin/
#   4. 打包运行时动态库到 bin/
#
# 用法:
#   ./build.sh              # 完整编译（带依赖库缓存）
#   ./build.sh --no-cache   # 强制重新编译依赖库
#   ./build.sh --clean      # 清理所有构建产物（含 sysroot / 工具链）后退出
#   ./build.sh --help, -h   # 显示本帮助
#
# 依赖（Ubuntu 上需先安装）:
#   sudo apt install -y build-essential curl tar cmake make file

set -euo pipefail

# ============================================================
# 配置（与 .github/workflows/linux.yml env 保持一致）
# ============================================================
ZLIB_VER=1.3.1
MBEDTLS_VER=3.6.5
JSONC_VER=0.19
JSONC_TAG=json-c-0.19-20260627
LIBEVENT_VER=2.2.2-alpha
LIBEVENT_TAG=release-2.2.2-alpha

# 与 linux.yml matrix 中 x86_64-linux-musl 项一致
TARGET=x86_64-linux-musl
ARCH_FLAG=linux-x86_64

SRC_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# 路径（与 linux.yml 一致，方便缓存复用）
# 必须用绝对路径：编译依赖库时会 cd 进源码子目录（如 zlib-src）再调用 $CC 和
# ./configure，相对路径 ./x86_64-linux-musl-cross、./sysroot 在子目录中会失效
# （症状：zlib configure 报 "Compiler error reporting is too harsh"）
TOOLCHAIN_DIR="$SRC_ROOT/${TARGET}-cross"
SYSROOT="$SRC_ROOT/sysroot"
BUILD_DIR=bin

# 选项
USE_CACHE=1
DO_CLEAN=0

# ============================================================
# 参数解析
# ============================================================
print_help() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    print_help ;;
    --clean)      DO_CLEAN=1 ;;
    --no-cache)   USE_CACHE=0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
  shift
done

cd "$SRC_ROOT"

# ============================================================
# 颜色 & 日志
# ============================================================
if [ -t 1 ]; then
  C_BLUE=$'\033[36m'; C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_RESET=$'\033[0m'
else
  C_BLUE=C_GREEN=C_RED=C_RESET=''
fi
info() { printf '%s%s%s\n' "$C_BLUE" "$*" "$C_RESET"; }
ok()   { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
err()  { printf '%s%s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }
die()  { err "错误: $*"; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "缺少依赖: $1（请先安装）"; }
require curl
require tar
require cmake
require make
require file

# ============================================================
# 步骤 1：下载 musl-gcc 工具链（等价 lmq8267/dl-musl action）
# ============================================================
setup_toolchain() {
  if [ -x "$TOOLCHAIN_DIR/bin/${TARGET}-gcc" ]; then
    info "==> 已存在 musl 工具链: $TOOLCHAIN_DIR"
    return
  fi

  info "==> 下载 musl-gcc 工具链到 $TOOLCHAIN_DIR ..."
  local url="https://github.com/lmq8267/Toolchain/releases/download/musl-cross/${TARGET}-cross.tgz"
  local tmp_tar; tmp_tar=$(mktemp)
  curl -fL "$url" -o "$tmp_tar" || die "下载失败: $url"
  mkdir -p "$(dirname "$TOOLCHAIN_DIR")"
  tar xzf "$tmp_tar" -C "$(dirname "$TOOLCHAIN_DIR")"
  rm -f "$tmp_tar"

  [ -x "$TOOLCHAIN_DIR/bin/${TARGET}-gcc" ] \
    || die "工具链解压后未找到 $TOOLCHAIN_DIR/bin/${TARGET}-gcc"
  ok "✓ musl 工具链就绪"
  "$TOOLCHAIN_DIR/bin/${TARGET}-gcc" -v
}

# 工具链可执行文件（与 dl-musl 设置一致）
export CC="$TOOLCHAIN_DIR/bin/${TARGET}-gcc"
export CXX="$TOOLCHAIN_DIR/bin/${TARGET}-g++"
export CPP="$TOOLCHAIN_DIR/bin/${TARGET}-cpp"
export AR="$TOOLCHAIN_DIR/bin/${TARGET}-ar"
export LD="$TOOLCHAIN_DIR/bin/${TARGET}-ld"
export RANLIB="$TOOLCHAIN_DIR/bin/${TARGET}-ranlib"
export STRIP="$TOOLCHAIN_DIR/bin/${TARGET}-strip"

# dl-musl 注入 -static 到环境变量（xfrpc 步骤会显式 unset）
export CFLAGS="-static -Os -ffunction-sections -fdata-sections"
export CXXFLAGS="$CFLAGS"
export CPPFLAGS="$CFLAGS"
export LDFLAGS="-static"

# ============================================================
# 分库缓存辅助函数
# ============================================================
# 标记文件目录（放 sysroot 下，随 sysroot 一起 --clean 删除）
_DEPCACHE_DIR="$SYSROOT/.cache"

# _dep_cached <dep_name> <expected_version> [artifact_paths...]
#   返回 0 表示缓存命中（标记版本精确匹配且所有产物文件均存在），1 表示需重编
#   注意：expected_version 应为该库版本 + 所有上游依赖版本的拼接，
#         这样上游版本变更时 marker 会自动失效，下游随之重编
_dep_cached() {
  local name="$1" expected="$2"; shift 2
  local marker="$_DEPCACHE_DIR/$name"
  [ "$USE_CACHE" = 1 ] || return 1
  # 版本标记文件必须存在且内容精确匹配
  [ -f "$marker" ] || return 1
  [ "$(cat "$marker")" = "$expected" ] || return 1
  # 所有关键产物必须全部存在（任一缺失视为缓存损坏，需重编）
  local f
  for f in "$@"; do
    [ -e "$f" ] || return 1
  done
  return 0
}

# _dep_mark <dep_name> <version>
_dep_mark() {
  mkdir -p "$_DEPCACHE_DIR"
  printf '%s' "$2" > "$_DEPCACHE_DIR/$1"
}

# _dep_rebuild_msg <dep_name> <expected_version>
_dep_rebuild_msg() {
  local name="$1" expected="$2"
  local marker="$_DEPCACHE_DIR/$name"
  local cur=""
  [ -f "$marker" ] && cur=$(cat "$marker")
  if [ -n "$cur" ] && [ "$cur" != "$expected" ]; then
    info "    → 版本变更: $cur → $expected，重新编译"
  else
    info "    → 标记或产物缺失，重新编译"
  fi
}

# ============================================================
# 步骤 2：交叉编译依赖库（zlib + mbedTLS + json-c + libevent）
#   每个库独立检查缓存（版本标记 + 关键产物），中途挂掉后重跑能复用已完成的库，
#   升级某个库版本时自动只重编该库及其依赖方（顺序由调用链保证：zlib→mbedTLS→libevent）
# ============================================================
build_deps() {
  mkdir -p "$SYSROOT" "$_DEPCACHE_DIR"

  local target_triple; target_triple=$($CC -dumpmachine)
  info "目标三元组: $target_triple / 编译器: $CC"
  info "缓存策略: 每库独立，标记目录 $_DEPCACHE_DIR"

  # 公共编译 / 链接标志（不使用 -static，依赖库均构建 .a / 部分 .so）
  local COMMON_CFLAGS="-I${SYSROOT}/include -Os -ffunction-sections -fdata-sections"
  local COMMON_LDFLAGS="-L${SYSROOT}/lib -Wl,--gc-sections"

  local skipped=0 built=0

  # ------------------------------------------------------------
  # 1/4: zlib 1.3.1（无上游依赖）
  # ------------------------------------------------------------
  info "===== [1/4] 编译 zlib $ZLIB_VER ====="
  if _dep_cached zlib "$ZLIB_VER" \
      "$SYSROOT/lib/libz.a" "$SYSROOT/lib/libz.so"; then
    ok "  ✓ zlib 缓存命中"
    skipped=$((skipped + 1))
  else
    _dep_rebuild_msg zlib "$ZLIB_VER"
    rm -rf zlib-src && mkdir zlib-src
    curl -sL "https://github.com/madler/zlib/archive/refs/tags/v${ZLIB_VER}.tar.gz" | \
      tar xz -C zlib-src --strip-components=1
    (
      cd zlib-src
      # LDFLAGS 显式置空：dl-musl 注入的 -static 会污染 zlib 自带示例
      CC=$CC AR=$AR RANLIB=$RANLIB \
        CFLAGS="$COMMON_CFLAGS -fPIC" LDFLAGS="" \
        ./configure --prefix="$SYSROOT" \
                    --libdir="$SYSROOT/lib" \
                    --includedir="$SYSROOT/include" \
        || { cat configure.log; die "zlib configure 失败，真实错误见上方日志"; }
      make -j"$(nproc)" libz.a libz.so.1.3.1
      make install
    )
    _dep_mark zlib "$ZLIB_VER"
    ok "✓ zlib 完成（静态 + 动态）"
    ls -lh "$SYSROOT/lib/libz.a" "$SYSROOT"/lib/libz.so*
    built=$((built + 1))
  fi

  # ------------------------------------------------------------
  # 2/4: mbedTLS（cmake 会 find zlib，marker 需绑定 zlib 版本）
  # ------------------------------------------------------------
  local MBEDTLS_FINGERPRINT="$MBEDTLS_VER:$ZLIB_VER"
  info "===== [2/4] 编译 mbedTLS $MBEDTLS_VER ====="
  if _dep_cached mbedtls "$MBEDTLS_FINGERPRINT" \
      "$SYSROOT/lib/libmbedtls.a" "$SYSROOT/lib/libmbedtls.so"; then
    ok "  ✓ mbedTLS 缓存命中"
    skipped=$((skipped + 1))
  else
    _dep_rebuild_msg mbedtls "$MBEDTLS_FINGERPRINT"
    rm -rf mbedtls-src && mkdir mbedtls-src
    curl -sL "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VER}/mbedtls-${MBEDTLS_VER}.tar.bz2" | \
      tar xj -C mbedtls-src --strip-components=1
    (
      cd mbedtls-src
      cmake -B build -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_SYSTEM_NAME=Linux \
        -DCMAKE_INSTALL_PREFIX="$SYSROOT" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_INSTALL_INCLUDEDIR=include \
        -DBUILD_SHARED_LIBS=OFF \
        -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF \
        -DUSE_SHARED_MBEDTLS_LIBRARY=ON -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DMBEDTLS_FATAL_WARNINGS=OFF \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
        -DCMAKE_FIND_ROOT_PATH="$SYSROOT" \
        -DCMAKE_C_FLAGS="$COMMON_CFLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$COMMON_LDFLAGS"
      cmake --build build -j"$(nproc)"
      cmake --install build
    )
    _dep_mark mbedtls "$MBEDTLS_FINGERPRINT"
    ok "✓ mbedTLS 完成（静态 + 动态）"
    ls -lh "$SYSROOT"/lib/libmbed*.a "$SYSROOT"/lib/libmbed*.so*
    built=$((built + 1))
  fi

  # ------------------------------------------------------------
  # 3/4: json-c（独立库，不依赖其他）
  # ------------------------------------------------------------
  info "===== [3/4] 编译 json-c $JSONC_VER ====="
  if _dep_cached jsonc "$JSONC_VER" \
      "$SYSROOT/lib/libjson-c.a"; then
    ok "  ✓ json-c 缓存命中"
    skipped=$((skipped + 1))
  else
    _dep_rebuild_msg jsonc "$JSONC_VER"
    rm -rf jsonc-src && mkdir jsonc-src
    curl -sL "https://github.com/json-c/json-c/releases/download/${JSONC_TAG}/json-c-${JSONC_VER}-nodoc.tar.gz" | \
      tar xz -C jsonc-src --strip-components=1
    (
      cd jsonc-src
      cmake -B build -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_INSTALL_PREFIX="$SYSROOT" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF -DDISABLE_BSYMBOLIC=ON \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
        -DCMAKE_C_FLAGS="$COMMON_CFLAGS"
      cmake --build build -j"$(nproc)"
      cmake --install build
    )
    _dep_mark jsonc "$JSONC_VER"
    ok "✓ json-c 完成"
    ls -lh "$SYSROOT/lib/libjson-c.a"
    built=$((built + 1))
  fi

  # ------------------------------------------------------------
  # 4/4: libevent（显式链接 mbedTLS，marker 需绑定 mbedTLS 版本）
  # ------------------------------------------------------------
  local LIBEVENT_FINGERPRINT="$LIBEVENT_VER:$MBEDTLS_VER"
  info "===== [4/4] 编译 libevent $LIBEVENT_VER ====="
  if _dep_cached libevent "$LIBEVENT_FINGERPRINT" \
      "$SYSROOT/lib/libevent.a" "$SYSROOT/include/event2/event-config.h"; then
    ok "  ✓ libevent 缓存命中"
    skipped=$((skipped + 1))
  else
    _dep_rebuild_msg libevent "$LIBEVENT_FINGERPRINT"
    rm -rf libevent-src && mkdir libevent-src
    curl -sL "https://github.com/libevent/libevent/releases/download/${LIBEVENT_TAG}/libevent-${LIBEVENT_VER}.tar.gz" | \
      tar xz -C libevent-src --strip-components=1
    (
      cd libevent-src
      cmake -B build -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_INSTALL_PREFIX="$SYSROOT" \
        -DBUILD_SHARED_LIBS=OFF \
        -DEVENT__DISABLE_TESTS=ON -DEVENT__DISABLE_SAMPLES=ON -DEVENT__DISABLE_REGRESS=ON \
        -DEVENT__DISABLE_OPENSSL=ON \
        -DEVENT__DISABLE_MBEDTLS=OFF \
        -DMBEDTLS_INCLUDE_DIR="$SYSROOT/include" \
        -DMBEDTLS_LIBRARY="$SYSROOT/lib/libmbedtls.a" \
        -DMBEDTLS_X509_LIBRARY="$SYSROOT/lib/libmbedx509.a" \
        -DMBEDTLS_CRYPTO_LIBRARY="$SYSROOT/lib/libmbedcrypto.a" \
        -DCMAKE_SHARED_LIBRARY_LINK_C_FLAGS="" \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
        -DCMAKE_C_FLAGS="$COMMON_CFLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$COMMON_LDFLAGS"
      # 只编译静态库，跳过共享库（避免 -static 与 .so 链接冲突）
      cmake --build build -j"$(nproc)" \
        --target event_core_static \
        --target event_extra_static \
        --target event_mbedtls_static \
        --target event_pthreads_static \
        --target event_static
      # cmake --install 会尝试安装不存在的 .so，手动复制所需文件
      cp build/lib/libevent*.a "$SYSROOT/lib/"
      cp -r include/* "$SYSROOT/include/"
      # 复制 cmake 生成的 config header（不在源码中）
      cp build/include/event2/event-config.h "$SYSROOT/include/event2/"
    )
    _dep_mark libevent "$LIBEVENT_FINGERPRINT"
    ok "✓ libevent 完成（event_mbedtls 后端）"
    ls -lh "$SYSROOT"/lib/libevent*.a
    built=$((built + 1))
  fi

  # 汇总
  info "依赖库: 本次编译 $built / 缓存命中 $skipped / 共 4"
}

# ============================================================
# 步骤 3：编译 xfrpc
# ============================================================
build_xfrpc() {
  info "===== 编译 xfrpc ====="
  mkdir -p "$BUILD_DIR"
  (
    cd "$BUILD_DIR"

    # 清空 dl-musl 注入的环境变量（含 -static 与 -I/-L 路径），
    # 否则 xfrpc 无法动态链接 mbedTLS（attempted static link of dynamic object）
    unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS

    # mbedTLS 为动态链接：$ORIGIN rpath 使 .so 与二进制同目录即可运行
    # 上游有 -Werror，需加 -Wno-* 绕过假阳性
    local COMMON_CFLAGS="-I${SYSROOT}/include -Os -ffunction-sections -fdata-sections -Wno-error=array-bounds"
    local COMMON_LDFLAGS="-L${SYSROOT}/lib -Wl,--gc-sections -Wl,-rpath,\$ORIGIN"

    cmake \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_C_FLAGS="$COMMON_CFLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$COMMON_LDFLAGS -Wl,--start-group" \
      -DCMAKE_FIND_ROOT_PATH="$SYSROOT" \
      -DLIBEVENT_INCLUDE_DIR="$SYSROOT/include" \
      -DLIBEVENT_LIB="$SYSROOT/lib/libevent.a" \
      -DLIBEVENT_CORE_LIB="$SYSROOT/lib/libevent_core.a" \
      -DLIBEVENT_PTHREADS_LIB="$SYSROOT/lib/libevent_pthreads.a" \
      -DLIBEVENT_EXTRA_LIB="$SYSROOT/lib/libevent_extra.a" \
      -DLIBEVENT_MBEDTLS_LIB="$SYSROOT/lib/libevent_mbedtls.a" \
      -DJSON-C_INCLUDE_DIR="$SYSROOT/include" \
      -DJSON-C_LIBRARY="$SYSROOT/lib/libjson-c.a" \
      -DZLIB_INCLUDE_DIR="$SYSROOT/include" \
      -DZLIB_LIBRARY="$SYSROOT/lib/libz.a" \
      -DMBEDTLS_INCLUDE_DIR="$SYSROOT/include" \
      -DMBEDTLS_LIBRARY="$SYSROOT/lib/libmbedtls.so" \
      -DMBEDX509_LIBRARY="$SYSROOT/lib/libmbedx509.so" \
      -DMBEDCRYPTO_LIBRARY="$SYSROOT/lib/libmbedcrypto.so" \
      -DDEBUG=ON \
      ..
    make -j"$(nproc)"
    "$STRIP" xfrpc
    du -m xfrpc || true
    file xfrpc
  )
  ok "✓ xfrpc 编译完成"
}

# ============================================================
# 步骤 4：打包运行时动态库
# ============================================================
package_artifacts() {
  info "===== 打包产物 ====="
  cd "$BUILD_DIR"

  # 统一命名: xfrpc-$TARGET
  mv xfrpc "xfrpc-${TARGET}"

  # 复制运行时动态库（mbedTLS 动态链接，rpath=$ORIGIN，需与二进制同目录）
  # cp -L 解引用符号链接，保证所有 SONAME 文件名齐全
  cp -L "$SYSROOT/lib/libmbedtls.so"* .
  cp -L "$SYSROOT/lib/libmbedx509.so"* .
  cp -L "$SYSROOT/lib/libmbedcrypto.so"* .
  "$STRIP" --strip-unneeded lib*.so* 2>/dev/null || true

  ok "✓ 产物打包完成"
  ls -lh
  cd "$SRC_ROOT"
}

# ============================================================
# 清理
# ============================================================
do_clean() {
  info "==> 清理构建产物..."
  rm -rf "$BUILD_DIR" \
         zlib-src mbedtls-src jsonc-src libevent-src \
         "$SYSROOT"
  ok "✓ 已清理: $BUILD_DIR / sysroot"
  exit 0
}

# ============================================================
# 主流程
# ============================================================
[ "$DO_CLEAN" = 1 ] && do_clean

setup_toolchain
build_deps
build_xfrpc
package_artifacts

ok "=========================================="
ok "✓ 全部完成！产物在 $SRC_ROOT/$BUILD_DIR/"
ok "  运行示例: cd $BUILD_DIR && LD_LIBRARY_PATH=. ./xfrpc-${TARGET} -c ../xfrpc.toml"
ok "=========================================="
