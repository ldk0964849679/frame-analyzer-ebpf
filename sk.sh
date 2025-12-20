#!/bin/bash
set -e

# 脚本说明：修复aya-ebpf特性名、创建空build.rs、验证编译
# 执行前确保：1. 脚本在项目根目录 2. 赋予执行权限 chmod +x fix-and-build.sh

echo "==================== 开始修复配置 ===================="

# 第一步：检查脚本执行路径，避免目录错误
if [ -d "./sk.sh" ]; then
    echo "错误：存在名为sk.sh的目录，请删除或重命名后再执行！"
    exit 1
fi

# 第二步：定义子包目录（统一处理）
SUBPACKAGES=(
    "frame-analyzer"
    "frame-analyzer-ebpf"
    "frame-analyzer-ebpf-common"
    "examples/simple-analyzer"
    "xtask"
)

# 第三步：替换aya-ebpf的no_std特性为ebpf（修复sed语法，用单引号包裹表达式）
echo "正在替换子包中的aya-ebpf特性名..."
for pkg in "${SUBPACKAGES[@]}"; do
    if [ -f "$pkg/Cargo.toml" ]; then
        echo "处理子包: $pkg"
        # 修复sed语法：单引号包裹完整表达式，避免双引号嵌套断裂
        sed -i 's/features = ["no_std"]/features = ["ebpf"]/g' "$pkg/Cargo.toml"
        sed -i 's/features = ["no_std", /features = ["ebpf", /g' "$pkg/Cargo.toml"
        sed -i 's/, "no_std"]/, "ebpf"]/g' "$pkg/Cargo.toml"
        # 确保workspace配置关联ebpf特性
        sed -i 's/aya-ebpf = { workspace = true }/aya-ebpf = { workspace = true, features = ["ebpf"] }/g' "$pkg/Cargo.toml"
        sed -i 's/aya-ebpf = { workspace = true, optional = true }/aya-ebpf = { workspace = true, features = ["ebpf"], optional = true }/g' "$pkg/Cargo.toml"
        echo "$pkg 特性替换完成"
    else
        echo "$pkg/Cargo.toml 不存在，跳过"
    fi
done

# 第四步：手动修正frame-analyzer-ebpf-common的特性块（避免sed漏改）
COMMON_PKG="frame-analyzer-ebpf-common/Cargo.toml"
if [ -f "$COMMON_PKG" ]; then
    echo "修正$COMMON_PKG的特性关联..."
    # 删除旧的bpf特性声明
    sed -i '/bpf = \["dep:aya-ebpf"\]/d' "$COMMON_PKG"
    # 追加新的bpf特性（关联ebpf）
    if ! grep -q 'bpf = ["dep:aya-ebpf/ebpf"]' "$COMMON_PKG"; then
        sed -i '/\[features\]/a bpf = ["dep:aya-ebpf/ebpf"]' "$COMMON_PKG"
    fi
    echo "$COMMON_PKG 特性修正完成"
fi

# 第五步：创建空build.rs文件
echo "创建空build.rs文件..."
for pkg in "${SUBPACKAGES[@]}"; do
    if [ -d "$pkg" ]; then
        touch "$pkg/build.rs"
        echo "已创建$pkg/build.rs"
    fi
done

echo "==================== 配置修复完成，开始编译验证 ===================="

# 第六步：执行编译脚本（若存在）
if [ -f "./build-ebpf-final.sh" ]; then
    echo "执行编译脚本..."
    chmod +x ./build-ebpf-final.sh
    ./build-ebpf-final.sh
else
    echo "未找到build-ebpf-final.sh，执行手动编译命令..."
    cargo build -Z build-std=core --target bpfel-unknown-none --release -p frame-analyzer-ebpf
fi

echo "==================== 操作完成 ===================="
