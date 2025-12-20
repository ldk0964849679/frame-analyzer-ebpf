#!/bin/bash

# 定义目标文件路径
HELPERS_FILE="./vendor/aya/ebpf/aya-ebpf-bindings/src/x86_64/helpers.rs"
BINDINGS_FILE="./vendor/aya/ebpf/aya-ebpf-bindings/src/x86_64/bindings.rs"

# 备份函数
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "${1}.bak"
        echo "已备份文件：$1 -> ${1}.bak"
    else
        echo "错误：文件 $1 不存在！"
        exit 1
    fi
}

# 备份两个目标文件
backup_file "$HELPERS_FILE"
backup_file "$BINDINGS_FILE"

# ==================== helpers.rs 修复 ====================
echo -e "\n开始修复 helpers.rs..."

# 1. 给transmute调用添加unsafe块（无多余分号，避免重复）
sed -i '/unsafe { ::core::mem::transmute/! s/::core::mem::transmute(\(.*\))/unsafe { ::core::mem::transmute(\1) }/g' "$HELPERS_FILE"

# 2. 给fun调用添加unsafe块（匹配所有参数，避免重复）
sed -i '/unsafe { fun(/! s/fun(\([^)]*\))\(.*\)/unsafe { fun(\1) }\2/g' "$HELPERS_FILE"

# 3. 清理双层unsafe嵌套
sed -i 's/unsafe { unsafe { \(fun(.*)\) } }/unsafe { \1 }/g' "$HELPERS_FILE"
sed -i 's/unsafe { unsafe { \(::core::mem::transmute(.*)\) } }/unsafe { \1 }/g' "$HELPERS_FILE"

# ==================== bindings.rs 修复 ====================
echo -e "\n开始修复 bindings.rs..."

# 1. 给from_raw_parts_mut调用添加unsafe块（避免重复）
sed -i '/unsafe { ::core::slice::from_raw_parts_mut/! s/::core::slice::from_raw_parts_mut(\(.*\))/unsafe { ::core::slice::from_raw_parts_mut(\1) }/g' "$BINDINGS_FILE"

# 2. 给from_raw_parts调用添加unsafe块（避免重复，若有）
sed -i '/unsafe { ::core::slice::from_raw_parts/! s/::core::slice::from_raw_parts(\(.*\))/unsafe { ::core::slice::from_raw_parts(\1) }/g' "$BINDINGS_FILE"

# 3. 清理双层unsafe嵌套
sed -i 's/unsafe { unsafe { \(::core::slice::from_raw_parts.*\) } }/unsafe { \1 }/g' "$BINDINGS_FILE"

# 提示完成
echo -e "\n全量修复完成！"
echo "修复内容："
echo "1. helpers.rs：transmute/fun调用的unsafe块添加+嵌套清理"
echo "2. bindings.rs：from_raw_parts/from_raw_parts_mut的unsafe块添加+嵌套清理"
echo "注：所有修改均避免重复包裹，适配Rust 2024 unsafe语义"
