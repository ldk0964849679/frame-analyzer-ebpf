# 1. 进入项目根目录
cd /workspaces/frame-analyzer-ebpf

# 2. 遍历查询vendor/aya下所有Cargo.toml文件（关键）
find ./vendor/aya -name "Cargo.toml" -type f

# 3. 遍历查询vendor/aya下所有名为aya的目录
find ./vendor/aya -name "aya" -type d

# 4. 遍历查询vendor/aya下所有名为aya-ebpf的目录
find ./vendor/aya -name "aya-ebpf" -type d
