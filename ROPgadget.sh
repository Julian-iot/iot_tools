#!/bin/bash

# --- 参数定义 ---
# 使用一个分隔符 -- 来区分 [目标] 和 [ROPgadget的参数]
# 用法: $0 [目标1 目标2 ...] -- [ROPgadget的参数...]

# --- 初始化变量 ---
TARGETS=()
ROP_OPTIONS=()
separator_found=false

# --- 解析参数 ---
for arg in "$@"; do
  if [ "$arg" == "--" ]; then
    separator_found=true
    continue # 跳过分隔符本身
  fi

  if [ "$separator_found" == true ]; then
    ROP_OPTIONS+=("$arg")
  else
    TARGETS+=("$arg")
  fi
done

# --- 输入验证 ---
if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "错误: 未提供任何目标文件或目录。"
  echo "用法: $0 <文件|目录|通配符...> -- <ROPgadget参数...>"
  echo "例如: $0 ./lib -- --only \"jr\""
  exit 1
fi

if ! command -v ROPgadget &> /dev/null; then
    echo "错误: 未找到 'ROPgadget' 命令。请先安装: pip install ropgadget"
    exit 1
fi

# --- 主逻辑 ---
echo "=== ROPgadget 批量扫描器 ==="
if [ ${#ROP_OPTIONS[@]} -gt 0 ]; then
  echo "--- 使用ROPgadget参数: ${ROP_OPTIONS[*]}"
fi

# 遍历所有识别出的目标
for target in "${TARGETS[@]}"; do
  # --- 情况1: 目标是一个目录 ---
  if [ -d "$target" ]; then
    echo -e "\n[+] 正在扫描目录: $target"
    for f in "$target"/*; do
      # 确保只处理目录中的文件
      if [ -f "$f" ]; then
        printf "\n== 分析文件: %s ==\n" "$f"
        ROPgadget --binary "$f" "${ROP_OPTIONS[@]}"
      fi
    done
  # --- 情况2: 目标是一个文件 ---
  elif [ -f "$target" ]; then
    echo -e "\n[+] 正在扫描文件: $target"
    ROPgadget --binary "$target" "${ROP_OPTIONS[@]}"
  # --- 情况3: 目标不存在 ---
  else
    echo -e "\n[!] 警告: '$target' 不是一个有效的文件或目录，已跳过。"
  fi
done

echo -e "\n=== 所有任务已完成 ==="