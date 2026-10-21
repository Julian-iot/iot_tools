#!/bin/bash

# --- 函数定义 ---

# 模式一：分析文件中的关键字 (此函数无变化)
analyze_file_for_keywords() {
    local file_path="$1"
    local pattern1="$2"
    local pattern2="$3"
    # ... 此函数内部代码与上一版完全相同 ...
    local nm_output
    nm_output=$(nm -D "$file_path" 2>/dev/null)
    if [ -z "$nm_output" ]; then return; fi

    if [ -n "$pattern2" ]; then
        local output1 output2
        output1=$(echo -n "$nm_output" | grep --color=always "${pattern1}")
        output2=$(echo -n "$nm_output" | grep --color=always "${pattern2}")
        if [[ -n "$output1" && -n "$output2" ]]; then
            echo -e "\n>>> 文件 [\e[33m${file_path}\e[0m] 同时包含 [\e[32m${pattern1}\e[0m] 和 [\e[32m${pattern2}\e[0m]"
            echo "--- 匹配 [${pattern1}] 的结果:"
            echo "$output1"
            echo "--- 匹配 [${pattern2}] 的结果:"
            echo "$output2"
        fi
    else
        local output1
        output1=$(echo -n "$nm_output" | grep --color=always "${pattern1}")
        if [ -n "$output1" ]; then
            echo -e "\n>>> 文件 [\e[33m${file_path}\e[0m] 包含关键字 [\e[32m${pattern1}\e[0m]"
            echo "$output1"
        fi
    fi
}


# 模式二：【已重构】比较两个文件，找出共同符号及其各自的类型
find_common_symbols() {
    local file1="$1"
    local file2="$2"

    echo -e "\n--- 正在比较文件 [\e[33m$file1\e[0m] 和 [\e[33m$file2\e[0m] ---"
    
    # 使用 join 命令来合并两个 nm 输出的结果
    # 输出将被格式化为三列：符号名，文件1中的类型，文件2中的类型
    local common_symbols_with_types
    common_symbols_with_types=$(join <(nm -D "$file1" 2>/dev/null | awk '{print $NF, $(NF-1)}' | sort) \
                                   <(nm -D "$file2" 2>/dev/null | awk '{print $NF, $(NF-1)}' | sort))

    if [ -n "$common_symbols_with_types" ]; then
        echo "--- 共同存在的符号 (Common Symbols with Types):"
        # 打印表头
        printf "%-40s %-15s %-15s\n" "符号名称 (Symbol Name)" "类型 (in $file1)" "类型 (in $file2)"
        printf "%-40s %-15s %-15s\n" "----------------------------------------" "---------------" "---------------"
        # 格式化输出每一行
        echo "$common_symbols_with_types" | awk '{printf "%-40s %-15s %-15s\n", $1, $2, $3}'
    else
        echo "--- 未发现共同存在的符号 ---"
    fi
}


# --- 帮助信息 ---
usage() {
    echo "使用方法: $0 <命令> [参数...]"
    echo ""
    echo "可用命令:"
    echo "  find <目标文件或目录> <关键字1> [关键字2]   在目标中按关键字查找符号。"
    # 更新了 diff 命令的描述
    echo "  diff <文件1> <文件2>                      比较两个文件，找出共同符号及其各自的类型。"
    echo ""
    echo "示例:"
    echo "  $0 find ./lib \"crypto\" \"SHA256\""
    echo "  $0 diff ./lib/libcrypto.so ./lib/libssl.so"
    exit 1
}

# --- 主程序入口 (无变化) ---
if [ "$#" -eq 0 ]; then
    usage
fi

COMMAND="$1"
shift

case "$COMMAND" in
    find)
        if [[ "$#" -ne 2 && "$#" -ne 3 ]]; then usage; fi
        target="$1"
        pattern1="$2"
        pattern2="$3"

        echo "--- 开始关键字查找模式 ---"
        if [ -d "$target" ]; then
            echo "[+] 目标是一个目录，开始遍历..."
            for f in "${target}"/*; do
                if [ -f "$f" ]; then analyze_file_for_keywords "$f" "$pattern1" "$pattern2"; fi
            done
        elif [ -f "$target" ]; then
            echo "[+] 目标是一个文件，直接分析..."
            analyze_file_for_keywords "$target" "$pattern1" "$pattern2"
        else
            echo "错误: 目标 '$target' 不是一个有效的文件或目录。" >&2
            exit 1
        fi
        ;;
    diff)
        if [ "$#" -ne 2 ]; then usage; fi
        file1="$1"
        file2="$2"

        if [[ ! -f "$file1" || ! -f "$file2" ]]; then
            echo "错误: 两个参数都必须是有效的文件。" >&2
            exit 1
        fi
        
        echo "--- 开始文件比较模式 ---"
        find_common_symbols "$file1" "$file2"
        ;;
    *)
        echo "错误: 未知命令 '$COMMAND'" >&2
        usage
        ;;
esac

echo -e "\n--- 所有任务已完成 ---"