import idautils
import ida_funcs

search_str = "CsteSystem"  # 目标函数名
target_func_ea = None  

# 遍历所有函数，寻找 **完全匹配** 的 `J_atoi`
for func_ea in idautils.Functions():
    func_name = ida_funcs.get_func_name(func_ea)
    if func_name == search_str:  # 严格匹配
        target_func_ea = func_ea
        print(f"[+] Found {func_name} at 0x{func_ea:X}")
        break  

if target_func_ea:
    print(f"\n[+] Searching for references to {search_str}...\n")

    found_refs = False
    for ref_ea in idautils.CodeRefsTo(target_func_ea, 0):  # 遍历所有调用 `J_atoi` 的地址
        caller_func = ida_funcs.get_func(ref_ea)  # 获取调用 `J_atoi` 的函数
        if caller_func:
            caller_name = ida_funcs.get_func_name(caller_func.start_ea)

            # **过滤掉 sub_xxx**
            if caller_name.startswith("sub_"):
                continue  # 跳过不打印

            print(f"[*] {caller_name} calls {search_str} at [0x{ref_ea:X}]")  # 只显示调用地址
            found_refs = True

    if not found_refs:
        print("[-] No valid references found (excluding sub_xxx).")
else:
    print("[-] Function J_atoi not found.")