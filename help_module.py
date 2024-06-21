import idautils
import idc
import ida_typeinf

def get_jpm_call_count(func_start, func_end):
    jmp_count = 0
    call_count = 0
    start_addr = idc.get_func_attr(func_start, idc.FUNCATTR_START)
    current_addr = start_addr
    while current_addr < func_end:
        line = idc.GetDisasm(current_addr)
        #print(line)
        if 'jmp' in line.lower() or 'jne' in line.lower():
            jmp_count += 1
        if 'je' in line.lower() or 'jz' in line.lower():
            jmp_count += 1
        if 'jle' in line.lower() or 'jnz' in line.lower():
            jmp_count += 1
        if 'call' in line.lower():
            call_count += 1
        try:
            current_addr = idc.next_head(current_addr)
        except: continue

    return jmp_count, call_count


def calc_args_count(func):
    args_count = 0
    list_refs = idautils.CodeRefsTo(func, False)
    for i in list_refs:
        try:
            args_count = len(ida_typeinf.get_arg_addrs(i))
            break
        except:
            continue
    return args_count


def get_func_refs_count(func_start, func_end):
    func_code_refs = set()
    start_addr = idc.get_func_attr(func_start, idc.FUNCATTR_START)
    current_addr = start_addr
    while current_addr < func_end:
        list_refs = idautils.CodeRefsFrom(current_addr, False)
        #print(list_refs)
        for i in list_refs:
            if(i > func_end or i < func_start): func_code_refs.add(i)
        try:
            current_addr = idc.next_head(current_addr)
        except: continue
        #print(current_addr)
    return len(func_code_refs)
