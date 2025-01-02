from ida_bytes import *
from ida_idc import *
import ida_graph as graph
import ida_kernwin as kernwin
from ida_dbg import *
from ida_funcs import *
from ida_name import *
from ida_segment import *
import ida_xref as xref
import ida_hexrays as hexrays
import idc
#import ida_idaapi as idaapi
import idautils
import idaapi

# 宏定义初始化
BADADDR = 0xffffffffffffffff


def get_from_xrefs(ea_t:int) -> list[str]:
    """
        获得选定地址的引用地址列表,地址列表里包含引用的name或地址字符串
    """
    
    rtn = []
    # cref 代码引用
    addr = xref.get_first_cref_from(ea_t) # 从起始地址开始找
    while addr != BADADDR: # 非错误地址
        name = idc.get_func_name(addr) # 获取地址的名字
        if name == '': # 如果引用地址不属于函数
            name = hex(addr) # 取name为地址值
        if name not in rtn: # 如果name不在已知列表里，这里为了性能可以优化为用字典去重
            rtn.append(name) # 添加name
        addr = xref.get_next_cref_from(addr,ea_t) # 寻找下一个地址
    # 结束后获得了一份代码引用表，**这里可能为空。**
    
    # dref 数据引用
    addr = xref.get_first_dref_from(ea_t) 
    while addr != BADADDR: 
        name = idc.get_func_name(addr) 
        if name == '': 
            name = hex(addr) 
        if name not in rtn: 
            rtn.append(name)
        addr = xref.get_next_dref_from(addr,ea_t) 
    # 结束后获得了一份数据引用表，**这里可能为空。**
    
    # fcref 函数引用
    addr = xref.get_first_fcref_from(ea_t) 
    while addr != BADADDR: 
        name = idc.get_func_name(addr) 
        if name == '': 
            name = hex(addr) 
        if name not in rtn: 
            rtn.append(name) 
        addr = xref.get_next_fcref_from(addr,ea_t) 
    # 结束后获得了一份函数引用表，**这里可能为空。**
    
    return rtn # 返回
def get_to_xrefs(ea_t:int) -> list[str]:
    """
        获得选定地址的被引用地址列表,地址列表里包含引用的name或地址字符串
    """
    rtn = []
    # cref 代码引用
    addr = xref.get_first_cref_to(ea_t) # 从起始地址开始找
    while addr != BADADDR: # 非错误地址
        name = idc.get_func_name(addr) # 获取地址的名字
        if name == '': # 如果引用地址不属于函数
            name = hex(addr) # 取name为地址值
        if name not in rtn: # 如果name不在已知列表里，这里为了性能可以优化为用字典去重
            rtn.append(name) # 添加name
        addr = xref.get_next_cref_to(addr,ea_t) # 寻找下一个地址
    # 结束后获得了一份代码引用表，**这里可能为空。**
    
    # dref 数据引用
    addr = xref.get_first_dref_to(ea_t) 
    while addr != BADADDR: 
        name = idc.get_func_name(addr) 
        if name == '': 
            name = hex(addr) 
        if name not in rtn: 
            rtn.append(name)
        addr = xref.get_next_dref_to(addr,ea_t) 
    # 结束后获得了一份数据引用表，**这里可能为空。**
    
    # fcref 函数引用
    addr = xref.get_first_fcref_to(ea_t) 
    while addr != BADADDR: 
        name = idc.get_func_name(addr) 
        if name == '': 
            name = hex(addr) 
        if name not in rtn: 
            rtn.append(name) 
        addr = xref.get_next_fcref_to(addr,ea_t) 
    # 结束后获得了一份函数引用表，**这里可能为空。**
    
    return rtn # 返回

def __find_func_from_xref(src_func_addr:int,dst_func_addr:int) -> bool:
    """
    从起始函数开始搜，找有没有东西引用到了目标函数
    """
    xref_func = []
    from_xrefs = get_from_xrefs(src_func_addr) # 获取起始函数的引用函数表
    print(from_xrefs)
    while(True):
        #print(len(from_xrefs))
        if len(from_xrefs) == 1: # 如果引用表被使用完
            return False # 则退出，返回False
        rtn = from_xrefs.pop() # 弹出引用，这里因为后续的添加是 +=，因此每次会弹出最新的，有点像深度优先搜索。
        if rtn[:2] == '0x':
            addr = int(rtn)
        else:
            addr = idc.get_name_ea_simple(rtn)
        if idc.get_name(addr) != idc.get_name(dst_func_addr) :# **需要测试**
            from_xrefs += get_from_xrefs(addr)  # 如果引用的这个函数下还有其他引用，将其他引用添加进来。
        else:
            return True

def find_func_to_xref(src_func_addr:int,dst_func_addr:int) -> bool:
    """
    从起始函数开始搜，找有没有东西引用到了目标函数
    """
    xref_func = []
    from_xrefs = get_to_xrefs(src_func_addr) # 获取起始函数的被引用函数表
    
    while(True):
        #print(from_xrefs)
        #print(len(from_xrefs))
        if len(from_xrefs) == 0: # 如果被引用表被使用完
            return False # 则退出，返回False
        rtn = from_xrefs.pop() # 弹出被引用地址的name，这里因为后续的添加是 +=，因此每次会弹出最新的，有点像深度优先搜索。
        if rtn[:2] == '0x': # 根据name获得addr
            addr = int(rtn,base=16) # 可能是归属函数jmp_table在数据段的引用这一类
        else:
            addr = idc.get_name_ea_simple(rtn) # 直接属于一个函数，获得地址
            #print(hex(addr))
        if idc.get_name(addr) != idc.get_name(dst_func_addr) :# **需要测试**，可以优化
            from_xrefs += get_to_xrefs(addr)  # 如果引用的这个函数下还有其他引用，将其他引用添加进来。
        else:
            return True


seg_text: segment_t = get_segm_by_name(".text")
seg_start = seg_text.start_ea#0x8049C21#
seg_end = seg_text.end_ea#0x8060950#
ptr = seg_start
algs = {
    "alg1":{},
    "alg2":{},
    "alg3":{},
    "alg4":{}
}

tmp_alg3 = []
alg_level = ""
while ptr <= seg_end:
    # ** 这些跳转到下一条语句后continue应该写跳转到下一个函数。
    opcode = idc.print_insn_mnem(ptr)
    if "xor" in opcode:  # rule 1, find not clear xor
        
        func_name = idc.get_func_name(ptr)
        func_start = idc.get_name_ea(ptr,func_name) # 获得当前地址的归属函数名，再获取这个函数名的起始地址。
        
        oprand1 = idc.print_operand(ptr, 0)
        oprand2 = idc.print_operand(ptr, 1)
        #print(oprand1,oprand2)
        if oprand1 != oprand2:
            # 一级可疑处理，有嫌疑的算法
            #alg_level = "xor_alg1" # 一级可疑
            # 二级可疑处理，存在交叉引用
            t = xref.get_first_cref_to(func_start) # 查看可疑函数的交叉引用
            if t == BADADDR:
                algs["alg1"][func_name] = hex(ptr)
                # if func_start not in algs["alg1"]:
                #     algs["alg1"].append(func_start) # 将可疑函数的地址添加到可疑算法字典
                ptr = idc.next_head(ptr)  # 跳转到下一条语句
                continue # 如果没有交叉引用，那就只是一级可疑
            else:
                # 四级可疑，如果交叉引用可以直接追溯到main那就是四级可疑。
                if find_func_to_xref(func_start,idc.get_name_ea_simple('main_main')):
                    algs["alg4"][func_name] = hex(ptr)
                    #print(type(algs["alg4"]),type(func_start))
                    # if func_start not in algs["alg4"]: # 防止重复添加
                    #     algs["alg4"].append(hex(func_start)) 
                    ptr = idc.next_head(ptr)  # 是四级可疑就直接跳，不考虑骚鸡
                    continue # 如果没有交叉引用，那就只是一级可疑

                algs["alg2"][func_name] = hex(ptr)
                #alg_level = "xor_alg2" # 二级可疑
                # if func_start not in algs["alg2"]:
                #     algs["alg2"].append(func_start)
                # 三级可疑处理，引用且多次
                t = xref.get_next_cref_to(t,func_start) # 获取下一个交叉引用地址
                while t != BADADDR: # 并便利交叉引用地址
                    xref_func_name = idc.get_func_name(t) 
                    if xref_func_name not in tmp_alg3: # 将初次检测到的可疑交叉引用添加到可疑/临时列表
                        tmp_alg3 += xref_func_name
                    else:
                        algs["alg3"][func_name] = hex(ptr)
                    # elif idc.get_name_ea(xref_func_name) not in algs["alg3"]: 
                    #     algs["alg3"].append(idc.get_name_ea(xref_func_name)) # 如果这个可疑交叉引用引用了多个或者多次可疑的东西，则它是三级可疑

                
            #xref.get_next_cref_to(t,idc.get_name_ea(ptr,idc.get_func_name(ptr)))

    ptr = idc.next_head(ptr)  # 跳转到下一条语句
print(algs['alg4'])
