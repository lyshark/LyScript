# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
import os,sys

# 得到程序的内存镜像中的机器码
def get_memory_hex_ascii(address,offset,len):
    count = 0
    ref_memory_list = []
    for index in range(offset,len):
        # 读出数据
        char = dbg.read_memory_byte(address + index)
        count = count + 1

        if count % 16 == 0:
            if (char) < 16:
                ref_memory_list.append("0" + hex((char))[2:])
            else:
                ref_memory_list.append(hex((char))[2:])
        else:
            if (char) < 16:
                ref_memory_list.append("0" + hex((char))[2:])
            else:
                ref_memory_list.append(hex((char))[2:])
    return ref_memory_list


# 在指定区域内搜索特定的机器码,如果完全匹配则返回
def search_hex_ascii(address,offset,len,hex_array):
    # 得到指定区域内存机器码
    ref_memory_list = get_memory_hex_ascii(address,offset,len)

    array = []

    # 循环输出字节
    for index in range(0,len + len(hex_array)):

        # 如果有则继续装
        if len(hex_array) != len(array):
            array.append(ref_memory_list[offset + index])

        else:
            for y in range(0,len(array)):
                if array[y] != ref_memory_list[offset + index + y]:
                    return False

        array.clear()
    return False

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    eip = dbg.get_register("eip")

    # 得到模块基地址
    module_base = dbg.get_base_from_address(dbg.get_local_base())
    
    re = search_hex_ascii(module_base,0,100,hex_array=["0x4d","0x5a"])
    
    dbg.close()