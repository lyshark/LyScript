# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
import pefile

if __name__ == "__main__":
    # 初始化
    dbg = MyDebug()
    dbg.connect()

    # 得到所有加载过的模块
    module_list = dbg.get_all_module()

    print("-" * 100)
    print("模块名 \t\t\t 基址随机化 \t\t DEP保护 \t\t 强制完整性 \t\t SEH异常保护 \t\t")
    print("-" * 100)

    for module_index in module_list:
        print("{:15}\t\t".format(module_index.get("name")),end="")

        # 依次读入程序所载入的模块
        byte_array = bytearray()
        for index in range(0, 4096):
            read_byte = dbg.read_memory_byte(module_index.get("base") + index)
            byte_array.append(read_byte)

        oPE = pefile.PE(data=byte_array)

        # 随机基址 => hex(pe.OPTIONAL_HEADER.DllCharacteristics) & 0x40 == 0x40
        if ((oPE.OPTIONAL_HEADER.DllCharacteristics & 64) == 64):
            print("True\t\t\t",end="")
        else:
            print("False\t\t\t",end="")
        # 数据不可执行 DEP => hex(pe.OPTIONAL_HEADER.DllCharacteristics) & 0x100 == 0x100
        if ((oPE.OPTIONAL_HEADER.DllCharacteristics & 256) == 256):
            print("True\t\t\t",end="")
        else:
            print("False\t\t\t",end="")
        # 强制完整性=> hex(pe.OPTIONAL_HEADER.DllCharacteristics) & 0x80 == 0x80
        if ((oPE.OPTIONAL_HEADER.DllCharacteristics & 128) == 128):
            print("True\t\t\t",end="")
        else:
            print("False\t\t\t",end="")
        if ((oPE.OPTIONAL_HEADER.DllCharacteristics & 1024) == 1024):
            print("True\t\t\t",end="")
        else:
            print("False\t\t\t",end="")
        print()
    dbg.close()