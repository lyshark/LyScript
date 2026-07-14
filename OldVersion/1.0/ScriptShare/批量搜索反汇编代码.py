# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    local_base_start = dbg.get_local_base()
    local_base_end = local_base_start + dbg.get_local_size()
    print("开始地址: {} --> 结束地址: {}".format(hex(local_base_start),hex(local_base_end)))

    search_asm = ['test eax,eax', 'cmp esi, edi', 'pop edi', 'cmp esi,edi', 'jmp esp']

    while local_base_start <= local_base_end:
        disasm = dbg.get_disasm_one_code(local_base_start)
        print("地址: 0x{:08x} --> 反汇编: {}".format(local_base_start,disasm))

        # 寻找指令
        for index in range(0, len(search_asm)):
            if disasm == search_asm[index]:
                print("地址: {} --> 反汇编: {}".format(hex(local_base_start), disasm))

        # 递增计数器
        local_base_start = local_base_start + dbg.get_disasm_operand_size(local_base_start)

    dbg.close()