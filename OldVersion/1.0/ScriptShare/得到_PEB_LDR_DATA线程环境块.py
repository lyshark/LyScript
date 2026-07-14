# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug(address="127.0.0.1")
    dbg.connect()

    # 保存当前EIP
    eip = dbg.get_register("eip")

    # 创建堆
    heap_addres = dbg.create_alloc(1024)
    print("堆空间地址: {}".format(hex(heap_addres)))

    # 写出汇编指令
    # mov eax,fs:[0x30] 得到 _PEB
    dbg.assemble_at(heap_addres,"mov eax,fs:[0x30]")
    asmfs_size = dbg.get_disasm_operand_size(heap_addres)

    # 写出汇编指令
    # mov eax,[eax+0x0C] 得到 _PEB_LDR_DATA
    dbg.assemble_at(heap_addres + asmfs_size, "mov eax, [eax + 0x0C]")
    asmeax_size = dbg.get_disasm_operand_size(heap_addres + asmfs_size)

    # 跳转回EIP位置
    dbg.assemble_at(heap_addres+ asmfs_size + asmeax_size , "jmp {}".format(hex(eip)))

    # 设置EIP到堆首地址
    dbg.set_register("eip",heap_addres)

    dbg.close()