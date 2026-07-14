# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 传入汇编指令列表,直接将机器码写入对端内存
def write_opcode_from_assemble(dbg_ptr,asm_list):
    addr_count = 0
    addr = dbg_ptr.create_alloc(1024)
    if addr != 0:
        for index in asm_list:
            asm_size = dbg_ptr.assemble_code_size(index)
            if asm_size != 0:
                # print("长度: {}".format(asm_size))
                write = dbg_ptr.assemble_write_memory(addr + addr_count, index)
                if write == True:
                    addr_count = addr_count + asm_size
                else:
                    dbg_ptr.delete_alloc(addr)
                    return 0
            else:
                dbg_ptr.delete_alloc(addr)
                return 0
    else:
        return 0
    return addr

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 得到messagebox内存地址
    msg_ptr = dbg.get_module_from_function("user32.dll","MessageBoxA")
    call = "call {}".format(str(hex(msg_ptr)))
    print("函数地址: {}".format(call))

    # 写出指令集到内存
    asm_list = ['push 0','push 0','push 0','push 0',call]
    write_addr = write_opcode_from_assemble(dbg,asm_list)
    print("写出地址: {}".format(hex(write_addr)))

    # 设置执行属性
    dbg.set_local_protect(write_addr,32,1024)

    # 将EIP设置到指令集位置
    dbg.set_register("eip",write_addr)

    # 执行代码
    dbg.set_debug("Run")
    dbg.close()