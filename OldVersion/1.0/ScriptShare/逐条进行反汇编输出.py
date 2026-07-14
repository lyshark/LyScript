# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 封装反汇编多条函数
def disasm_code(dbg_ptr, eip, count):
    disasm_length = 0

    for index in range(0, count):
        # 获取一条反汇编代码
        disasm_asm = dbg_ptr.get_disasm_one_code(eip + disasm_length)
        disasm_addr = eip + disasm_length

        # 某些指令无法被计算出长度,此处可以添加直接跳过
        if(disasm_asm == "push 0xC0000409"):
            disasm_size = 5
        else:
            disasm_size = dbg_ptr.assemble_code_size(disasm_asm)

        print("内存地址: 0x{:08x} | 反汇编: {:35} | 长度: {}  | 机器码: "
		.format(disasm_addr, disasm_asm, disasm_size),end="")

        # 逐字节读入机器码
        for length in range(0, disasm_size):
            read = dbg_ptr.read_memory_byte(disasm_addr + length)
            print("{:02x} ".format(read),end="")
        print()

        # 递增地址
        disasm_length = disasm_length + disasm_size

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    eip = dbg.get_register("eip")
    disasm_code(dbg, eip, 55)

    dbg.close()
