# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 传入汇编代码,得到对应机器码
def get_opcode_from_assemble(dbg_ptr,asm):
    byte_code = bytearray()

    addr = dbg_ptr.create_alloc(1024)
    if addr != 0:
        asm_size = dbg_ptr.assemble_code_size(asm)
        # print("汇编代码占用字节: {}".format(asm_size))

        write = dbg_ptr.assemble_write_memory(addr,asm)
        if write == True:
            for index in range(0,asm_size):
                read = dbg_ptr.read_memory_byte(addr + index)
                # print("{:02x} ".format(read),end="")
                byte_code.append(read)
        dbg_ptr.delete_alloc(addr)
        return byte_code
    else:
        return bytearray(0)

# 搜索机器码,如果存在则返回
def SearchOpCode(dbg_ptr, Search):

    # 搜索机器码并转换为列表
    op_code = []
    for index in Search:
        byte_array = get_opcode_from_assemble(dbg, index)
        for index in byte_array:
            op_code.append(hex(index))

    # print("机器码列表: {}".format(op_code))

    # 将机器码列表转换为字符串
    # 1.先转成字符串列表
    x = [str(i) for i in op_code]

    # 2.将字符串列表转为字符串
    # search_code = ' '.join(x).replace("0x","")
    search_code = []

    # 增加小于三位前面的0
    for l in range(0,len(x)):
        if len(x[l]) <= 3:
            # 如果是小于3位数则在前面增加0
            # print(''.join(x[l]).replace("0x","").zfill(2))
            search_code.append(''.join(x[l]).replace("0x","").zfill(2))
        else:
            search_code.append(''.join(x[l]).replace("0x", ""))

    # 3.变成字符串
    search_code = ' '.join(search_code).replace("0x", "")
    print("被搜索字符串: {}".format(search_code))

    # 调用搜索命令
    ref = dbg.scan_memory_one(search_code)
    if ref != None or ref != 0:
        return ref
    else:
        return 0
    return 0

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # 搜索一个指令序列,用于快速查找构建漏洞利用代码
    SearchCode = [
        ["pop ecx", "pop ebp", "ret", "push ebp"],
        ["push ebp", "mov ebp,esp"],
        ["mov ecx, dword ptr ds:[eax+0x3C]", "add ecx, eax"]
    ]

    # 检索内存指令集
    for item in range(0, len(SearchCode)):
        Search = SearchCode[item]
        ret = SearchOpCode(dbg, Search)
        print("所搜指令所在内存: {}".format(hex(ret)))

    dbg.close()