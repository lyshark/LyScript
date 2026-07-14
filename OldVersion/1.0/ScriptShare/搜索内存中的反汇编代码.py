# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 检索指定序列中是否存在一段特定的指令集
def SearchOpCode(OpCodeList,SearchCode,ReadByte):
    SearchCount = len(SearchCode)
    for item in range(0,ReadByte):
        count = 0
        OpCode_Dic = OpCodeList[ 0 + item : SearchCount + item ]
        # print("切割字典: {}".format(OpCode_Dic))
        try:
            for x in range(0,SearchCount):
                if OpCode_Dic[x].get("opcode") == SearchCode[x]:
                    #print(OpCode_Dic[x].get("addr"),OpCode_Dic[x].get("opcode"))
                    count = count + 1
                    if count == SearchCount:
                        #print(OpCode_Dic[0].get("addr"))
                        return OpCode_Dic[0].get("addr")
                        exit(0)
        except Exception:
            pass

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # 得到EIP位置
    eip = dbg.get_register("eip")

    # 反汇编前1000行
    disasm_dict = dbg.get_disasm_code(eip,1000)

    # 搜索一个指令序列,用于快速查找构建漏洞利用代码
    SearchCode = [
        ["push 0xC0000409", "call 0x003F1B38", "pop ecx"],
        ["mov ebp, esp", "sub esp, 0x324"]
    ]

    # 检索内存指令集
    for item in range(0,len(SearchCode)):
        Search = SearchCode[item]
        # disasm_dict = 返回汇编指令 Search = 寻找指令集 1000 = 向下检索长度
        ret = SearchOpCode(disasm_dict,Search,1000)
        if ret != None:
            print("指令集: {} --> 首次出现地址: {}".format(SearchCode[item],hex(ret)))

    dbg.close()