# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 将可执行文件中的单数转换为 0x00 格式
def ReadHexCode(code):
    hex_code = []

    for index in code:
        if index >= 0 and index <= 15:
            #print("0" + str(hex(index).replace("0x","")))
            hex_code.append("0" + str(hex(index).replace("0x","")))
        else:
            hex_code.append(hex(index).replace("0x",""))
            #print(hex(index).replace("0x",""))

    return hex_code

# 获取到内存中的机器码
def GetCode():
    try:
        ref_code = []
        dbg = MyDebug()
        connect_flag = dbg.connect()
        if connect_flag != 1:
            return None

        start_address = dbg.get_local_base()
        end_address = start_address + dbg.get_local_size()

        # 循环得到机器码
        for index in range(start_address,end_address):
            read_bytes = dbg.read_memory_byte(index)
            ref_code.append(read_bytes)

        dbg.close()
        return ref_code
    except Exception:
        return False

# 在字节数组中匹配是否与特征码一致
def SearchHexCode(Code,SearchCode,ReadByte):
    SearchCount = len(SearchCode)
    #print("特征码总长度: {}".format(SearchCount))
    for item in range(0,ReadByte):
        count = 0
        # 对十六进制数切片,每次向后遍历SearchCount
        OpCode = Code[ 0+item :SearchCount+item ]
        #print("切割数组: {} --> 对比: {}".format(OpCode,SearchCode))
        try:
            for x in range(0,SearchCount):
                if OpCode[x] == SearchCode[x]:
                    count = count + 1
                    #print("寻找特征码计数: {} {} {}".format(count,OpCode[x],SearchCode[x]))
                    if count == SearchCount:
                        # 如果找到了,就返回True,否则返回False
                        return True
                        exit(0)
        except Exception:
            pass
    return False

if __name__ == "__main__":
    # 读取到内存机器码
    ref_code = GetCode()
    if ref_code != False:
        # 转为十六进制
        hex_code = ReadHexCode(ref_code)
        code_size = len(hex_code)

        # 指定要搜索的特征码序列
        search = ['c0', '74', '0d', '66', '3b', 'c6', '77', '08']

        # 搜索特征: hex_code = exe的字节码,search=搜索特征码,code_size = 搜索大小
        ret = SearchHexCode(hex_code, search, code_size)
        if ret == True:
            print("特征码 {} 存在".format(search))
        else:
            print("特征码 {} 不存在".format(search))
    else:
        print("读入失败")