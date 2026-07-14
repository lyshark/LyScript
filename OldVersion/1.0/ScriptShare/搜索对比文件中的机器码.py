# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

import os,sys

# 该过程用于将可执行文件转换为 0x00格式
def Read_HexCode(filename):
    Code = []
    with open(filename,"rb") as fp:
        HexCode = fp.read()
        for each in HexCode:
            if each >= 0 and each <= 15:
                #print("0" + str(hex(each).replace("0x","")))
                Code.append("0" + str(hex(each).replace("0x","")))
            else:
                Code.append(hex(each).replace("0x",""))
                #print(hex(each).replace("0x",""))
    return Code

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
    file_name = "./win.exe"
    file_size = os.path.getsize(file_name)
    # 读取可执行文件的十六进制数
    read_byte = Read_HexCode("./win.exe")
    # 指定要搜索的特征码序列
    search = ['6e', '6f', '74', '20', '62']
    # 搜索特征: read_byte = exe的字节码,search=搜索特征码,file_size = 搜索大小
    ret = SearchHexCode(read_byte,search,file_size)
    if ret == True:
        print("特征码 {} 存在".format(search))
    else:
        print("特征码 {} 不存在".format(search))