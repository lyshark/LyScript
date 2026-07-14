# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 将shellcode读入内存
def read_shellcode(path):
    shellcode_list = []
    with open(path,"r",encoding="utf-8") as fp:
        for index in fp.readlines():
            shellcode_line = index.replace('"',"").replace(" ","").replace("\n","").replace(";","")
            for code in shellcode_line.split("\\x"):
                if code != "" and code != "\\n":
                    shellcode_list.append("0x" + code)
    return shellcode_list

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 开辟堆空间
    address = dbg.create_alloc(1024)
    print("开辟堆空间: {}".format(hex(address)))
    if address == False:
        exit()

    # 设置内存可执行属性
    dbg.set_local_protect(address,32,1024)

    # 从文本中读取shellcode
    shellcode = read_shellcode("d://shellcode.txt")

    # 循环写入到内存
    for code_byte in range(0,len(shellcode)):
        bytef = int(shellcode[code_byte],16)
        dbg.write_memory_byte(code_byte + address, bytef)

    # 设置EIP位置
    dbg.set_register("eip",address)

    input()
    dbg.delete_alloc(address)

    dbg.close()