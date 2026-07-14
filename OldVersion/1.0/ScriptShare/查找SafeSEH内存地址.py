from LyScript32 import MyDebug
import struct

LOG_HANDLERS = True

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 得到PE头部基地址
    memory_image_base = dbg.get_base_from_address(dbg.get_local_base())

    peoffset = dbg.read_memory_dword(memory_image_base + int(0x3c))
    pebase = memory_image_base + peoffset

    flags = dbg.read_memory_word(pebase + int(0x5e))
    if(flags & int(0x400)) != 0:
        print("SafeSEH | NoHandler")

    numberofentries = dbg.read_memory_dword(pebase + int(0x74))
    if numberofentries > 10:

        # 读取 pebase+int(0x78)+8*10 | pebase+int(0x78)+8*10+4  读取八字节,分成两部分读取
        sectionaddress, sectionsize = [dbg.read_memory_dword(pebase+int(0x78)+8*10),
                                       dbg.read_memory_dword(pebase+int(0x78)+8*10 + 4)
                                       ]
        sectionaddress += memory_image_base
        data = dbg.read_memory_dword(sectionaddress)
        condition = (sectionsize != 0) and ((sectionsize == int(0x40)) or (sectionsize == data))

        if condition == False:
            print("[-] SafeSEH 无保护")
        if data < int(0x48):
            print("[-] 无法识别的DLL/EXE程序")

        sehlistaddress, sehlistsize = [dbg.read_memory_dword(sectionaddress+int(0x40)),
                                       dbg.read_memory_dword(sectionaddress+int(0x40) + 4)
                                       ]
        if sehlistaddress != 0 and sehlistsize != 0:
            print("[+] SafeSEH 保护中 | 长度: {}".format(sehlistsize))
            if LOG_HANDLERS == True:
                for i in range(sehlistsize):
                    sehaddress = dbg.read_memory_dword(sehlistaddress + 4 * i)
                    sehaddress += memory_image_base
                    print("SEHAddress = {}".format(hex(sehaddress)))

    dbg.close()