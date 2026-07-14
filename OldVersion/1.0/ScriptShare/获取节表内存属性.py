# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    conn = dbg.connect()

    section = dbg.get_section()
    for i in section:
        section_address = hex(i.get("addr"))
        section_name = i.get("name")
        section_size = i.get("size")
        section_type = dbg.get_local_protect(i.get("addr"))
        print(f"地址: {section_address} -> 名字: {section_name} -> 大小: {section_size}bytes -> ",end="")

        if(section_type == 32):
            print("属性: 执行/读取")
        elif(section_type == 30):
            print("属性: 执行")
        elif(section_type == 2):
            print("属性: 只读")
        elif(section_type == 4):
            print("属性: 读写")
        elif(section_type == 1):
            print("属性: 空属性")
        else:
            print("属性: 读/写/控制")

    dbg.close()
    pass