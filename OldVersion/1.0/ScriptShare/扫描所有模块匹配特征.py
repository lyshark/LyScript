# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 获取所有模块
    for entry in dbg.get_all_module():
        eip = entry.get("entry")
        base = entry.get("base")
        name = entry.get("name")

        if eip != 0:
            # 设置EIP到模块入口处
            dbg.set_register("eip",eip)

            # 开始搜索特征
            search = dbg.scan_memory_one("ff 25 ??")
            if search != 0 or search != None:

                # 如果找到了,则反汇编此行
                dasm = dbg.disasm_fast_at(search)

                print("addr = {} | base = {} | module = {} | search_addr = {} | dasm = {}"
                      .format(eip,base,name,eip,dasm.get("disasm")))

    dbg.close()