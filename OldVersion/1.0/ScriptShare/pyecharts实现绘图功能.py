# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
from pyecharts import options as opts
from pyecharts.charts import Bar
 
def GrapBar(asm_list,count_list,title):
    bar = Bar()
    bar.add_xaxis(asm_list)
    bar.add_yaxis(title, count_list)
    bar.set_global_opts(title_opts=opts.TitleOpts(title="main", subtitle="sub main"))
    bar.render("index.html")
 
if __name__ == "__main__":
    dbg = MyDebug()
    conn = dbg.connect()
 
    # 得到EIP位置
    base = dbg.get_local_base()
    size = dbg.get_local_size()
 
    # 反汇编
    disasm_dict = dbg.get_disasm_code(base,size)
 
    count_push = 0
    count_call = 0
    count_call1 = 0
    je_count = 0
 
    for ds in disasm_dict:
        if ds.get("opcode") == "push dword ptr ss:[ebp+0x14]":
            count_push = count_push+1
 
        if ds.get("opcode") == "call esi":
            count_call = count_call + 1
 
        if ds.get("opcode") == "call dword ptr ds:[0x00402038]":
            count_call1 += 1
 
        if ds.get("opcode") == "je 0x0040181F":
            je_count+=1
 
    txt = ["push dword ptr ss:[ebp+0x14]","call esi","call 0x00402038","je 0x0040181F"]
    val = [count_push,count_call,count_call1,je_count]
    GrapBar(txt,val,"频率计数")
    dbg.close()
