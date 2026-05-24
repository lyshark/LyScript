from x64dbg import Config,BaseHttpClient
from x64dbg import Debugger
from x64dbg import Dissassembly
from x64dbg import Module
from x64dbg import Memory
from x64dbg import Process
from x64dbg import Gui
import json

if __name__ == "__main__":
    config = Config(address="127.0.0.1", port=8000)

    if not config.is_server_available():
        print("error")
    else:
        http_client = BaseHttpClient(config, debug=False)

        debugger = Debugger(http_client)

        eip = debugger.get_register("rbx")
        print(eip)

        r8 = debugger.get_register("r8")
        print(r8)