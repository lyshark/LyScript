from x32dbg import Config,BaseHttpClient
from x32dbg import Debugger
from x32dbg import Dissassembly
from x32dbg import Module
from x32dbg import Memory
from x32dbg import Process
from x32dbg import Gui
import json

if __name__ == "__main__":
    config = Config(address="127.0.0.1", port=8000)

    if not config.is_server_available():
        print("error")
    else:
        http_client = BaseHttpClient(config, debug=False)

        debugger = Debugger(http_client)

        eip = debugger.IsDebugger()
        print(eip)