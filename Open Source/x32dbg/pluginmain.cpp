// By LyShark

#include "header.h"

// ÇëÇóÊý¾Ý½á¹¹
struct RequestData
{
	RequestType type;
	std::vector<std::string> params;
};

// CJSONÖÇÄÜÖ¸Õë·â×°
struct CJsonDeleter
{
	void operator()(cJSON* ptr) const
	{
		if (ptr != nullptr)
		{
			cJSON_Delete(ptr);
		}
	}
};
using CJsonPtr = std::unique_ptr<cJSON, CJsonDeleter>;

// ÏìÓ¦Êý¾Ý½á¹¹
struct ResponseData
{
	bool success;
	CJsonPtr result;

	// Ä¬ÈÏ¹¹Ôìº¯Êý
	ResponseData() : success(false), result(cJSON_CreateObject()) {}

	// ÒÆ¶¯¹¹Ôìº¯Êý
	ResponseData(ResponseData&& other)
		: success(other.success), result(std::move(other.result))
	{
		other.success = false;
	}

	// ÒÆ¶¯¸³ÖµÔËËã·û
	ResponseData& operator=(ResponseData&& other)
	{
		if (this != &other)
		{
			success = other.success;
			result = std::move(other.result);
			other.success = false;
		}
		return *this;
	}

	// É¾³ý¿½±´¹¹Ôìº¯ÊýºÍ¿½±´¸³ÖµÔËËã·û
	ResponseData(const ResponseData&) = delete;
	ResponseData& operator=(const ResponseData&) = delete;
};

// ¿çÆ½Ì¨Ïß³Ì¹¤¾ßÀà£¨±£ÁôWindowsÊµÏÖ£¬É¾³ýÈßÓàµÄelse·ÖÖ§£©
class ThreadUtils
{
public:
	using ThreadHandle = HANDLE;
	using MutexHandle = HANDLE;

	static ThreadHandle create_thread(LPTHREAD_START_ROUTINE func)
	{
		return CreateThread(nullptr, 0, func, nullptr, 0, nullptr);
	}

	static void join_thread(ThreadHandle handle)
	{
		if (handle != nullptr)
		{
			WaitForSingleObject(handle, INFINITE);
			CloseHandle(handle);
		}
	}

	static MutexHandle create_mutex()
	{
		return CreateMutex(nullptr, FALSE, nullptr);
	}

	static void lock_mutex(MutexHandle mutex)
	{
		WaitForSingleObject(mutex, INFINITE);
	}

	static void unlock_mutex(MutexHandle mutex)
	{
		ReleaseMutex(mutex);
	}

	static void destroy_mutex(MutexHandle mutex)
	{
		CloseHandle(mutex);
	}
};

// ·þÎñÆ÷ÉÏÏÂÎÄÀà£¨ÐÞ¸´WindowsÏÂMutex³õÊ¼»¯Âß¼­£©
class ServerContext
{
public:
	mg_mgr mgr;
	std::atomic<bool> running;
	ThreadUtils::ThreadHandle thread;
	ThreadUtils::MutexHandle mutex;
	std::string listen_addr;
	class RequestHandler* handler;

	ServerContext() : running(false), handler(nullptr)
	{
		// Ö±½ÓÊ¹ÓÃWindowsÏß³Ì¹¤¾ßÀà³õÊ¼»¯£¬É¾³ýÈßÓàµÄ¿çÆ½Ì¨·ÖÖ§
		mutex = ThreadUtils::create_mutex();
		mg_mgr_init(&mgr);
	}

	~ServerContext()
	{
		ThreadUtils::destroy_mutex(mutex);
		mg_mgr_free(&mgr);
	}
};

// ÇëÇó½âÎöÆ÷
class RequestParser
{
public:
	static RequestData parse(cJSON* req_json)
	{
		RequestData data;
		data.type = RequestType::Unknown;

		// Ôö¼Ó²ÎÊý¿ÕÖ¸ÕëÅÐ¶Ï£¬±ÜÃâ·ÃÎÊ¿Õ¶ÔÏó
		if (!req_json) return data;

		cJSON* class_name = cJSON_GetObjectItemCaseSensitive(req_json, "class");
		cJSON* interface = cJSON_GetObjectItemCaseSensitive(req_json, "interface");
		cJSON* param_list = cJSON_GetObjectItemCaseSensitive(req_json, "params");

		// ÑéÖ¤»ù±¾²ÎÊý£¨ÔÊÐíparam_listÎª¿ÕÊý×é£¬ÐÞÕýÔ­Âß¼­ÖÐ"±ØÐëÊÇÊý×é"µÄÑÏ¸ñÏÞÖÆ£©
		if (!cJSON_IsString(class_name) || !class_name->valuestring ||
			!cJSON_IsString(interface) || !interface->valuestring)
		{
			return data;
		}

		// ½âÎö²ÎÊýÁÐ±í£¨Èç¹ûparam_list´æÔÚÇÒÊÇÊý×é²Å½âÎö£¬±ÜÃâ¿ÕÖ¸Õë·ÃÎÊ£©
		if (param_list && cJSON_IsArray(param_list))
		{
			for (int i = 0; i < cJSON_GetArraySize(param_list); i++)
			{
				cJSON* param = cJSON_GetArrayItem(param_list, i);
				if (cJSON_IsString(param) && param->valuestring)
				{
					data.params.push_back(param->valuestring);
				}
				else if (cJSON_IsNumber(param))
				{
					data.params.push_back(std::to_string(param->valueint));
				}
			}
		}

		// ÀàÐÍÓ³Éä£¨È·±£ÓëÊµ¼Ê½Ó¿ÚÃûÍêÈ«Æ¥Åä£©
		std::string cls = class_name->valuestring;
		std::string iface = interface->valuestring;

		if (cls == "Debugger")
		{
			// ÈôÌáÊ¾£º
			// ²éÕÒÓ³Éä±í£ºÕÒµ½Ôò¸³Öµ¶ÔÓ¦ RequestType£¬Î´ÕÒµ½ÔòÉèÎª Unknown
			auto iter = DebuggerIfaceMap.find(iface);
			data.type = (iter != DebuggerIfaceMap.end()) ? iter->second : RequestType::Unknown;
		}
		else if (cls == "Dissassembly")
		{
			if (iface == "DisasmOneCode")
			{
				data.type = RequestType::Dissassembly_DisasmOneCode;
			}
			else if (iface == "DisasmCountCode")
			{
				data.type = RequestType::Dissassembly_DisasmCountCode;
			}
			else if (iface == "DisasmOperand")
			{
				data.type = RequestType::Dissassembly_DisasmOperand;
			}
			else if (iface == "DisasmFastAtFunction")
			{
				data.type = RequestType::Dissassembly_DisasmFastAtFunction;
			}
			else if (iface == "GetOperandSize")
			{
				data.type = RequestType::Dissassembly_GetOperandSize;
			}
			else if (iface == "GetBranchDestination")
			{
				data.type = RequestType::Dissassembly_GetBranchDestination;
			}
			else if (iface == "GuiGetDisassembly")
			{
				data.type = RequestType::Dissassembly_GuiGetDisassembly;
			}
			else if (iface == "AssembleMemoryEx")
			{
				data.type = RequestType::Dissassembly_AssembleMemoryEx;
			}
			else if (iface == "AssembleCodeSize")
			{
				data.type = RequestType::Dissassembly_AssembleCodeSize;
			}
			else if (iface == "AssembleCodeHex")
			{
				data.type = RequestType::Dissassembly_AssembleCodeHex;
			}
			else if (iface == "AssembleAtFunctionEx")
			{
				data.type = RequestType::Dissassembly_AssembleAtFunctionEx;
			}
			else
			{
				data.type = RequestType::Unknown;
			}
		}
		else if (cls == "Module")
		{
			if (iface == "GetModuleBaseAddress")
			{
				data.type = RequestType::Module_GetModuleBaseAddress;
			}
			else if (iface == "GetModuleProcAddress")
			{
				data.type = RequestType::Module_GetModuleProcAddress;
			}
			else if (iface == "GetBaseFromAddr")
			{
				data.type = RequestType::Module_GetBaseFromAddr;
			}
			else if (iface == "GetBaseFromName")
			{
				data.type = RequestType::Module_GetBaseFromName;
			}
			else if (iface == "GetSizeFromAddress")
			{
				data.type = RequestType::Module_GetSizeFromAddress;
			}
			else if (iface == "GetSizeFromName")
			{
				data.type = RequestType::Module_GetSizeFromName;
			}
			else if (iface == "GetOEPFromName")
			{
				data.type = RequestType::Module_GetOEPFromName;
			}
			else if (iface == "GetOEPFromAddr")
			{
				data.type = RequestType::Module_GetOEPFromAddr;
			}
			else if (iface == "GetPathFromName")
			{
				data.type = RequestType::Module_GetPathFromName;
			}
			else if (iface == "GetPathFromAddr")
			{
				data.type = RequestType::Module_GetPathFromAddr;
			}
			else if (iface == "GetNameFromAddr")
			{
				data.type = RequestType::Module_GetNameFromAddr;
			}
			else if (iface == "GetMainModuleSectionCount")
			{
				data.type = RequestType::Module_GetMainModuleSectionCount;
			}
			else if (iface == "GetMainModulePath")
			{
				data.type = RequestType::Module_GetMainModulePath;
			}
			else if (iface == "GetMainModuleSize")
			{
				data.type = RequestType::Module_GetMainModuleSize;
			}
			else if (iface == "GetMainModuleName")
			{
				data.type = RequestType::Module_GetMainModuleName;
			}
			else if (iface == "GetMainModuleEntry")
			{
				data.type = RequestType::Module_GetMainModuleEntry;
			}
			else if (iface == "GetMainModuleBase")
			{
				data.type = RequestType::Module_GetMainModuleBase;
			}
			else if (iface == "SectionCountFromName")
			{
				data.type = RequestType::Module_SectionCountFromName;
			}
			else if (iface == "SectionCountFromAddr")
			{
				data.type = RequestType::Module_SectionCountFromAddr;
			}
			else if (iface == "GetModuleAt")
			{
				data.type = RequestType::Module_GetModuleAt;
			}
			else if (iface == "GetWindowHandle")
			{
				data.type = RequestType::Module_GetWindowHandle;
			}
			else if (iface == "GetInfoFromAddr")
			{
				data.type = RequestType::Module_GetInfoFromAddr;
			}
			else if (iface == "GetInfoFromName")
			{
				data.type = RequestType::Module_GetInfoFromName;
			}
			else if (iface == "GetSectionFromAddr")
			{
				data.type = RequestType::Module_GetSectionFromAddr;
			}
			else if (iface == "GetSectionFromName")
			{
				data.type = RequestType::Module_GetSectionFromName;
			}
			else if (iface == "GetSectionListFromAddr")
			{
				data.type = RequestType::Module_GetSectionListFromAddr;
			}
			else if (iface == "GetSectionListFromName")
			{
				data.type = RequestType::Module_GetSectionListFromName;
			}
			else if (iface == "GetMainModuleInfoEx")
			{
				data.type = RequestType::Module_GetMainModuleInfoEx;
			}
			else if (iface == "GetSection")
			{
				data.type = RequestType::Module_GetSection;
			}
			else if (iface == "GetAllModule")
			{
				data.type = RequestType::Module_GetAllModule;
			}
			else if (iface == "GetImport")
			{
				data.type = RequestType::Module_GetImport;
			}
			else if (iface == "GetExport")
			{
				data.type = RequestType::Module_GetExport;
			}
			else
			{
				data.type = RequestType::Unknown;
			}
		}
		else if (cls == "Memory")
		{
			if (iface == "GetBase")
			{
				data.type = RequestType::Memory_GetBase;
			}
			else if (iface == "GetLocalBase")
			{
				data.type = RequestType::Memory_GetLocalBase;
			}
			else if (iface == "GetSize")
			{
				data.type = RequestType::Memory_GetSize;
			}
			else if (iface == "GetLocalSize")
			{
				data.type = RequestType::Memory_GetLocalSize;
			}
			else if (iface == "GetProtect")
			{
				data.type = RequestType::Memory_GetProtect;
			}
			else if (iface == "GetLocalProtect")
			{
				data.type = RequestType::Memory_GetLocalProtect;
			}
			else if (iface == "GetLocalPageSize")
			{
				data.type = RequestType::Memory_GetLocalPageSize;
			}
			else if (iface == "GetPageSize")
			{
				data.type = RequestType::Memory_GetPageSize;
			}
			else if (iface == "IsValidReadPtr")
			{
				data.type = RequestType::Memory_IsValidReadPtr;
			}
			else if (iface == "GetSectionMap")
			{
				data.type = RequestType::Memory_GetSectionMap;
			}

			else if (iface == "SetProtect")
			{
				data.type = RequestType::Memory_SetProtect;
			}
			else if (iface == "GetXrefCountAt")
				data.type = RequestType::Memory_GetXrefCountAt;
			else if (iface == "GetXrefTypeAt")
				data.type = RequestType::Memory_GetXrefTypeAt;
			else if (iface == "GetFunctionTypeAt")
				data.type = RequestType::Memory_GetFunctionTypeAt;
			else if (iface == "IsJumpGoingToExecute")
				data.type = RequestType::Memory_IsJumpGoingToExecute;
			else if (iface == "RemoteAlloc")
				data.type = RequestType::Memory_RemoteAlloc;
			else if (iface == "RemoteFree")
				data.type = RequestType::Memory_RemoteFree;
			else if (iface == "StackPush")
				data.type = RequestType::Memory_StackPush;
			else if (iface == "StackPop")
				data.type = RequestType::Memory_StackPop;
			else if (iface == "StackPeek")
				data.type = RequestType::Memory_StackPeek;
			else if (iface == "ScanModule")
				data.type = RequestType::Memory_ScanModule;
			else if (iface == "ScanRange")
				data.type = RequestType::Memory_ScanRange;
			else if (iface == "ScanModuleAll")
				data.type = RequestType::Memory_ScanModuleAll;
			else if (iface == "WritePattern")
				data.type = RequestType::Memory_WritePattern;
			else if (iface == "ReplacePattern")
				data.type = RequestType::Memory_ReplacePattern;

			else if (iface == "ReadByte")
			{
				data.type = RequestType::Memory_ReadByte;
			}
			else if (iface == "ReadWord")
			{
				data.type = RequestType::Memory_ReadWord;
			}
			else if (iface == "ReadDword")
			{
				data.type = RequestType::Memory_ReadDword;
			}
#ifdef _WIN64
			else if (iface == "ReadQword")
			{
				data.type = RequestType::Memory_ReadQword;
			}
#endif
			else if (iface == "ReadPtr")
			{
				data.type = RequestType::Memory_ReadPtr;
			}
			else if (iface == "WriteByte")
			{
				data.type = RequestType::Memory_WriteByte;
			}
			else if (iface == "WriteWord")
			{
				data.type = RequestType::Memory_WriteWord;
			}
			else if (iface == "WriteDword")
			{
				data.type = RequestType::Memory_WriteDword;
			}
#ifdef _WIN64
			else if (iface == "WriteQword")
			{
				data.type = RequestType::Memory_WriteQword;
			}
#endif
			else if (iface == "WritePtr")
			{
				data.type = RequestType::Memory_WritePtr;
			}
			else
			{
				data.type = RequestType::Unknown;
			}
		}

		else if (cls == "Process")
		{
			if (iface == "GetThreadList")
				data.type = RequestType::Process_GetThreadList;
			else if (iface == "GetHandle")
				data.type = RequestType::Process_GetHandle;
			else if (iface == "GetThreadHandle")
				data.type = RequestType::Process_GetThreadHandle;
			else if (iface == "GetPid")
				data.type = RequestType::Process_GetPid;
			else if (iface == "GetTid")
				data.type = RequestType::Process_GetTid;
			else if (iface == "GetTeb")
				data.type = RequestType::Process_GetTeb;
			else if (iface == "GetPeb")
				data.type = RequestType::Process_GetPeb;
			else if (iface == "GetMainThreadId")
				data.type = RequestType::Process_GetMainThreadId;
			else
				data.type = RequestType::Unknown;
		}

		else if (cls == "Script")
		{
			if (iface == "RunCmd")
				data.type = RequestType::Script_RunCmd;
			else if (iface == "RunCmdRef")
				data.type = RequestType::Script_RunCmdRef;
			else if (iface == "Load")
				data.type = RequestType::Script_Load;
			else if (iface == "Unload")
				data.type = RequestType::Script_Unload;
			else if (iface == "Run")
				data.type = RequestType::Script_Run;
			else if (iface == "SetIp")
				data.type = RequestType::Script_SetIp;
			else
				data.type = RequestType::Unknown;
		}

		else if (cls == "Gui")
		{
			if (iface == "SetComment")
				data.type = RequestType::Gui_SetComment;
			else if (iface == "Log")
				data.type = RequestType::Gui_Log;
			else if (iface == "AddStatusBarMessage")
				data.type = RequestType::Gui_AddStatusBarMessage;
			else if (iface == "ClearLog")
				data.type = RequestType::Gui_ClearLog;
			else if (iface == "ShowCpu")
				data.type = RequestType::Gui_ShowCpu;
			else if (iface == "UpdateAllViews")
				data.type = RequestType::Gui_UpdateAllViews;

			else if (iface == "GetInput")
				data.type = RequestType::Gui_GetInput;
			else if (iface == "Confirm")
				data.type = RequestType::Gui_Confirm;
			else if (iface == "ShowMessage")
				data.type = RequestType::Gui_ShowMessage;
			else if (iface == "AddArgumentBracket")
				data.type = RequestType::Gui_AddArgumentBracket;
			else if (iface == "DelArgumentBracket")
				data.type = RequestType::Gui_DelArgumentBracket;
			else if (iface == "AddFunctionBracket")
				data.type = RequestType::Gui_AddFunctionBracket;
			else if (iface == "DelFunctionBracket")
				data.type = RequestType::Gui_DelFunctionBracket;
			else if (iface == "AddLoopBracket")
				data.type = RequestType::Gui_AddLoopBracket;
			else if (iface == "DelLoopBracket")
				data.type = RequestType::Gui_DelLoopBracket;
			else if (iface == "SetLabel")
				data.type = RequestType::Gui_SetLabel;
			else if (iface == "ResolveLabel")
				data.type = RequestType::Gui_ResolveLabel;
			else if (iface == "ClearAllLabels")
				data.type = RequestType::Gui_ClearAllLabels;

			else
				data.type = RequestType::Unknown;
		}








		else
		{
			data.type = RequestType::Unknown;
		}



		return data;
	}
};

// GUI´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class GuiHandler
{
public:
	static ResponseData handle_gui_set_comment(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨µØÖ· + ×¢ÊÍÄÚÈÝ£©
		if (params.size() != 2) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 2: [address, comment_text]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Add comment to 0x00401000: [\"0x00401000\", \"Main function entry\"]");
			return resp;
		}

		const std::string addr_str = params[0];
		const std::string comment = params[1];

		// Ð£ÑéµØÖ··Ç¿ÕÇÒÓÐÐ§
		unsigned long long address = 0;
		if (!parse_value(addr_str, address) || address == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_address", addr_str.c_str());
			return resp;
		}

		// Ð£Ñé×¢ÊÍ·Ç¿Õ
		if (comment.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Comment text cannot be empty");
			cJSON_AddStringToObject(resp.result.get(), "target_address", addr_str.c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÉèÖÃ×¢ÊÍ
			BOOL set_success = DbgSetCommentAt(static_cast<duint>(address), comment.c_str());

			// 3. ´¦Àí½á¹û
			resp.success = (set_success != FALSE);
			if (resp.success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Comment set successfully");
				cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(address).c_str());
				cJSON_AddNumberToObject(resp.result.get(), "target_address_dec", address);
				cJSON_AddStringToObject(resp.result.get(), "comment_text", comment.c_str());
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to set comment (invalid address or permission denied)");
				cJSON_AddStringToObject(resp.result.get(), "target_address", addr_str.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while setting comment");
			cJSON_AddStringToObject(resp.result.get(), "target_address", addr_str.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_log(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÈÕÖ¾ÎÄ±¾£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [log_text]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Log message: [\"User triggered breakpoint at 0x00401000\"]");
			return resp;
		}

		const std::string log_text = params[0];
		if (log_text.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Log text cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÊä³öÈÕÖ¾
			_plugin_logprintf(log_text.c_str());

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Log message printed successfully");
			cJSON_AddStringToObject(resp.result.get(), "log_text", log_text.c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "Message appears in debugger's log window");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while printing log message");
			cJSON_AddStringToObject(resp.result.get(), "log_text", log_text.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_add_status_bar_message(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨×´Ì¬À¸ÎÄ±¾£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [status_text]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Show status: [\"Analysis completed successfully\"]");
			return resp;
		}

		const std::string status_text = params[0];
		if (status_text.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Status bar text cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÌí¼Ó×´Ì¬À¸ÏûÏ¢
			GuiAddStatusBarMessage(status_text.c_str());

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Status bar message added successfully");
			cJSON_AddStringToObject(resp.result.get(), "status_text", status_text.c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "Message appears in debugger's status bar (temporary)");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while adding status bar message");
			cJSON_AddStringToObject(resp.result.get(), "status_text", status_text.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_clear_log(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÇå¿ÕÈÕÖ¾
			GuiLogClear();

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Debugger log cleared successfully");
			cJSON_AddStringToObject(resp.result.get(), "note", "All entries in the log window have been removed");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while clearing log");
		}

		return resp;
	}

	static ResponseData handle_gui_show_cpu(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÇÐ»»µ½CPU´°¿Ú
			GuiShowCpu();

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Debugger switched to CPU disassembly view");
			cJSON_AddStringToObject(resp.result.get(), "note", "CPU view shows assembly instructions and execution state");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while switching to CPU view");
		}

		return resp;
	}

	static ResponseData handle_gui_update_all_views(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýË¢ÐÂÊÓÍ¼
			GuiUpdateAllViews();

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "All debugger views updated successfully");
			cJSON_AddStringToObject(resp.result.get(), "note", "Refreshed memory, registers, stack, and other open views");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while updating views");
		}

		return resp;
	}

	static ResponseData handle_gui_get_input(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÊäÈë¿òÌáÊ¾ÎÄ±¾£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [prompt_text]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Prompt for username: [\"Enter target username:\"]");
			return resp;
		}

		const std::string prompt = params[0];
		if (prompt.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Prompt text cannot be empty");
			return resp;
		}

		try {
			char user_input[256] = { 0 }; // Ô­º¯ÊýÏÞÖÆ256×Ö½Ú
			BOOL input_success = GuiGetLineWindow(prompt.c_str(), user_input);

			// 2. ´¦Àí½á¹û£¨input_success=false£ºÓÃ»§È¡ÏûÊäÈë£©
			if (!input_success) {
				resp.success = true; // È¡ÏûÊäÈë²»Ëã´íÎó
				cJSON_AddStringToObject(resp.result.get(), "message", "User canceled input (dialog closed)");
				cJSON_AddStringToObject(resp.result.get(), "prompt_text", prompt.c_str());
				return resp;
			}

			// 3. ³É¹¦»ñÈ¡ÊäÈë
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Input dialog closed with user input");
			cJSON_AddStringToObject(resp.result.get(), "prompt_text", prompt.c_str());
			cJSON_AddStringToObject(resp.result.get(), "user_input", user_input);
			cJSON_AddNumberToObject(resp.result.get(), "input_length", strlen(user_input));
			cJSON_AddStringToObject(resp.result.get(), "note", "Input is limited to 255 characters (truncated if longer)");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while showing input dialog");
			cJSON_AddStringToObject(resp.result.get(), "prompt_text", prompt.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_confirm(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨È·ÈÏ¿òÌáÊ¾ÎÄ±¾£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [confirm_text]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Confirm deletion: [\"Delete selected breakpoint?\"]");
			return resp;
		}

		const std::string confirm_text = params[0];
		if (confirm_text.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Confirm text cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡ÓÃ»§Ñ¡Ôñ£¨Ô­º¯Êý·µ»Øint£º1=Yes£¬0=No£©
			int user_choice = GuiScriptMsgyn(confirm_text.c_str());

			// 3. ´¦Àí½á¹û
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Confirm dialog closed with user choice");
			cJSON_AddStringToObject(resp.result.get(), "confirm_text", confirm_text.c_str());
			cJSON_AddNumberToObject(resp.result.get(), "user_choice", user_choice);
			cJSON_AddStringToObject(resp.result.get(), "choice_description",
				user_choice == 1 ? "Yes (user confirmed)" : "No (user rejected)");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while showing confirm dialog");
			cJSON_AddStringToObject(resp.result.get(), "confirm_text", confirm_text.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_show_message(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÌáÊ¾ÎÄ±¾£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [message_text]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Show completion message: [\"Analysis finished!\"]");
			return resp;
		}

		const std::string msg_text = params[0];
		if (msg_text.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Message text cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êýµ¯³öÌáÊ¾¿ò
			GuiScriptMessage(msg_text.c_str());

			// 3. ´¦Àí½á¹û£¨ÎÞ·µ»ØÖµ£¬Ä¬ÈÏ³É¹¦£©
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Message dialog shown successfully");
			cJSON_AddStringToObject(resp.result.get(), "message_text", msg_text.c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "Dialog requires user to click 'OK' to close");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while showing message dialog");
			cJSON_AddStringToObject(resp.result.get(), "message_text", msg_text.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_add_argument_bracket(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨ÆðÊ¼µØÖ·¡¢½áÊøµØÖ·£©
		if (params.size() != 2) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 2: [start_address, end_address]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Mark args 0x00401000-0x00401008: [\"0x00401000\", \"0x00401008\"]");
			return resp;
		}

		// ½âÎö²¢Ð£ÑéµØÖ·
		unsigned long long start_addr = 0, end_addr = 0;
		if (!parse_value(params[0], start_addr) || start_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid start address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_start_addr", params[0].c_str());
			return resp;
		}
		if (!parse_value(params[1], end_addr) || end_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid end address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_end_addr", params[1].c_str());
			return resp;
		}
		if (start_addr >= end_addr) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Start address must be less than end address");
			cJSON_AddStringToObject(resp.result.get(), "start_addr_hex", format_address(start_addr).c_str());
			cJSON_AddStringToObject(resp.result.get(), "end_addr_hex", format_address(end_addr).c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÌí¼ÓÀ¨ºÅ
			BOOL add_success = DbgArgumentAdd(
				static_cast<duint>(start_addr),
				static_cast<duint>(end_addr)
				);

			// 3. ´¦Àí½á¹û
			resp.success = add_success;
			if (add_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Argument bracket added successfully (comment section)");


				cJSON_AddStringToObject(
					resp.result.get(),
					"range_hex",
					// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
					(format_address(start_addr) + " - " + format_address(end_addr)).c_str()
					);
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to add argument bracket (invalid range or duplicate)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while adding argument bracket");


			cJSON_AddStringToObject(
				resp.result.get(),
				"range_hex",
				// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
				(format_address(start_addr) + " - " + format_address(end_addr)).c_str()
				);
		}

		return resp;
	}

	static ResponseData handle_gui_del_argument_bracket(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨À¨ºÅËùÔÚµØÖ·£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [bracket_address]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Delete bracket at 0x00401000: [\"0x00401000\"]");
			return resp;
		}

		// ½âÎöµØÖ·
		unsigned long long bracket_addr = 0;
		if (!parse_value(params[0], bracket_addr) || bracket_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid bracket address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_address", params[0].c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÉ¾³ýÀ¨ºÅ
			BOOL del_success = DbgArgumentDel(static_cast<duint>(bracket_addr));

			// 3. ´¦Àí½á¹û
			resp.success = del_success;
			if (del_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Argument bracket deleted successfully (comment section)");
				cJSON_AddStringToObject(resp.result.get(), "bracket_address_hex", format_address(bracket_addr).c_str());
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to delete argument bracket (no bracket found at address)");
				cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(bracket_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while deleting argument bracket");
			cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(bracket_addr).c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_add_function_bracket(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨ÆðÊ¼µØÖ·¡¢½áÊøµØÖ·£©
		if (params.size() != 2) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 2: [start_address, end_address]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Mark function 0x00401000-0x00401050: [\"0x00401000\", \"0x00401050\"]");
			return resp;
		}

		// ½âÎö²¢Ð£ÑéµØÖ·
		unsigned long long start_addr = 0, end_addr = 0;
		if (!parse_value(params[0], start_addr) || start_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid function start address");
			cJSON_AddStringToObject(resp.result.get(), "invalid_start_addr", params[0].c_str());
			return resp;
		}
		if (!parse_value(params[1], end_addr) || end_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid function end address");
			cJSON_AddStringToObject(resp.result.get(), "invalid_end_addr", params[1].c_str());
			return resp;
		}
		if (start_addr >= end_addr) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Function start address must be less than end address");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÌí¼ÓÀ¨ºÅ
			BOOL add_success = DbgFunctionAdd(
				static_cast<duint>(start_addr),
				static_cast<duint>(end_addr)
				);

			// 3. ´¦Àí½á¹û
			resp.success = add_success;
			if (add_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Function bracket added successfully (machine code section)");


				cJSON_AddStringToObject(
					resp.result.get(),
					"function_range_hex",
					// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
					(format_address(start_addr) + " - " + format_address(end_addr)).c_str()
					);


			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to add function bracket (invalid range or duplicate)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while adding function bracket");

			cJSON_AddStringToObject(
				resp.result.get(),
				"function_range_hex",
				// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
				(format_address(start_addr) + " - " + format_address(end_addr)).c_str()
				);

		}

		return resp;
	}

	static ResponseData handle_gui_add_loop_bracket(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ñ­»·ÆðÊ¼µØÖ·¡¢Ñ­»·½áÊøµØÖ·£©
		if (params.size() != 2) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 2: [loop_start, loop_end]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Mark loop 0x00401020-0x00401040: [\"0x00401020\", \"0x00401040\"]");
			return resp;
		}

		// ½âÎö²¢Ð£ÑéµØÖ·
		unsigned long long loop_start = 0, loop_end = 0;
		if (!parse_value(params[0], loop_start) || loop_start == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid loop start address");
			cJSON_AddStringToObject(resp.result.get(), "invalid_start", params[0].c_str());
			return resp;
		}
		if (!parse_value(params[1], loop_end) || loop_end == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid loop end address");
			cJSON_AddStringToObject(resp.result.get(), "invalid_end", params[1].c_str());
			return resp;
		}
		if (loop_start >= loop_end) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Loop start address must be less than end address");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÌí¼ÓÑ­»·À¨ºÅ
			BOOL add_success = DbgLoopAdd(
				static_cast<duint>(loop_start),
				static_cast<duint>(loop_end)
				);

			// 3. ´¦Àí½á¹û
			resp.success = add_success;
			if (add_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Loop bracket added successfully (disassembly section)");


				cJSON_AddStringToObject(
					resp.result.get(),
					"loop_range_hex",
					// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
					(format_address(loop_start) + " - " + format_address(loop_end)).c_str()
					);


			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to add loop bracket (invalid range or not a loop)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while adding loop bracket");



			cJSON_AddStringToObject(
				resp.result.get(),
				"loop_range_hex",
				// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
				(format_address(loop_start) + " - " + format_address(loop_end)).c_str()
				);


		}

		return resp;
	}

	static ResponseData handle_gui_set_label(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä¿±êµØÖ·¡¢±êÇ©Ãû£©
		if (params.size() != 2) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 2: [target_address, label_name]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Label 0x00401000 as 'MainEntry': [\"0x00401000\", \"MainEntry\"]");
			return resp;
		}

		const std::string addr_str = params[0];
		const std::string label_name = params[1];

		// Ð£ÑéµØÖ·
		unsigned long long target_addr = 0;
		if (!parse_value(addr_str, target_addr) || target_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid target address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_address", addr_str.c_str());
			return resp;
		}

		// Ð£Ñé±êÇ©Ãû£¨·Ç¿Õ£¬±ÜÃâÎÞÐ§±êÇ©£©
		if (label_name.empty() || label_name.size() > 64) { // ¼ÙÉè±êÇ©Ãû×î´ó64×Ö·û
			cJSON_AddStringToObject(resp.result.get(), "error", "Label name must be 1-64 characters (non-empty)");
			cJSON_AddStringToObject(resp.result.get(), "invalid_label", label_name.c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÉèÖÃ±êÇ©
			BOOL set_success = DbgSetLabelAt(
				static_cast<duint>(target_addr),
				label_name.c_str()
				);

			// 3. ´¦Àí½á¹û
			resp.success = set_success;
			if (set_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Label set successfully");
				cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(resp.result.get(), "label_name", label_name.c_str());
				cJSON_AddStringToObject(resp.result.get(), "note", "Label will override existing label at the same address");
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to set label (invalid address or invalid label characters)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while setting label");
			cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(target_addr).c_str());
			cJSON_AddStringToObject(resp.result.get(), "label_name", label_name.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_resolve_label(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨±êÇ©Ãû£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [label_name]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Find address of 'MainEntry': [\"MainEntry\"]");
			return resp;
		}

		const std::string label_name = params[0];
		if (label_name.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Label name cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý½âÎö±êÇ©
			duint label_addr = Script::Misc::ResolveLabel(label_name.c_str());

			// 3. ´¦Àí½á¹û£¨label_addr <=0£º±êÇ©²»´æÔÚ£©
			if (label_addr <= 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Label not found (check label name spelling)");
				cJSON_AddStringToObject(resp.result.get(), "target_label", label_name.c_str());
				return resp;
			}

			// ³É¹¦½âÎö
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Label resolved to address successfully");
			cJSON_AddStringToObject(resp.result.get(), "label_name", label_name.c_str());
			cJSON_AddStringToObject(resp.result.get(), "resolved_address_hex", format_address(static_cast<unsigned long long>(label_addr)).c_str());
			cJSON_AddNumberToObject(resp.result.get(), "resolved_address_dec", static_cast<unsigned long long>(label_addr));

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while resolving label");
			cJSON_AddStringToObject(resp.result.get(), "target_label", label_name.c_str());
		}

		return resp;
	}

	static ResponseData handle_gui_clear_all_labels(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨µ«ÐèÈ·ÈÏ²Ù×÷£©
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÇå¿Õ±êÇ©
			Script::Label::Clear();

			// 3. ´¦Àí½á¹û£¨ÌáÊ¾·çÏÕ£©
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "All labels cleared successfully");
			cJSON_AddStringToObject(resp.result.get(), "warning",
				"This operation is irreversible - all user-defined labels have been deleted");
			cJSON_AddStringToObject(resp.result.get(), "note", "Re-add labels via Gui.SetLabel if needed");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while clearing all labels");
		}

		return resp;
	}

	static ResponseData handle_gui_del_function_bracket(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨»úÆ÷ÂëÀ¨ºÅËùÔÚµØÖ·£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [function_bracket_address]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Delete function bracket at 0x00401000: [\"0x00401000\"]");
			return resp;
		}

		// ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨·Ç0£©
		unsigned long long bracket_addr = 0;
		if (!parse_value(params[0], bracket_addr) || bracket_addr == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid function bracket address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_address", params[0].c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÉ¾³ý»úÆ÷ÂëÀ¨ºÅ£¨Ô­º¯Êý²ÎÊýÎªduint£¬ÐèÀàÐÍ×ª»»£©
			BOOL del_success = DbgFunctionDel(static_cast<duint>(bracket_addr));

			// 3. ´¦Àí½á¹û£¨Çø·Ö¡°É¾³ý³É¹¦¡±ºÍ¡°ÎÞ¶ÔÓ¦À¨ºÅ¡±£©
			resp.success = del_success;
			if (del_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Function bracket deleted successfully (machine code section)");
				cJSON_AddStringToObject(resp.result.get(), "deleted_bracket_address_hex", format_address(bracket_addr).c_str());
				cJSON_AddStringToObject(resp.result.get(), "note", "Bracket marks a function range in the disassembly view");
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to delete function bracket (no function bracket found at address)");
				cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(bracket_addr).c_str());
			}

			// Æ½Ì¨±êÊ¶£¨ÓëÆäËû½Ó¿Ú±£³ÖÒ»ÖÂ£©
#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			// ²¶»ñÒâÍâÒì³££¨ÈçµØÖ·Ô½½ç¡¢½Ó¿Úµ÷ÓÃÊ§°Ü£©
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while deleting function bracket");
			cJSON_AddStringToObject(resp.result.get(), "target_address_hex", format_address(bracket_addr).c_str());
		}

		return resp;
	}

	// ÎÞ·¨É¾³ý±êÇ©
	static ResponseData handle_gui_del_loop_bracket(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ñ­»·À¨ºÅÆðÊ¼µØÖ·¡¢Ñ­»·À¨ºÅ½áÊøµØÖ·£©
		if (params.size() != 2) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 2: [loop_bracket_start, loop_bracket_end]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Delete loop bracket 0x00401020-0x00401040: [\"0x00401020\", \"0x00401040\"]");
			return resp;
		}

		// ½âÎö²¢Ð£ÑéµØÖ··¶Î§£¨ÆðÊ¼<½áÊø£¬¾ù·Ç0£©
		unsigned long long loop_start = 0, loop_end = 0;
		// Ð£ÑéÆðÊ¼µØÖ·
		if (!parse_value(params[0], loop_start) || loop_start == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid loop bracket start address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_start_address", params[0].c_str());
			return resp;
		}
		// Ð£Ñé½áÊøµØÖ·
		if (!parse_value(params[1], loop_end) || loop_end == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid loop bracket end address. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_end_address", params[1].c_str());
			return resp;
		}
		// Ð£ÑéµØÖ··¶Î§ºÏ·¨ÐÔ£¨ÆðÊ¼ < ½áÊø£©
		if (loop_start >= loop_end) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Loop bracket start address must be less than end address");
			cJSON_AddStringToObject(resp.result.get(), "loop_start_hex", format_address(loop_start).c_str());
			cJSON_AddStringToObject(resp.result.get(), "loop_end_hex", format_address(loop_end).c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÉ¾³ýÑ­»·À¨ºÅ£¨Ô­º¯ÊýµÚÒ»¸ö²ÎÊýÎªint£¬ÐèÇ¿ÖÆ×ª»»£»µÚ¶þ¸öÎªduint£©
			BOOL del_success = DbgLoopDel(
				static_cast<int>(loop_start),
				static_cast<duint>(loop_end)
				);

			// 3. ´¦Àí½á¹û
			resp.success = del_success;
			if (del_success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Loop bracket deleted successfully (disassembly section)");



				cJSON_AddStringToObject(
					resp.result.get(),
					"deleted_loop_range_hex",
					// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
					(format_address(loop_start) + " - " + format_address(loop_end)).c_str()
					);


				cJSON_AddStringToObject(resp.result.get(), "note", "Bracket marks a loop body in the disassembly view");
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to delete loop bracket (no matching loop bracket found for range)");


				cJSON_AddStringToObject(
					resp.result.get(),
					"target_loop_range_hex",
					// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
					(format_address(loop_start) + " - " + format_address(loop_end)).c_str()
					);
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while deleting loop bracket");


			cJSON_AddStringToObject(
				resp.result.get(),
				"target_loop_range_hex",
				// ¹Ø¼ü£ºÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str() ×ª»»Îª const char*
				(format_address(loop_start) + " - " + format_address(loop_end)).c_str()
				);
		}

		return resp;
	}



};




// ½Å±¾´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class ScriptHandler
{
public:
	static ResponseData handle_script_run_cmd(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÃüÁî×Ö·û´®£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [command_string]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Execute 'break 0x00401000': [\"break 0x00401000\"]");
			return resp;
		}

		const std::string cmd = params[0];
		if (cmd.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Command string cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÖ´ÐÐÃüÁî
			BOOL exec_success = DbgCmdExec(cmd.c_str());

			// 3. ´¦Àí½á¹û
			resp.success = (exec_success != FALSE);
			if (resp.success) {
				cJSON_AddStringToObject(resp.result.get(), "message", "Command executed successfully");
				cJSON_AddStringToObject(resp.result.get(), "executed_command", cmd.c_str());
			}
			else {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to execute command (invalid syntax or unknown command)");
				cJSON_AddStringToObject(resp.result.get(), "failed_command", cmd.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while executing command");
			cJSON_AddStringToObject(resp.result.get(), "command", cmd.c_str());
		}

		return resp;
	}

	static ResponseData handle_script_run_cmd_ref(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨½Å±¾ÃüÁî×Ö·û´®£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [script_command]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Execute 'mod.main()' and get result: [\"mod.main()\"]");
			return resp;
		}

		const std::string cmd = params[0];
		if (cmd.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Script command string cannot be empty");
			return resp;
		}

		try {
			// 2. ²½Öè1£º·ÖÅäÁÙÊ±ÄÚ´æ£¨¿çÆ½Ì¨´¦Àí£©
			unsigned long long temp_addr = 0;
#ifdef _WIN64
			temp_addr = Script::Memory::RemoteAlloc(0, 8); // x64ÐèÒª8×Ö½ÚÄÚ´æ
#else
			temp_addr = static_cast<unsigned long long>(Script::Memory::RemoteAlloc(0, 4)); // x86ÐèÒª4×Ö½Ú
#endif

			if (temp_addr == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to allocate temporary memory for script execution");
				cJSON_AddStringToObject(resp.result.get(), "note", "Check process memory availability or permissions");
				return resp;
			}

			// 3. ²½Öè2£º¹¹Ôì½Å±¾ÃüÁî£¨¸ñÊ½£º[ÁÙÊ±µØÖ·]=ÃüÁî£©
			char szCmd[256] = { 0 };
			int sprintf_result = sprintf_s(szCmd, "[%llx]=%s", temp_addr, cmd.c_str());
			if (sprintf_result < 0 || sprintf_result >= 256) { // ¼ì²é»º³åÇøÒç³ö
				Script::Memory::RemoteFree(temp_addr); // ÊÍ·ÅÒÑ·ÖÅäÄÚ´æ
				cJSON_AddStringToObject(resp.result.get(), "error", "Script command too long (exceeds 255 characters)");
				return resp;
			}

			// 4. ²½Öè3£ºÖ´ÐÐ½Å±¾ÃüÁî
			BOOL script_success = DbgScriptCmdExec(szCmd);
			if (!script_success) {
				Script::Memory::RemoteFree(temp_addr); // ÊÍ·ÅÄÚ´æ
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to execute script command");
				cJSON_AddStringToObject(resp.result.get(), "constructed_command", szCmd);
				cJSON_AddStringToObject(resp.result.get(), "original_command", cmd.c_str());
				return resp;
			}

			// 5. ²½Öè4£º¶ÁÈ¡½Å±¾·µ»ØÖµ£¨¿çÆ½Ì¨´¦Àí£©
			unsigned long long result_value = 0;
#ifdef _WIN64
			result_value = Script::Memory::ReadQword(temp_addr);
#else
			result_value = static_cast<unsigned long long>(Script::Memory::ReadDword(static_cast<duint>(temp_addr)));
#endif

			// 6. ²½Öè5£ºÊÍ·ÅÁÙÊ±ÄÚ´æ£¨ÎÞÂÛ½á¹ûÈçºÎ¶¼ÐèÊÍ·Å£©
			BOOL free_success = Script::Memory::RemoteFree(temp_addr);
			if (!free_success) {
				// ÄÚ´æÊÍ·ÅÊ§°Ü½ö¾¯¸æ£¬²»Ó°ÏìÖ÷½á¹û
				cJSON_AddStringToObject(resp.result.get(), "warning", "Temporary memory may not be freed properly (potential memory leak)");
			}

			// 7. ´¦Àí·µ»ØÖµ
			if (result_value == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Script command returned zero (may indicate execution failure)");
				cJSON_AddStringToObject(resp.result.get(), "command", cmd.c_str());
				return resp;
			}

			// ³É¹¦½á¹û
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Script command executed successfully with return value");
			cJSON_AddStringToObject(resp.result.get(), "executed_command", cmd.c_str());
			cJSON_AddNumberToObject(resp.result.get(), "return_value_decimal", result_value);
			cJSON_AddStringToObject(resp.result.get(), "return_value_hex", format_address(result_value).c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "Return value is stored in temporary memory and then read back");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error during script command execution");
			cJSON_AddStringToObject(resp.result.get(), "command", cmd.c_str());
		}

		return resp;
	}

	static ResponseData handle_script_load(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨½Å±¾ÎÄ¼þÂ·¾¶£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [script_file_path]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Load script 'C:\\scripts\\debug.js': [\"C:\\\\scripts\\\\debug.js\"]");
			return resp;
		}

		const std::string file_path = params[0];
		if (file_path.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Script file path cannot be empty");
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý¼ÓÔØ½Å±¾
			DbgScriptLoad(file_path.c_str());

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦£¨Êµ¼ÊÏîÄ¿ÖÐ½¨ÒéDbgScriptLoad·µ»ØBOOL£©
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Script loaded successfully");
			cJSON_AddStringToObject(resp.result.get(), "script_path", file_path.c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "If script contains errors, execution may fail later");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Failed to load script (file not found or invalid format)");
			cJSON_AddStringToObject(resp.result.get(), "script_path", file_path.c_str());
		}

		return resp;
	}

	static ResponseData handle_script_unload(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÐ¶ÔØ½Å±¾
			DbgScriptUnload();

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Current script unloaded successfully");
			cJSON_AddStringToObject(resp.result.get(), "note", "All script resources and state have been released");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while unloading script");
		}

		return resp;
	}

	static ResponseData handle_script_run(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨½Å±¾ID/Èë¿Úµã£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [script_id/entry_point]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Run script with ID 1: [\"1\"]");
			return resp;
		}

		const std::string script_id_str = params[0];
		unsigned long long script_id = 0;
		if (!parse_value(script_id_str, script_id) || script_id == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid script ID. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_id", script_id_str.c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÔËÐÐ½Å±¾
			DbgScriptRun(static_cast<duint>(script_id)); // ¼ÙÉèDbgScriptRun½ÓÊÜduint²ÎÊý

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Script started successfully");
			cJSON_AddNumberToObject(resp.result.get(), "script_id", script_id);
			cJSON_AddStringToObject(resp.result.get(), "note", "Check script output for execution results or errors");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Failed to run script (invalid ID or script not loaded)");
			cJSON_AddNumberToObject(resp.result.get(), "script_id", script_id);
		}

		return resp;
	}

	static ResponseData handle_script_set_ip(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨½Å±¾IPÎ»ÖÃ£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [script_ip_position]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Set script IP to position 5: [\"5\"]");
			return resp;
		}

		const std::string ip_str = params[0];
		unsigned long long script_ip = 0;
		if (!parse_value(ip_str, script_ip) || script_ip == 0) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid script IP position. Use non-zero hex (0x...) or decimal");
			cJSON_AddStringToObject(resp.result.get(), "invalid_ip", ip_str.c_str());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯ÊýÉèÖÃ½Å±¾IP
			DbgScriptSetIp(static_cast<duint>(script_ip)); // ¼ÙÉè½ÓÊÜduint²ÎÊý

			// Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏÊÓÎª³É¹¦
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Script IP position set successfully");
			cJSON_AddNumberToObject(resp.result.get(), "script_ip_position", script_ip);
			cJSON_AddStringToObject(resp.result.get(), "note", "Next script execution will start from this position");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Failed to set script IP (invalid position or script not loaded)");
			cJSON_AddNumberToObject(resp.result.get(), "script_ip_position", script_ip);
		}

		return resp;
	}
};

// ½ø³ÌÓëÏß³Ì´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class ProcessHandler
{
public:
	static ResponseData handle_process_get_thread_list(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡Ïß³ÌÁÐ±í
			std::vector<thread_list> threads = GetLocalThreadList();

			if (threads.empty()) {
				resp.success = true;
				cJSON_AddStringToObject(resp.result.get(), "message", "No active threads found in the process");
				cJSON_AddNumberToObject(resp.result.get(), "thread_count", 0);
				return resp;
			}

			// 3. ×ª»»Ïß³ÌÁÐ±íÎªJSONÊý×é
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved active threads");
			cJSON_AddNumberToObject(resp.result.get(), "thread_count", threads.size());

			cJSON* threadArray = cJSON_CreateArray();
			for (const auto& thread : threads) {
				cJSON_AddItemToArray(threadArray, threadListToJson(thread));
			}
			cJSON_AddItemToObject(resp.result.get(), "threads", threadArray);

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving thread list");
		}

		return resp;
	}

	static ResponseData handle_process_get_handle(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡½ø³Ì¾ä±ú
			unsigned long long handle = 0;
#ifdef _WIN64
			handle = (unsigned long long)DbgGetProcessHandle();
#else
			handle = (unsigned long long)DbgGetProcessHandle();
#endif

			if (handle == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to get process handle (invalid or no process attached)");
				return resp;
			}

			// 3. ´¦Àí½á¹û£¨¾ä±úÍ¨³£ÎªÐ¡ÕûÊý£¬Ê®Áù½øÖÆÏÔÊ¾¸üÖ±¹Û£©
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved process handle");
			cJSON_AddStringToObject(resp.result.get(), "process_handle_hex", format_address(handle, 8).c_str()); // ¾ä±ú²¹8Î»
			cJSON_AddNumberToObject(resp.result.get(), "process_handle_dec", handle);
			cJSON_AddStringToObject(resp.result.get(), "note", "Handle can be used with Windows API functions (e.g., ReadProcessMemory)");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving process handle");
		}

		return resp;
	}

	static ResponseData handle_process_get_thread_handle(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡Ïß³Ì¾ä±ú
			unsigned long long handle = 0;
#ifdef _WIN64
			handle = (unsigned long long)DbgGetThreadHandle();
#else
			handle = (unsigned long long)DbgGetThreadHandle();
#endif

			if (handle == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to get thread handle (invalid or no thread selected)");
				return resp;
			}

			// 3. ´¦Àí½á¹û
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved thread handle");
			cJSON_AddStringToObject(resp.result.get(), "thread_handle_hex", format_address(handle, 8).c_str());
			cJSON_AddNumberToObject(resp.result.get(), "thread_handle_dec", handle);
			cJSON_AddStringToObject(resp.result.get(), "note", "Handle refers to the currently selected thread in the debugger");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving thread handle");
		}

		return resp;
	}

	static ResponseData handle_process_get_pid(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡PID
			unsigned long long pid = 0;
#ifdef _WIN64
			pid = static_cast<unsigned long long>(DbgGetProcessId());
#else
			pid = static_cast<unsigned long long>(DbgGetProcessId());
#endif

			if (pid == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to get process ID (no process attached)");
				return resp;
			}

			// 3. ´¦Àí½á¹û£¨PIDÍ¨³£ÎªÊ®½øÖÆÏÔÊ¾£©
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved process ID");
			cJSON_AddNumberToObject(resp.result.get(), "process_id", pid);
			cJSON_AddStringToObject(resp.result.get(), "process_id_hex", format_address(pid, 8).c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "PID is a unique identifier for the process in the system");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving process ID");
		}

		return resp;
	}

	static ResponseData handle_process_get_tid(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡TID
			unsigned long long tid = 0;
#ifdef _WIN64
			tid = static_cast<unsigned long long>(DbgGetThreadId());
#else
			tid = static_cast<unsigned long long>(DbgGetThreadId());
#endif

			if (tid == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to get thread ID (no thread selected)");
				return resp;
			}

			// 3. ´¦Àí½á¹û
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved thread ID");
			cJSON_AddNumberToObject(resp.result.get(), "thread_id", tid);
			cJSON_AddStringToObject(resp.result.get(), "thread_id_hex", format_address(tid, 8).c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "TID is a unique identifier for the thread in the system");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving thread ID");
		}

		return resp;
	}

	static ResponseData handle_process_get_teb(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ïß³ÌID£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [thread_id(hex/decimal)]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Get TEB of thread 1234: [\"1234\"] or [\"0x4D2\"]");
			return resp;
		}

		const std::string tid_str = params[0];

		try {
			// 2. ½âÎöÏß³ÌID
			unsigned long long tid = 0;
			if (!parse_value(tid_str, tid) || tid == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Invalid thread ID. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(resp.result.get(), "invalid_tid", tid_str.c_str());
				return resp;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡TEBµØÖ·
			unsigned long long teb_addr = 0;
#ifdef _WIN64
			teb_addr = DbgGetTebAddress(tid);
#else
			teb_addr = static_cast<unsigned long long>(DbgGetTebAddress(static_cast<duint>(tid)));
#endif

			if (teb_addr == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to get TEB address (invalid thread ID or access denied)");
				cJSON_AddNumberToObject(resp.result.get(), "thread_id", tid);
				return resp;
			}

			// 4. ´¦Àí½á¹û£¨TEBµØÖ·ÎªÄÚ´æµØÖ·£¬ÐèÊ®Áù½øÖÆÏÔÊ¾£©
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved TEB address");
			cJSON_AddNumberToObject(resp.result.get(), "thread_id", tid);
			cJSON_AddStringToObject(resp.result.get(), "teb_address_hex", format_address(teb_addr).c_str());
			cJSON_AddNumberToObject(resp.result.get(), "teb_address_dec", teb_addr);
			cJSON_AddStringToObject(resp.result.get(), "note",
				"TEB (Thread Environment Block) contains thread-specific data (e.g., stack limits, exception handling)");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving TEB address");
			cJSON_AddStringToObject(resp.result.get(), "thread_id", tid_str.c_str());
		}

		return resp;
	}

	static ResponseData handle_process_get_peb(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨½ø³ÌID£©
		if (params.size() != 1) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. Expected 1: [process_id(hex/decimal)]");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(resp.result.get(), "example", "Get PEB of process 5678: [\"5678\"] or [\"0x162E\"]");
			return resp;
		}

		const std::string pid_str = params[0];

		try {
			// 2. ½âÎö½ø³ÌID
			unsigned long long pid = 0;
			if (!parse_value(pid_str, pid) || pid == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Invalid process ID. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(resp.result.get(), "invalid_pid", pid_str.c_str());
				return resp;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡PEBµØÖ·
			unsigned long long peb_addr = 0;
#ifdef _WIN64
			peb_addr = DbgGetPebAddress(pid);
#else
			peb_addr = static_cast<unsigned long long>(DbgGetPebAddress(static_cast<duint>(pid)));
#endif

			if (peb_addr == 0) {
				cJSON_AddStringToObject(resp.result.get(), "error", "Failed to get PEB address (invalid process ID or access denied)");
				cJSON_AddNumberToObject(resp.result.get(), "process_id", pid);
				return resp;
			}

			// 4. ´¦Àí½á¹û
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved PEB address");
			cJSON_AddNumberToObject(resp.result.get(), "process_id", pid);
			cJSON_AddStringToObject(resp.result.get(), "peb_address_hex", format_address(peb_addr).c_str());
			cJSON_AddNumberToObject(resp.result.get(), "peb_address_dec", peb_addr);
			cJSON_AddStringToObject(resp.result.get(), "note",
				"PEB (Process Environment Block) contains process-specific data (e.g., module list, heap info)");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving PEB address");
			cJSON_AddStringToObject(resp.result.get(), "process_id", pid_str.c_str());
		}

		return resp;
	}

	static ResponseData handle_process_get_main_thread_id(const std::vector<std::string>& params) {
		ResponseData resp;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty()) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Invalid parameter count. This interface requires no parameters");
			cJSON_AddNumberToObject(resp.result.get(), "received_count", params.size());
			return resp;
		}

		try {
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡Ö÷Ïß³ÌID
			unsigned long long main_tid = 0;
#ifdef _WIN64
			main_tid = static_cast<unsigned long long>(GuiGetMainThreadId());
#else
			main_tid = static_cast<unsigned long long>(GuiGetMainThreadId());
#endif

			if (main_tid == 0) {
				resp.success = true; // Ö÷½ø³Ì¿ÉÄÜÎÞÖ÷Ïß³Ì£¬µ«²»Ëã´íÎó
				cJSON_AddStringToObject(resp.result.get(), "message", "Main thread ID not found (possibly a system process)");
				cJSON_AddNumberToObject(resp.result.get(), "main_thread_id", 0);
				return resp;
			}

			// 3. ´¦Àí½á¹û
			resp.success = true;
			cJSON_AddStringToObject(resp.result.get(), "message", "Successfully retrieved main thread ID");
			cJSON_AddNumberToObject(resp.result.get(), "main_thread_id", main_tid);
			cJSON_AddStringToObject(resp.result.get(), "main_thread_id_hex", format_address(main_tid, 8).c_str());
			cJSON_AddStringToObject(resp.result.get(), "note", "Main thread is typically the initial thread created when the process starts");

#ifdef _WIN64
			cJSON_AddStringToObject(resp.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(resp.result.get(), "platform", "x86");
#endif
		}
		catch (...) {
			cJSON_AddStringToObject(resp.result.get(), "error", "Unexpected error while retrieving main thread ID");
		}

		return resp;
	}
};


// ÄÚ´æ´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class MemoryHandler
{
public:
	// ¸ù¾ÝµØÖ·»ñÈ¡ÄÚ´æÄ£¿é»ùÖ·£¨Memory.GetBase£©
	static ResponseData handle_get_memory_base(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get base of module containing 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿é»ùµØÖ·£¨Çø·ÖÆ½Ì¨£©
			unsigned long long base_address = 0;
#ifdef _WIN64
			base_address = Script::Memory::GetBase(target_addr);
#else
			base_address = Script::Memory::GetBase(static_cast<duint>(target_addr));
#endif

			// 4. ´¦Àí½á¹û
			if (base_address != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module base address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "base_address_value", base_address);
				cJSON_AddStringToObject(response.result.get(), "base_address_hex", format_address(base_address).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Base address is the starting address of the module containing the input address");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module base address (address not in any valid memory region)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module base address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}
	// »ñÈ¡µ±Ç°Ö¸ÁîÖ¸ÕëËùÔÚÄ£¿é»ùÖ·£¨Memory.GetLocalBase£©
	static ResponseData handle_get_memory_local_base(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. »ñÈ¡µ±Ç°Ö¸ÁîÖ¸Õë£¨EIP/RIP£©²¢²éÑ¯»ùµØÖ·£¨Çø·ÖÆ½Ì¨£©
			unsigned long long ip_address = 0;
			unsigned long long base_address = 0;

#ifdef _WIN64
			ip_address = Script::Register::GetRIP();
			base_address = Script::Memory::GetBase(ip_address);
#else
			ip_address = Script::Register::GetEIP();
			base_address = Script::Memory::GetBase(static_cast<duint>(ip_address));
#endif

			// 3. ´¦Àí½á¹û
			if (base_address != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Local module base address retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddNumberToObject(response.result.get(), "ip_value", ip_address);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_address).c_str());
				cJSON_AddNumberToObject(response.result.get(), "base_address_value", base_address);
				cJSON_AddStringToObject(response.result.get(), "base_address_hex", format_address(base_address).c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get local module base address (invalid instruction pointer)");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_address).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting local module base address");
		}

		return response;
	}
	// ¸ù¾ÝµØÖ·»ñÈ¡ÄÚ´æÄ£¿é´óÐ¡£¨Memory.GetSize£©
	static ResponseData handle_get_memory_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get size of module containing 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿é´óÐ¡£¨Çø·ÖÆ½Ì¨£©
			unsigned long long module_size = 0;
#ifdef _WIN64
			module_size = Script::Memory::GetSize(target_addr);
#else
			module_size = Script::Memory::GetSize(static_cast<duint>(target_addr));
#endif

			// 4. ´¦Àí½á¹û
			if (module_size != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module memory size retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "module_size_bytes", module_size);
				cJSON_AddStringToObject(response.result.get(), "module_size_human", format_bytes(module_size).c_str()); // ¸¨Öúº¯Êý£º×ª»»ÎªKB/MB
				cJSON_AddStringToObject(response.result.get(), "note", "Size represents the total memory allocated for the module");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module memory size (address not in any valid memory region)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module memory size");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ñÈ¡µ±Ç°Ö¸ÁîÖ¸ÕëËùÔÚÄ£¿é´óÐ¡£¨Memory.GetLocalSize£©
	static ResponseData handle_get_memory_local_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. »ñÈ¡µ±Ç°Ö¸ÁîÖ¸Õë£¨EIP/RIP£©²¢²éÑ¯Ä£¿é´óÐ¡£¨Çø·ÖÆ½Ì¨£©
			unsigned long long ip_address = 0;
			unsigned long long module_size = 0;

#ifdef _WIN64
			ip_address = Script::Register::GetRIP();
			module_size = Script::Memory::GetSize(ip_address);
#else
			ip_address = Script::Register::GetEIP();
			module_size = Script::Memory::GetSize(static_cast<duint>(ip_address));
#endif

			// 3. ´¦Àí½á¹û
			if (module_size != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Local module memory size retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddNumberToObject(response.result.get(), "ip_value", ip_address);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_address).c_str());
				cJSON_AddNumberToObject(response.result.get(), "module_size_bytes", module_size);
				cJSON_AddStringToObject(response.result.get(), "module_size_human", format_bytes(module_size).c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get local module memory size (invalid instruction pointer)");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_address).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting local module memory size");
		}

		return response;
	}



	// ¸ù¾ÝµØÖ·»ñÈ¡ÄÚ´æ±£»¤ÊôÐÔ£¨Memory.GetProtect£©
	static ResponseData handle_get_memory_protect(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get protection of address 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡ÄÚ´æ±£»¤ÊôÐÔ£¨Çø·ÖÆ½Ì¨£©
			unsigned long long protect_flags = 0;
#ifdef _WIN64
			protect_flags = Script::Memory::GetProtect(target_addr);
#else
			protect_flags = Script::Memory::GetProtect(static_cast<duint>(target_addr));
#endif

			// 4. ´¦Àí½á¹û
			if (protect_flags != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory protection attributes retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "protect_flags_value", protect_flags);
				cJSON_AddStringToObject(response.result.get(), "protect_flags_hex", format_address(protect_flags).c_str());
				cJSON_AddStringToObject(response.result.get(), "protect_flags_description", protect_flags_to_string(protect_flags).c_str());

				// ²¹³ä³£ÓÃÊôÐÔËµÃ÷
				cJSON_AddBoolToObject(response.result.get(), "is_readable",
					(protect_flags & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0);
				cJSON_AddBoolToObject(response.result.get(), "is_writable",
					(protect_flags & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0);
				cJSON_AddBoolToObject(response.result.get(), "is_executable",
					(protect_flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get memory protection attributes (address not in any valid memory region)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting memory protection attributes");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ñÈ¡µ±Ç°Ö¸ÁîÖ¸ÕëÎ»ÖÃÄÚ´æ±£»¤ÊôÐÔ£¨Memory.GetLocalProtect£©
	static ResponseData handle_get_memory_local_protect(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. »ñÈ¡µ±Ç°Ö¸ÁîÖ¸Õë£¨EIP/RIP£©²¢²éÑ¯±£»¤ÊôÐÔ£¨Çø·ÖÆ½Ì¨£©
			unsigned long long ip_address = 0;
			unsigned long long protect_flags = 0;

#ifdef _WIN64
			ip_address = Script::Register::GetRIP();
			protect_flags = Script::Memory::GetProtect(ip_address);
#else
			ip_address = Script::Register::GetEIP();
			protect_flags = Script::Memory::GetProtect(static_cast<duint>(ip_address));
#endif

			// 3. ´¦Àí½á¹û
			if (protect_flags != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Local memory protection attributes retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddNumberToObject(response.result.get(), "ip_value", ip_address);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_address).c_str());
				cJSON_AddNumberToObject(response.result.get(), "protect_flags_value", protect_flags);
				cJSON_AddStringToObject(response.result.get(), "protect_flags_hex", format_address(protect_flags).c_str());
				cJSON_AddStringToObject(response.result.get(), "protect_flags_description", protect_flags_to_string(protect_flags).c_str());

				// ²¹³ä³£ÓÃÊôÐÔËµÃ÷
				cJSON_AddBoolToObject(response.result.get(), "is_readable",
					(protect_flags & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0);
				cJSON_AddBoolToObject(response.result.get(), "is_writable",
					(protect_flags & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0);
				cJSON_AddBoolToObject(response.result.get(), "is_executable",
					(protect_flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get local memory protection attributes (invalid instruction pointer)");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_address).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting local memory protection attributes");
		}

		return response;
	}

	// »ñÈ¡µ±Ç°Ö¸ÁîÖ¸ÕëËùÔÚÄÚ´æÒ³Ãæ´óÐ¡£¨Memory.GetLocalPageSize£©
	static ResponseData handle_get_memory_local_page_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. »ñÈ¡Ö¸ÁîÖ¸Õë²¢²éÑ¯Ò³Ãæ´óÐ¡£¨Çø·ÖÆ½Ì¨£©
			unsigned long long ip_addr = 0;
			unsigned long long page_size = 0;
#ifdef _WIN64
			ip_addr = Script::Register::GetRIP();
			page_size = DbgMemGetPageSize(ip_addr);
#else
			ip_addr = Script::Register::GetEIP();
			page_size = DbgMemGetPageSize(static_cast<duint>(ip_addr));
#endif

			// 3. ´¦Àí½á¹û£¨Ò³Ãæ´óÐ¡Í¨³£Îª4KB/2MB£¬0±íÊ¾Ê§°Ü£©
			if (page_size > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Local memory page size retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "page_size_bytes", page_size);
				cJSON_AddStringToObject(response.result.get(), "page_size_human", format_bytes(page_size).c_str()); // Èç"4.00 KB"
				cJSON_AddStringToObject(response.result.get(), "note", "Common page sizes: 4KB (0x1000), 2MB (0x200000)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get local memory page size (invalid instruction pointer)");
				cJSON_AddStringToObject(response.result.get(), "instruction_pointer",
#ifdef _WIN64
					"RIP"
#else
					"EIP"
#endif
					);
				cJSON_AddStringToObject(response.result.get(), "ip_hex", format_address(ip_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting local memory page size");
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡ÄÚ´æÒ³Ãæ´óÐ¡£¨Memory.GetPageSize£©
	static ResponseData handle_get_memory_page_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get page size of address 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ò³Ãæ´óÐ¡£¨Çø·ÖÆ½Ì¨£©
			unsigned long long page_size = 0;
#ifdef _WIN64
			page_size = DbgMemGetPageSize(target_addr);
#else
			page_size = DbgMemGetPageSize(static_cast<duint>(target_addr));
#endif

			// 4. ´¦Àí½á¹û
			if (page_size > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory page size retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "page_size_bytes", page_size);
				cJSON_AddStringToObject(response.result.get(), "page_size_human", format_bytes(page_size).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Page size is determined by OS memory management (4KB default for x86/x64)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get memory page size (address not in valid memory region)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting memory page size");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ÑéÖ¤ÄÚ´æÊÇ·ñ¿É¶ÁÈ¡£¨Memory.IsValidReadPtr£©
	static ResponseData handle_dbg_mem_is_valid_read_ptr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Check if 0x00401000 is readable: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿ÚÑéÖ¤¿É¶ÁÐÔ£¨Çø·ÖÆ½Ì¨£©
			BOOL is_valid = FALSE;
#ifdef _WIN64
			is_valid = DbgMemIsValidReadPtr(target_addr);
#else
			is_valid = DbgMemIsValidReadPtr(static_cast<duint>(target_addr));
#endif

			// 4. ´¦Àí½á¹û£¨²¼¶ûÖµÃ÷È·»¯£©
			response.success = true; // ÎÞÂÛÊÇ·ñ¿É¶Á£¬ÇëÇó±¾Éí³É¹¦
			cJSON_AddStringToObject(response.result.get(), "message", "Memory readability check completed");
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			cJSON_AddBoolToObject(response.result.get(), "is_valid_read_ptr", is_valid != FALSE);
			cJSON_AddStringToObject(response.result.get(), "note", "Valid = address points to readable memory (may still throw access violations in rare cases)");

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while checking memory readability");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ñÈ¡ÄÚ´æÓ³Éä½ÚÐÅÏ¢£¨Memory.GetSectionMap£©
	static ResponseData handle_get_memory_section(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨»ñÈ¡ÍêÕûÄÚ´æÓ³Éä£©
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡ÄÚ´æÓ³ÉäÁÐ±í£¨¸´ÓÃGetMemoryInfoÂß¼­£©
			std::vector<memory_info> mem_map_list = GetMemoryInfo();
			int region_count = static_cast<int>(mem_map_list.size());

			// 3. ´¦Àí½á¹û
			if (region_count > 0 && !mem_map_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory section map retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "total_memory_regions", region_count);
				cJSON_AddStringToObject(response.result.get(), "note", "Each entry represents a contiguous memory region with uniform attributes");

				// ¹¹½¨ÄÚ´æÇøÓòJSONÊý×é£¨Ó³Éämemory_infoÏòÁ¿£©
				cJSON* regions_array = cJSON_CreateArray();
				for (const auto& region : mem_map_list)
				{
					cJSON* region_obj = cJSON_CreateObject();
					// »ù´¡µØÖ·ÐÅÏ¢
					cJSON_AddStringToObject(region_obj, "allocation_base_hex", format_address(region.AllocationBase).c_str());
					cJSON_AddStringToObject(region_obj, "base_address_hex", format_address(region.BaseAddress).c_str());
					// ´óÐ¡ÐÅÏ¢
					cJSON_AddNumberToObject(region_obj, "region_size_bytes", region.RegionSize);
					cJSON_AddStringToObject(region_obj, "region_size_human", format_bytes(region.RegionSize).c_str());
					// ±£»¤ÊôÐÔ£¨ÊýÖµ+¿É¶ÁÃèÊö£©
					cJSON_AddStringToObject(region_obj, "allocation_protect", protect_flags_to_string(region.AllocationProtect).c_str());
					cJSON_AddStringToObject(region_obj, "current_protect", protect_flags_to_string(region.Protect).c_str());
					// ×´Ì¬ÓëÀàÐÍ
					cJSON_AddStringToObject(region_obj, "memory_state", mem_state_to_string(region.State).c_str());
					cJSON_AddStringToObject(region_obj, "memory_type", mem_type_to_string(region.Type).c_str());
					// ÆäËû×Ö¶Î
					cJSON_AddNumberToObject(region_obj, "region_index", region.Count);
					cJSON_AddStringToObject(region_obj, "page_info", region.PageInfo);
					cJSON_AddItemToArray(regions_array, region_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "memory_regions", regions_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get memory section map (no debugged process or no memory regions)");
				cJSON_AddNumberToObject(response.result.get(), "detected_regions_count", region_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting memory section map");
		}

		return response;
	}

	// ÉèÖÃÄÚ´æ±£»¤ÊôÐÔ£¨Memory.SetProtect£©
	static ResponseData handle_set_memory_protect(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë3¸ö²ÎÊý£¨µØÖ· + ´óÐ¡ + ±£»¤±êÖ¾£©
		if (params.size() != 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 3: [start_address] [region_size] [protect_flags(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Set 0x1000 bytes at 0x00401000 to READWRITE: [\"0x00401000\", \"4096\", \"0x04\"]");
			cJSON_AddStringToObject(response.result.get(), "common_flags", "PAGE_NOACCESS=0x01, PAGE_READONLY=0x02, PAGE_READWRITE=0x04, PAGE_EXECUTE_READ=0x20");
			return response;
		}

		const std::string addr_str = params[0];
		const std::string size_str = params[1];
		const std::string flags_str = params[2];

		try
		{
			// 2. ½âÎöÆðÊ¼µØÖ·²¢Ð£Ñé
			unsigned long long start_addr = 0;
			if (!parse_value(addr_str, start_addr) || start_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. ½âÎöÇøÓò´óÐ¡²¢Ð£Ñé£¨ÐèÎªÕýÕûÊý£©
			unsigned long long region_size = 0;
			if (!parse_value(size_str, region_size) || region_size == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid region size. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_size", size_str.c_str());
				return response;
			}

			// 4. ½âÎö±£»¤±êÖ¾²¢Ð£Ñé£¨ÐèÎªÓÐÐ§Windows±£»¤Öµ£©
			unsigned long long protect_flags = 0;
			if (!parse_value(flags_str, protect_flags) || protect_flags == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid protect flags. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_flags", flags_str.c_str());
				return response;
			}

			// 5. µ÷ÓÃ½Ó¿ÚÉèÖÃ±£»¤ÊôÐÔ£¨Çø·ÖÆ½Ì¨£¬×ª»»²ÎÊýÀàÐÍ£©
			BOOL set_success = FALSE;
#ifdef _WIN64
			set_success = Script::Memory::SetProtect(start_addr, static_cast<size_t>(region_size), static_cast<DWORD>(protect_flags));
#else
			set_success = Script::Memory::SetProtect(static_cast<duint>(start_addr), static_cast<size_t>(region_size), static_cast<DWORD>(protect_flags));
#endif

			// 6. ´¦Àí½á¹û
			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory protection attributes set successfully");
				// ´«Èë²ÎÊýÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "start_address_hex", format_address(start_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "region_size_bytes", region_size);
				cJSON_AddStringToObject(response.result.get(), "region_size_human", format_bytes(region_size).c_str());
				cJSON_AddStringToObject(response.result.get(), "target_protect", protect_flags_to_string(protect_flags).c_str());
				cJSON_AddStringToObject(response.result.get(), "warning", "Changing protection may cause crashes if memory is accessed incorrectly");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set memory protection (invalid address, size, or unsupported flags)");
				cJSON_AddStringToObject(response.result.get(), "start_address_hex", format_address(start_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "target_protect_flags", format_address(protect_flags).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting memory protection");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_size", size_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_flags", flags_str.c_str());
		}

		return response;
	}


	// »ñÈ¡Ö¸¶¨µØÖ·½»²æÒýÓÃ¼ÆÊý£¨Memory.GetXrefCountAt£©
	static ResponseData handle_memory_get_xref_count_at(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get xref count of 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨·Ç0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡½»²æÒýÓÃ¼ÆÊý£¨Çø·ÖÆ½Ì¨£©
			unsigned long long xref_count = 0;
#ifdef _WIN64
			xref_count = DbgGetXrefCountAt(target_addr);
#else
			xref_count = DbgGetXrefCountAt(static_cast<duint>(target_addr));
#endif

			// 4. ·â×°½á¹û£¨¼ÆÊýÎª0ÊÇÓÐÐ§½á¹û£¬²»ÊÓÎªÊ§°Ü£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Cross-reference count retrieved successfully");
			// µØÖ·ÐÅÏ¢
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			cJSON_AddNumberToObject(response.result.get(), "target_address_decimal", target_addr);
			// ½»²æÒýÓÃ¼ÆÊý
			cJSON_AddNumberToObject(response.result.get(), "xref_count", xref_count);
			cJSON_AddStringToObject(response.result.get(), "note", "Xref count = 0 means no code/data references this address");

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting cross-reference count");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸¨Öúº¯Êý£ºXREFTYPEÃ¶¾Ù×ª¿É¶Á×Ö·û´®
	static std::string xref_type_to_desc(int xref_type)
	{
		switch (xref_type)
		{
		case XREF_NONE:  return "XREF_NONE (0) - No cross-reference";
		case XREF_DATA:  return "XREF_DATA (1) - Data reference (e.g., pointer access)";
		case XREF_JMP:   return "XREF_JMP (2) - Jump reference (e.g., JMP instruction)";
		case XREF_CALL:  return "XREF_CALL (3) - Call reference (e.g., CALL instruction)";
		default:         return "UNKNOWN_XREF_TYPE (" + std::to_string(xref_type) + ") - Invalid type";
		}
	}

	// »ñÈ¡Ö¸¶¨µØÖ·½»²æÒýÓÃÀàÐÍ£¨Memory.GetXrefTypeAt£©
	static ResponseData handle_memory_get_xref_type_at(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get xref type of 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡½»²æÒýÓÃÀàÐÍ£¨Ã¶¾Ù×ªÆ½Ì¨ÀàÐÍ£©
			XREFTYPE xref_type = XREF_NONE;
#ifdef _WIN64
			xref_type = static_cast<XREFTYPE>(DbgGetXrefTypeAt(target_addr));
#else
			xref_type = static_cast<XREFTYPE>(DbgGetXrefTypeAt(static_cast<duint>(target_addr)));
#endif

			// 4. ·â×°½á¹û£¨º¬Ã¶¾ÙÖµÓë¿É¶ÁÃèÊö£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Cross-reference type retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			cJSON_AddNumberToObject(response.result.get(), "xref_type_value", static_cast<int>(xref_type));
			cJSON_AddStringToObject(response.result.get(), "xref_type_description", xref_type_to_desc(static_cast<int>(xref_type)).c_str());

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting cross-reference type");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸¨Öúº¯Êý£ºFUNCTYPEÃ¶¾Ù×ª¿É¶Á×Ö·û´®
	static std::string func_type_to_desc(int func_type)
	{
		switch (func_type)
		{
		case FUNC_NONE:   return "FUNC_NONE (0) - Not in any function";
		case FUNC_BEGIN:  return "FUNC_BEGIN (1) - Start of a function (e.g., prologue)";
		case FUNC_MIDDLE: return "FUNC_MIDDLE (2) - Middle of a function (e.g., body)";
		case FUNC_END:    return "FUNC_END (3) - End of a function (e.g., epilogue/RET)";
		case FUNC_SINGLE: return "FUNC_SINGLE (4) - Single-instruction function";
		default:          return "UNKNOWN_FUNC_TYPE (" + std::to_string(func_type) + ") - Invalid type";
		}
	}

	// »ñÈ¡Ö¸¶¨µØÖ·º¯ÊýÀàÐÍ£¨Memory.GetFunctionTypeAt£©
	static ResponseData handle_memory_get_function_type_at(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get function type of 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡º¯ÊýÀàÐÍ£¨Ã¶¾Ù×ªÆ½Ì¨ÀàÐÍ£©
			FUNCTYPE func_type = FUNC_NONE;
#ifdef _WIN64
			func_type = static_cast<FUNCTYPE>(DbgGetFunctionTypeAt(target_addr));
#else
			func_type = static_cast<FUNCTYPE>(DbgGetFunctionTypeAt(static_cast<duint>(target_addr)));
#endif

			// 4. ·â×°½á¹û
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Function type retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			cJSON_AddNumberToObject(response.result.get(), "func_type_value", static_cast<int>(func_type));
			cJSON_AddStringToObject(response.result.get(), "func_type_description", func_type_to_desc(static_cast<int>(func_type)).c_str());

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting function type");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ÅÐ¶ÏÌø×ªÊÇ·ñÖ¸Ïò¿ÉÖ´ÐÐÄÚ´æ£¨Memory.IsJumpGoingToExecute£©
	static ResponseData handle_memory_is_jump_going_to_execute(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ìø×ªÖ¸ÁîµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [jump_instruction_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Check jump at 0x00401005: [\"0x00401005\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long jump_addr = 0;
			if (!parse_value(addr_str, jump_addr) || jump_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid jump instruction address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯ÊýÅÐ¶ÏÌø×ªÄ¿±êÊÇ·ñ¿ÉÖ´ÐÐ
			BOOL is_exec = FALSE;
#ifdef _WIN64
			is_exec = DbgIsJumpGoingToExecute(jump_addr);
#else
			is_exec = DbgIsJumpGoingToExecute(static_cast<duint>(jump_addr));
#endif

			// 4. ·â×°½á¹û£¨²¼¶ûÖµÃ÷È·»¯£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Jump target executability check completed");
			cJSON_AddStringToObject(response.result.get(), "jump_instruction_address_hex", format_address(jump_addr).c_str());
			cJSON_AddBoolToObject(response.result.get(), "is_jump_target_executable", is_exec != FALSE);
			cJSON_AddStringToObject(response.result.get(), "note", "True = jump target is in executable memory (e.g., .text section)");

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while checking jump target executability");
			cJSON_AddStringToObject(response.result.get(), "jump_instruction_address", addr_str.c_str());
		}

		return response;
	}

	// Ô¶³Ì·ÖÅäÄÚ´æ£¨Memory.RemoteAlloc£©
	static ResponseData handle_memory_remote_alloc(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨·ÖÅä»ùÖ· + ·ÖÅä´óÐ¡£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [alloc_base_address(hex/decimal)] [alloc_size_bytes(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Alloc 4KB at 0x00500000: [\"0x00500000\", \"4096\"]");
			return response;
		}

		const std::string base_str = params[0];   // ·ÖÅä»ùÖ·£¨0±íÊ¾×Ô¶¯·ÖÅä£©
		const std::string size_str = params[1];   // ·ÖÅä´óÐ¡£¨±ØÐë>0£©

		try
		{
			// 2. ½âÎö·ÖÅä»ùÖ·£¨ÔÊÐí0£¬´ú±í×Ô¶¯Ñ¡Ôñ»ùÖ·£©
			unsigned long long alloc_base = 0;
			if (!parse_value(base_str, alloc_base))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid alloc base address. Use hex (0x...) or decimal (0 = auto-allocate)");
				cJSON_AddStringToObject(response.result.get(), "invalid_base_address", base_str.c_str());
				return response;
			}

			// 3. ½âÎö·ÖÅä´óÐ¡£¨±ØÐë>0£©
			unsigned long long alloc_size = 0;
			if (!parse_value(size_str, alloc_size) || alloc_size == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid alloc size. Use positive hex (0x...) or decimal (e.g., 4096 for 4KB)");
				cJSON_AddStringToObject(response.result.get(), "invalid_size", size_str.c_str());
				return response;
			}

			// 4. µ÷ÓÃÔ­º¯Êý·ÖÅäÄÚ´æ£¨Çø·ÖÆ½Ì¨£©
			unsigned long long allocated_addr = 0;
#ifdef _WIN64
			allocated_addr = Script::Memory::RemoteAlloc(alloc_base, static_cast<size_t>(alloc_size));
#else
			allocated_addr = Script::Memory::RemoteAlloc(static_cast<duint>(alloc_base), static_cast<size_t>(alloc_size));
#endif

			// 5. ´¦Àí½á¹û
			if (allocated_addr != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory allocated successfully");
				cJSON_AddStringToObject(response.result.get(), "requested_base_address_hex", format_address(alloc_base).c_str());
				cJSON_AddNumberToObject(response.result.get(), "allocated_size_bytes", alloc_size);
				cJSON_AddStringToObject(response.result.get(), "allocated_size_human", format_bytes(alloc_size).c_str());
				cJSON_AddStringToObject(response.result.get(), "allocated_address_hex", format_address(allocated_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "warning", "Free allocated memory with Memory.RemoteFree to avoid leaks");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to allocate memory (invalid base address, insufficient space, or permission denied)");
				cJSON_AddStringToObject(response.result.get(), "requested_base_address_hex", format_address(alloc_base).c_str());
				cJSON_AddNumberToObject(response.result.get(), "requested_size_bytes", alloc_size);
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while allocating memory");
			cJSON_AddStringToObject(response.result.get(), "requested_base_address", base_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "requested_size", size_str.c_str());
		}

		return response;
	}

	// Ô¶³ÌÊÍ·ÅÄÚ´æ£¨Memory.RemoteFree£©
	static ResponseData handle_memory_remote_free(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨´ýÊÍ·ÅµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [allocated_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Free memory at 0x00500000: [\"0x00500000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨·Ç0£©
			unsigned long long free_addr = 0;
			if (!parse_value(addr_str, free_addr) || free_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid allocated address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯ÊýÊÍ·ÅÄÚ´æ£¨Çø·ÖÆ½Ì¨£©
			BOOL free_success = FALSE;
#ifdef _WIN64
			free_success = Script::Memory::RemoteFree(free_addr);
#else
			free_success = Script::Memory::RemoteFree(static_cast<duint>(free_addr));
#endif

			// 4. ´¦Àí½á¹û
			if (free_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory freed successfully");
				cJSON_AddStringToObject(response.result.get(), "freed_address_hex", format_address(free_addr).c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to free memory (address not allocated, already freed, or permission denied)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(free_addr).c_str());
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while freeing memory");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¶ÑÕ»ÈëÕ»²Ù×÷£¨Memory.StackPush£©
	static ResponseData handle_memory_stack_push(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÈëÕ»Öµ£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value_to_push(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Push 0x1234 to stack: [\"0x1234\"]");
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			// 2. ½âÎöÈëÕ»Öµ£¨Ö§³ÖÈÎÒâÆ½Ì¨ÔÊÐíµÄÊýÖµ·¶Î§£©
			unsigned long long push_value = 0;
			if (!parse_value(value_str, push_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value to push. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯ÊýÖ´ÐÐÈëÕ»£¨Çø·ÖÆ½Ì¨£©
			unsigned long long stack_addr = 0;
#ifdef _WIN64
			stack_addr = Script::Stack::Push(push_value); // x64Õ»¿í8×Ö½Ú
#else
			stack_addr = Script::Stack::Push(static_cast<duint>(push_value)); // x86Õ»¿í4×Ö½Ú
#endif

			// 4. ´¦Àí½á¹û£¨stack_addr != 0±íÊ¾ÈëÕ»³É¹¦£©
			if (stack_addr != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Value pushed to stack successfully");
				cJSON_AddStringToObject(response.result.get(), "pushed_value_hex", format_address(push_value).c_str());
				cJSON_AddNumberToObject(response.result.get(), "pushed_value_decimal", push_value);
				cJSON_AddStringToObject(response.result.get(), "stack_width",
#ifdef _WIN64
					"8 bytes (x64)"
#else
					"4 bytes (x86)"
#endif
					);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to push value to stack (insufficient stack space or invalid value)");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", format_address(push_value).c_str());
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while pushing to stack");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ¶ÑÕ»³öÕ»²Ù×÷£¨Memory.StackPop£©
	static ResponseData handle_memory_stack_pop(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨µ¯³öÕ»¶¥Öµ£©
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface (pops top of stack)");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃÔ­º¯ÊýÖ´ÐÐ³öÕ»£¨Çø·ÖÆ½Ì¨£©
			unsigned long long pop_value = 0;
#ifdef _WIN64
			pop_value = Script::Stack::Pop(); // x64µ¯³ö8×Ö½ÚÖµ
#else
			pop_value = Script::Stack::Pop(); // x86µ¯³ö4×Ö½ÚÖµ
#endif

			// 3. ´¦Àí½á¹û£¨pop_value != 0±íÊ¾³öÕ»³É¹¦£¬0¿ÉÄÜÊÇÓÐÐ§µ¯³öÖµ£¬Ðè½áºÏÔ­º¯ÊýÂß¼­£©
			response.success = true; // ÎÞÂÛµ¯³öÖµÊÇ·ñÎª0£¬ÇëÇó±¾Éí³É¹¦
			cJSON_AddStringToObject(response.result.get(), "message", "Stack pop operation completed");
			cJSON_AddStringToObject(response.result.get(), "popped_value_hex", format_address(pop_value).c_str());
			cJSON_AddNumberToObject(response.result.get(), "popped_value_decimal", pop_value);
			cJSON_AddStringToObject(response.result.get(), "stack_width",
#ifdef _WIN64
				"8 bytes (x64)"
#else
				"4 bytes (x86)"
#endif
				);
			cJSON_AddStringToObject(response.result.get(), "note", "Popped value = 0 may be valid (e.g., NULL pointer), check stack state for failure");

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while popping from stack (e.g., stack underflow)");
		}

		return response;
	}

	// ¶ÑÕ»¼ì²é²Ù×÷£¨Memory.StackPeek£©
	static ResponseData handle_memory_stack_peek(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÔÊÐí0¸ö»ò1¸ö²ÎÊý£¨1¸ö=Õ»Æ«ÒÆ£¬0¸ö=Õ»¶¥£©
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 0 or 1: [stack_offset(hex/decimal) - optional]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "examples", "Peek top: [] | Peek offset 8: [\"8\"]");
			return response;
		}

		try
		{
			// 2. ½âÎöÕ»Æ«ÒÆ£¨ÎÞ²ÎÊýÔòÎª0£¬¼´Õ»¶¥£©
			unsigned long long stack_offset = 0;
			if (params.size() == 1)
			{
				const std::string offset_str = params[0];
				if (!parse_value(offset_str, stack_offset))
				{
					cJSON_AddStringToObject(response.result.get(), "error", "Invalid stack offset. Use hex (0x...) or decimal");
					cJSON_AddStringToObject(response.result.get(), "invalid_offset", offset_str.c_str());
					return response;
				}
			}

			// 3. µ÷ÓÃÔ­º¯Êý²é¿´¶ÑÕ»£¨Çø·ÖÆ½Ì¨£©
			unsigned long long peek_value = 0;
#ifdef _WIN64
			if (stack_offset == 0)
				peek_value = Script::Stack::Peek(); // ÎÞÆ«ÒÆ=Õ»¶¥
			else
				peek_value = Script::Stack::Peek(stack_offset); // ´øÆ«ÒÆ
#else
			if (stack_offset == 0)
				peek_value = Script::Stack::Peek();
			else
				peek_value = Script::Stack::Peek(static_cast<duint>(stack_offset));
#endif

			// 4. ´¦Àí½á¹û
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Stack peek operation completed");
			cJSON_AddStringToObject(response.result.get(), "peek_mode", stack_offset == 0 ? "Stack top" : "Stack offset");
			if (stack_offset != 0)
				cJSON_AddStringToObject(response.result.get(), "stack_offset_hex", format_address(stack_offset).c_str());
			cJSON_AddStringToObject(response.result.get(), "peeked_value_hex", format_address(peek_value).c_str());
			cJSON_AddNumberToObject(response.result.get(), "peeked_value_decimal", peek_value);
			cJSON_AddStringToObject(response.result.get(), "stack_width",
#ifdef _WIN64
				"8 bytes (x64)"
#else
				"4 bytes (x86)"
#endif
				);

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while peeking stack (e.g., invalid offset or stack underflow)");
		}

		return response;
	}


	// Ä£¿éÄÚÉ¨ÃèÌØÕ÷Âë£¨·µ»ØµÚÒ»¸öÆ¥Åä£©£¨Memory.ScanModule£©
	static ResponseData handle_memory_scan_module(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2-3¸ö²ÎÊý£¨ÌØÕ÷Âë¡¢Ä£¿é»ùÖ·¡¢[ÆðÊ¼Î»ÖÃ]£©
		if (params.size() < 2 || params.size() > 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2-3: [pattern] [module_base_address] [start_address(optional)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Scan 'FF 25 ??' in module 0x00400000: [\"FF 25 ??\", \"0x00400000\"] or [\"FF 25 ??\", \"0x00400000\", \"0x00401000\"]");
			cJSON_AddStringToObject(response.result.get(), "pattern_format", "Hex bytes separated by space, support wildcard '??' (e.g., 'FF 25 ?? ?? ?? ??')");
			return response;
		}

		const std::string pattern = params[0];
		const std::string module_base_str = params[1];
		const std::string start_addr_str = (params.size() == 3) ? params[2] : "0";

		try
		{
			// 2. Ð£ÑéÌØÕ÷Âë¸ñÊ½
			if (!is_valid_pattern(pattern))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid pattern format. Use hex bytes (2 digits) separated by space, support '??' wildcard");
				cJSON_AddStringToObject(response.result.get(), "invalid_pattern", pattern.c_str());
				return response;
			}

			// 3. ½âÎöÄ£¿é»ùÖ·£¨·Ç0£©
			unsigned long long module_base = 0;
			if (!parse_value(module_base_str, module_base) || module_base == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid module base address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_module_base", module_base_str.c_str());
				return response;
			}

			// 4. ½âÎöÆðÊ¼É¨ÃèÎ»ÖÃ£¨0=Ä¬ÈÏÄ£¿é»ùÖ·£©
			unsigned long long start_addr = 0;
			if (!parse_value(start_addr_str, start_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address. Use hex (0x...) or decimal (0 = module base)");
				cJSON_AddStringToObject(response.result.get(), "invalid_start_address", start_addr_str.c_str());
				return response;
			}

			// 5. µ÷ÓÃºËÐÄº¯ÊýÉ¨ÃèÄ£¿é
			unsigned long long match_addr = 0;
#ifdef _WIN64
			match_addr = FindMemoryCode(pattern, static_cast<duint>(module_base), static_cast<duint>(start_addr));
#else
			match_addr = FindMemoryCode(pattern, static_cast<duint>(module_base), static_cast<duint>(start_addr));
#endif

			// 6. ´¦Àí½á¹û£¨Ô­º¯Êý·µ»Ø-1=ÎÞÐ§·¶Î§£¬0=ÎÞÆ¥Åä£¬ÆäËû=Æ¥ÅäµØÖ·£©
			if (match_addr == static_cast<unsigned long long>(-1))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Start address out of module range (check module base and start address)");
				cJSON_AddStringToObject(response.result.get(), "module_base_hex", addr_to_hex_str(module_base).c_str());
				cJSON_AddStringToObject(response.result.get(), "start_address_hex", addr_to_hex_str(start_addr).c_str());
			}
			else if (match_addr == 0)
			{
				response.success = true; // ÇëÇó³É¹¦µ«ÎÞÆ¥Åä
				cJSON_AddStringToObject(response.result.get(), "message", "No matching pattern found in module");
				cJSON_AddStringToObject(response.result.get(), "module_base_hex", addr_to_hex_str(module_base).c_str());
				cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
				cJSON_AddNumberToObject(response.result.get(), "match_count", 0);
			}
			else
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "First matching pattern found in module");
				cJSON_AddStringToObject(response.result.get(), "module_base_hex", addr_to_hex_str(module_base).c_str());
				cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
				cJSON_AddNumberToObject(response.result.get(), "match_count", 1);
				cJSON_AddStringToObject(response.result.get(), "first_match_address_hex", addr_to_hex_str(match_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "first_match_address_decimal", match_addr);
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while scanning pattern in module");
			cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
			cJSON_AddStringToObject(response.result.get(), "module_base", module_base_str.c_str());
		}

		return response;
	}

	// Ö¸¶¨·¶Î§É¨ÃèÌØÕ÷Âë£¨·µ»ØµÚÒ»¸öÆ¥Åä£©£¨Memory.ScanRange£©
	static ResponseData handle_memory_scan_range(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë3¸ö²ÎÊý£¨ÌØÕ÷Âë¡¢ÆðÊ¼µØÖ·¡¢É¨Ãè³¤¶È£©
		if (params.size() != 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 3: [pattern] [start_address] [scan_length_bytes]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Scan 'FF 25' from 0x00401000 for 4096 bytes: [\"FF 25\", \"0x00401000\", \"4096\"]");
			return response;
		}

		const std::string pattern = params[0];
		const std::string start_addr_str = params[1];
		const std::string scan_len_str = params[2];

		try
		{
			// 2. Ð£ÑéÌØÕ÷Âë¸ñÊ½
			if (!is_valid_pattern(pattern))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid pattern format. Use hex bytes (2 digits) separated by space, support '??' wildcard");
				cJSON_AddStringToObject(response.result.get(), "invalid_pattern", pattern.c_str());
				return response;
			}

			// 3. ½âÎöÆðÊ¼µØÖ·£¨·Ç0£©
			unsigned long long start_addr = 0;
			if (!parse_value(start_addr_str, start_addr) || start_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_start_address", start_addr_str.c_str());
				return response;
			}

			// 4. ½âÎöÉ¨Ãè³¤¶È£¨>0£©
			unsigned long long scan_len = 0;
			if (!parse_value(scan_len_str, scan_len) || scan_len == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid scan length. Use positive hex (0x...) or decimal (e.g., 4096 for 4KB)");
				cJSON_AddStringToObject(response.result.get(), "invalid_scan_length", scan_len_str.c_str());
				return response;
			}

			// 5. µ÷ÓÃÔ­º¯ÊýÉ¨Ãè·¶Î§£¨Í³Ò»µ÷ÓÃFindMemÂß¼­£¬ÓëÔ­º¯ÊýÒ»ÖÂ£©
			unsigned long long match_addr = 0;
#ifdef _WIN64
			match_addr = Script::Pattern::FindMem(start_addr, scan_len, pattern.c_str());
#else
			match_addr = Script::Pattern::FindMem(static_cast<duint>(start_addr), scan_len, pattern.c_str());
#endif

			// 6. ´¦Àí½á¹û£¨0=ÎÞÆ¥Åä£¬ÆäËû=Æ¥ÅäµØÖ·£©
			if (match_addr == 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "No matching pattern found in range");
				/*
				cJSON_AddStringToObject(response.result.get(), "scan_range",
					addr_to_hex_str(start_addr).c_str() + "-" + addr_to_hex_str(start_addr + scan_len - 1)
					);
					*/

				// ÐÞ¸´µÚÒ»¸ö´íÎó£ºÕýÈ·Æ´½Ó×Ö·û´®
				std::string start_str = addr_to_hex_str(start_addr);
				std::string end_str = addr_to_hex_str(start_addr + scan_len - 1);
				std::string range_str = start_str + "-" + end_str;
				cJSON_AddStringToObject(response.result.get(), "scan_range", range_str.c_str());

				cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
				cJSON_AddNumberToObject(response.result.get(), "match_count", 0);
			}
			else
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "First matching pattern found in range");
				/*
				cJSON_AddStringToObject(response.result.get(), "scan_range",
					addr_to_hex_str(start_addr).c_str + " - " + addr_to_hex_str(start_addr + scan_len - 1)
					);
					*/
				std::string start_str = addr_to_hex_str(start_addr);
				std::string end_str = addr_to_hex_str(start_addr + scan_len - 1);
				std::string range_str = start_str + " - " + end_str;
				cJSON_AddStringToObject(response.result.get(), "scan_range", range_str.c_str());


				cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
				cJSON_AddNumberToObject(response.result.get(), "match_count", 1);

				cJSON_AddStringToObject(response.result.get(), "first_match_address_hex", addr_to_hex_str(match_addr).c_str());

				cJSON_AddNumberToObject(response.result.get(), "first_match_address_decimal", match_addr);
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while scanning pattern in range");
			cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
			cJSON_AddStringToObject(response.result.get(), "scan_start_address", start_addr_str.c_str());
		}

		return response;
	}

	// Ä£¿éÄÚÉ¨ÃèÌØÕ÷Âë£¨·µ»ØËùÓÐÆ¥Åä£©£¨Memory.ScanModuleAll£©
	static ResponseData handle_memory_scan_module_all(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2-3¸ö²ÎÊý£¨ÌØÕ÷Âë¡¢Ä£¿é»ùÖ·¡¢[ÆðÊ¼Î»ÖÃ]£©
		if (params.size() < 2 || params.size() > 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2-3: [pattern] [module_base_address] [start_address(optional)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Scan all 'FF 25 ??' in module 0x00400000: [\"FF 25 ??\", \"0x00400000\"]");
			return response;
		}

		const std::string pattern = params[0];
		const std::string module_base_str = params[1];
		const std::string start_addr_str = (params.size() == 3) ? params[2] : "0";

		try
		{
			// 2. Ð£ÑéÌØÕ÷Âë¸ñÊ½
			if (!is_valid_pattern(pattern))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid pattern format. Use hex bytes (2 digits) separated by space, support '??' wildcard");
				cJSON_AddStringToObject(response.result.get(), "invalid_pattern", pattern.c_str());
				return response;
			}

			// 3. ½âÎöÄ£¿é»ùÖ·£¨·Ç0£©
			unsigned long long module_base = 0;
			if (!parse_value(module_base_str, module_base) || module_base == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid module base address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_module_base", module_base_str.c_str());
				return response;
			}

			// 4. ½âÎöÆðÊ¼É¨ÃèÎ»ÖÃ£¨0=Ä¬ÈÏÄ£¿é»ùÖ·£©
			unsigned long long start_addr = 0;
			if (!parse_value(start_addr_str, start_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address. Use hex (0x...) or decimal (0 = module base)");
				cJSON_AddStringToObject(response.result.get(), "invalid_start_address", start_addr_str.c_str());
				return response;
			}

			// 5. µ÷ÓÃºËÐÄº¯Êý»ñÈ¡ËùÓÐÆ¥Åä
			std::vector<duint> match_addrs;
#ifdef _WIN64
			auto match_addrs_64 = FindAllMemoryCode(pattern, static_cast<duint>(module_base), static_cast<duint>(start_addr));
			match_addrs.assign(match_addrs_64.begin(), match_addrs_64.end());
#else
			match_addrs = FindAllMemoryCode(pattern, static_cast<duint>(module_base), static_cast<duint>(start_addr));
#endif

			// 6. ´¦Àí½á¹û£¨¿ÕÁÐ±í=ÎÞÆ¥Åä£¬·ñÔò·µ»ØËùÓÐµØÖ·£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Module pattern scan completed");
			cJSON_AddStringToObject(response.result.get(), "module_base_hex", addr_to_hex_str(module_base).c_str());
			cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
			cJSON_AddNumberToObject(response.result.get(), "total_match_count", match_addrs.size());

			// ¹¹½¨Æ¥ÅäµØÖ·Êý×é£¨Ê®Áù½øÖÆ×Ö·û´®£©
			cJSON* match_array = cJSON_CreateArray();
			for (duint addr : match_addrs)
			{
				cJSON_AddItemToArray(match_array, cJSON_CreateString(addr_to_hex_str(addr).c_str()));
			}
			cJSON_AddItemToObject(response.result.get(), "all_match_addresses_hex", match_array);

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while scanning all patterns in module");
			cJSON_AddStringToObject(response.result.get(), "scanned_pattern", pattern.c_str());
			cJSON_AddStringToObject(response.result.get(), "module_base", module_base_str.c_str());
		}

		return response;
	}

	// ÄÚ´æÐ´ÈëÌØÕ÷Âë£¨Memory.WritePattern£©
	static ResponseData handle_memory_write_pattern(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë3¸ö²ÎÊý£¨Ð´ÈëÌØÕ÷Âë¡¢ÆðÊ¼µØÖ·¡¢Ð´Èë³¤¶È£©
		if (params.size() != 3)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 3: [write_pattern] [start_address] [write_length_bytes]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Write '90 90' to 0x00401000 (2 bytes): [\"90 90\", \"0x00401000\", \"2\"]");
			return response;
		}

		const std::string write_pattern = params[0];
		const std::string start_addr_str = params[1];
		const std::string write_len_str = params[2];

		try
		{
			// 2. Ð£ÑéÐ´ÈëÌØÕ÷Âë¸ñÊ½£¨ÎÞÍ¨Åä·û£¬±ØÐëÊÇÈ·¶¨×Ö½Ú£©
			if (!is_valid_pattern(write_pattern))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid write pattern format. Use hex bytes (2 digits) separated by space (no '??' wildcard)");
				cJSON_AddStringToObject(response.result.get(), "invalid_write_pattern", write_pattern.c_str());
				return response;
			}
			// ×ª»»ÌØÕ÷ÂëÎª×Ö½ÚÊý×é£¬Ð£Ñé³¤¶ÈÆ¥Åä
			auto write_bytes = pattern_to_bytes(write_pattern);
			size_t pattern_byte_count = write_bytes.size();

			// 3. ½âÎöÆðÊ¼µØÖ·£¨·Ç0£©
			unsigned long long start_addr = 0;
			if (!parse_value(start_addr_str, start_addr) || start_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_start_address", start_addr_str.c_str());
				return response;
			}

			// 4. ½âÎöÐ´Èë³¤¶È£¨>0£¬ÇÒÓëÌØÕ÷Âë×Ö½ÚÊýÒ»ÖÂ£©
			unsigned long long write_len = 0;
			if (!parse_value(write_len_str, write_len) || write_len == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid write length. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_write_length", write_len_str.c_str());
				return response;
			}
			if (write_len != pattern_byte_count)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Write length mismatch with pattern byte count");
				cJSON_AddNumberToObject(response.result.get(), "specified_write_length_bytes", write_len);
				cJSON_AddNumberToObject(response.result.get(), "pattern_byte_count", pattern_byte_count);
				return response;
			}

			// 5. µ÷ÓÃÔ­º¯ÊýÐ´ÈëÄÚ´æ
#ifdef _WIN64
			Script::Pattern::WriteMem(start_addr, write_len, write_pattern.c_str());
#else
			Script::Pattern::WriteMem(static_cast<duint>(start_addr), write_len, write_pattern.c_str());
#endif

			// 6. ´¦Àí½á¹û£¨Ô­º¯ÊýÎÞ·µ»ØÖµ£¬Ä¬ÈÏ³É¹¦£¬ÐèÌáÊ¾·çÏÕ£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Pattern written to memory successfully");

			/*
			cJSON_AddStringToObject(response.result.get(), "write_range",
				addr_to_hex_str(start_addr).c_str + " - " + addr_to_hex_str(start_addr + write_len - 1)
				);
				*/

			// ÏÈ´´½¨ÁÙÊ±×Ö·û´®±äÁ¿½øÐÐÆ´½Ó
			std::string start_str = addr_to_hex_str(start_addr);
			std::string end_str = addr_to_hex_str(start_addr + write_len - 1);
			std::string range_str = start_str + "-" + end_str;

			// ÕýÈ·µ÷ÓÃcJSON_AddStringToObject£¬È·±£c_str()´øÀ¨ºÅ
			cJSON_AddStringToObject(response.result.get(), "write_range", range_str.c_str());



			cJSON_AddStringToObject(response.result.get(), "written_pattern", write_pattern.c_str());
			cJSON_AddNumberToObject(response.result.get(), "written_byte_count", write_len);
			cJSON_AddStringToObject(response.result.get(), "warning",
				"1. Ensure target memory is writable (check with Memory.GetProtect)\n"
				"2. Incorrect writes may cause process crashes or data corruption"
				);

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while writing pattern to memory");
			cJSON_AddStringToObject(response.result.get(), "written_pattern", write_pattern.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_address", start_addr_str.c_str());
		}

		return response;
	}

	// ÄÚ´æËÑË÷²¢Ìæ»»ÌØÕ÷Âë£¨Memory.ReplacePattern£©
	static ResponseData handle_memory_replace_pattern(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë4¸ö²ÎÊý£¨ËÑË÷ÌØÕ÷Âë¡¢Ìæ»»ÌØÕ÷Âë¡¢ÆðÊ¼µØÖ·¡¢ËÑË÷³¤¶È£©
		if (params.size() != 4)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 4: [search_pattern] [replace_pattern] [start_address] [search_length_bytes]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Replace 'FF 25' with '90 90' in 0x00401000-0x00402000: [\"FF 25\", \"90 90\", \"0x00401000\", \"4096\"]");
			return response;
		}

		const std::string search_pattern = params[0];
		const std::string replace_pattern = params[1];
		const std::string start_addr_str = params[2];
		const std::string search_len_str = params[3];

		try
		{
			// 2. Ð£ÑéËÑË÷/Ìæ»»ÌØÕ÷Âë¸ñÊ½£¨ËÑË÷Ö§³ÖÍ¨Åä·û£¬Ìæ»»ÎÞÍ¨Åä·û£©
			if (!is_valid_pattern(search_pattern))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid search pattern format. Use hex bytes + '??' wildcard");
				cJSON_AddStringToObject(response.result.get(), "invalid_search_pattern", search_pattern.c_str());
				return response;
			}
			if (!is_valid_pattern(replace_pattern) || replace_pattern.find("??") != std::string::npos)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid replace pattern format. Use hex bytes (no '??' wildcard)");
				cJSON_AddStringToObject(response.result.get(), "invalid_replace_pattern", replace_pattern.c_str());
				return response;
			}

			// 3. Ð£ÑéËÑË÷ÓëÌæ»»ÌØÕ÷Âë×Ö½ÚÊýÒ»ÖÂ£¨·ñÔòÌæ»»³¤¶È²»Æ¥Åä£©
			auto search_bytes = pattern_to_bytes(search_pattern);
			auto replace_bytes = pattern_to_bytes(replace_pattern);
			if (search_bytes.size() != replace_bytes.size())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Search and replace pattern byte count mismatch");
				cJSON_AddNumberToObject(response.result.get(), "search_pattern_byte_count", search_bytes.size());
				cJSON_AddNumberToObject(response.result.get(), "replace_pattern_byte_count", replace_bytes.size());
				return response;
			}

			// 4. ½âÎöÆðÊ¼µØÖ·£¨·Ç0£©
			unsigned long long start_addr = 0;
			if (!parse_value(start_addr_str, start_addr) || start_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_start_address", start_addr_str.c_str());
				return response;
			}

			// 5. ½âÎöËÑË÷³¤¶È£¨>0£©
			unsigned long long search_len = 0;
			if (!parse_value(search_len_str, search_len) || search_len == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid search length. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_search_length", search_len_str.c_str());
				return response;
			}

			// 6. µ÷ÓÃÔ­º¯ÊýËÑË÷²¢Ìæ»»
			bool replace_success = false;
#ifdef _WIN64
			replace_success = Script::Pattern::SearchAndReplaceMem(start_addr, search_len, search_pattern.c_str(), replace_pattern.c_str());
#else
			replace_success = Script::Pattern::SearchAndReplaceMem(static_cast<duint>(start_addr), search_len, search_pattern.c_str(), replace_pattern.c_str());
#endif

			// 7. ´¦Àí½á¹û
			response.success = true; // ÇëÇó±¾Éí³É¹¦£¬replace_success±íÊ¾Ìæ»»ÊÇ·ñÃüÖÐ
			if (replace_success)
			{
				cJSON_AddStringToObject(response.result.get(), "message", "Pattern search and replace completed successfully");
				cJSON_AddStringToObject(response.result.get(), "replace_status", "At least one matching pattern was replaced");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "message", "Pattern search and replace completed (no matches found)");
				cJSON_AddStringToObject(response.result.get(), "replace_status", "No matching patterns to replace");
			}

			// ²¹³äÏêÏ¸ÐÅÏ¢
			cJSON_AddStringToObject(response.result.get(), "search_pattern", search_pattern.c_str());
			cJSON_AddStringToObject(response.result.get(), "replace_pattern", replace_pattern.c_str());
			/*
			cJSON_AddStringToObject(response.result.get(), "search_range",
				addr_to_hex_str(start_addr).c_str + " - " + addr_to_hex_str(start_addr + search_len - 1)
				);

			cJSON_AddStringToObject(response.result.get(), "warning",
				"1. Ensure target memory is writable (check with Memory.GetProtect)\n"
				"2. Replacing critical code/data may cause process instability"
				);
				*/

			// ÏÈ½«µØÖ·×ª»»Îª×Ö·û´®²¢Æ´½Ó
			std::string start_address = addr_to_hex_str(start_addr);
			std::string end_address = addr_to_hex_str(start_addr + search_len - 1);
			std::string range_str = start_address + " - " + end_address;

			// ÕýÈ·Ìí¼Óµ½JSON¶ÔÏó
			cJSON_AddStringToObject(response.result.get(), "search_range", range_str.c_str());

			// ·½·¨1£ºÊ¹ÓÃstd::stringÆ´½Ó
			std::string warning_msg = "1. Ensure target memory is writable (check with Memory.GetProtect)\n"
				"2. Replacing critical code/data may cause process instability";
			cJSON_AddStringToObject(response.result.get(), "warning", warning_msg.c_str());

			// ·½·¨2£º±£³ÖÔ­Ê¼·ç¸ñµ«È·±£ÕýÈ·Æ´½Ó
			cJSON_AddStringToObject(response.result.get(), "warning",
				"1. Ensure target memory is writable (check with Memory.GetProtect)\n"
				"2. Replacing critical code/data may cause process instability");



			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while searching and replacing pattern");
			cJSON_AddStringToObject(response.result.get(), "search_pattern", search_pattern.c_str());
			cJSON_AddStringToObject(response.result.get(), "replace_pattern", replace_pattern.c_str());
		}

		return response;
	}






	// ¶ÁÄÚ´æ×Ö½Ú£¨1×Ö½Ú£©£¨Memory.ReadByte£©
	static ResponseData handle_read_memory_byte(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Read byte at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú¶Á×Ö½Ú£¨ÐÞ¸´£ºÍ³Ò»ÓÃScript::Memory::GetLastErrorÅÐ¶Ï£©
			BYTE read_value = 0;
			BOOL read_success = FALSE;
#ifdef _WIN64
			read_value = Script::Memory::ReadByte(target_addr);
#else
			read_value = Script::Memory::ReadByte(static_cast<duint>(target_addr));
#endif
			// ÐÞ¸´£ºx86²»ÔÙÓÃÏµÍ³GetLastError£¬Í³Ò»ÓÃµ÷ÊÔÆ÷½Ó¿Ú
			read_success = (GetLastError() == 0);

			// 4. ´¦Àí½á¹û£¨Çø·Ö¡°¶ÁÈ¡Ê§°Ü¡±ºÍ¡°¶ÁÈ¡µ½0¡±£©
			if (read_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory byte read successfully");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "read_value_decimal", read_value);
				cJSON_AddStringToObject(response.result.get(), "read_value_hex", format_address(static_cast<unsigned int>(read_value), 2).c_str()); // 2Î»Ê®Áù½øÖÆ
				cJSON_AddStringToObject(response.result.get(), "data_type", "Byte (1 byte, 0-255)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to read memory byte (address invalid or unreadable)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while reading memory byte");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¶ÁÄÚ´æ×Ö£¨2×Ö½Ú£¬16Î»ÎÞ·ûºÅÕûÊý£©£¨Memory.ReadWord£©
	static ResponseData handle_read_memory_word(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Read word at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨·Ç0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú¶ÁWord£¨Çø·ÖÆ½Ì¨£¬´¦Àí¶ÁÈ¡×´Ì¬£©
			WORD read_value = 0;
			BOOL read_success = FALSE;
#ifdef _WIN64
			read_value = Script::Memory::ReadWord(target_addr);
			read_success = (GetLastError() == 0); // ÒÀÀµµ÷ÊÔÆ÷½Ó¿ÚÅÐ¶Ï¶ÁÈ¡ÊÇ·ñ³É¹¦
#else
			read_value = Script::Memory::ReadWord(static_cast<duint>(target_addr));
			read_success = (GetLastError() == 0);
#endif

			// 4. ´¦Àí½á¹û
			if (read_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory word read successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				// ¶ÁÈ¡Öµ£¨Ê®½øÖÆ+4Î»Ê®Áù½øÖÆ£©
				cJSON_AddNumberToObject(response.result.get(), "read_value_decimal", static_cast<unsigned int>(read_value));
				cJSON_AddStringToObject(response.result.get(), "read_value_hex", format_address(static_cast<unsigned int>(read_value), 4).c_str()); // ²¹ÁãÎª4Î»
				// Êý¾ÝÀàÐÍËµÃ÷
				cJSON_AddStringToObject(response.result.get(), "data_type", "Word (2 bytes, unsigned 16-bit integer, 0-65535)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to read memory word (address invalid, unreadable, or misaligned)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Word reads require 2-byte alignment (address must be even) on some architectures");
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while reading memory word");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¶ÁÄÚ´æË«×Ö£¨4×Ö½Ú£¬32Î»ÎÞ·ûºÅÕûÊý£©£¨Memory.ReadDword£©
	static ResponseData handle_read_memory_dword(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Read dword at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨·Ç0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú¶ÁDword£¨Çø·ÖÆ½Ì¨£¬Í³Ò»ÓÃScript::Memory::GetLastErrorÅÐ¶Ï³É¹¦£©
			DWORD read_value = 0;
			BOOL read_success = FALSE;
#ifdef _WIN64
			read_value = Script::Memory::ReadDword(target_addr);
#else
			read_value = Script::Memory::ReadDword(static_cast<duint>(target_addr));
#endif
			// Í³Ò»£ºÍ¨¹ýµ÷ÊÔÆ÷ÄÚ´æ½Ó¿Ú»ñÈ¡´íÎóÂë£¬±ÜÃâ»ìÓÃÏµÍ³GetLastError
			read_success = (GetLastError() == 0);

			// 4. ´¦Àí½á¹û
			if (read_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory dword read successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				// ¶ÁÈ¡Öµ£¨Ê®½øÖÆ+8Î»Ê®Áù½øÖÆ£¬Í³Ò»ÓÃformat_address²¹Áã£©
				cJSON_AddNumberToObject(response.result.get(), "read_value_decimal", static_cast<unsigned long long>(read_value));
				cJSON_AddStringToObject(response.result.get(), "read_value_hex", format_address(static_cast<unsigned long long>(read_value), 8).c_str()); // ²¹ÁãÎª8Î»
				// Êý¾ÝÀàÐÍËµÃ÷
				cJSON_AddStringToObject(response.result.get(), "data_type", "Dword (4 bytes, unsigned 32-bit integer, 0-4294967295)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to read memory dword (address invalid, unreadable, or misaligned)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Dword reads require 4-byte alignment (address mod 4 == 0) on most architectures");
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...) // ÐÞ¸´£ºcatch¿éÒÆÖÁº¯ÊýÄÚ²¿£¬½ô¸útry
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while reading memory dword");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¶ÁÄÚ´æËÄ×Ö£¨8×Ö½Ú£¬x64×¨Êô£©£¨Memory.ReadQword£©
#ifdef _WIN64
	static ResponseData handle_read_memory_qword(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Read qword at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú¶ÁËÄ×Ö£¨Í³Ò»´íÎóÅÐ¶Ï£©
			unsigned long long read_value = 0;
			BOOL read_success = FALSE;
			read_value = Script::Memory::ReadQword(target_addr);
			read_success = (GetLastError() == 0); // Í³Ò»ÓÃµ÷ÊÔÆ÷´íÎó½Ó¿Ú

			// 4. ´¦Àí½á¹û£¨ÐÞ¸´£ºÓÃformat_addressÍ³Ò»¸ñÊ½£¬Ìæ´úformat_hex£©
			if (read_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory qword read successfully");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "read_value_decimal", read_value);
				// ÐÞ¸´£ºÓÃformat_address²¹ÁãÎª16Î»£¬ÓëÆäËûº¯Êý·ç¸ñÒ»ÖÂ
				cJSON_AddStringToObject(response.result.get(), "read_value_hex", format_address(read_value, 16).c_str()); 
				cJSON_AddStringToObject(response.result.get(), "data_type", "Qword (8 bytes, x64 exclusive)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to read memory qword (address invalid or unreadable)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while reading memory qword");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
}
#endif

	// ¶ÁÄÚ´æÖ¸Õë£¨Æ½Ì¨Ö¸Õë´óÐ¡£ºx86=4×Ö½Ú£¬x64=8×Ö½Ú£©£¨Memory.ReadPtr£©
	static ResponseData handle_read_memory_ptr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Read pointer at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú¶ÁÖ¸Õë£¨Çø·ÖÆ½Ì¨£¬Í³Ò»ÅÐ¶Ï¶ÁÈ¡½á¹û£©
			unsigned long long read_value = 0;
			BOOL read_success = FALSE;
#ifdef _WIN64
			read_value = Script::Memory::ReadPtr(target_addr);
#else
			read_value = Script::Memory::ReadPtr(static_cast<duint>(target_addr));
#endif
			// ÐÞ¸´£ºx86Æ½Ì¨²»ÔÙÓ²±àÂëÎªtrue£¬Í³Ò»ÓÃµ÷ÊÔÆ÷´íÎó½Ó¿ÚÅÐ¶Ï
			read_success = (GetLastError() == 0);

			// 4. ´¦Àí½á¹û
			if (read_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory pointer read successfully");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "read_ptr_value_decimal", read_value);
				cJSON_AddStringToObject(response.result.get(), "read_ptr_value_hex", format_address(read_value).c_str()); // Ö¸ÕëµØÖ·¸ñÊ½
				cJSON_AddStringToObject(response.result.get(), "data_type",
#ifdef _WIN64
					"Pointer (8 bytes, x64)"
#else
					"Pointer (4 bytes, x86)"
#endif
					);
				cJSON_AddStringToObject(response.result.get(), "note", "Value represents a memory address (may be NULL=0)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to read memory pointer (address invalid or unreadable)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while reading memory pointer");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// Ð´ÄÚ´æ×Ö½Ú£¨1×Ö½Ú£©£¨Memory.WriteByte£©
	static ResponseData handle_write_memory_byte(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨µØÖ· + Öµ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [memory_address(hex/decimal)] [byte_value(0-255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Write 0x12 to 0x00401000: [\"0x00401000\", \"18\"] or [\"0x00401000\", \"0x12\"]");
			return response;
		}

		const std::string addr_str = params[0];
		const std::string value_str = params[1];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£Ñé
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. ½âÎöÐ´ÈëÖµ²¢Ð£Ñé·¶Î§£¨Byte: 0-255£©
			unsigned long long value_raw = 0;
			if (!parse_value(value_str, value_raw) || value_raw > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid byte value. Must be 0-255 (decimal) or 0x00-0xFF (hex)");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}
			BYTE write_value = static_cast<BYTE>(value_raw);

			// 4. µ÷ÓÃ½Ó¿ÚÐ´×Ö½Ú£¨Çø·ÖÆ½Ì¨£©
			BOOL write_success = FALSE;
#ifdef _WIN64
			write_success = Script::Memory::WriteByte(target_addr, write_value);
#else
			write_success = Script::Memory::WriteByte(static_cast<duint>(target_addr), write_value);
#endif

			// 5. ´¦Àí½á¹û
			if (write_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory byte written successfully");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "written_value_decimal", write_value);
				cJSON_AddStringToObject(response.result.get(), "written_value_hex", format_address(static_cast<unsigned int>(write_value), 2).c_str());
				cJSON_AddStringToObject(response.result.get(), "data_type", "Byte (1 byte)");
				cJSON_AddStringToObject(response.result.get(), "warning", "Ensure memory is writable (check with GetProtect) to avoid access violations");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to write memory byte (address invalid, read-only, or access denied)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while writing memory byte");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// Ð´ÄÚ´æ×Ö£¨2×Ö½Ú£¬16Î»ÎÞ·ûºÅÕûÊý£©£¨Memory.WriteWord£©
	static ResponseData handle_write_memory_word(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨µØÖ· + Ð´ÈëÖµ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [memory_address(hex/decimal)] [word_value(0-65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Write 0x1234 to 0x00401000: [\"0x00401000\", \"4660\"] or [\"0x00401000\", \"0x1234\"]");
			return response;
		}

		const std::string addr_str = params[0];  // ÄÚ´æµØÖ·
		const std::string value_str = params[1]; // Ð´ÈëÖµ

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£Ñé£¨·Ç0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. ½âÎöÐ´ÈëÖµ²¢Ð£Ñé·¶Î§£¨Word£º0-65535 = 0x0000-0xFFFF£©
			unsigned long long value_raw = 0;
			if (!parse_value(value_str, value_raw) || value_raw > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid word value. Must be 0-65535 (decimal) or 0x0000-0xFFFF (hex)");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}
			WORD write_value = static_cast<WORD>(value_raw); // ×ª»»Îª16Î»ÎÞ·ûºÅÕûÊý

			// 4. µ÷ÓÃ½Ó¿ÚÐ´×Ö£¨Çø·ÖÆ½Ì¨£©
			BOOL write_success = FALSE;
#ifdef _WIN64
			write_success = Script::Memory::WriteWord(target_addr, write_value);
#else
			write_success = Script::Memory::WriteWord(static_cast<duint>(target_addr), write_value);
#endif

			// 5. ´¦Àí½á¹û
			if (write_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory word written successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				// Ð´ÈëÖµÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "written_value_decimal", static_cast<unsigned int>(write_value));
				cJSON_AddStringToObject(response.result.get(), "written_value_hex", format_address(static_cast<unsigned int>(write_value), 4).c_str());
				// Êý¾ÝÀàÐÍÓë¾¯¸æ
				cJSON_AddStringToObject(response.result.get(), "data_type", "Word (2 bytes, unsigned 16-bit integer)");
				cJSON_AddStringToObject(response.result.get(), "warning",
					"1. Ensure memory is writable (check with Memory.GetProtect first)\n"
					"2. Word writes require 2-byte alignment (address must be even) to avoid crashes"
					);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to write memory word (address invalid, read-only, misaligned, or access denied)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "failed_value_hex", format_address(static_cast<unsigned int>(write_value), 4).c_str());
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while writing memory word");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// Ð´ÄÚ´æË«×Ö£¨4×Ö½Ú£¬32Î»ÎÞ·ûºÅÕûÊý£©£¨Memory.WriteDword£©
	static ResponseData handle_write_memory_dword(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨µØÖ· + Ð´ÈëÖµ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [memory_address(hex/decimal)] [dword_value(0-4294967295)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Write 0x12345678 to 0x00401000: [\"0x00401000\", \"305419896\"] or [\"0x00401000\", \"0x12345678\"]");
			return response;
		}

		const std::string addr_str = params[0];  // ÄÚ´æµØÖ·
		const std::string value_str = params[1]; // Ð´ÈëÖµ

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£Ñé£¨·Ç0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. ½âÎöÐ´ÈëÖµ²¢Ð£Ñé·¶Î§£¨Dword£º0-4294967295 = 0x00000000-0xFFFFFFFF£©
			unsigned long long value_raw = 0;
			if (!parse_value(value_str, value_raw) || value_raw > 0xFFFFFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid dword value. Must be 0-4294967295 (decimal) or 0x00000000-0xFFFFFFFF (hex)");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}
			DWORD write_value = static_cast<DWORD>(value_raw); // ×ª»»Îª32Î»ÎÞ·ûºÅÕûÊý

			// 4. µ÷ÓÃ½Ó¿ÚÐ´Ë«×Ö£¨Çø·ÖÆ½Ì¨£©
			BOOL write_success = FALSE;
#ifdef _WIN64
			write_success = Script::Memory::WriteDword(target_addr, write_value);
#else
			write_success = Script::Memory::WriteDword(static_cast<duint>(target_addr), write_value);
#endif

			// 5. ´¦Àí½á¹û
			if (write_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory dword written successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				// Ð´ÈëÖµÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "written_value_decimal", static_cast<unsigned long long>(write_value));
				cJSON_AddStringToObject(response.result.get(), "written_value_hex", format_address(static_cast<unsigned long long>(write_value), 8).c_str());
				// Êý¾ÝÀàÐÍÓë¾¯¸æ
				cJSON_AddStringToObject(response.result.get(), "data_type", "Dword (4 bytes, unsigned 32-bit integer)");
				cJSON_AddStringToObject(response.result.get(), "warning",
					"1. Ensure memory is writable (check with Memory.GetProtect first)\n"
					"2. Dword writes require 4-byte alignment (address mod 4 == 0) to avoid crashes"
					);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to write memory dword (address invalid, read-only, misaligned, or access denied)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "failed_value_hex", format_address(static_cast<unsigned long long>(write_value), 8).c_str());
			}

			// Æ½Ì¨±êÊ¶
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while writing memory dword");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// Ð´ÄÚ´æËÄ×Ö£¨8×Ö½Ú£¬64Î»ÎÞ·ûºÅÕûÊý£¬x64×¨Êô£©£¨Memory.WriteQword£©
#ifdef _WIN64
	static ResponseData handle_write_memory_qword(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä¿±êÄÚ´æµØÖ· + 64Î»Öµ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [target_memory_address(hex/decimal)] [qword_value(0-0xFFFFFFFFFFFFFFFF)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Write 0x123456789ABCDEF0 to 0x00007FFB8C700000: [\"0x00007FFB8C700000\", \"0x123456789ABCDEF0\"]");
			cJSON_AddStringToObject(response.result.get(), "note", "This interface is x64-exclusive (Qword = 8-byte unsigned integer)");
			return response;
		}

		const std::string target_addr_str = params[0]; // Ä¿±êÄÚ´æµØÖ·£¨Ð´ÈëQwordµÄµØÖ·£©
		const std::string qword_value_str = params[1]; // ´ýÐ´ÈëµÄ64Î»Öµ

		try
		{
			// 2. ½âÎöÄ¿±êÄÚ´æµØÖ·£¨Ðè·Ç0£¬·ñÔòÎÞÐ§£©
			unsigned long long target_addr = 0;
			if (!parse_value(target_addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target memory address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_target_address", target_addr_str.c_str());
				return response;
			}

			// 3. ½âÎö´ýÐ´ÈëµÄQwordÖµ£¨Ð£Ñé64Î»·¶Î§£º0 - 0xFFFFFFFFFFFFFFFF£©
			unsigned long long qword_value = 0;
			if (!parse_value(qword_value_str, qword_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid Qword value. Use hex (0x...) or decimal format");
				cJSON_AddStringToObject(response.result.get(), "invalid_qword_value", qword_value_str.c_str());
				return response;
			}

			// QwordÎª64Î»ÎÞ·ûºÅÕûÊý£¬×î´óÖµ¹Ì¶¨Îª0xFFFFFFFFFFFFFFFF£¨x64×¨Êô£©
			const unsigned long long MAX_QWORD_VALUE = 0xFFFFFFFFFFFFFFFF;
			if (qword_value > MAX_QWORD_VALUE)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Qword value exceeds 64-bit unsigned integer range (0 - 0xFFFFFFFFFFFFFFFF)");
				cJSON_AddStringToObject(response.result.get(), "invalid_qword_value", format_address(qword_value).c_str());
				cJSON_AddStringToObject(response.result.get(), "max_allowed_value", "0xFFFFFFFFFFFFFFFF (18446744073709551615 in decimal)");
				return response;
			}

			// 4. µ÷ÓÃµ÷ÊÔÆ÷½Ó¿ÚÐ´Qword£¨x64Æ½Ì¨Ö±½ÓÊ¹ÓÃ64Î»²ÎÊý£©
			BOOL write_success = Script::Memory::WriteQword(target_addr, qword_value);

			// 5. ´¦ÀíÐ´Èë½á¹û
			if (write_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory Qword written successfully (x64)");

				// Ä¿±êµØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_memory_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_memory_address_decimal", target_addr);

				// Ð´ÈëÖµÐÅÏ¢£¨16Î»Ê®Áù½øÖÆ²¹Áã£¬·ûºÏ64Î»ÏÔÊ¾¹æ·¶£©
				cJSON_AddStringToObject(response.result.get(), "written_qword_value_hex", format_address(qword_value, 16).c_str());
				cJSON_AddNumberToObject(response.result.get(), "written_qword_value_decimal", qword_value);

				// 64Î»Æ½Ì¨ÌØÓÐËµÃ÷
				cJSON_AddStringToObject(response.result.get(), "data_type", "Qword (8 bytes, unsigned 64-bit integer, x64 exclusive)");
				cJSON_AddStringToObject(response.result.get(), "alignment_requirement", "8-byte alignment (address mod 8 == 0) - critical for x64 architecture");
				cJSON_AddStringToObject(response.result.get(), "warning",
					"1. Verify target address is writable with Memory.GetProtect before writing\n"
					"2. Misalignment (address not 8-byte aligned) may cause access violations or crashes\n"
					"3. Qword values are often used for pointers or large integers in x64 processes"
					);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to write memory Qword (x64)");
				cJSON_AddStringToObject(response.result.get(), "possible_causes",
					"1. Target address is invalid or not in the process's address space\n"
					"2. Memory is read-only (check with Memory.GetProtect)\n"
					"3. Address is not 8-byte aligned (required for x64 Qword operations)\n"
					"4. Insufficient privileges to modify this memory region"
					);
				cJSON_AddStringToObject(response.result.get(), "target_memory_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "failed_qword_value_hex", format_address(qword_value, 16).c_str());
			}

			cJSON_AddStringToObject(response.result.get(), "platform", "x64"); // Ã÷È·±êÊ¶x64Æ½Ì¨
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while writing memory Qword (x64)");
			cJSON_AddStringToObject(response.result.get(), "target_memory_address", target_addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_qword_value", qword_value_str.c_str());
		}

		return response;
	}
#endif // _WIN64

	// Ð´ÄÚ´æÖ¸Õë£¨Æ½Ì¨×¨Êô´óÐ¡£ºx86=4×Ö½Ú£¬x64=8×Ö½Ú£©£¨Memory.WritePtr£©
	static ResponseData handle_write_memory_ptr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä¿±êÄÚ´æµØÖ· + ´ýÐ´ÈëµÄÖ¸ÕëÖµ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [target_memory_address(hex/decimal)] [pointer_value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example_x86", "Write pointer 0x00401000 to address 0x00500000: [\"0x00500000\", \"0x00401000\"]");
			cJSON_AddStringToObject(response.result.get(), "example_x64", "Write pointer 0x00007FFB8C700000 to address 0x00500000: [\"0x00500000\", \"0x00007FFB8C700000\"]");
			return response;
		}

		const std::string target_addr_str = params[0]; // Ä¿±êÄÚ´æµØÖ·£¨ÒªÐ´ÈëÖ¸ÕëµÄµØÖ·£©
		const std::string ptr_value_str = params[1];   // ´ýÐ´ÈëµÄÖ¸ÕëÖµ£¨Ö¸ÏòµÄÄ¿±êµØÖ·£©

		try
		{
			// 2. ½âÎöÄ¿±êÄÚ´æµØÖ·£¨Ðè·Ç0£¬·ñÔòÎÞÐ§£©
			unsigned long long target_addr = 0;
			if (!parse_value(target_addr_str, target_addr) || target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target memory address. Use non-zero hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_target_address", target_addr_str.c_str());
				return response;
			}

			// 3. ½âÎö´ýÐ´ÈëµÄÖ¸ÕëÖµ£¨°´Æ½Ì¨Ð£Ñé·¶Î§£¬±ÜÃâ³¬³öµØÖ·¿Õ¼ä£©
			unsigned long long ptr_value = 0;
			if (!parse_value(ptr_value_str, ptr_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid pointer value. Use hex (0x...) or decimal format");
				cJSON_AddStringToObject(response.result.get(), "invalid_pointer_value", ptr_value_str.c_str());
				return response;
			}

			// Æ½Ì¨×¨ÊôÖ¸ÕëÖµ·¶Î§Ð£Ñé£¨x86×î´ó4×Ö½ÚµØÖ·£¬x64×î´ó8×Ö½ÚµØÖ·£©
#ifdef _WIN64
			const unsigned long long MAX_PTR_VALUE = 0xFFFFFFFFFFFFFFFF; // x64 8×Ö½ÚµØÖ·¿Õ¼äÉÏÏÞ
			const char* PTR_SIZE_DESC = "8 bytes (x64)";
			const char* ALIGNMENT_DESC = "8-byte alignment (address mod 8 == 0)";
#else
			const unsigned long long MAX_PTR_VALUE = 0xFFFFFFFF; // x86 4×Ö½ÚµØÖ·¿Õ¼äÉÏÏÞ
			const char* PTR_SIZE_DESC = "4 bytes (x86)";
			const char* ALIGNMENT_DESC = "4-byte alignment (address mod 4 == 0)";
#endif
			if (ptr_value > MAX_PTR_VALUE)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Pointer value exceeds current platform's address space limit");
				cJSON_AddStringToObject(response.result.get(), "platform_limit",
					"x86: 0x00000000 - 0xFFFFFFFF (4 bytes)\n"
					"x64: 0x0000000000000000 - 0xFFFFFFFFFFFFFFFF (8 bytes)"
					);
				cJSON_AddStringToObject(response.result.get(), "invalid_pointer_value", format_address(ptr_value).c_str());
				return response;
			}

			// 4. µ÷ÓÃµ÷ÊÔÆ÷½Ó¿ÚÐ´Ö¸Õë£¨°´Æ½Ì¨×ª»»²ÎÊýÀàÐÍ£©
			BOOL write_success = FALSE;
#ifdef _WIN64
			// x64£ºÖ¸ÕëÎª8×Ö½Ú£¬Ä¿±êµØÖ·ºÍÖ¸ÕëÖµ¾ùÓÃunsigned long long
			write_success = Script::Memory::WritePtr(target_addr, ptr_value);
#else
			// x86£ºÖ¸ÕëÎª4×Ö½Ú£¬Ä¿±êµØÖ·ºÍÖ¸ÕëÖµ×ª»»Îªduint£¨32Î»ÎÞ·ûºÅÕûÊý£©
			write_success = Script::Memory::WritePtr(static_cast<duint>(target_addr), static_cast<duint>(ptr_value));
#endif

			// 5. ´¦ÀíÐ´Èë½á¹û
			if (write_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Memory pointer written successfully");

				// Ä¿±êÄÚ´æµØÖ·ÐÅÏ¢£¨Ð´ÈëÖ¸ÕëµÄµØÖ·£©
				cJSON_AddStringToObject(response.result.get(), "target_memory_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_memory_address_decimal", target_addr);

				// Ð´ÈëµÄÖ¸ÕëÖµÐÅÏ¢£¨Ö¸ÏòµÄÄ¿±êµØÖ·£©
				cJSON_AddStringToObject(response.result.get(), "written_pointer_value_hex", format_address(ptr_value).c_str()); // ÓÃµØÖ·¸ñÊ½ÏÔÊ¾£¨²¹Áã¸ü¹æ·¶£©
				cJSON_AddNumberToObject(response.result.get(), "written_pointer_value_decimal", ptr_value);

				// Æ½Ì¨ÓëÖ¸ÕëÊôÐÔËµÃ÷
				cJSON_AddStringToObject(response.result.get(), "pointer_size", PTR_SIZE_DESC);
				cJSON_AddStringToObject(response.result.get(), "alignment_requirement", ALIGNMENT_DESC);
				cJSON_AddStringToObject(
					response.result.get(),
					"warning",
					// ¹Ø¼ü£ºÓÃÀ¨ºÅ°ü¹üÆ´½Ó±í´ïÊ½£¬×îºóµ÷ÓÃ .c_str()
					(
					"1. Before writing: Use Memory.GetProtect to confirm the target address is writable\n"
					"2. Invalid pointer values (e.g., unallocated addresses) may cause process crashes\n"
					"3. Ensure alignment (" + std::string(ALIGNMENT_DESC) + ")"
					" to avoid access violations"
					).c_str()
					);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to write memory pointer");
				cJSON_AddStringToObject(
					response.result.get(),
					"possible_causes",
					(
					"1. Target memory address is invalid or not in the process's address space\n"
					"2. Target memory is read-only (check with Memory.GetProtect)\n"
					"3. Address misalignment (" + std::string(ALIGNMENT_DESC) + ")\n"
					"4. Insufficient process permissions"
					).c_str()  // ¹Ø¼ü£º×ª»»Îª const char*
					);
				cJSON_AddStringToObject(response.result.get(), "target_memory_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "failed_pointer_value_hex", format_address(ptr_value).c_str());
			}

			// Æ½Ì¨±êÊ¶£¨±£³ÖÓëÆäËû½Ó¿ÚÒ»ÖÂ£©
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			// ²¶»ñÒâÍâÒì³££¨Èç½âÎöÊ§°Ü¡¢½Ó¿Úµ÷ÓÃ±ÀÀ£µÈ£©
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while writing memory pointer");
			cJSON_AddStringToObject(response.result.get(), "target_memory_address", target_addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_pointer_value", ptr_value_str.c_str());
		}

		return response;
	}
};

// µ÷ÊÔ´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class DebuggerHandler
{
public:
	static ResponseData handle_wait(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.Wait");
			return response;
		}

		// µ÷ÓÃµ÷ÊÔµÈ´ý½Ó¿Ú£¨Ôö¼Ó¿ÕÖ¸Õë±£»¤£¬±ÜÃâº¯Êýµ÷ÓÃÒì³££©
		if (Script::Debug::Wait)
		{
			Script::Debug::Wait();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_wait_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger is now in wait state");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::Wait function not found");
		}

		return response;
	}

	static ResponseData handle_run(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.Run");
			return response;
		}

		// µ÷ÓÃµ÷ÊÔÔËÐÐ½Ó¿Ú
		if (Script::Debug::Run)
		{
			Script::Debug::Run();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_run_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger is now running");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::Run function not found");
		}

		return response;
	}

	static ResponseData handle_pause(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.Pause");
			return response;
		}

		if (Script::Debug::Pause)
		{
			Script::Debug::Pause();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_pause_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger has been paused");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::Pause function not found");
		}

		return response;
	}

	static ResponseData handle_stop(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.Stop");
			return response;
		}

		if (Script::Debug::Stop)
		{
			Script::Debug::Stop();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_stop_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger has been stopped");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::Stop function not found");
		}

		return response;
	}

	static ResponseData handle_step_in(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.StepIn");
			return response;
		}

		if (Script::Debug::StepIn)
		{
			Script::Debug::StepIn();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_stepin_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger performed step in");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::StepIn function not found");
		}

		return response;
	}

	static ResponseData handle_step_out(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.StepOut");
			return response;
		}

		if (Script::Debug::StepOut)
		{
			Script::Debug::StepOut();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_stepout_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger performed step out");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::StepOut function not found");
		}

		return response;
	}

	static ResponseData handle_step_over(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.StepOver");
			return response;
		}

		if (Script::Debug::StepOver)
		{
			Script::Debug::StepOver();
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_stepover_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger performed step over");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::StepOver function not found");
		}

		return response;
	}

	static ResponseData handle_is_debugger(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.IsDebugger");
			return response;
		}

		BOOL isDebugger = DbgIsDebugging();

		if (isDebugger)
		{
			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_debugger", isDebugger);
			cJSON_AddStringToObject(response.result.get(), "message", isDebugger ? "Debugger is active" : "Debugger is not active");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::IsDebugger function not found");
		}

		return response;
	}

	static ResponseData handle_is_running(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.IsRunning");
			return response;
		}

		// µ÷ÓÃµ÷ÊÔÆ÷ÔËÐÐ×´Ì¬¼ì²éº¯Êý
		BOOL isRunning = DbgIsRunning();

		// ÎÞÂÛ·µ»ØÖµÈçºÎ£¬¶¼ÊÓÎª³É¹¦»ñÈ¡×´Ì¬
		response.success = true;
		cJSON_AddBoolToObject(response.result.get(), "is_running", isRunning);
		cJSON_AddStringToObject(response.result.get(), "message", isRunning ? "Debugger is running" : "Debugger is not running");

		// ÒÆ³ý´íÎóµÄelse·ÖÖ§£¬ÒòÎªDbgIsRunning()µ÷ÓÃ³É¹¦¾Í²»Ó¦·µ»Øº¯ÊýÎ´ÕÒµ½µÄ´íÎó

		return response;
	}

	static ResponseData handle_is_running_locked(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.IsRunningLocked");
			return response;
		}

		BOOL isLocked = DbgIsRunLocked();

		if (isLocked)
		{
			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_running_locked", isLocked);
			cJSON_AddStringToObject(response.result.get(), "message", isLocked ? "Debugger is running in locked state" : "Debugger is not running in locked state");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::IsRunningLocked function not found");
		}

		return response;
	}

	static ResponseData handle_open_debug(const std::vector<std::string>& params)
	{
		ResponseData response;

		// Ô­Ê¼º¯ÊýÐèÒªCommand_String_A²ÎÊý£¬Òò´ËÐèÒª´Óparams»ñÈ¡
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing command parameter for Debugger.OpenDebug");
			return response;
		}

		// ¹¹Ôìµ÷ÊÔ³õÊ¼»¯ÃüÁî£¨¶ÔÓ¦Ô­Ê¼º¯ÊýµÄInitDebugÂß¼­£©
		std::string cmd = "InitDebug " + params[0];
		BOOL execResult = DbgCmdExec(cmd.c_str());

		if (execResult)
		{
			// ÃüÁîÖ´ÐÐ³É¹¦£¨¶ÔÓ¦Ô­Ê¼º¯ÊýµÄFlag=1£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_opened_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger initialized successfully");
			cJSON_AddStringToObject(response.result.get(), "executed_command", cmd.c_str());
		}
		else
		{
			// ÃüÁîÖ´ÐÐÊ§°Ü£¨¶ÔÓ¦Ô­Ê¼º¯ÊýµÄFlag=0£©
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to initialize debugger");
			cJSON_AddStringToObject(response.result.get(), "failed_command", cmd.c_str());
		}

		return response;
	}

	static ResponseData handle_close_debug(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.CloseDebug");
			return response;
		}

		BOOL CloseDbg = DbgCmdExec("StopDebug");

		if (CloseDbg)
		{
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_closed_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger has been closed");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::CloseDebug function not found");
		}

		return response;
	}

	static ResponseData handle_detach_debug(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.DetachDebug");
			return response;
		}

		BOOL DTDbg = DbgCmdExec("DetachDebugger");

		if (DTDbg)
		{
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "state", "debugger_detached_success");
			cJSON_AddStringToObject(response.result.get(), "message", "Debugger has been detached");
		}
		else
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Script::Debug::DetachDebug function not found");
		}

		return response;
	}

	static ResponseData handle_show_break_point(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ¶ÏµãÁÐ±í²»ÐèÒª²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.ShowBreakPoint");
			return response;
		}

		try
		{
			std::vector<BreakPointList> bk_list;
			BPMAP map;

			// »ñÈ¡¶ÏµãÁÐ±í
			if (!DbgGetBpList((BPXTYPE)0, &map))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to retrieve breakpoint list");
				return response;
			}

			// ´´½¨¶ÏµãÊý×é
			cJSON* breakpointsArray = cJSON_CreateArray();
			if (!breakpointsArray)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to create breakpoints array");
				return response;
			}

			// Ìî³ä¶ÏµãÊý¾Ý
			for (int x = 0; x < map.count; x++)
			{
				BreakPointList ptr = { 0 };

				// ¸´ÖÆ»ù±¾¶ÏµãÐÅÏ¢
				ptr.bpxtype = map.bp[x].type;
				ptr.address = map.bp[x].addr;
				ptr.enabled = map.bp[x].enabled;
				ptr.singleshoot = map.bp[x].singleshoot;
				ptr.active = map.bp[x].active;

				// Ê¹ÓÃ¸ü°²È«µÄ×Ö·û´®¸´ÖÆº¯Êý
				strcpy_s(ptr.name, sizeof(ptr.name), map.bp[x].name);
				strcpy_s(ptr.mod, sizeof(ptr.mod), map.bp[x].mod);

				ptr.slot = map.bp[x].slot;
				ptr.hitCount = map.bp[x].hitCount;
				ptr.fastResume = map.bp[x].fastResume;
				ptr.silent = map.bp[x].silent;

				strcpy_s(ptr.breakCondition, sizeof(ptr.breakCondition), map.bp[x].breakCondition);
				strcpy_s(ptr.logText, sizeof(ptr.logText), map.bp[x].logText);
				strcpy_s(ptr.logCondition, sizeof(ptr.logCondition), map.bp[x].logCondition);
				strcpy_s(ptr.commandText, sizeof(ptr.commandText), map.bp[x].commandText);
				strcpy_s(ptr.commandCondition, sizeof(ptr.commandCondition), map.bp[x].commandCondition);

				bk_list.push_back(ptr);

				// ´´½¨JSON¶ÔÏó²¢Ìí¼Óµ½Êý×é
				cJSON* breakpointObj = cJSON_CreateObject();
				if (breakpointObj)
				{
					cJSON_AddNumberToObject(breakpointObj, "type", ptr.bpxtype);
					// Ê¹ÓÃ×Ô¶¨ÒåµÄµØÖ·¸ñÊ½»¯º¯ÊýÌæ´úStringUtils::FormatAddress
					// cJSON_AddStringToObject(breakpointObj, "address", format_address(ptr.address).c_str());
					cJSON_AddNumberToObject(breakpointObj, "address", ptr.address);
					cJSON_AddBoolToObject(breakpointObj, "enabled", ptr.enabled != 0);
					cJSON_AddBoolToObject(breakpointObj, "singleshoot", ptr.singleshoot != 0);
					cJSON_AddBoolToObject(breakpointObj, "active", ptr.active != 0);
					cJSON_AddStringToObject(breakpointObj, "name", ptr.name);
					cJSON_AddStringToObject(breakpointObj, "module", ptr.mod);
					cJSON_AddNumberToObject(breakpointObj, "slot", ptr.slot);
					cJSON_AddNumberToObject(breakpointObj, "hit_count", ptr.hitCount);
					cJSON_AddBoolToObject(breakpointObj, "fast_resume", ptr.fastResume != 0);
					cJSON_AddBoolToObject(breakpointObj, "silent", ptr.silent != 0);
					cJSON_AddStringToObject(breakpointObj, "break_condition", ptr.breakCondition);
					cJSON_AddStringToObject(breakpointObj, "log_text", ptr.logText);
					cJSON_AddStringToObject(breakpointObj, "log_condition", ptr.logCondition);
					cJSON_AddStringToObject(breakpointObj, "command_text", ptr.commandText);
					cJSON_AddStringToObject(breakpointObj, "command_condition", ptr.commandCondition);

					cJSON_AddItemToArray(breakpointsArray, breakpointObj);
				}
			}

			// ½«¶ÏµãÊý×éÌí¼Óµ½ÏìÓ¦
			cJSON_AddItemToObject(response.result.get(), "breakpoints", breakpointsArray);
			cJSON_AddNumberToObject(response.result.get(), "count", bk_list.size());
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Breakpoints retrieved successfully");
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "An unexpected error occurred while retrieving breakpoints");
		}

		return response;
	}

	static ResponseData handle_set_break_point(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£ºÐèÒªÒ»¸öµØÖ·²ÎÊý
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing address parameter for Debugger.SetBreakPoint");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only address is expected");
			return response;
		}

		try
		{
			// ½âÎöµØÖ·²ÎÊý£¨Ö§³ÖÊ®Áù½øÖÆºÍÊ®½øÖÆ£©
			unsigned long long addrValue = 0;
			const char* addrStr = params[0].c_str();

			// ³¢ÊÔ½âÎöÊ®Áù½øÖÆ£¨0xÇ°×º£©»òÊ®½øÖÆ
			char* endPtr = nullptr;
			if (params[0].substr(0, 2) == "0x")
			{
				addrValue = strtoull(addrStr, &endPtr, 16);
			}
			else
			{
				addrValue = strtoull(addrStr, &endPtr, 10);
			}

			// ÑéÖ¤µØÖ·½âÎö½á¹û
			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", addrStr);
				return response;
			}

			// µ÷ÓÃÉèÖÃ¶ÏµãµÄºËÐÄº¯Êý
#ifdef _WIN64
			BOOL isSet = Script::Debug::SetBreakpoint(addrValue);
#else
			BOOL isSet = Script::Debug::SetBreakpoint(static_cast<duint>(addrValue));
#endif

			// ¸ñÊ½»¯µØÖ·×Ö·û´®ÓÃÓÚÏìÓ¦
			std::string formattedAddr = format_address(addrValue);

			if (isSet)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Breakpoint set successfully");
				cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
				cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set breakpoint");
				cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
				cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
			}
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "An unexpected error occurred while setting breakpoint");
		}

		return response;
	}

	// È¡Ïû¶Ïµã´¦Àí·½·¨
	static ResponseData handle_delete_break_point(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£ºÐèÒªÒ»¸öµØÖ·²ÎÊý
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing address parameter for Debugger.DeleteBreakPoint");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only address is expected");
			return response;
		}

		try
		{
			// ½âÎöµØÖ·²ÎÊý£¨Ö§³ÖÊ®Áù½øÖÆºÍÊ®½øÖÆ£©
			unsigned long long addrValue = 0;
			const char* addrStr = params[0].c_str();
			char* endPtr = nullptr;

			if (params[0].substr(0, 2) == "0x")
			{
				addrValue = strtoull(addrStr, &endPtr, 16);
			}
			else
			{
				addrValue = strtoull(addrStr, &endPtr, 10);
			}

			// ÑéÖ¤µØÖ·½âÎö½á¹û
			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", addrStr);
				return response;
			}

			// µ÷ÓÃÉ¾³ý¶ÏµãµÄºËÐÄº¯Êý
#ifdef _WIN64
			BOOL isDeleted = Script::Debug::DeleteBreakpoint(addrValue);
#else
			BOOL isDeleted = Script::Debug::DeleteBreakpoint(static_cast<duint>(addrValue));
#endif

			// ¸ñÊ½»¯µØÖ·×Ö·û´®
			std::string formattedAddr = format_address(addrValue);

			if (isDeleted)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Breakpoint deleted successfully");
				cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
				cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to delete breakpoint (may not exist)");
				cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
				cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
			}
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "An unexpected error occurred while deleting breakpoint");
		}

		return response;
	}

	// ¼ì²é¶ÏµãÊÇ·ñ±»ÃüÖÐ´¦Àí·½·¨
	static ResponseData handle_check_break_point(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£ºÐèÒªÒ»¸öµØÖ·²ÎÊý
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing address parameter for Debugger.CheckBreakPoint");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only address is expected");
			return response;
		}

		try
		{
			// ½âÎöµØÖ·²ÎÊý
			unsigned long long targetAddr = 0;
			const char* addrStr = params[0].c_str();
			char* endPtr = nullptr;

			if (params[0].substr(0, 2) == "0x")
			{
				targetAddr = strtoull(addrStr, &endPtr, 16);
			}
			else
			{
				targetAddr = strtoull(addrStr, &endPtr, 10);
			}

			// ÑéÖ¤µØÖ·½âÎö½á¹û
			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", addrStr);
				return response;
			}

			// »ñÈ¡µ±Ç°Ö¸ÁîÖ¸Õë¼Ä´æÆ÷Öµ£¨Çø·Ö32/64Î»£©
#ifdef _WIN64
			unsigned long long currentEip = Script::Register::GetRIP();  // 64Î»Ê¹ÓÃRIP
#else
			unsigned long long currentEip = Script::Register::GetEIP();  // 32Î»Ê¹ÓÃEIP
#endif

			// ÅÐ¶ÏÊÇ·ñÃüÖÐ¶Ïµã£¨µ±Ç°EIPµÈÓÚÄ¿±êµØÖ·£©
			bool isHit = (currentEip == targetAddr);

			// ¸ñÊ½»¯µØÖ·×Ö·û´®
			std::string formattedTargetAddr = format_address(targetAddr);
			std::string formattedCurrentEip = format_address(currentEip);

			// ¹¹½¨ÏìÓ¦Êý¾Ý
			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_hit", isHit);
			cJSON_AddStringToObject(response.result.get(), "message", isHit ? "Breakpoint is hit" : "Breakpoint not hit");
			cJSON_AddStringToObject(response.result.get(), "target_address", formattedTargetAddr.c_str());
			cJSON_AddNumberToObject(response.result.get(), "target_address_value", targetAddr);
			cJSON_AddStringToObject(response.result.get(), "current_eip", formattedCurrentEip.c_str());
			cJSON_AddNumberToObject(response.result.get(), "current_eip_value", currentEip);
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "An unexpected error occurred while checking breakpoint");
		}

		return response;
	}

	// 1. ¼ì²é¶ÏµãÊÇ·ñ±»½ûÓÃ£¨Debugger.CheckBreakDisable£©
	static ResponseData handle_check_break_disable(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£º½öÐè 1 ¸öµØÖ·²ÎÊý
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing address parameter for Debugger.CheckBreakDisable");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only address is expected");
			return response;
		}

		try
		{
			// ½âÎöµØÖ·£¨Ö§³ÖÊ®Áù½øÖÆ"0xÇ°×º"ºÍÊ®½øÖÆ£©
			unsigned long long addrValue = 0;
			const char* addrStr = params[0].c_str();
			char* endPtr = nullptr;

			if (params[0].substr(0, 2) == "0x")
			{
				addrValue = strtoull(addrStr, &endPtr, 16); // Ê®Áù½øÖÆ½âÎö
			}
			else
			{
				addrValue = strtoull(addrStr, &endPtr, 10); // Ê®½øÖÆ½âÎö
			}

			// Ð£ÑéµØÖ·½âÎöÓÐÐ§ÐÔ£¨±ÜÃâ²¿·Ö½âÎö»òÎÞÐ§×Ö·û£©
			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", addrStr);
				return response;
			}

			// µ÷ÓÃ x64dbg ½Ó¿Ú¼ì²é¶Ïµã½ûÓÃ×´Ì¬£¨DbgIsBpDisabled ÒªÇó duint ÀàÐÍ£©
			BOOL isDisabled = DbgIsBpDisabled(static_cast<duint>(addrValue));
			std::string formattedAddr = format_address(addrValue);

			// ¹¹½¨ÏìÓ¦£¨²¹³ä"ÎÞ¶Ïµã"µÄÌáÊ¾£¬±ÜÃâÆçÒå£©
			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_disabled", isDisabled != 0);
			cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
			cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
			cJSON_AddStringToObject(response.result.get(), "hint", "False = breakpoint is enabled OR no breakpoint exists at this address");
			cJSON_AddStringToObject(response.result.get(), "message",
				isDisabled ? "Breakpoint is disabled" : "Breakpoint is enabled or not exists");
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while checking breakpoint disable status");
		}

		return response;
	}

	// 2. »ñÈ¡Ö¸¶¨µØÖ·µÄ¶ÏµãÀàÐÍ£¨Debugger.CheckBreakPointType£©
	static ResponseData handle_check_break_point_type(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£º½öÐè 1 ¸öµØÖ·²ÎÊý
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing address parameter for Debugger.CheckBreakPointType");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only address is expected");
			return response;
		}

		try
		{
			// ½âÎöµØÖ·
			unsigned long long addrValue = 0;
			const char* addrStr = params[0].c_str();
			char* endPtr = nullptr;

			addrValue = (params[0].substr(0, 2) == "0x")
				? strtoull(addrStr, &endPtr, 16)
				: strtoull(addrStr, &endPtr, 10);

			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", addrStr);
				return response;
			}

			// µ÷ÓÃ x64dbg ½Ó¿Ú»ñÈ¡¶ÏµãÀàÐÍ£¨Çø·Ö 32/64 Î»£©
#ifdef _WIN64
			unsigned long long bpType = static_cast<unsigned long long>(
				DbgGetBpxTypeAt(static_cast<duint>(addrValue))
				);
#else
			duint bpType = DbgGetBpxTypeAt(static_cast<duint>(addrValue));
#endif

			std::string formattedAddr = format_address(addrValue);
			std::string typeDesc; // ¶ÏµãÀàÐÍÃèÊö£¨ÔöÇ¿¿É¶ÁÐÔ£©

			// Ó³Éä x64dbg BPXTYPE Ã¶¾Ùµ½ÎÄ×ÖÃèÊö
			switch (static_cast<BPXTYPE>(bpType))
			{
			case BPXTYPE::bp_normal:
				typeDesc = "Software Breakpoint (INT3)"; // Èí¼þ¶ÏµãÍ¨³£¶ÔÓ¦ bp_normal
				break;
			case BPXTYPE::bp_hardware:
				// Ó²¼þ¶ÏµãÀàÐÍÏ¸·Ö¿É½áºÏ HardwareType£¨ÈçÖ´ÐÐ/Ð´Èë/·ÃÎÊ£©
				typeDesc = "Hardware Breakpoint";
				break;
			case BPXTYPE::bp_memory:
				typeDesc = "Memory Page Breakpoint"; // ÄÚ´æ¶Ïµã¶ÔÓ¦ bp_memory
				break;
			case BPXTYPE::bp_dll:
				typeDesc = "DLL Breakpoint"; // DLL Ïà¹Ø¶Ïµã
				break;
			case BPXTYPE::bp_exception:
				typeDesc = "Exception Breakpoint"; // Òì³£¶Ïµã
				break;
			case BPXTYPE::bp_none:
				typeDesc = "No Breakpoint"; // ÎÞ¶Ïµã
				break;
			default:
				typeDesc = "Unknown Breakpoint Type";
				break;
			}

			// ¹¹½¨ÏìÓ¦
			response.success = true;
			cJSON_AddNumberToObject(response.result.get(), "breakpoint_type_value", bpType);
			cJSON_AddStringToObject(response.result.get(), "breakpoint_type_desc", typeDesc.c_str());
			cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
			cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
			cJSON_AddStringToObject(response.result.get(), "message",
				bpType != 0 ? "Breakpoint type retrieved successfully" : "No breakpoint exists at this address");
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving breakpoint type");
		}

		return response;
	}

	// 3. ÉèÖÃÓ²¼þ¶Ïµã£¨Debugger.SetHardwareBreakPoint£©
	static ResponseData handle_set_hardware_break_point(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£ºÐè 2 ¸ö²ÎÊý£¨µØÖ· + ÀàÐÍ£º0=Access, 1=Write, 2=Execute£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [address] [breakpoint_type(0=Access,1=Write,2=Execute)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// ½âÎöµÚ 1 ¸ö²ÎÊý£ºÄ¿±êµØÖ·
			unsigned long long addrValue = 0;
			const char* addrStr = params[0].c_str();
			char* endPtr = nullptr;

			addrValue = (params[0].substr(0, 2) == "0x")
				? strtoull(addrStr, &endPtr, 16)
				: strtoull(addrStr, &endPtr, 10);

			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addrStr);
				return response;
			}

			// ½âÎöµÚ 2 ¸ö²ÎÊý£ºÓ²¼þ¶ÏµãÀàÐÍ£¨±ØÐëÊÇ 0/1/2£©
			int typeValue = -1;
			try
			{
				typeValue = std::stoi(params[1]); // ×ª»»ÎªÕûÊý
			}
			catch (const std::invalid_argument&)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid breakpoint type. Must be integer (0=Access,1=Write,2=Execute)");
				cJSON_AddStringToObject(response.result.get(), "invalid_type", params[1].c_str());
				return response;
			}
			catch (const std::out_of_range&)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Breakpoint type out of integer range");
				cJSON_AddStringToObject(response.result.get(), "invalid_type", params[1].c_str());
				return response;
			}

			// Ð£ÑéÀàÐÍ·¶Î§
			if (typeValue < 0 || typeValue > 2)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Breakpoint type out of range. Allowed values: 0(Access), 1(Write), 2(Execute)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_type_value", typeValue);
				return response;
			}

			// Ó³ÉäÀàÐÍÖµµ½ Script::Debug Ó²¼þ¶ÏµãÃ¶¾Ù
			Script::Debug::HardwareType hwType = Script::Debug::HardwareExecute; // ³õÊ¼»¯Ä¬ÈÏÖµ
			std::string typeDesc;
			// 2. Ê¹ÓÃÃ¶¾ÙÖµÖ±½ÓÓ³Éä£¬±ÜÃâÄ§·¨Êý×Ö£¬ÔöÇ¿¿É¶ÁÐÔ
			switch (typeValue)
			{
			case static_cast<int>(Script::Debug::HardwareAccess) :
				hwType = Script::Debug::HardwareAccess;
				typeDesc = "Hardware Access (Read/Write)";
				break;
			case static_cast<int>(Script::Debug::HardwareWrite) :
				hwType = Script::Debug::HardwareWrite;
				typeDesc = "Hardware Write";
				break;
			case static_cast<int>(Script::Debug::HardwareExecute) :
				hwType = Script::Debug::HardwareExecute;
				typeDesc = "Hardware Execute";
				break;
			default:
				// 3. ÔöÇ¿Ä¬ÈÏÇé¿öµÄ½¡×³ÐÔ£ºÌí¼ÓÈÕÖ¾ÌáÊ¾Î´ÖªÀàÐÍ£¬±ãÓÚµ÷ÊÔ
				typeDesc = "Unknown Hardware Breakpoint Type (value: " + std::to_string(typeValue) + ")";
				// ¿É¸ù¾ÝÊµ¼ÊÐèÇóÌí¼ÓÈÕÖ¾Êä³ö£¬ÀýÈç£º
				// _plugin_logprintf("Warning: Unknown hardware breakpoint type value: %d\n", typeValue);
				break;
			}

			// µ÷ÓÃ x64dbg ½Ó¿ÚÉèÖÃÓ²¼þ¶Ïµã
			BOOL isSet = Script::Debug::SetHardwareBreakpoint(
				static_cast<duint>(addrValue),
				hwType
				);

			std::string formattedAddr = format_address(addrValue);

			// ¹¹½¨ÏìÓ¦
			if (isSet)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Hardware breakpoint set successfully");
				cJSON_AddStringToObject(response.result.get(), "breakpoint_type", typeDesc.c_str());
				cJSON_AddNumberToObject(response.result.get(), "breakpoint_type_value", typeValue);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set hardware breakpoint (may exceed hw breakpoint limit or invalid address)");
				cJSON_AddStringToObject(response.result.get(), "breakpoint_type", typeDesc.c_str());
				cJSON_AddNumberToObject(response.result.get(), "breakpoint_type_value", typeValue);
			}
			cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
			cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting hardware breakpoint");
		}

		return response;
	}

	// 4. È¡ÏûÓ²¼þ¶Ïµã£¨Debugger.DeleteHardwareBreakPoint£©
	static ResponseData handle_delete_hardware_break_point(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ÑéÖ¤²ÎÊý£º½öÐè 1 ¸öµØÖ·²ÎÊý
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing address parameter for Debugger.DeleteHardwareBreakPoint");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only address is expected");
			return response;
		}

		try
		{
			// ½âÎöµØÖ·
			unsigned long long addrValue = 0;
			const char* addrStr = params[0].c_str();
			char* endPtr = nullptr;

			addrValue = (params[0].substr(0, 2) == "0x")
				? strtoull(addrStr, &endPtr, 16)
				: strtoull(addrStr, &endPtr, 10);

			if (endPtr == addrStr || *endPtr != '\0')
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", addrStr);
				return response;
			}

			// µ÷ÓÃ x64dbg ½Ó¿ÚÈ¡ÏûÓ²¼þ¶Ïµã
			BOOL isDeleted = Script::Debug::DeleteHardwareBreakpoint(
				static_cast<duint>(addrValue)
				);

			std::string formattedAddr = format_address(addrValue);

			// ¹¹½¨ÏìÓ¦
			if (isDeleted)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Hardware breakpoint deleted successfully");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to delete hardware breakpoint (may not exist at this address)");
			}
			cJSON_AddStringToObject(response.result.get(), "address", formattedAddr.c_str());
			cJSON_AddNumberToObject(response.result.get(), "address_value", addrValue);
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while deleting hardware breakpoint");
		}

		return response;
	}

	// ´¦Àí¼Ä´æÆ÷»ñÈ¡ÇëÇó£¨Debugger.GetRegister£©
	static ResponseData handle_get_register(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨¼Ä´æÆ÷Ãû£¬Èç"EAX"¡¢"RAX"£©
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameter: register name (e.g., EAX, RAX)");
			cJSON_AddStringToObject(response.result.get(), "hint", "Supported registers: DR0-DR7, EAX/RAX, EBX/RBX, ... (case-sensitive)");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only register name is expected");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string register_name = params[0];
		// Ð£Ñé¼Ä´æÆ÷Ãû·Ç¿Õ
		if (register_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Register name cannot be empty");
			return response;
		}

		try
		{
			// 2. »ñÈ¡¼Ä´æÆ÷Ë÷Òý£¨µ÷ÓÃ¸¨Öúº¯Êý£©
			int register_id = get_register_index(register_name);
			if (register_id == -1)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid register name");
				cJSON_AddStringToObject(response.result.get(), "invalid_register", register_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "hint", "Register names are case-sensitive (e.g., use 'EAX' not 'eax')");
				return response;
			}

			// 3. µ÷ÓÃx64dbg½Ó¿Ú»ñÈ¡¼Ä´æÆ÷Öµ£¨Çø·Ö32/64Î»ÀàÐÍ£©
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::Get(
				static_cast<Script::Register::RegisterEnum>(register_id)
				);
#else
			duint reg_value = Script::Register::Get(
				static_cast<Script::Register::RegisterEnum>(register_id)
				);
#endif

			// 4. ¸ñÊ½»¯¼Ä´æÆ÷Öµ£¨Ê®Áù½øÖÆ×Ö·û´®£¬±ãÓÚÔÄ¶Á£©
			std::string formatted_value = format_address(reg_value); // ¸´ÓÃÖ®Ç°µÄµØÖ·¸ñÊ½»¯º¯Êý

			// 5. ¹¹½¨ÏìÓ¦JSON£¨°üº¬ÍêÕûµÄ¼Ä´æÆ÷ÐÅÏ¢£©
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", register_name.c_str());
			cJSON_AddNumberToObject(response.result.get(), "register_index", register_id);
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value); // Ê®½øÖÆÊýÖµ
			cJSON_AddStringToObject(response.result.get(), "value_hex", formatted_value.c_str()); // Ê®Áù½øÖÆ×Ö·û´®
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			// ²¶»ñÎ´ÖªÒì³££¬±ÜÃâ²å¼þ±ÀÀ£
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving register value");
			cJSON_AddStringToObject(response.result.get(), "register_name", register_name.c_str());
		}

		return response;
	}

	// ¸¨Öúº¯Êý£ºµØÖ·¸ñÊ½»¯£¨¸´ÓÃÖ®Ç°¶¨Òå£¬È·±£ÊýÖµÏÔÊ¾Ò»ÖÂ£©
	static std::string format_address(unsigned long long address)
	{
		char buffer[32];
#ifdef _WIN64
		sprintf_s(buffer, sizeof(buffer), "0x%016llX", address);
#else
		sprintf_s(buffer, sizeof(buffer), "0x%08X", (unsigned int)address);
#endif
		return std::string(buffer);
	}

	// ------------------------------
	// 1. Í¨ÓÃ¼Ä´æÆ÷£¨EAX/AX/AH/AL µÈ£©
	// ------------------------------
	// »ñÈ¡ EAX ¼Ä´æÆ÷
	static ResponseData handle_get_eax(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetEAX");
			return response;
		}

		try
		{
			// »ñÈ¡¼Ä´æÆ÷Öµ£¨Çø·Ö32/64Î»£©
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetEAX();
#else
			duint reg_value = Script::Register::GetEAX();
#endif

			// ¹¹½¨ÏìÓ¦
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "EAX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving EAX value");
		}

		return response;
	}

	// »ñÈ¡ AX ¼Ä´æÆ÷
	static ResponseData handle_get_ax(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetAX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetAX();
#else
			duint reg_value = Script::Register::GetAX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "AX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving AX value");
		}

		return response;
	}

	// »ñÈ¡ AH ¼Ä´æÆ÷
	static ResponseData handle_get_ah(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetAH");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetAH();
#else
			duint reg_value = Script::Register::GetAH();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "AH");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving AH value");
		}

		return response;
	}

	// »ñÈ¡ AL ¼Ä´æÆ÷
	static ResponseData handle_get_al(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetAL");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetAL();
#else
			duint reg_value = Script::Register::GetAL();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "AL");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving AL value");
		}

		return response;
	}

	// »ñÈ¡ EBX ¼Ä´æÆ÷
	static ResponseData handle_get_ebx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetEBX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetEBX();
#else
			duint reg_value = Script::Register::GetEBX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "EBX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving EBX value");
		}

		return response;
	}

	// »ñÈ¡ BX ¼Ä´æÆ÷
	static ResponseData handle_get_bx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetBX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetBX();
#else
			duint reg_value = Script::Register::GetBX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "BX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving BX value");
		}

		return response;
	}

	// »ñÈ¡ BH ¼Ä´æÆ÷
	static ResponseData handle_get_bh(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetBH");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetBH();
#else
			duint reg_value = Script::Register::GetBH();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "BH");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving BH value");
		}

		return response;
	}

	// »ñÈ¡ BL ¼Ä´æÆ÷
	static ResponseData handle_get_bl(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetBL");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetBL();
#else
			duint reg_value = Script::Register::GetBL();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "BL");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving BL value");
		}

		return response;
	}

	// »ñÈ¡ ECX ¼Ä´æÆ÷
	static ResponseData handle_get_ecx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetECX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetECX();
#else
			duint reg_value = Script::Register::GetECX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "ECX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving ECX value");
		}

		return response;
	}

	// »ñÈ¡ CX ¼Ä´æÆ÷
	static ResponseData handle_get_cx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCX();
#else
			duint reg_value = Script::Register::GetCX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CX value");
		}

		return response;
	}

	// »ñÈ¡ CH ¼Ä´æÆ÷
	static ResponseData handle_get_ch(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCH");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCH();
#else
			duint reg_value = Script::Register::GetCH();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CH");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CH value");
		}

		return response;
	}

	// »ñÈ¡ CL ¼Ä´æÆ÷
	static ResponseData handle_get_cl(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCL");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCL();
#else
			duint reg_value = Script::Register::GetCL();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CL");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CL value");
		}

		return response;
	}

	// »ñÈ¡ EDX ¼Ä´æÆ÷
	static ResponseData handle_get_edx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetEDX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetEDX();
#else
			duint reg_value = Script::Register::GetEDX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "EDX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving EDX value");
		}

		return response;
	}

	// »ñÈ¡ DX ¼Ä´æÆ÷
	static ResponseData handle_get_dx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDX();
#else
			duint reg_value = Script::Register::GetDX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DX value");
		}

		return response;
	}

	// »ñÈ¡ DH ¼Ä´æÆ÷
	static ResponseData handle_get_dh(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDH");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDH();
#else
			duint reg_value = Script::Register::GetDH();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DH");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DH value");
		}

		return response;
	}

	// »ñÈ¡ DL ¼Ä´æÆ÷
	static ResponseData handle_get_dl(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDL");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDL();
#else
			duint reg_value = Script::Register::GetDL();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DL");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DL value");
		}

		return response;
	}

	// ------------------------------
	// 2. Ë÷Òý/»ùÖ·¼Ä´æÆ÷£¨EDI/DI/ESI/SI µÈ£©
	// ------------------------------
	// »ñÈ¡ EDI ¼Ä´æÆ÷
	static ResponseData handle_get_edi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetEDI");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetEDI();
#else
			duint reg_value = Script::Register::GetEDI();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "EDI");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving EDI value");
		}

		return response;
	}

	// »ñÈ¡ DI ¼Ä´æÆ÷
	static ResponseData handle_get_di(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDI");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDI();
#else
			duint reg_value = Script::Register::GetDI();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DI");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DI value");
		}

		return response;
	}

	// »ñÈ¡ ESI ¼Ä´æÆ÷
	static ResponseData handle_get_esi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetESI");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetESI();
#else
			duint reg_value = Script::Register::GetESI();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "ESI");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving ESI value");
		}

		return response;
	}

	// »ñÈ¡ SI ¼Ä´æÆ÷
	static ResponseData handle_get_si(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetSI");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetSI();
#else
			duint reg_value = Script::Register::GetSI();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "SI");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving SI value");
		}

		return response;
	}

	// »ñÈ¡ EBP ¼Ä´æÆ÷
	static ResponseData handle_get_ebp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetEBP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetEBP();
#else
			duint reg_value = Script::Register::GetEBP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "EBP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving EBP value");
		}

		return response;
	}

	// »ñÈ¡ BP ¼Ä´æÆ÷
	static ResponseData handle_get_bp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetBP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetBP();
#else
			duint reg_value = Script::Register::GetBP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "BP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving BP value");
		}

		return response;
	}

	// »ñÈ¡ ESP ¼Ä´æÆ÷
	static ResponseData handle_get_esp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetESP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetESP();
#else
			duint reg_value = Script::Register::GetESP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "ESP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving ESP value");
		}

		return response;
	}

	// »ñÈ¡ SP ¼Ä´æÆ÷
	static ResponseData handle_get_sp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetSP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetSP();
#else
			duint reg_value = Script::Register::GetSP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "SP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving SP value");
		}

		return response;
	}

	// »ñÈ¡ EIP ¼Ä´æÆ÷
	static ResponseData handle_get_eip(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetEIP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetEIP();
#else
			duint reg_value = Script::Register::GetEIP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "EIP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving EIP value");
		}

		return response;
	}

	// ------------------------------
	// 3. µ÷ÊÔ¼Ä´æÆ÷£¨DR0-DR7£©
	// ------------------------------
	// »ñÈ¡ DR0 ¼Ä´æÆ÷
	static ResponseData handle_get_dr0(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDR0");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDR0();
#else
			duint reg_value = Script::Register::GetDR0();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DR0");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DR0 value");
		}

		return response;
	}

	// »ñÈ¡ DR1 ¼Ä´æÆ÷
	static ResponseData handle_get_dr1(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDR1");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDR1();
#else
			duint reg_value = Script::Register::GetDR1();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DR1");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DR1 value");
		}

		return response;
	}

	// »ñÈ¡ DR2 ¼Ä´æÆ÷
	static ResponseData handle_get_dr2(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDR2");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDR2();
#else
			duint reg_value = Script::Register::GetDR2();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DR2");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DR2 value");
		}

		return response;
	}

	// »ñÈ¡ DR3 ¼Ä´æÆ÷
	static ResponseData handle_get_dr3(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDR3");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDR3();
#else
			duint reg_value = Script::Register::GetDR3();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DR3");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DR3 value");
		}

		return response;
	}

	// »ñÈ¡ DR6 ¼Ä´æÆ÷
	static ResponseData handle_get_dr6(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDR6");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDR6();
#else
			duint reg_value = Script::Register::GetDR6();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DR6");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DR6 value");
		}

		return response;
	}

	// »ñÈ¡ DR7 ¼Ä´æÆ÷
	static ResponseData handle_get_dr7(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDR7");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetDR7();
#else
			duint reg_value = Script::Register::GetDR7();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "Register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "DR7");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DR7 value");
		}

		return response;
	}

	// »ñÈ¡ CAX ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_cax(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCAX");
			return response;
		}

		try
		{
			// »ñÈ¡¼Ä´æÆ÷Öµ£¨Çø·Ö32/64Î»£©
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCAX();
#else
			duint reg_value = Script::Register::GetCAX();
#endif

			// ¹¹½¨ÏìÓ¦
			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CAX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CAX value");
		}

		return response;
	}

	// »ñÈ¡ CBX ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_cbx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCBX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCBX();
#else
			duint reg_value = Script::Register::GetCBX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CBX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CBX value");
		}

		return response;
	}

	// »ñÈ¡ CCX ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_ccx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCCX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCCX();
#else
			duint reg_value = Script::Register::GetCCX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CCX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CCX value");
		}

		return response;
	}

	// »ñÈ¡ CDX ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_cdx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCDX");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCDX();
#else
			duint reg_value = Script::Register::GetCDX();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CDX");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CDX value");
		}

		return response;
	}

	// »ñÈ¡ CSI ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_csi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCSI");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCSI();
#else
			duint reg_value = Script::Register::GetCSI();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CSI");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CSI value");
		}

		return response;
	}

	// »ñÈ¡ CDI ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_cdi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCDI");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCDI();
#else
			duint reg_value = Script::Register::GetCDI();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CDI");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CDI value");
		}

		return response;
	}

	// »ñÈ¡ CBP ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_cbp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCBP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCBP();
#else
			duint reg_value = Script::Register::GetCBP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CBP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CBP value");
		}

		return response;
	}

	// »ñÈ¡ CSP ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_csp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCSP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCSP();
#else
			duint reg_value = Script::Register::GetCSP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CSP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CSP value");
		}

		return response;
	}

	// »ñÈ¡ CIP ¼Ä´æÆ÷£¨CFÏµÁÐ£©
	static ResponseData handle_get_cip(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCIP");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCIP();
#else
			duint reg_value = Script::Register::GetCIP();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CIP");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CIP value");
		}

		return response;
	}

	// »ñÈ¡ CFLAGS ¼Ä´æÆ÷£¨CFÏµÁÐ£¬±êÖ¾¼Ä´æÆ÷¼¯ºÏ£©
	static ResponseData handle_get_cflags(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCFLAGS");
			return response;
		}

		try
		{
#ifdef _WIN64
			unsigned long long reg_value = Script::Register::GetCFLAGS();
#else
			duint reg_value = Script::Register::GetCFLAGS();
#endif

			response.success = true;
			cJSON_AddStringToObject(response.result.get(), "message", "CF-series CFLAGS register value retrieved successfully");
			cJSON_AddStringToObject(response.result.get(), "register_name", "CFLAGS");
			cJSON_AddNumberToObject(response.result.get(), "value_decimal", reg_value);
			cJSON_AddStringToObject(response.result.get(), "value_hex", format_address(reg_value).c_str());
			cJSON_AddStringToObject(response.result.get(), "register_type", "CF-series (context-specific flag collection)");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CFLAGS value");
		}

		return response;
	}


	// »ñÈ¡ ZF£¨Áã±êÖ¾£©
	static ResponseData handle_get_zf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetZF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetZF(); // ²¼¶û×´Ì¬£ºÖÃÎ»=true£¬Î´ÖÃÎ»=false

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "ZF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("ZF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Zero Flag (ZF) is set" : "Zero Flag (ZF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving ZF flag");
		}

		return response;
	}

	// »ñÈ¡ OF£¨Òç³ö±êÖ¾£©
	static ResponseData handle_get_of(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetOF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetOF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "OF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("OF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Overflow Flag (OF) is set" : "Overflow Flag (OF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving OF flag");
		}

		return response;
	}

	// »ñÈ¡ CF£¨½øÎ»±êÖ¾£©
	static ResponseData handle_get_cf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetCF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetCF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "CF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("CF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Carry Flag (CF) is set" : "Carry Flag (CF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving CF flag");
		}

		return response;
	}

	// »ñÈ¡ PF£¨ÆæÅ¼±êÖ¾£©
	static ResponseData handle_get_pf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetPF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetPF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "PF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("PF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Parity Flag (PF) is set" : "Parity Flag (PF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving PF flag");
		}

		return response;
	}

	// »ñÈ¡ SF£¨·ûºÅ±êÖ¾£©
	static ResponseData handle_get_sf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetSF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetSF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "SF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("SF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Sign Flag (SF) is set" : "Sign Flag (SF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving SF flag");
		}

		return response;
	}

	// »ñÈ¡ TF£¨ÏÝÚå±êÖ¾£©
	static ResponseData handle_get_tf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetTF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetTF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "TF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("TF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Trap Flag (TF) is set" : "Trap Flag (TF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving TF flag");
		}

		return response;
	}

	// »ñÈ¡ AF£¨¸¨Öú½øÎ»±êÖ¾£©
	static ResponseData handle_get_af(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetAF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetAF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "AF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("AF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Auxiliary Carry Flag (AF) is set" : "Auxiliary Carry Flag (AF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving AF flag");
		}

		return response;
	}

	// »ñÈ¡ DF£¨·½Ïò±êÖ¾£©
	static ResponseData handle_get_df(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetDF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetDF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "DF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("DF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Direction Flag (DF) is set" : "Direction Flag (DF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving DF flag");
		}

		return response;
	}

	// »ñÈ¡ IF£¨ÖÐ¶Ï±êÖ¾£©
	static ResponseData handle_get_if(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters expected for Debugger.GetIF");
			return response;
		}

		try
		{
			BOOL isSet = Script::Flag::GetIF();

			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", "IF");
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description("IF").c_str());
			cJSON_AddStringToObject(response.result.get(), "message", isSet ? "Interrupt Flag (IF) is set" : "Interrupt Flag (IF) is not set");
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving IF flag");
		}

		return response;
	}

	// Í¨ÓÃ±êÖ¾¼Ä´æÆ÷»ñÈ¡£¨°´±êÖ¾Ãû²éÑ¯£¬Èç"ZF"¡¢"CF"£©
	static ResponseData handle_get_flag_register(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ²ÎÊýÐ£Ñé£ºÐè1¸ö²ÎÊý£¨±êÖ¾Ãû£¬Èç"ZF"£©
		if (params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Missing parameter: flag name (e.g., ZF, CF)");
			cJSON_AddStringToObject(response.result.get(), "supported_flags", "ZF, OF, CF, PF, SF, TF, AF, DF, IF (case-sensitive)");
			return response;
		}
		if (params.size() > 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Too many parameters. Only flag name is expected");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string flag_name = params[0];
		if (flag_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Flag name cannot be empty");
			return response;
		}

		try
		{
			// Ó³Éä±êÖ¾Ãûµ½Ë÷Òý
			int flag_index = get_flag_index(flag_name);
			if (flag_index == -1)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid flag name");
				cJSON_AddStringToObject(response.result.get(), "invalid_flag", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "supported_flags", "ZF, OF, CF, PF, SF, TF, AF, DF, IF (case-sensitive)");
				return response;
			}

			// »ñÈ¡±êÖ¾×´Ì¬
			BOOL isSet = Script::Flag::Get(static_cast<Script::Flag::FlagEnum>(flag_index));

			// ¹¹½¨ÏìÓ¦
			response.success = true;
			cJSON_AddBoolToObject(response.result.get(), "is_set", isSet != 0);
			cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
			cJSON_AddNumberToObject(response.result.get(), "flag_index", flag_index);
			cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
			// ¹Ø¼üÐÞ¸Ä£ºÔÚ×Ö·û´®Æ´½Ó½á¹ûºóÌí¼Ó .c_str() ×ª»»ÎªC·ç¸ñ×Ö·û´®
			cJSON_AddStringToObject(
				response.result.get(), 
				"message",
				(isSet ? (flag_name + " flag is set") : (flag_name + " flag is not set")).c_str()
				);
#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving flag status");
			cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
		}

		return response;
	}


	// Í¨ÓÃ¼Ä´æÆ÷ÉèÖÃ£¨Debugger.SetRegister£©
	static ResponseData handle_set_register(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨¼Ä´æÆ÷Ãû + ÉèÖÃÖµ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [register_name] [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Set EAX to 0x1234: [\"EAX\", \"0x1234\"]");
			return response;
		}

		const std::string reg_name = params[0];
		const std::string value_str = params[1];

		// Ð£Ñé¼Ä´æÆ÷Ãû·Ç¿Õ
		if (reg_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Register name cannot be empty");
			return response;
		}

		try
		{
			// 2. ½âÎöÉèÖÃÖµ£¨Ö§³ÖÊ®Áù½øÖÆ0xÇ°×º/Ê®½øÖÆ£©
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 3. Ó³Éä¼Ä´æÆ÷Ãûµ½Ë÷Òý
			int reg_index = get_register_index(reg_name);
			if (reg_index == -1)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid register name");
				cJSON_AddStringToObject(response.result.get(), "invalid_register", reg_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "hint", "Register names are case-sensitive (e.g., use 'EAX' not 'eax')");
				return response;
			}

			// 4. µ÷ÓÃx64dbg½Ó¿ÚÉèÖÃ¼Ä´æÆ÷Öµ£¨Çø·Ö32/64Î»ÀàÐÍ£©
			BOOL set_success = FALSE;
#ifdef _WIN64
			set_success = Script::Register::Set(
				static_cast<Script::Register::RegisterEnum>(reg_index),
				set_value // 64Î»Ö±½ÓÊ¹ÓÃunsigned long long
				);
#else
			set_success = Script::Register::Set(
				static_cast<Script::Register::RegisterEnum>(reg_index),
				static_cast<duint>(set_value) // 32Î»×ª»»Îªduint
				);
#endif

			// 5. ¸ñÊ½»¯ÖµÓÃÓÚÏìÓ¦
			std::string formatted_value = format_value(set_value);

			// 6. ¹¹½¨ÏìÓ¦
			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Register value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", reg_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "register_index", reg_index);
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set register value (may be read-only or invalid index)");
				cJSON_AddStringToObject(response.result.get(), "register_name", reg_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "register_index", reg_index);
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting register value");
			cJSON_AddStringToObject(response.result.get(), "register_name", reg_name.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// ÌØ¶¨¼Ä´æÆ÷ÉèÖÃ£ºEAX/AX/AH/AL
	// ------------------------------
	// ÉèÖÃ EAX ¼Ä´æÆ÷£¨32/64Î»Í¨ÓÃ£¬ÖµÎÞÎ»¿íÏÞÖÆ£©
	static ResponseData handle_set_eax(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸öÉèÖÃÖµ
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			// 2. ½âÎöÉèÖÃÖµ
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃx64dbg½Ó¿ÚÉèÖÃEAX£¨Çø·Ö32/64Î»ÀàÐÍ£©
			BOOL set_success = FALSE;
#ifdef _WIN64
			set_success = Script::Register::SetEAX(set_value);
#else
			set_success = Script::Register::SetEAX(static_cast<duint>(set_value));
#endif

			// 4. ¸ñÊ½»¯Öµ
			std::string formatted_value = format_value(set_value);

			// 5. ¹¹½¨ÏìÓ¦
			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "EAX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "EAX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set EAX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting EAX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ AX ¼Ä´æÆ÷£¨16Î»£¬Öµ·¶Î§£º0~65535£©
	static ResponseData handle_set_ax(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// Ð£Ñé16Î»¼Ä´æÆ÷Öµ·¶Î§£¨0~65535£©
			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetAX(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "AX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "AX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set AX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting AX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ AH ¼Ä´æÆ÷£¨8Î»£¬Öµ·¶Î§£º0~255£©
	static ResponseData handle_set_ah(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// Ð£Ñé8Î»¼Ä´æÆ÷Öµ·¶Î§£¨0~255£©
			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetAH(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "AH value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "AH");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set AH value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting AH value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ AL ¼Ä´æÆ÷£¨8Î»£¬Öµ·¶Î§£º0~255£©
	static ResponseData handle_set_al(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetAL(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "AL value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "AL");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set AL value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting AL value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// ÌØ¶¨¼Ä´æÆ÷ÉèÖÃ£ºEBX/BX/BH/BL£¨Ä£°å¸´ÓÃ£¬Âß¼­Í¬ÉÏ£©
	// ------------------------------
	static ResponseData handle_set_ebx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetEBX(set_value);
#else
			BOOL set_success = Script::Register::SetEBX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "EBX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "EBX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set EBX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting EBX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_bx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetBX(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "BX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "BX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set BX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting BX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_bh(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetBH(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "BH value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "BH");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set BH value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting BH value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_bl(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetBL(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "BL value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "BL");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set BL value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting BL value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// ÆäËûÌØ¶¨¼Ä´æÆ÷£¨ECX/CX/CH/CL¡¢EDX/DX/DH/DL µÈ£©
	// ËµÃ÷£ºÂß¼­ÓëÉÏÊö EBX/BX/BH/BL ÍêÈ«Ò»ÖÂ£¬½öÐèÐÞ¸ÄÒÔÏÂ3´¦£º
	// 1. º¯ÊýÃû£¨Èç handle_set_ecx£©£»
	// 2. ¼Ä´æÆ÷Ãû£¨Èç "ECX"£©£»
	// 3. µ÷ÓÃµÄ½Ó¿Ú£¨Èç Script::Register::SetECX£©£»
	// 4. Î»¿íÏÞÖÆ£¨Èç CX Îª16Î»£¬CH/CL Îª8Î»£©¡£
	// ÒÔÏÂ½öÊ¾Àý handle_set_ecx£¬ÆäËû¿É²Î¿¼À©Õ¹¡£
	// ------------------------------
	static ResponseData handle_set_ecx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetECX(set_value);
#else
			BOOL set_success = Script::Register::SetECX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "ECX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "ECX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set ECX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting ECX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// CX/CH/CL ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_cx(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ²ÎÊýÐ£Ñé£ºÐè1¸öÉèÖÃÖµ
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value)) // ¸´ÓÃÖ®Ç°µÄÊýÖµ½âÎöº¯Êý
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 16Î»¼Ä´æÆ÷Öµ·¶Î§¼ì²é£¨0~65535£©
			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			// µ÷ÓÃx64dbg½Ó¿ÚÉèÖÃCX
			BOOL set_success = Script::Register::SetCX(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			// ¹¹½¨ÏìÓ¦
			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_ch(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 8Î»¼Ä´æÆ÷Öµ·¶Î§¼ì²é£¨0~255£©
			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetCH(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CH value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CH");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CH value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CH value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cl(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetCL(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CL value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CL");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CL value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CL value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// EDX/DX/DH/DL ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_edx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetEDX(set_value);
#else
			BOOL set_success = Script::Register::SetEDX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "EDX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "EDX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set EDX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting EDX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetDX(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dh(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetDH(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DH value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DH");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DH value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DH value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dl(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~255)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 8-bit limit (0~255)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetDL(static_cast<unsigned char>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DL value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DL");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DL value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DL value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// EDI/DI ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_edi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetEDI(set_value);
#else
			BOOL set_success = Script::Register::SetEDI(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "EDI value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "EDI");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set EDI value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting EDI value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_di(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetDI(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DI value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DI");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DI value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DI value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// ESI/SI ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_esi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetESI(set_value);
#else
			BOOL set_success = Script::Register::SetESI(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "ESI value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "ESI");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set ESI value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting ESI value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_si(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetSI(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "SI value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "SI");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set SI value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting SI value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// EBP/BP ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_ebp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetEBP(set_value);
#else
			BOOL set_success = Script::Register::SetEBP(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "EBP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "EBP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set EBP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting EBP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_bp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetBP(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "BP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "BP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set BP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting BP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// ESP/SP ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_esp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetESP(set_value);
#else
			BOOL set_success = Script::Register::SetESP(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "ESP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "ESP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set ESP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting ESP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_sp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal, 0~65535)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			if (set_value > 0xFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 16-bit limit (0~65535)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

			BOOL set_success = Script::Register::SetSP(static_cast<unsigned short>(set_value));
			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "SP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "SP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set SP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting SP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// EIP ¼Ä´æÆ÷ÉèÖÃ
	// ------------------------------
	static ResponseData handle_set_eip(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetEIP(set_value);
#else
			BOOL set_success = Script::Register::SetEIP(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "EIP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "EIP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set EIP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting EIP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// DRµ÷ÊÔ¼Ä´æÆ÷ÉèÖÃ£¨DR0-DR3¡¢DR6-DR7£©
	// ------------------------------
	static ResponseData handle_set_dr0(const std::vector<std::string>& params)
	{
		ResponseData response;

		// ²ÎÊýÐ£Ñé£ºÐè1¸öÉèÖÃÖµ
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value)) // ¸´ÓÃÊýÖµ½âÎöº¯Êý
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// µ÷ÓÃx64dbg½Ó¿ÚÉèÖÃDR0£¨Çø·ÖÆ½Ì¨ÀàÐÍ£©
			BOOL set_success = FALSE;
#ifdef _WIN64
			set_success = Script::Register::SetDR0(set_value);
#else
			set_success = Script::Register::SetDR0(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			// ¹¹½¨ÏìÓ¦
			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DR0 value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DR0");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DR0 value (may be read-only in current context)");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DR0 value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dr1(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetDR1(set_value);
#else
			BOOL set_success = Script::Register::SetDR1(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DR1 value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DR1");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DR1 value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DR1 value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dr2(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetDR2(set_value);
#else
			BOOL set_success = Script::Register::SetDR2(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DR2 value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DR2");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DR2 value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DR2 value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dr3(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetDR3(set_value);
#else
			BOOL set_success = Script::Register::SetDR3(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DR3 value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DR3");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DR3 value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DR3 value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dr6(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetDR6(set_value);
#else
			BOOL set_success = Script::Register::SetDR6(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DR6 value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DR6");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DR6 value (debug status register may be read-only)");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DR6 value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_dr7(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetDR7(set_value);
#else
			BOOL set_success = Script::Register::SetDR7(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "DR7 value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "DR7");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DR7 value (debug control register may have restrictions)");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DR7 value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// CÇ°×º¼Ä´æÆ÷ÉèÖÃ£¨CAX¡¢CBX¡¢CCXµÈ£©
	// ------------------------------
	static ResponseData handle_set_cax(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCAX(set_value);
#else
			BOOL set_success = Script::Register::SetCAX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CAX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CAX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CAX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CAX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cbx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCBX(set_value);
#else
			BOOL set_success = Script::Register::SetCBX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CBX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CBX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CBX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CBX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_ccx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCCX(set_value);
#else
			BOOL set_success = Script::Register::SetCCX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CCX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CCX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CCX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CCX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cdx(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCDX(set_value);
#else
			BOOL set_success = Script::Register::SetCDX(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CDX value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CDX");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CDX value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CDX value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_csi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCSI(set_value);
#else
			BOOL set_success = Script::Register::SetCSI(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CSI value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CSI");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CSI value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CSI value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cdi(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCDI(set_value);
#else
			BOOL set_success = Script::Register::SetCDI(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CDI value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CDI");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CDI value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CDI value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cbp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCBP(set_value);
#else
			BOOL set_success = Script::Register::SetCBP(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CBP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CBP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CBP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CBP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_csp(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCSP(set_value);
#else
			BOOL set_success = Script::Register::SetCSP(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CSP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CSP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CSP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CSP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cip(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCIP(set_value);
#else
			BOOL set_success = Script::Register::SetCIP(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CIP value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CIP");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CIP value");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CIP value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	static ResponseData handle_set_cflags(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [value(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];

		try
		{
			unsigned long long set_value = 0;
			if (!parse_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid value format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// ±êÖ¾¼Ä´æÆ÷Í¨³£Îª32Î»£¬Ìí¼Ó·¶Î§¼ì²é
			if (set_value > 0xFFFFFFFF)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Value exceeds 32-bit limit (0~4294967295)");
				cJSON_AddNumberToObject(response.result.get(), "invalid_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_value_hex", format_value(set_value).c_str());
				return response;
			}

#ifdef _WIN64
			BOOL set_success = Script::Register::SetCFLAGS(static_cast<unsigned int>(set_value));
#else
			BOOL set_success = Script::Register::SetCFLAGS(static_cast<duint>(set_value));
#endif

			std::string formatted_value = format_value(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "CFlags value set successfully");
				cJSON_AddStringToObject(response.result.get(), "register_name", "CFlags");
				cJSON_AddNumberToObject(response.result.get(), "set_value_decimal", set_value);
				cJSON_AddStringToObject(response.result.get(), "set_value_hex", formatted_value.c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CFlags value (flags register may have restrictions)");
				cJSON_AddStringToObject(response.result.get(), "target_value_hex", formatted_value.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CFlags value");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// Í¨ÓÃ±êÖ¾ÉèÖÃ£¨Debugger.SetFlagRegister£©
	static ResponseData handle_set_flag_register(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨±êÖ¾Ãû + ÉèÖÃÖµ0/1£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [flag_name] [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Set ZF to 1: [\"ZF\", \"1\"]; Clear CF: [\"CF\", \"0\"]");
			return response;
		}

		const std::string flag_name = params[0];
		const std::string value_str = params[1];

		// Ð£Ñé±êÖ¾Ãû·Ç¿Õ
		if (flag_name.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Flag name cannot be empty");
			return response;
		}

		try
		{
			// 2. ½âÎöÉèÖÃÖµ£¨½öÖ§³Ö0/1£©
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 3. Ó³Éä±êÖ¾Ãûµ½Ë÷Òý£¨Ð£Ñé±êÖ¾ÓÐÐ§ÐÔ£©
			int flag_index = get_flag_index(flag_name);
			if (flag_index == -1)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid flag name");
				cJSON_AddStringToObject(response.result.get(), "invalid_flag", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "supported_flags", "ZF, OF, CF, PF, SF, TF, AF, DF, IF (case-sensitive)");
				return response;
			}

			// 4. µ÷ÓÃx64dbg½Ó¿ÚÉèÖÃ±êÖ¾Î»
			BOOL set_success = Script::Flag::Set(
				static_cast<Script::Flag::FlagEnum>(flag_index),
				set_value
				);

			// 5. ¹¹½¨ÏìÓ¦
			if (set_success)
			{
				response.success = true;


				// 2. ÔÚÔ­Î»ÖÃµ÷ÓÃ£¬Í¬Ê±Ìí¼Óc_str()×ª»»
				cJSON_AddStringToObject(
					response.result.get(),
					"message",
					getFlagMessage(flag_name, set_value).c_str() // ×ª»»Îªconst char*
					);
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "flag_index", flag_index);
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set flag (may be read-only in current context)");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting flag");
			cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ------------------------------
	// ÌØ¶¨±êÖ¾ÉèÖÃ£ºZF/OF/CF/PF/SF/TF/AF/DF/IF
	// ------------------------------
	// ÉèÖÃ ZF£¨Áã±êÖ¾£©
	static ResponseData handle_set_zf(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸öÉèÖÃÖµ£¨0/1£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "ZF";

		try
		{
			// 2. ½âÎöÉèÖÃÖµ£¨½öÖ§³Ö0/1£©
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃx64dbg½Ó¿ÚÉèÖÃZF
			BOOL set_success = Script::Flag::SetZF(set_value);

			// 4. ¹¹½¨ÏìÓ¦
			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"ZF (Zero Flag) set successfully" : "ZF (Zero Flag) cleared successfully");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set ZF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting ZF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ OF£¨Òç³ö±êÖ¾£©
	static ResponseData handle_set_of(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "OF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetOF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"OF (Overflow Flag) set successfully" : "OF (Overflow Flag) cleared successfully");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set OF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting OF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ CF£¨½øÎ»±êÖ¾£©
	static ResponseData handle_set_cf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "CF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetCF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"CF (Carry Flag) set successfully" : "CF (Carry Flag) cleared successfully");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set CF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting CF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ PF£¨ÆæÅ¼±êÖ¾£©
	static ResponseData handle_set_pf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "PF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetPF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"PF (Parity Flag) set successfully" : "PF (Parity Flag) cleared successfully");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set PF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting PF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ SF£¨·ûºÅ±êÖ¾£©
	static ResponseData handle_set_sf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "SF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetSF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"SF (Sign Flag) set successfully" : "SF (Sign Flag) cleared successfully");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set SF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting SF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ TF£¨ÏÝÚå±êÖ¾£©
	static ResponseData handle_set_tf(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "TF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetTF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"TF (Trap Flag) set successfully (single-step debugging enabled)" : "TF (Trap Flag) cleared successfully (single-step debugging disabled)");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set TF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting TF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ AF£¨¸¨Öú½øÎ»±êÖ¾£©
	static ResponseData handle_set_af(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "AF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetAF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"AF (Auxiliary Carry Flag) set successfully" : "AF (Auxiliary Carry Flag) cleared successfully");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set AF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting AF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ DF£¨·½Ïò±êÖ¾£©
	static ResponseData handle_set_df(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "DF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetDF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"DF (Direction Flag) set successfully (string index increment)" : "DF (Direction Flag) cleared successfully (string index decrement)");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set DF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting DF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}

	// ÉèÖÃ IF£¨ÖÐ¶Ï±êÖ¾£©
	static ResponseData handle_set_if(const std::vector<std::string>& params)
	{
		ResponseData response;

		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [set_value(0=clear,1=set)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		const std::string value_str = params[0];
		const std::string flag_name = "IF";

		try
		{
			BOOL set_value = FALSE;
			if (!parse_flag_value(value_str, set_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid set value. Only 0 (clear) or 1 (set) is allowed");
				cJSON_AddStringToObject(response.result.get(), "invalid_value", value_str.c_str());
				return response;
			}

			BOOL set_success = Script::Flag::SetIF(set_value);

			if (set_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", set_value ?
					"IF (Interrupt Flag) set successfully (maskable interrupts enabled)" : "IF (Interrupt Flag) cleared successfully (maskable interrupts disabled)");
				cJSON_AddStringToObject(response.result.get(), "flag_name", flag_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "description", get_flag_description(flag_name).c_str());
				cJSON_AddBoolToObject(response.result.get(), "is_set", set_value != 0);
				cJSON_AddNumberToObject(response.result.get(), "set_value", set_value);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to set IF flag");
				cJSON_AddNumberToObject(response.result.get(), "target_set_value", set_value);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while setting IF flag");
			cJSON_AddStringToObject(response.result.get(), "target_value", value_str.c_str());
		}

		return response;
	}
};


// ·´»ã±à´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class DissassemblyHandler
{
public:
	// µ¥ÐÐ´úÂë·´»ã±à´¦Àí£¨Debugger.DisasmOneCode£©
	static ResponseData handle_disasm_one_code(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨·´»ã±àÄ¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Disasm at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long addr_value = 0;
			if (!parse_value(addr_str, addr_value))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ·ÓÐÐ§ÐÔ£¨±ÜÃâ0µØÖ·µÈÎÞÐ§Öµ£¬Ô­º¯ÊýÅÐ¶Ïaddress != 0£©
			if (addr_value == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address: 0 is not a valid executable address");
				cJSON_AddNumberToObject(response.result.get(), "invalid_address_value", addr_value);
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(addr_value).c_str());
				return response;
			}

			// 4. µ÷ÓÃx64dbg½Ó¿ÚÖ´ÐÐµ¥ÐÐ·´»ã±à
			BASIC_INSTRUCTION_INFO asminfo = { 0 }; // ³õÊ¼»¯½á¹¹Ìå£¨ÓëÔ­º¯ÊýÒ»ÖÂ£©
			DbgDisasmFastAt(static_cast<duint>(addr_value), &asminfo);

			// 5. ´¦Àí·´»ã±à½á¹û£¨Ð£ÑéÊÇ·ñ³É¹¦»ñÈ¡Ö¸ÁîÐÅÏ¢£©
			if (asminfo.instruction[0] != '\0')
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Single instruction disassembly successful");
				// µØÖ·ÐÅÏ¢£¨Ô­Ê¼Öµ+¸ñÊ½»¯×Ö·û´®£©
				cJSON_AddNumberToObject(response.result.get(), "address_value", addr_value);
				cJSON_AddStringToObject(response.result.get(), "address_hex", format_address(addr_value).c_str());
				// ·´»ã±à½á¹û£¨Ö¸Áî×Ö·û´®+Ö¸Áî³¤¶È£©
				cJSON_AddStringToObject(response.result.get(), "instruction", asminfo.instruction);
				cJSON_AddNumberToObject(response.result.get(), "instruction_size", asminfo.size);
				cJSON_AddStringToObject(response.result.get(), "instruction_desc", "Length of the disassembled instruction in bytes");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to disassemble instruction (invalid address or non-executable memory)");
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", addr_value);
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(addr_value).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error during disassembly");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ÅúÁ¿·´»ã±à´¦Àí£¨Dissassembly.DisasmCountCode£©
	static ResponseData handle_disasm_count_code(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨ÆðÊ¼µØÖ· + Ö¸ÁîÊýÁ¿£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [start_address(hex/decimal)] [instruction_count(positive integer)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Disasm 5 instructions at 0x00401000: [\"0x00401000\", \"5\"]");
			return response;
		}

		const std::string addr_str = params[0];
		const std::string count_str = params[1];

		try
		{
			// 2. ½âÎöÆðÊ¼µØÖ·
			unsigned long long start_addr = 0;
			if (!parse_value(addr_str, start_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid start address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// Ð£ÑéµØÖ·ÓÐÐ§ÐÔ£¨·Ç0µØÖ·£©
			if (start_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Start address cannot be 0 (invalid executable address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(start_addr).c_str());
				return response;
			}

			// 3. ½âÎöÖ¸ÁîÊýÁ¿£¨±ØÐëÎªÕýÕûÊý£©
			int instruction_count = 0;
			try
			{
				size_t pos;
				instruction_count = std::stoi(count_str, &pos);
				if (pos != count_str.size() || instruction_count <= 0)
				{
					throw std::invalid_argument("Not a positive integer");
				}
			}
			catch (const std::exception&)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid instruction count. Must be a positive integer");
				cJSON_AddStringToObject(response.result.get(), "invalid_count", count_str.c_str());
				return response;
			}

			// 4. µ÷ÓÃ·´»ã±àºËÐÄº¯Êý£¨¸´ÓÃÔ­DisasmCodeÂß¼­£©
			std::vector<disasm> disasm_result = DisasmCode(static_cast<duint>(start_addr), instruction_count);

			// 5. ´¦Àí·´»ã±à½á¹û
			if (!disasm_result.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Batch disassembly successful");
				cJSON_AddNumberToObject(response.result.get(), "requested_count", instruction_count);
				cJSON_AddNumberToObject(response.result.get(), "actual_count", disasm_result.size());
				cJSON_AddStringToObject(response.result.get(), "start_address_hex", format_address(start_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "start_address_value", start_addr);

				// ´´½¨Ö¸ÁîÊý×é£¨Ìæ´úÔ­SocketÖðÌõ·¢ËÍÂß¼­£©
				cJSON* instructions_array = cJSON_CreateArray();
				for (const auto& inst : disasm_result)
				{
					cJSON* inst_obj = cJSON_CreateObject();
					// µØÖ·ÐÅÏ¢£¨Çø·ÖÆ½Ì¨ÏÔÊ¾£©
					cJSON_AddNumberToObject(inst_obj, "address_value", inst.address);
					cJSON_AddStringToObject(inst_obj, "address_hex", format_address(inst.address).c_str());
					// Ö¸ÁîÐÅÏ¢
					cJSON_AddStringToObject(inst_obj, "instruction", inst.instruction);
					cJSON_AddNumberToObject(inst_obj, "size", inst.size);
					cJSON_AddStringToObject(inst_obj, "size_desc", "Length of the instruction in bytes");
					cJSON_AddItemToArray(instructions_array, inst_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "instructions", instructions_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to disassemble instructions (invalid address range or non-executable memory)");
				cJSON_AddStringToObject(response.result.get(), "start_address_hex", format_address(start_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "requested_count", instruction_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error during batch disassembly");
			cJSON_AddStringToObject(response.result.get(), "start_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "requested_count", count_str.c_str());
		}

		return response;
	}

	// »ñÈ¡·´»ã±à²Ù×÷Êý£¨Dissassembly.DisasmOperand£©
	static ResponseData handle_disasm_operand(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get operand at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ·ÓÐÐ§ÐÔ£¨·Ç0µØÖ·£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Target address cannot be 0 (invalid executable address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃ·´»ã±à½Ó¿Ú»ñÈ¡²Ù×÷Êý
			BASIC_INSTRUCTION_INFO asminfo = { 0 };
			DbgDisasmFastAt(static_cast<duint>(target_addr), &asminfo);

			// 5. ´¦Àí½á¹û£¨Ô­º¯ÊýÅÐ¶Ïaddress != 0¼´³¢ÊÔ»ñÈ¡£¬´Ë´¦²¹³ä·´»ã±à³É¹¦Ð£Ñé£©
			if (asminfo.instruction[0] != '\0')
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Operand information retrieved successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
				// ²Ù×÷ÊýÐÅÏ¢£¨¶ÔÓ¦Ô­º¯ÊýµÄasminfo.value.valueºÍvalue.size£©
				cJSON_AddNumberToObject(response.result.get(), "operand_value", asminfo.value.value);
				cJSON_AddNumberToObject(response.result.get(), "operand_size", asminfo.value.size);
				cJSON_AddStringToObject(response.result.get(), "operand_size_desc", "Size of the operand in bytes");
				// ²¹³äÖ¸ÁîÄÚÈÝ£¨¸¨Öúµ÷ÊÔ£©
				cJSON_AddStringToObject(response.result.get(), "instruction", asminfo.instruction);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to retrieve operand (invalid address or non-executable memory)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving operand");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ñÈ¡·´»ã±àµØÖ·ÊôÐÔ£¨Dissassembly.DisasmFastAtFunction£©
	static ResponseData handle_disasm_fast_at_function(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get instruction properties at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ·ÓÐÐ§ÐÔ£¨·Ç0µØÖ·£¬ÓëÔ­º¯Êýptr.Command_int_A != 0Ò»ÖÂ£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Target address cannot be 0 (invalid executable address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃ·´»ã±à½Ó¿Ú»ñÈ¡ÊôÐÔ
			BASIC_INSTRUCTION_INFO dasm_info = { 0 };
			DbgDisasmFastAt(static_cast<duint>(target_addr), &dasm_info);

			// 5. ´¦Àí½á¹û£¨Ô­º¯ÊýÅÐ¶Ïdasm_info.size >= 1ÎªÓÐÐ§£©
			if (dasm_info.size >= 1)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Instruction properties retrieved successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
				// Ö¸ÁîÊôÐÔ£¨ÓëÔ­º¯Êý·µ»Ø×Ö¶ÎÒ»Ò»¶ÔÓ¦£©
				cJSON_AddNumberToObject(response.result.get(), "instruction_size", dasm_info.size);          // »úÆ÷Âë³¤¶È
				cJSON_AddStringToObject(response.result.get(), "size_desc", "Length of the instruction in bytes");
				cJSON_AddBoolToObject(response.result.get(), "is_branch", dasm_info.branch != 0);             // ÊÇ·ñ·ÖÖ§£¨0=·ñ£¬·Ç0=ÊÇ£©
				cJSON_AddBoolToObject(response.result.get(), "is_call", dasm_info.call != 0);                 // ÊÇ·ñÊÇcall£¨0=·ñ£¬·Ç0=ÊÇ£©
				cJSON_AddNumberToObject(response.result.get(), "instruction_type", dasm_info.type);           // Ö¸ÁîÀàÐÍ£¨Ô­Ê¼Ã¶¾ÙÖµ£©
				cJSON_AddStringToObject(response.result.get(), "type_desc", "Instruction type (architecture-specific enum)");
				cJSON_AddStringToObject(response.result.get(), "instruction", dasm_info.instruction);         // ·´»ã±àÖ¸Áî×Ö·û´®
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to retrieve instruction properties (invalid or unrecognized instruction)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_size", dasm_info.size);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving instruction properties");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}


	// »ñÈ¡»ã±à»úÆ÷Âë³¤¶È£¨Dissassembly.GetOperandSize£©
	static ResponseData handle_get_operand_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get instruction size at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ·ÓÐÐ§ÐÔ£¨·Ç0µØÖ·£¬ÓëÔ­º¯Êýaddr != 0Ò»ÖÂ£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Target address cannot be 0 (invalid executable address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃ·´»ã±à½Ó¿Ú»ñÈ¡³¤¶È
			BASIC_INSTRUCTION_INFO asminfo = { 0 };
			DbgDisasmFastAt(static_cast<duint>(target_addr), &asminfo);

			// 5. ´¦Àí½á¹û
			if (asminfo.size > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Instruction size retrieved successfully");
				// µØÖ·ÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
				// »úÆ÷Âë³¤¶È£¨¶ÔÓ¦Ô­º¯ÊýµÄasminfo.size£©
				cJSON_AddNumberToObject(response.result.get(), "instruction_size", asminfo.size);
				cJSON_AddStringToObject(response.result.get(), "size_desc", "Length of the instruction machine code in bytes");
				// ²¹³äÖ¸ÁîÄÚÈÝ£¨¸¨ÖúÈ·ÈÏ£©
				cJSON_AddStringToObject(response.result.get(), "instruction", asminfo.instruction);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to retrieve instruction size (invalid address or non-executable memory)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_size", asminfo.size);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving instruction size");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ñÈ¡CALL/JMPÌø×ªÄ¿±ê£¨Dissassembly.GetBranchDestination£©
	static ResponseData handle_get_branch_destination(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·/0£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(0=current RIP/EIP, positive hex/decimal=specific address)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get current EIP's branch: [\"0\"]; Get 0x00401000's branch: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];
		unsigned long long target_addr = 0;
		bool is_current_ip = false;

		try
		{
			// 2. ½âÎö²ÎÊý£¨Çø·Ö¡°0=µ±Ç°IP¡±ºÍ¡°ÕýÊý=Ö¸¶¨µØÖ·¡±£©
			if (addr_str == "0")
			{
				is_current_ip = true; // ±ê¼ÇÎª¡°È¡µ±Ç°IP¡±Ä£Ê½
			}
			else
			{
				// ½âÎöÖ¸¶¨µØÖ·£¨±ØÐëÎªÕýÊý£©
				if (!parse_value(addr_str, target_addr) || target_addr <= 0)
				{
					cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address. Use 0 (current IP) or positive hex/decimal");
					cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
					return response;
				}
			}

			// 3. ºËÐÄÂß¼­£º»ñÈ¡Ìø×ªÄ¿±ê£¨Çø·ÖÆ½Ì¨£©
			unsigned long long current_ip = 0;
			unsigned long long branch_dest = 0;
			BOOL get_success = FALSE;

			if (is_current_ip)
			{
				// Ä£Ê½1£ºÈ¡µ±Ç°IP£¨x64=RIP£¬x86=EIP£©
#ifdef _WIN64
				current_ip = Script::Register::GetRIP();
#else
				current_ip = Script::Register::GetEIP();
#endif
				branch_dest = DbgGetBranchDestination(static_cast<duint>(current_ip));
				get_success = (branch_dest != 0); // Ìø×ªÄ¿±ê·Ç0ÊÓÎªÓÐÐ§
			}
			else
			{
				// Ä£Ê½2£ºÈ¡Ö¸¶¨µØÖ·
				current_ip = target_addr;
				branch_dest = DbgGetBranchDestination(static_cast<duint>(current_ip));
				get_success = (branch_dest != 0);
			}

			// 4. ´¦Àí½á¹û
			if (get_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Branch destination retrieved successfully");
				// µ±Ç°µØÖ·ÐÅÏ¢£¨ÓÃÓÚÈ·ÈÏÀ´Ô´£©
				cJSON_AddStringToObject(response.result.get(), "source_address_type", is_current_ip ? "current RIP/EIP" : "specified address");
				cJSON_AddNumberToObject(response.result.get(), "source_address_value", current_ip);
				cJSON_AddStringToObject(response.result.get(), "source_address_hex", format_address(current_ip).c_str());
				// Ìø×ªÄ¿±êÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "branch_destination_value", branch_dest);
				cJSON_AddStringToObject(response.result.get(), "branch_destination_hex", format_address(branch_dest).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Destination is 0 if the instruction is not CALL/JMP or has no valid branch");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get branch destination (instruction is not CALL/JMP or invalid address)");
				cJSON_AddStringToObject(response.result.get(), "source_address_hex", format_address(current_ip).c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_destination", branch_dest);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving branch destination");
			cJSON_AddStringToObject(response.result.get(), "input_address", addr_str.c_str());
		}

		return response;
	}

	// µ¥ÐÐ·´»ã±à£¨·µ»Ø»ã±à´úÂë£©£¨Dissassembly.GuiGetDisassembly£©
	static ResponseData handle_gui_get_disassembly(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä¿±êµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [target_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Gui disasm at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ·ÓÐÐ§ÐÔ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A != 0£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Target address cannot be 0 (invalid executable address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃUI²ã·´»ã±à½Ó¿Ú£¨Ô­º¯ÊýÂß¼­£º256×Ö½Ú»º³åÇø£©
			char dasm_buf[256] = { 0 };
			BOOL disasm_success = GuiGetDisassembly(static_cast<duint>(target_addr), dasm_buf);

			// 5. ´¦Àí½á¹û£¨Ð£Ñé·´»ã±à½á¹û·Ç¿Õ£©
			if (disasm_success && strlen(dasm_buf) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "GUI disassembly successful");
				// µØÖ·ÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				// ·´»ã±à½á¹û£¨½ö·µ»Ø»ã±à´úÂë£¬ÓëÔ­º¯ÊýÂß¼­Ò»ÖÂ£©
				cJSON_AddStringToObject(response.result.get(), "disassembly_instruction", dasm_buf);
				cJSON_AddStringToObject(response.result.get(), "note", "This uses UI-layer disassembly logic (GuiGetDisassembly)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "GUI disassembly failed (invalid address or non-executable memory)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "detected_instruction", dasm_buf);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error during GUI disassembly");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ã±à×Ö·û´®Ð´ÈëÄÚ´æ£¨Dissassembly.AssembleMemoryEx£©
	static ResponseData handle_assemble_memory_ex(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä¿±êµØÖ· + »ã±à×Ö·û´®£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [target_address(hex/decimal)] [assembly_string]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Assemble 'push ebp' to 0x00401000: [\"0x00401000\", \"push ebp\"]");
			return response;
		}

		const std::string addr_str = params[0];
		const std::string asm_str = params[1];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéºËÐÄÌõ¼þ£¨Ô­º¯Êý£ºµØÖ··Ç0 + »ã±à×Ö·û´®·Ç¿Õ£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Target address cannot be 0 (invalid writable memory)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}
			if (asm_str.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string cannot be empty");
				return response;
			}
			// Ð£Ñé»ã±à×Ö·û´®³¤¶È£¨Ô­º¯ÊýÓÃ256×Ö½Ú»º³åÇø£¬±ÜÃâ³¬³¤£©
			if (asm_str.size() >= 256)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string exceeds 255 characters (limit of underlying buffer)");
				cJSON_AddNumberToObject(response.result.get(), "string_length", asm_str.size());
				return response;
			}

			// 4. µ÷ÓÃ»ã±à½Ó¿ÚÐ´ÈëÄÚ´æ£¨Ô­º¯ÊýÂß¼­£º¸´ÖÆµ½256×Ö½Ú»º³åÇøºóµ÷ÓÃ£©
			char asm_buf[256] = { 0 };
			strncpy(asm_buf, asm_str.c_str(), sizeof(asm_buf) - 1); // ±ÜÃâÔ½½ç
			BOOL assemble_success = Script::Assembler::AssembleMem(
				static_cast<duint>(target_addr),
				asm_buf
				);

			// 5. ´¦Àí½á¹û
			if (assemble_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Assembly successful and written to memory");
				// ÊäÈëÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				// Ä¿±êµØÖ·ÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Ensure the target address has write permission (e.g., not read-only code segment)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly failed (invalid instruction syntax or unwritable memory)");
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error during assembly");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
		}

		return response;
	}

	// ÔÚÖ¸¶¨µØÖ·Ð´Èë»ã±àÖ¸Áî£¨Dissassembly.AssembleAtFunctionEx£©
	static ResponseData handle_assemble_at_function_ex(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä¿±êµØÖ· + »ã±àÖ¸Áî×Ö·û´®£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [target_address(hex/decimal)] [assembly_string]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Assemble 'mov eax, 1' at 0x00401000: [\"0x00401000\", \"mov eax, 1\"]");
			return response;
		}

		const std::string addr_str = params[0];
		const std::string asm_str = params[1];

		try
		{
			// 2. ½âÎöÄ¿±êµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid target address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéºËÐÄÌõ¼þ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A != 0£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Target address cannot be 0 (invalid writable memory)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}
			if (asm_str.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string cannot be empty");
				return response;
			}
			// Ð£Ñé»ã±à×Ö·û´®³¤¶È
			if (asm_str.size() >= 256)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string exceeds 255 characters (limit of underlying buffer)");
				cJSON_AddNumberToObject(response.result.get(), "string_length", asm_str.size());
				return response;
			}

			// 4. µ÷ÓÃ»ã±à½Ó¿ÚÐ´ÈëÄÚ´æ£¨Ô­º¯ÊýÂß¼­£ºDbgAssembleAt£©
			BOOL assemble_success = DbgAssembleAt(
				static_cast<duint>(target_addr),
				asm_str.c_str()
				);

			// 5. ´¦Àí½á¹û
			if (assemble_success)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Assembly successful and written to target address");
				// ÊäÈëÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				// Ä¿±êµØÖ·ÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Ensure the target address has write permission (e.g., not read-only code segment)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly failed (invalid instruction syntax, unwritable memory, or invalid address)");
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error during assembly to memory");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
		}

		return response;
	}

	// »ñÈ¡»ã±àÖ¸ÁîÊ®Áù½øÖÆ»úÆ÷Âë£¨Dissassembly.AssembleCodeHex£©
	static ResponseData handle_assemble_code_hex(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨»ã±àÖ¸Áî×Ö·û´®£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [assembly_string]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get hex of 'push ebp': [\"push ebp\"]");
			return response;
		}

		const std::string asm_str = params[0];

		try
		{
			// 2. Ð£Ñé»ã±à×Ö·û´®·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïstrlen(asm_code) != 0£©
			if (asm_str.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string cannot be empty");
				return response;
			}
			// Ð£Ñé³¤¶È£¨Ô­º¯ÊýÓÃ256×Ö½Ú»º³åÇø£©
			if (asm_str.size() >= 256)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string exceeds 255 characters (limit of underlying buffer)");
				cJSON_AddNumberToObject(response.result.get(), "string_length", asm_str.size());
				return response;
			}

			// 3. µ÷ÓÃ»ã±à½Ó¿ÚÉú³É»úÆ÷Âë£¨Ô­º¯ÊýÂß¼­£©
			char asm_buf[256] = { 0 };
			strncpy(asm_buf, asm_str.c_str(), sizeof(asm_buf) - 1);
			unsigned char machine_code[256] = { 0 };
			int code_size = 0;

			BOOL assemble_success = Script::Assembler::Assemble(
				0,                  // µØÖ·²ÎÊýºöÂÔ
				machine_code,
				&code_size,
				asm_buf
				);

			// 4. ×ª»»»úÆ÷ÂëÎªÊ®Áù½øÖÆ×Ö·û´®£¨Ô­º¯ÊýÑ­»·sprintfÂß¼­£©
			std::string hex_str;
			if (assemble_success && code_size > 0)
			{
				char hex_buf[4]; // Ã¿¸ö×Ö½ÚÕ¼2Î»Ê®Áù½øÖÆ + ¿Õ¸ñ£¨Èç"55 "£©
				for (int i = 0; i < code_size; i++)
				{
					sprintf_s(hex_buf, sizeof(hex_buf), "%02X ", machine_code[i]);
					hex_str += hex_buf;
				}
				// ÒÆ³ýÄ©Î²¶àÓà¿Õ¸ñ
				if (!hex_str.empty())
					hex_str.pop_back();
			}

			// 5. ´¦Àí½á¹û
			if (assemble_success && code_size > 0 && !hex_str.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Assembly hex machine code generated successfully");
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				cJSON_AddNumberToObject(response.result.get(), "machine_code_size", code_size);
				cJSON_AddStringToObject(response.result.get(), "machine_code_hex", hex_str.c_str());
				cJSON_AddStringToObject(response.result.get(), "hex_desc", "Space-separated hexadecimal representation of machine code bytes");
				cJSON_AddStringToObject(response.result.get(), "note", "This is a dry-run (no memory write performed)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to generate hex machine code (invalid instruction syntax)");
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_size", code_size);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while generating hex machine code");
			cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
		}

		return response;
	}

	// »ñÈ¡»ã±àÖ¸Áî³¤¶È£¨Dissassembly.AssembleCodeSize£©
	static ResponseData handle_assemble_code_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨»ã±àÖ¸Áî×Ö·û´®£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [assembly_string]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get size of 'push ebp': [\"push ebp\"]");
			return response;
		}

		const std::string asm_str = params[0];

		try
		{
			// 2. Ð£Ñé»ã±à×Ö·û´®·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïstrlen(asm_code) != 0£©
			if (asm_str.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string cannot be empty");
				return response;
			}
			// Ð£Ñé³¤¶È£¨Ô­º¯ÊýÓÃ256×Ö½Ú»º³åÇø£©
			if (asm_str.size() >= 256)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Assembly string exceeds 255 characters (limit of underlying buffer)");
				cJSON_AddNumberToObject(response.result.get(), "string_length", asm_str.size());
				return response;
			}

			// 3. µ÷ÓÃ»ã±à½Ó¿Ú¼ÆËã³¤¶È£¨Ô­º¯ÊýÂß¼­£ººöÂÔµØÖ·²ÎÊý£¬½ö¼ÆËã³¤¶È£©
			char asm_buf[256] = { 0 };
			strncpy(asm_buf, asm_str.c_str(), sizeof(asm_buf) - 1);
			unsigned char machine_code[256] = { 0 }; // ÁÙÊ±´æ´¢»úÆ÷Âë£¨²»Ê¹ÓÃ£©
			int code_size = 0;

			BOOL assemble_success = Script::Assembler::Assemble(
				0,                  // µØÖ·²ÎÊýºöÂÔ£¨Ô­º¯Êý´«Èë0£©
				machine_code,
				&code_size,
				asm_buf
				);

			// 4. ´¦Àí½á¹û
			if (assemble_success && code_size > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Assembly size calculated successfully");
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				cJSON_AddNumberToObject(response.result.get(), "machine_code_size", code_size);
				cJSON_AddStringToObject(response.result.get(), "size_desc", "Length of the assembled machine code in bytes");
				cJSON_AddStringToObject(response.result.get(), "note", "This is a dry-run (no memory write performed)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to calculate assembly size (invalid instruction syntax)");
				cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_size", code_size);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while calculating assembly size");
			cJSON_AddStringToObject(response.result.get(), "assembly_string", asm_str.c_str());
		}

		return response;
	}
};


// Ä£¿é´¦ÀíÆ÷£¨ÓÅ»¯·µ»ØÐÅÏ¢£¬Óë½Ó¿Ú¹¦ÄÜÆ¥Åä£©
class ModuleHandler
{
public:
	// »ñÈ¡Ä£¿é»ùµØÖ·£¨Module.GetModuleBaseAddress£©
	static ResponseData handle_get_module_base_address(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension, e.g., 'kernel32.dll')]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get base of kernel32.dll: [\"kernel32.dll\"]; Get base of notepad.exe: [\"notepad.exe\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃx64dbg½Ó¿Ú»ñÈ¡Ä£¿é»ùµØÖ·£¨Çø·ÖÆ½Ì¨ÀàÐÍ£©
			unsigned long long module_base = 0;
#ifdef _WIN64
			module_base = DbgModBaseFromName(module_name.c_str());
#else
			module_base = static_cast<unsigned long long>(DbgModBaseFromName(module_name.c_str()));
#endif

			// 4. ´¦Àí½á¹û
			if (module_base != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module base address retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				// »ùµØÖ·ÐÅÏ¢£¨ÊýÖµ+Ê®Áù½øÖÆ×Ö·û´®£©
				cJSON_AddNumberToObject(response.result.get(), "base_address_value", module_base);
				cJSON_AddStringToObject(response.result.get(), "base_address_hex", format_address(module_base).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Module name is case-insensitive in most cases (e.g., 'KERNEL32.DLL' = 'kernel32.dll')");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module base address (module not loaded or invalid name)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving module base address");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}

	// »ñÈ¡Ä£¿éÖÐÖ¸¶¨º¯ÊýµØÖ·£¨Module.GetModuleProcAddress£©
	static ResponseData handle_get_module_proc_address(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä£¿éÃû + º¯ÊýÃû£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [module_name] [function_name(exported function)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get CreateFileA in kernel32.dll: [\"kernel32.dll\", \"CreateFileA\"]");
			return response;
		}

		const std::string module_name = params[0];
		const std::string func_name = params[1];

		try
		{
			// 2. Ð£Ñé²ÎÊý·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶ÏAºÍB¾ù·Ç¿Õ£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}
			if (func_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Function name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡º¯ÊýµØÖ·£¨Çø·ÖÆ½Ì¨ÀàÐÍ£©
			unsigned long long func_addr = 0;
#ifdef _WIN64
			func_addr = Script::Misc::RemoteGetProcAddress(module_name.c_str(), func_name.c_str());
#else
			func_addr = static_cast<unsigned long long>(Script::Misc::RemoteGetProcAddress(module_name.c_str(), func_name.c_str()));
#endif

			// 4. ´¦Àí½á¹û
			if (func_addr != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module function address retrieved successfully");
				// ÊäÈëÐÅÏ¢
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "function_name", func_name.c_str());
				// º¯ÊýµØÖ·ÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "function_address_value", func_addr);
				cJSON_AddStringToObject(response.result.get(), "function_address_hex", format_address(func_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "Only works for exported functions (non-exported functions cannot be found)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get function address (module not loaded, function not exported, or invalid names)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "target_function_name", func_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving module function address");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			cJSON_AddStringToObject(response.result.get(), "target_function_name", func_name.c_str());
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿éÊ×µØÖ·£¨Module.GetBaseFromAddr£©
	static ResponseData handle_get_base_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get module base of address 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöÄÚ´æµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid memory address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ··Ç0£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A != 0£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿é»ùµØÖ·£¨Çø·ÖÆ½Ì¨ÀàÐÍ£©
			unsigned long long module_base = 0;
#ifdef _WIN64
			module_base = Script::Module::BaseFromAddr(target_addr);
#else
			module_base = static_cast<unsigned long long>(Script::Module::BaseFromAddr(static_cast<duint>(target_addr)));
#endif

			// 5. ´¦Àí½á¹û
			if (module_base != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module base address from memory address retrieved successfully");
				// ÊäÈëµØÖ·ÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				// Ä£¿é»ùµØÖ·ÐÅÏ¢
				cJSON_AddNumberToObject(response.result.get(), "module_base_address_value", module_base);
				cJSON_AddStringToObject(response.result.get(), "module_base_address_hex", format_address(module_base).c_str());
				cJSON_AddStringToObject(response.result.get(), "note", "The input address must belong to a loaded module (e.g., code/data segment of a DLL/EXE)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module base address (address does not belong to any loaded module)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "target_address_value", target_addr);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while retrieving module base from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡»ùµØÖ·£¨Module.GetBaseFromName£©
	static ResponseData handle_get_base_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get base of ntdll.dll: [\"ntdll.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡»ùµØÖ·£¨Çø·ÖÆ½Ì¨£©
			unsigned long long module_base = 0;
#ifdef _WIN64
			module_base = Script::Module::BaseFromName(module_name.c_str());
#else
			module_base = static_cast<unsigned long long>(Script::Module::BaseFromName(module_name.c_str()));
#endif

			// 4. ´¦Àí½á¹û
			if (module_base != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module base address from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "base_address_value", module_base);
				cJSON_AddStringToObject(response.result.get(), "base_address_hex", format_address(module_base).c_str());
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module base (module not loaded or invalid name)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting base from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿é´óÐ¡£¨Module.GetSizeFromAddress£©
	static ResponseData handle_get_size_from_address(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get size of module containing 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ··Ç0£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A != 0£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿é´óÐ¡£¨ÐÞÕýÔ­´úÂëx64·ÖÖ§±ÊÎó£ºBaseFromAddr -> SizeFromAddr£©
			unsigned long long module_size = 0;
#ifdef _WIN64
			module_size = Script::Module::SizeFromAddr(target_addr);  // Ô­´úÂë´Ë´¦Îª±ÊÎó£¬ÒÑÐÞÕý
#else
			module_size = static_cast<unsigned long long>(Script::Module::SizeFromAddr(static_cast<duint>(target_addr)));
#endif

			// 5. ´¦Àí½á¹û
			if (module_size != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module size from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "module_size_bytes", module_size);
				cJSON_AddStringToObject(response.result.get(), "size_desc", "Total size of the module in bytes (including all sections)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module size (address not in any loaded module)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting size from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡Ä£¿é´óÐ¡£¨Module.GetSizeFromName£©
	static ResponseData handle_get_size_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get size of kernel32.dll: [\"kernel32.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿é´óÐ¡£¨Çø·ÖÆ½Ì¨£©
			unsigned long long module_size = 0;
#ifdef _WIN64
			module_size = Script::Module::SizeFromName(module_name.c_str());
#else
			module_size = static_cast<unsigned long long>(Script::Module::SizeFromName(module_name.c_str()));
#endif

			// 4. ´¦Àí½á¹û
			if (module_size != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module size from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "module_size_bytes", module_size);
				cJSON_AddStringToObject(response.result.get(), "size_desc", "Total size of the module in bytes (including all sections)");
				cJSON_AddStringToObject(response.result.get(), "note", "Size may include padding or uninitialized data sections");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module size (module not loaded or invalid name)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting size from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡Èë¿ÚµãOEP£¨Module.GetOEPFromName£©
	static ResponseData handle_get_oep_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get OEP of notepad.exe: [\"notepad.exe\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡OEP£¨Çø·ÖÆ½Ì¨£©
			unsigned long long oep_address = 0;
#ifdef _WIN64
			oep_address = Script::Module::EntryFromName(module_name.c_str());
#else
			oep_address = static_cast<unsigned long long>(Script::Module::EntryFromName(module_name.c_str()));
#endif

			// 4. ´¦Àí½á¹û
			if (oep_address != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module OEP from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "oep_address_value", oep_address);
				cJSON_AddStringToObject(response.result.get(), "oep_address_hex", format_address(oep_address).c_str());
				cJSON_AddStringToObject(response.result.get(), "oep_desc", "Original Entry Point - the address where execution starts in the module");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get OEP (module not loaded, invalid name, or no entry point)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting OEP from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Èë¿ÚµãOEP£¨Module.GetOEPFromAddr£©
	static ResponseData handle_get_oep_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get OEP of module containing 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. Ð£ÑéµØÖ··Ç0£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A != 0£©
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 4. µ÷ÓÃ½Ó¿Ú»ñÈ¡OEP£¨Çø·ÖÆ½Ì¨£©
			unsigned long long oep_address = 0;
#ifdef _WIN64
			oep_address = Script::Module::EntryFromAddr(target_addr);
#else
			oep_address = static_cast<unsigned long long>(Script::Module::EntryFromAddr(static_cast<duint>(target_addr)));
#endif

			// 5. ´¦Àí½á¹û
			if (oep_address != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module OEP from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "oep_address_value", oep_address);
				cJSON_AddStringToObject(response.result.get(), "oep_address_hex", format_address(oep_address).c_str());
				cJSON_AddStringToObject(response.result.get(), "oep_desc", "Original Entry Point - the address where execution starts in the module");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get OEP (address not in any loaded module or module has no entry point)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting OEP from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡Ä£¿éÂ·¾¶£¨Module.PathFromName£©
	static ResponseData handle_path_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get path of kernel32.dll: [\"kernel32.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿éÂ·¾¶£¨Ô­º¯Êý512×Ö½Ú»º³åÇø£©
			char module_path[512] = { 0 };
			BOOL get_success = Script::Module::PathFromName(module_name.c_str(), module_path);

			// 4. ´¦Àí½á¹û
			if (get_success && strlen(module_path) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module path from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddStringToObject(response.result.get(), "module_full_path", module_path);
				cJSON_AddStringToObject(response.result.get(), "path_desc", "Full file system path of the loaded module");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module path (module not loaded, invalid name, or path exceeds 512 bytes)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module path from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿éÍêÕûÂ·¾¶£¨Module.PathFromAddr£©
	static ResponseData handle_path_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get path of module containing 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿éÂ·¾¶
			char module_path[512] = { 0 };
			BOOL get_success = Script::Module::PathFromAddr(static_cast<duint>(target_addr), module_path);

			// 4. ´¦Àí½á¹û
			if (get_success && strlen(module_path) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module path from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "module_full_path", module_path);
				cJSON_AddStringToObject(response.result.get(), "path_desc", "Full file system path of the module containing the input address");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module path (address not in any loaded module or path exceeds 512 bytes)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module path from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿éÃû³Æ£¨Module.NameFromAddr£©
	static ResponseData handle_name_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get module name of address 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿éÃû³Æ
			char module_name[512] = { 0 };
			BOOL get_success = Script::Module::NameFromAddr(static_cast<duint>(target_addr), module_name);

			// 4. ´¦Àí½á¹û
			if (get_success && strlen(module_name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module name from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name);
				cJSON_AddStringToObject(response.result.get(), "name_desc", "Name of the module containing the input address (including extension)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module name (address not in any loaded module)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module name from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// »ñÈ¡Ö÷Ä£¿é½ÚÊýÁ¿£¨Module.GetMainModuleSectionCount£©
	static ResponseData handle_get_main_module_section_count(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨Ô­º¯ÊýÎÞÊäÈë£©
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ö÷Ä£¿é½ÚÊýÁ¿£¨Çø·ÖÆ½Ì¨£©
			unsigned long long section_count = 0;
#ifdef _WIN64
			section_count = Script::Module::GetMainModuleSectionCount();
#else
			section_count = static_cast<unsigned long long>(Script::Module::GetMainModuleSectionCount());
#endif

			// 3. ´¦Àí½á¹û
			if (section_count > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module section count retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "main_module_section_count", section_count);
				cJSON_AddStringToObject(response.result.get(), "count_desc", "Number of sections in the main module's PE file (e.g., .text, .data, .rdata)");
				cJSON_AddStringToObject(response.result.get(), "note", "Main module refers to the debugged executable (e.g., notepad.exe)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module section count (no debugged process or invalid PE file)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module section count");
		}

		return response;
	}

	// »ñÈ¡Ö÷Ä£¿éÍêÕûÂ·¾¶£¨Module.GetMainModulePath£©
	static ResponseData handle_get_main_module_path(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨Ô­º¯ÊýÎÞÊäÈë£©
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ö÷Ä£¿éÂ·¾¶£¨Ô­º¯Êý512×Ö½Ú»º³åÇø£©
			char main_module_path[512] = { 0 };
			BOOL get_success = Script::Module::GetMainModulePath(main_module_path);

			// 3. ´¦Àí½á¹û
			if (get_success && strlen(main_module_path) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module path retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "main_module_full_path", main_module_path);
				cJSON_AddStringToObject(response.result.get(), "path_desc", "Full file system path of the debugged main executable");
				cJSON_AddStringToObject(response.result.get(), "note", "Main module is the primary executable being debugged (e.g., C:\\Windows\\notepad.exe)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module path (no debugged process or path exceeds 512 bytes)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module path");
		}

		return response;
	}

	// »ñÈ¡Ö÷Ä£¿é´óÐ¡£¨Module.GetMainModuleSize£©
	static ResponseData handle_get_main_module_size(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨Ö÷Ä£¿éÎª±»µ÷ÊÔ³ÌÐò£¬ÎÞÐèÊäÈë£©
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ö÷Ä£¿é´óÐ¡£¨Çø·ÖÆ½Ì¨£¬ÐÞÕýÔ­º¯ÊýÀàÐÍÅÐ¶Ï£©
			unsigned long long module_size = 0;
#ifdef _WIN64
			module_size = Script::Module::GetMainModuleSize();
#else
			module_size = static_cast<unsigned long long>(Script::Module::GetMainModuleSize());
#endif

			// 3. ´¦Àí½á¹û£¨´óÐ¡Îª0±íÊ¾Ê§°Ü£¬Ö÷Ä£¿é´óÐ¡²»¿ÉÄÜÎª0£©
			if (module_size > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module size retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "main_module_size_bytes", module_size);
				cJSON_AddStringToObject(response.result.get(), "size_desc", "Total size of the debugged main module (including all sections)");
				cJSON_AddStringToObject(response.result.get(), "note", "Main module refers to the primary executable being debugged (e.g., notepad.exe)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module size (no debugged process or invalid main module)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module size");
		}

		return response;
	}

	// »ñÈ¡Ö÷Ä£¿éÃû³Æ£¨Module.GetMainModuleName£©
	static ResponseData handle_get_main_module_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ö÷Ä£¿éÃû³Æ£¨Ô­º¯Êý512×Ö½Ú»º³åÇø£©
			char module_name[512] = { 0 };
			BOOL get_success = Script::Module::GetMainModuleName(module_name);

			// 3. ´¦Àí½á¹û£¨Ãû³Æ·Ç¿Õ±íÊ¾³É¹¦£©
			if (get_success && strlen(module_name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "main_module_name", module_name);
				cJSON_AddStringToObject(response.result.get(), "name_desc", "Name of the debugged main module (including file extension)");
				cJSON_AddStringToObject(response.result.get(), "note", "e.g., 'notepad.exe' for the Notepad main executable");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module name (no debugged process or name exceeds 512 bytes)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module name");
		}

		return response;
	}

	// »ñÈ¡Ö÷Ä£¿éÈë¿ÚµØÖ·£¨Module.GetMainModuleEntry£©
	static ResponseData handle_get_main_module_entry(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ö÷Ä£¿éÈë¿ÚµØÖ·£¨Çø·ÖÆ½Ì¨£©
			unsigned long long entry_addr = 0;
#ifdef _WIN64
			entry_addr = Script::Module::GetMainModuleEntry();
#else
			entry_addr = static_cast<unsigned long long>(Script::Module::GetMainModuleEntry());
#endif

			// 3. ´¦Àí½á¹û£¨Èë¿ÚµØÖ··Ç0±íÊ¾³É¹¦£¬ÐÞÕýÔ­º¯Êý²¼¶ûÅÐ¶Ï´íÎó£©
			if (entry_addr != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module entry point (OEP) retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "main_module_entry_value", entry_addr);
				cJSON_AddStringToObject(response.result.get(), "main_module_entry_hex", format_address(entry_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "entry_desc", "Original Entry Point (OEP) of the debugged main module - execution starts here");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module entry point (no debugged process or invalid PE file)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module entry point");
		}

		return response;
	}

	// »ñÈ¡Ö÷Ä£¿é»ùµØÖ·£¨Module.GetMainModuleBase£©
	static ResponseData handle_get_main_module_base(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ö÷Ä£¿é»ùµØÖ·£¨Çø·ÖÆ½Ì¨£©
			unsigned long long module_base = 0;
#ifdef _WIN64
			module_base = Script::Module::GetMainModuleBase();
#else
			module_base = static_cast<unsigned long long>(Script::Module::GetMainModuleBase());
#endif

			// 3. ´¦Àí½á¹û£¨»ùµØÖ··Ç0±íÊ¾³É¹¦£¬ÐÞÕýÔ­º¯Êý²¼¶ûÅÐ¶Ï´íÎó£©
			if (module_base != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module base address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "main_module_base_value", module_base);
				cJSON_AddStringToObject(response.result.get(), "main_module_base_hex", format_address(module_base).c_str());
				cJSON_AddStringToObject(response.result.get(), "base_desc", "Load base address of the debugged main module in memory");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module base address (no debugged process or invalid main module)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module base address");
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡½ÚÇøÊýÁ¿£¨Module.SectionCountFromName£©
	static ResponseData handle_section_count_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get section count of kernel32.dll: [\"kernel32.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡½ÚÇøÊýÁ¿£¨Çø·ÖÆ½Ì¨£©
			unsigned long long section_count = 0;
#ifdef _WIN64
			section_count = Script::Module::SectionCountFromName(module_name.c_str());
#else
			section_count = static_cast<unsigned long long>(Script::Module::SectionCountFromName(module_name.c_str()));
#endif

			// 4. ´¦Àí½á¹û£¨½ÚÇøÊýÁ¿·Ç0±íÊ¾³É¹¦£¬PEÎÄ¼þÖÁÉÙÓÐ1¸ö½Ú£©
			if (section_count > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module section count from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_count", section_count);
				cJSON_AddStringToObject(response.result.get(), "count_desc", "Number of PE sections in the module (e.g., .text, .data, .rdata)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section count (module not loaded, invalid name, or non-PE file)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting section count from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éµØÖ·»ñÈ¡½ÚÇøÊýÁ¿£¨Module.SectionCountFromAddr£©
	static ResponseData handle_section_count_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get section count of module containing 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡½ÚÇøÊýÁ¿£¨Çø·ÖÆ½Ì¨£©
			unsigned long long section_count = 0;
#ifdef _WIN64
			section_count = Script::Module::SectionCountFromAddr(target_addr);
#else
			section_count = static_cast<unsigned long long>(Script::Module::SectionCountFromAddr(static_cast<duint>(target_addr)));
#endif

			// 4. ´¦Àí½á¹û£¨½ÚÇøÊýÁ¿·Ç0±íÊ¾³É¹¦£©
			if (section_count > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module section count from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_count", section_count);
				cJSON_AddStringToObject(response.result.get(), "count_desc", "Number of PE sections in the module containing the input address");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section count (address not in any loaded module or non-PE file)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting section count from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿éÃû³Æ£¨Module.GetModuleAt£©
	static ResponseData handle_get_module_at(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get module at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr))
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address format. Use hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}
			if (target_addr == 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Memory address cannot be 0 (invalid address)");
				cJSON_AddStringToObject(response.result.get(), "invalid_address_hex", format_address(target_addr).c_str());
				return response;
			}

			// 3. µ÷ÓÃ½Ó¿Ú»ñÈ¡Ä£¿éÃû³Æ£¨Ô­º¯Êý512×Ö½Ú»º³åÇø£©
			char module_name[512] = { 0 };
			BOOL get_success = DbgGetModuleAt(static_cast<duint>(target_addr), module_name);

			// 4. ´¦Àí½á¹û
			if (get_success && strlen(module_name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module name at address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name);
				cJSON_AddStringToObject(response.result.get(), "note", "Relies on DbgGetModuleAt (may differ from NameFromAddr in edge cases)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module name (address not in any loaded module)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module at address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}
	// »ñÈ¡µ÷ÊÔÆ÷´°¿Ú¾ä±ú£¨Module.GetWindowHandle£©
	static ResponseData handle_get_window_handle(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃ½Ó¿Ú»ñÈ¡´°¿Ú¾ä±ú£¨HWND×ªÊýÖµÀàÐÍ£¬Çø·ÖÆ½Ì¨£©
			unsigned long long window_handle = 0;
			HWND hwnd = GuiGetWindowHandle();
			if (hwnd != nullptr)
			{
#ifdef _WIN64
				window_handle = reinterpret_cast<unsigned long long>(hwnd);
#else
				window_handle = reinterpret_cast<unsigned long>(hwnd);
#endif
			}

			// 3. ´¦Àí½á¹û
			if (window_handle != 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Debugger window handle retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "window_handle_value", window_handle);
				cJSON_AddStringToObject(response.result.get(), "window_handle_hex", format_address(window_handle).c_str());
				cJSON_AddStringToObject(response.result.get(), "handle_desc", "HWND of the debugger's main window (used for Windows API operations like ShowWindow)");
				cJSON_AddStringToObject(response.result.get(), "warning", "This is the debugger's own window handle, not related to the debugged process's modules");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get debugger window handle (debugger GUI not initialized)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting debugger window handle");
		}

		return response;
	}

	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿éÍêÕûÐÅÏ¢£¨Module.GetInfoFromAddr£©
	static ResponseData handle_get_info_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get module info at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A > 0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr <= 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid address. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡Ä£¿éÍêÕûÐÅÏ¢£¨¸´ÓÃGetInfoFromAddrÂß¼­£©
			module_info module_data = GetInfoFromAddr(static_cast<duint>(target_addr));

			// 4. Ð£Ñé½á¹¹ÌåÓÐÐ§ÐÔ£¨»ùÖ··Ç0»òÃû³Æ·Ç¿Õ±íÊ¾ÓÐÐ§£©
			if (module_data.base != 0 || strlen(module_data.name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module full info from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());

				// ¹¹½¨Ä£¿éÐÅÏ¢JSON¶ÔÏó£¨Ó³Éämodule_info½á¹¹Ìå£©
				cJSON* module_info_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(module_info_obj, "base_address_value", module_data.base);
				cJSON_AddStringToObject(module_info_obj, "base_address_hex", format_address(module_data.base).c_str());
				cJSON_AddNumberToObject(module_info_obj, "module_size_bytes", module_data.size);
				cJSON_AddNumberToObject(module_info_obj, "section_count", module_data.sectionCount);
				cJSON_AddStringToObject(module_info_obj, "module_name", module_data.name);
				cJSON_AddStringToObject(module_info_obj, "module_full_path", module_data.path);
				cJSON_AddItemToObject(response.result.get(), "module_info", module_info_obj);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module full info (address not in any loaded module)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module full info from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}

	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡Ä£¿éÍêÕûÐÅÏ¢£¨Module.GetInfoFromName£©
	static ResponseData handle_get_info_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get module info of kernel32.dll: [\"kernel32.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡Ä£¿éÍêÕûÐÅÏ¢£¨¸´ÓÃGetInfoFromNameÂß¼­£©
			module_info module_data = GetInfoFromName(const_cast<char*>(module_name.c_str()));

			// 4. Ð£Ñé½á¹¹ÌåÓÐÐ§ÐÔ
			if (module_data.base != 0 || strlen(module_data.name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module full info from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());

				// ¹¹½¨Ä£¿éÐÅÏ¢JSON¶ÔÏó
				cJSON* module_info_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(module_info_obj, "base_address_value", module_data.base);
				cJSON_AddStringToObject(module_info_obj, "base_address_hex", format_address(module_data.base).c_str());
				cJSON_AddNumberToObject(module_info_obj, "module_size_bytes", module_data.size);
				cJSON_AddNumberToObject(module_info_obj, "section_count", module_data.sectionCount);
				cJSON_AddStringToObject(module_info_obj, "module_name", module_data.name);
				cJSON_AddStringToObject(module_info_obj, "module_full_path", module_data.path);
				cJSON_AddItemToObject(response.result.get(), "module_info", module_info_obj);

				// ÌáÊ¾Ô­º¯ÊýÇ±ÔÚÎÊÌâ
				cJSON_AddStringToObject(response.result.get(), "warning", "Original function marked 'has issues' - verify info consistency with other interfaces");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get module full info (module not loaded or invalid name)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module full info from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}
	// ¸ù¾ÝµØÖ·ºÍ½ÚÐòºÅ»ñÈ¡½ÚÇøÐÅÏ¢£¨Module.GetSectionFromAddr£©
	static ResponseData handle_get_section_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä£¿éµØÖ· + ½ÚÐòºÅ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [module_address(hex/decimal)] [section_index(non-negative integer)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get section 0 of module at 0x00400000: [\"0x00400000\", \"0\"]");
			return response;
		}

		const std::string addr_str = params[0];
		const std::string index_str = params[1];

		try
		{
			// 2. ½âÎöÄ£¿éµØÖ·£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A > 0£©
			unsigned long long module_addr = 0;
			if (!parse_value(addr_str, module_addr) || module_addr <= 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid module address. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. ½âÎö½ÚÐòºÅ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_B >= 0£©
			int section_index = -1;
			try
			{
				size_t pos;
				section_index = std::stoi(index_str, &pos);
				if (pos != index_str.size() || section_index < 0)
				{
					throw std::invalid_argument("Non-negative integer required");
				}
			}
			catch (const std::exception&)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid section index. Use non-negative integer (e.g., 0, 1, 2)");
				cJSON_AddStringToObject(response.result.get(), "invalid_index", index_str.c_str());
				return response;
			}

			// 4. µ÷ÓÃÔ­º¯Êý»ñÈ¡½ÚÇøÐÅÏ¢£¨¸´ÓÃGetSectionFromAddrÂß¼­£©
			addr_module_info section_data = GetSectionFromAddr(
				static_cast<duint>(module_addr),
				static_cast<duint>(section_index)
				);

			// 5. Ð£Ñé½á¹¹ÌåÓÐÐ§ÐÔ£¨½ÚµØÖ··Ç0»òÃû³Æ·Ç¿Õ±íÊ¾ÓÐÐ§£©
			if (section_data.addr != 0 || strlen(section_data.name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Section info retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "module_address_value", module_addr);
				cJSON_AddStringToObject(response.result.get(), "module_address_hex", format_address(module_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_index", section_index);

				// ¹¹½¨½ÚÇøÐÅÏ¢JSON¶ÔÏó£¨Ó³Éäaddr_module_info½á¹¹Ìå£©
				cJSON* section_info_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(section_info_obj, "section_address_value", section_data.addr);
				cJSON_AddStringToObject(section_info_obj, "section_address_hex", format_address(section_data.addr).c_str());
				cJSON_AddNumberToObject(section_info_obj, "section_size_bytes", section_data.size);
				cJSON_AddStringToObject(section_info_obj, "section_name", section_data.name);
				cJSON_AddItemToObject(response.result.get(), "section_info", section_info_obj);

				cJSON_AddStringToObject(response.result.get(), "note", "Section index starts from 0 (0 = first section, e.g., .text)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section info (invalid module address or section index out of range)");
				cJSON_AddStringToObject(response.result.get(), "module_address_hex", format_address(module_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_index", section_index);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting section info");
			cJSON_AddStringToObject(response.result.get(), "module_address", addr_str.c_str());
			cJSON_AddStringToObject(response.result.get(), "section_index", index_str.c_str());
		}

		return response;
	}
	// ¸ù¾ÝÄ£¿éÃûºÍ½ÚÐòºÅ»ñÈ¡½ÚÇøÐÅÏ¢£¨Module.GetSectionFromName£©
	static ResponseData handle_get_section_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë2¸ö²ÎÊý£¨Ä£¿éÃû + ½ÚÐòºÅ£©
		if (params.size() != 2)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 2: [module_name(including extension)] [section_index(non-negative integer)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get section 0 of kernel32.dll: [\"kernel32.dll\", \"0\"]");
			return response;
		}

		const std::string module_name = params[0];
		const std::string index_str = params[1];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. ½âÎö½ÚÐòºÅ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A >= 0£©
			int section_index = -1;
			try
			{
				size_t pos;
				section_index = std::stoi(index_str, &pos);
				if (pos != index_str.size() || section_index < 0)
				{
					throw std::invalid_argument("Non-negative integer required");
				}
			}
			catch (const std::exception&)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid section index. Use non-negative integer (e.g., 0, 1, 2)");
				cJSON_AddStringToObject(response.result.get(), "invalid_index", index_str.c_str());
				return response;
			}

			// 4. µ÷ÓÃÔ­º¯Êý»ñÈ¡½ÚÇøÐÅÏ¢£¨¸´ÓÃGetSectionFromNameÂß¼­£©
			addr_module_info section_data = GetSectionFromName(
				const_cast<char*>(module_name.c_str()),
				static_cast<duint>(section_index)
				);

			// 5. Ð£Ñé½á¹¹ÌåÓÐÐ§ÐÔ£¨½ÚµØÖ··Ç0»òÃû³Æ·Ç¿Õ±íÊ¾ÓÐÐ§£©
			if (section_data.addr != 0 || strlen(section_data.name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Section info from module name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_index", section_index);

				// ¹¹½¨½ÚÇøÐÅÏ¢JSON¶ÔÏó£¨Ó³Éäaddr_module_info½á¹¹Ìå£©
				cJSON* section_info_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(section_info_obj, "section_address_value", section_data.addr);
				cJSON_AddStringToObject(section_info_obj, "section_address_hex", format_address(section_data.addr).c_str());
				cJSON_AddNumberToObject(section_info_obj, "section_size_bytes", section_data.size);
				cJSON_AddStringToObject(section_info_obj, "section_name", section_data.name);
				cJSON_AddItemToObject(response.result.get(), "section_info", section_info_obj);

				cJSON_AddStringToObject(response.result.get(), "note", "Section index starts from 0 (0 = first section, e.g., .text)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section info (module not loaded or section index out of range)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_index", section_index);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting section info from module name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
			cJSON_AddStringToObject(response.result.get(), "section_index", index_str.c_str());
		}

		return response;
	}
	// ¸ù¾ÝµØÖ·»ñÈ¡Ä£¿é½ÚÇøÁÐ±í£¨Module.GetSectionListFromAddr£©
	static ResponseData handle_get_section_list_from_addr(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨ÄÚ´æµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [memory_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get all sections of module at 0x00401000: [\"0x00401000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A > 0£©
			unsigned long long target_addr = 0;
			if (!parse_value(addr_str, target_addr) || target_addr <= 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid module address. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡½ÚÇøÁÐ±í£¨¸´ÓÃGetSectionListFromAddrÂß¼­£©
			std::vector<local_section_list> section_list;
			duint section_count = GetSectionListFromAddr(static_cast<duint>(target_addr), section_list);

			// 4. ´¦Àí½á¹û£¨½ÚÇøÊýÁ¿>0±íÊ¾ÓÐÐ§£©
			if (section_count > 0 && !section_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module section list from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "input_address_value", target_addr);
				cJSON_AddStringToObject(response.result.get(), "input_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_count", section_count);

				// ¹¹½¨½ÚÇøÁÐ±íJSONÊý×é£¨Ó³Éälocal_section_listÏòÁ¿£©
				cJSON* sections_array = cJSON_CreateArray();
				for (const auto& sec : section_list)
				{
					cJSON* sec_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(sec_obj, "section_address_value", sec.address);
					cJSON_AddStringToObject(sec_obj, "section_address_hex", format_address(sec.address).c_str());
					cJSON_AddStringToObject(sec_obj, "section_name", sec.name);
					cJSON_AddNumberToObject(sec_obj, "section_size_bytes", sec.size);
					cJSON_AddItemToArray(sections_array, sec_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "sections", sections_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section list (address not in any loaded module or no sections)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(target_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_section_count", section_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting section list from address");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}
	// ¸ù¾ÝÄ£¿éÃû»ñÈ¡Ä£¿é½ÚÇøÁÐ±í£¨Module.GetSectionListFromName£©
	static ResponseData handle_get_section_list_from_name(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get all sections of kernel32.dll: [\"kernel32.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡½ÚÇøÁÐ±í£¨¸´ÓÃGetSectionListFromNameÂß¼­£©
			std::vector<local_section_list> section_list;
			duint section_count = GetSectionListFromName(const_cast<char*>(module_name.c_str()), section_list);

			// 4. ´¦Àí½á¹û
			if (section_count > 0 && !section_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module section list from name retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_count", section_count);

				// ¹¹½¨½ÚÇøÁÐ±íJSONÊý×é
				cJSON* sections_array = cJSON_CreateArray();
				for (const auto& sec : section_list)
				{
					cJSON* sec_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(sec_obj, "section_address_value", sec.address);
					cJSON_AddStringToObject(sec_obj, "section_address_hex", format_address(sec.address).c_str());
					cJSON_AddStringToObject(sec_obj, "section_name", sec.name);
					cJSON_AddNumberToObject(sec_obj, "section_size_bytes", sec.size);
					cJSON_AddItemToArray(sections_array, sec_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "sections", sections_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section list (module not loaded or no sections)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_section_count", section_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting section list from name");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}
	// »ñÈ¡Ö÷Ä£¿éÍêÕûÐÅÏ¢£¨Module.GetMainModuleInfoEx£©
	static ResponseData handle_get_main_module_info_ex(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡Ö÷Ä£¿éÐÅÏ¢£¨¸´ÓÃGetMainModuleInfoExÂß¼­£©
			module_info main_module_data = GetMainModuleInfoEx();

			// 3. Ð£Ñé½á¹¹ÌåÓÐÐ§ÐÔ£¨»ùÖ··Ç0»òÃû³Æ·Ç¿Õ±íÊ¾ÓÐÐ§£©
			if (main_module_data.base != 0 || strlen(main_module_data.name) > 0)
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Main module full info retrieved successfully");

				// ¹¹½¨Ö÷Ä£¿éÐÅÏ¢JSON¶ÔÏó£¨Ó³Éämodule_info½á¹¹Ìå£©
				cJSON* module_info_obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(module_info_obj, "base_address_value", main_module_data.base);
				cJSON_AddStringToObject(module_info_obj, "base_address_hex", format_address(main_module_data.base).c_str());
				cJSON_AddNumberToObject(module_info_obj, "module_size_bytes", main_module_data.size);
				cJSON_AddNumberToObject(module_info_obj, "section_count", main_module_data.sectionCount);
				cJSON_AddStringToObject(module_info_obj, "module_name", main_module_data.name);
				cJSON_AddStringToObject(module_info_obj, "module_full_path", main_module_data.path);
				cJSON_AddItemToObject(response.result.get(), "main_module_info", module_info_obj);

				cJSON_AddStringToObject(response.result.get(), "note", "Main module refers to the primary executable being debugged");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get main module info (no debugged process or invalid main module)");
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting main module full info");
		}

		return response;
	}
	// ¸ù¾ÝµØÖ·»ñÈ¡¼ÓÔØ³ÌÐò½Ú±í£¨Module.GetSection£©
	static ResponseData handle_get_section(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éµØÖ·£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_address(hex/decimal)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get sections of module at 0x00400000: [\"0x00400000\"]");
			return response;
		}

		const std::string addr_str = params[0];

		try
		{
			// 2. ½âÎöµØÖ·²¢Ð£ÑéÓÐÐ§ÐÔ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_int_A > 0£©
			unsigned long long module_addr = 0;
			if (!parse_value(addr_str, module_addr) || module_addr <= 0)
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Invalid module address. Use positive hex (0x...) or decimal");
				cJSON_AddStringToObject(response.result.get(), "invalid_address", addr_str.c_str());
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡½ÚÇøÁÐ±í£¨¸´ÓÃGetLocalSectionÂß¼­£©
			std::vector<local_section> section_list = GetLocalSection(static_cast<duint>(module_addr));
			int section_count = static_cast<int>(section_list.size());

			// 4. ´¦Àí½á¹û
			if (section_count > 0 && !section_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Module section table from address retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "module_address_value", module_addr);
				cJSON_AddStringToObject(response.result.get(), "module_address_hex", format_address(module_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_count", section_count);

				// ¹¹½¨½ÚÇøÁÐ±íJSONÊý×é£¨ÓëGetSectionListFromAddr¸ñÊ½Í³Ò»£©
				cJSON* sections_array = cJSON_CreateArray();
				for (const auto& sec : section_list)
				{
					cJSON* sec_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(sec_obj, "section_address_value", sec.address);
					cJSON_AddStringToObject(sec_obj, "section_address_hex", format_address(sec.address).c_str());
					cJSON_AddStringToObject(sec_obj, "section_name", sec.name);
					cJSON_AddNumberToObject(sec_obj, "section_size_bytes", sec.size);
					cJSON_AddItemToArray(sections_array, sec_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "sections", sections_array);

				cJSON_AddStringToObject(response.result.get(), "note", "Function is functionally equivalent to GetSectionListFromAddr (unified response format)");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get section table (invalid module address or no sections)");
				cJSON_AddStringToObject(response.result.get(), "target_address_hex", format_address(module_addr).c_str());
				cJSON_AddNumberToObject(response.result.get(), "section_count", section_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module section table");
			cJSON_AddStringToObject(response.result.get(), "target_address", addr_str.c_str());
		}

		return response;
	}
	// »ñÈ¡ËùÓÐ¼ÓÔØµÄÄ£¿é£¨Module.GetAllModule£©
	static ResponseData handle_get_all_module(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÎÞÐè²ÎÊý£¨»ñÈ¡ËùÓÐÄ£¿é£¬ÎÞÐèÊäÈë£©
		if (!params.empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "No parameters required for this interface");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			return response;
		}

		try
		{
			// 2. µ÷ÓÃÔ­º¯Êý»ñÈ¡ËùÓÐÄ£¿éÁÐ±í£¨¸´ÓÃGetLocalModuleÂß¼­£©
			std::vector<all_module_info> module_list = GetLocalModule();
			int module_count = static_cast<int>(module_list.size());

			// 3. ´¦Àí½á¹û£¨Ä£¿éÊýÁ¿>0±íÊ¾ÓÐÐ§£©
			if (module_count > 0 && !module_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "All loaded modules retrieved successfully");
				cJSON_AddNumberToObject(response.result.get(), "total_module_count", module_count);
				cJSON_AddStringToObject(response.result.get(), "note", "Includes system DLLs (e.g., kernel32.dll) and user modules (e.g., notepad.exe)");

				// ¹¹½¨Ä£¿éÁÐ±íJSONÊý×é£¨Ó³Éäall_module_infoÏòÁ¿£©
				cJSON* modules_array = cJSON_CreateArray();
				for (const auto& mod : module_list)
				{
					cJSON* mod_obj = cJSON_CreateObject();
					// »ùÖ·£¨ÊýÖµ+Ê®Áù½øÖÆ£©
					cJSON_AddNumberToObject(mod_obj, "base_address_value", mod.base);
					cJSON_AddStringToObject(mod_obj, "base_address_hex", format_address(mod.base).c_str());
					// Èë¿Úµã£¨OEP£©
					cJSON_AddNumberToObject(mod_obj, "entry_point_value", mod.entry);
					cJSON_AddStringToObject(mod_obj, "entry_point_hex", format_address(mod.entry).c_str());
					// Ãû³Æ¡¢Â·¾¶¡¢´óÐ¡
					cJSON_AddStringToObject(mod_obj, "module_name", mod.name);
					cJSON_AddStringToObject(mod_obj, "module_full_path", mod.path);
					cJSON_AddNumberToObject(mod_obj, "module_size_bytes", mod.size);
					cJSON_AddItemToArray(modules_array, mod_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "modules", modules_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get loaded modules (no debugged process or no modules loaded)");
				cJSON_AddNumberToObject(response.result.get(), "detected_module_count", module_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting all loaded modules");
		}

		return response;
	}
	// »ñÈ¡Ö¸¶¨Ä£¿éµÄµ¼Èë±í£¨Module.GetImport£©
	static ResponseData handle_get_import(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get imports of notepad.exe: [\"notepad.exe\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡µ¼Èë±í£¨¸´ÓÃGetLocalModuleImportÂß¼­£©
			std::vector<all_module_import> import_list = GetLocalModuleImport(const_cast<char*>(module_name.c_str()));
			int import_count = static_cast<int>(import_list.size());

			// 4. ´¦Àí½á¹û£¨µ¼Èëº¯ÊýÊýÁ¿>0±íÊ¾ÓÐÐ§£©
			if (import_count > 0 && !import_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Import table of module retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "total_import_count", import_count);
				cJSON_AddStringToObject(response.result.get(), "note", "Imported functions are from other modules (e.g., user32.dll->MessageBoxA)");

				// ¹¹½¨µ¼Èë±íJSONÊý×é£¨Ó³Éäall_module_importÏòÁ¿£©
				cJSON* imports_array = cJSON_CreateArray();
				for (const auto& imp : import_list)
				{
					cJSON* imp_obj = cJSON_CreateObject();
					cJSON_AddStringToObject(imp_obj, "function_name", imp.name);                  // º¯ÊýÃû£¨¿ÉÄÜ´øÐÞÊÎ£©
					cJSON_AddStringToObject(imp_obj, "undecorated_function_name", imp.undecorated_name); // Î´ÐÞÊÎÃû£¨Èç"MessageBoxA"£©
					cJSON_AddNumberToObject(imp_obj, "iat_va_value", imp.iat_va);                // IATÐéÄâµØÖ·
					cJSON_AddStringToObject(imp_obj, "iat_va_hex", format_address(imp.iat_va).c_str());
					cJSON_AddNumberToObject(imp_obj, "iat_rva_value", imp.iat_rva);              // IATÏà¶ÔÐéÄâµØÖ·
					cJSON_AddStringToObject(imp_obj, "iat_rva_hex", format_address(imp.iat_rva).c_str());
					cJSON_AddNumberToObject(imp_obj, "function_ordinal", imp.ordinal);            // º¯ÊýÐòºÅ£¨0±íÊ¾ÎÞÐòºÅ£©
					cJSON_AddItemToArray(imports_array, imp_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "import_functions", imports_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get import table (module not loaded or no imported functions)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_import_count", import_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module import table");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}
	// »ñÈ¡Ö¸¶¨Ä£¿éµÄµ¼³ö±í£¨Module.GetExport£©
	static ResponseData handle_get_export(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 1. ²ÎÊýÐ£Ñé£ºÐè´«Èë1¸ö²ÎÊý£¨Ä£¿éÃû£©
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid parameter count. Expected 1: [module_name(including extension)]");
			cJSON_AddNumberToObject(response.result.get(), "received_count", params.size());
			cJSON_AddStringToObject(response.result.get(), "example", "Get exports of kernel32.dll: [\"kernel32.dll\"]");
			return response;
		}

		const std::string module_name = params[0];

		try
		{
			// 2. Ð£ÑéÄ£¿éÃû·Ç¿Õ£¨Ô­º¯ÊýÅÐ¶Ïptr.Command_String_A[0] != '\0'£©
			if (module_name.empty())
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Module name cannot be empty");
				return response;
			}

			// 3. µ÷ÓÃÔ­º¯Êý»ñÈ¡µ¼³ö±í£¨¸´ÓÃGetLocalModuleExportÂß¼­£©
			std::vector<all_module_export> export_list = GetLocalModuleExport(const_cast<char*>(module_name.c_str()));
			int export_count = static_cast<int>(export_list.size());

			// 4. ´¦Àí½á¹û£¨µ¼³öº¯ÊýÊýÁ¿>0±íÊ¾ÓÐÐ§£©
			if (export_count > 0 && !export_list.empty())
			{
				response.success = true;
				cJSON_AddStringToObject(response.result.get(), "message", "Export table of module retrieved successfully");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "total_export_count", export_count);
				cJSON_AddStringToObject(response.result.get(), "note", "Exported functions are callable by other modules (e.g., kernel32.dll->GetProcAddress)");

				// ¹¹½¨µ¼³ö±íJSONÊý×é£¨Ó³Éäall_module_exportÏòÁ¿£©
				cJSON* exports_array = cJSON_CreateArray();
				for (const auto& exp : export_list)
				{
					cJSON* exp_obj = cJSON_CreateObject();
					cJSON_AddStringToObject(exp_obj, "function_name", exp.name);                  // º¯ÊýÃû
					cJSON_AddStringToObject(exp_obj, "forwarded_name", exp.forward_name);        // ×ª·¢Ãû£¨Èç"ntdll.RtlAllocateHeap"£¬¿Õ±íÊ¾·Ç×ª·¢£©
					cJSON_AddStringToObject(exp_obj, "undecorated_function_name", exp.undecorate_name); // Î´ÐÞÊÎÃû
					cJSON_AddBoolToObject(exp_obj, "is_forwarded", exp.forwarded != 0);          // ÊÇ·ñ×ª·¢º¯Êý
					cJSON_AddNumberToObject(exp_obj, "function_va_value", exp.va);                // º¯ÊýÐéÄâµØÖ·
					cJSON_AddStringToObject(exp_obj, "function_va_hex", format_address(exp.va).c_str());
					cJSON_AddNumberToObject(exp_obj, "function_rva_value", exp.rva);              // º¯ÊýÏà¶ÔÐéÄâµØÖ·
					cJSON_AddStringToObject(exp_obj, "function_rva_hex", format_address(exp.rva).c_str());
					cJSON_AddNumberToObject(exp_obj, "function_ordinal", exp.ordinal);            // º¯ÊýÐòºÅ
					cJSON_AddItemToArray(exports_array, exp_obj);
				}
				cJSON_AddItemToObject(response.result.get(), "export_functions", exports_array);
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "error", "Failed to get export table (module not loaded or no exported functions)");
				cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
				cJSON_AddNumberToObject(response.result.get(), "detected_export_count", export_count);
			}

#ifdef _WIN64
			cJSON_AddStringToObject(response.result.get(), "platform", "x64");
#else
			cJSON_AddStringToObject(response.result.get(), "platform", "x86");
#endif
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unexpected error while getting module export table");
			cJSON_AddStringToObject(response.result.get(), "target_module_name", module_name.c_str());
		}

		return response;
	}
};

// ÇëÇó´¦ÀíÆ÷
class RequestHandler
{
public:
	ResponseData handle_request(const RequestData& data)
	{
		switch (data.type)
		{
		case RequestType::Debugger_Wait:
			return DebuggerHandler::handle_wait(data.params);
		case RequestType::Debugger_Run:
			return DebuggerHandler::handle_run(data.params);
		case RequestType::Debugger_Pause:
			return DebuggerHandler::handle_pause(data.params);
		case RequestType::Debugger_Stop:
			return DebuggerHandler::handle_stop(data.params);
		case RequestType::Debugger_StepIn:
			return DebuggerHandler::handle_step_in(data.params);
		case RequestType::Debugger_StepOut:
			return DebuggerHandler::handle_step_out(data.params);
		case RequestType::Debugger_StepOver:
			return DebuggerHandler::handle_step_over(data.params);
		case RequestType::Debugger_IsDebugger:
			return DebuggerHandler::handle_is_debugger(data.params);
		case RequestType::Debugger_IsRunning:
			return DebuggerHandler::handle_is_running(data.params);
		case RequestType::Debugger_IsRunningLocked:
			return DebuggerHandler::handle_is_running_locked(data.params);
		case RequestType::Debugger_OpenDebug:
			return DebuggerHandler::handle_open_debug(data.params);
		case RequestType::Debugger_CloseDebug:
			return DebuggerHandler::handle_close_debug(data.params);
		case RequestType::Debugger_DetachDebug:
			return DebuggerHandler::handle_detach_debug(data.params);
		case RequestType::Debugger_ShowBreakPoint:
			return DebuggerHandler::handle_show_break_point(data.params);
		case RequestType::Debugger_SetBreakPoint:
			return DebuggerHandler::handle_set_break_point(data.params);
		case RequestType::Debugger_DeleteBreakPoint:
			return DebuggerHandler::handle_delete_break_point(data.params);
		case RequestType::Debugger_CheckBreakPoint:
			return DebuggerHandler::handle_check_break_point(data.params);
		case RequestType::Debugger_CheckBreakDisable:
			return DebuggerHandler::handle_check_break_disable(data.params);
		case RequestType::Debugger_CheckBreakPointType:
			return DebuggerHandler::handle_check_break_point_type(data.params);
		case RequestType::Debugger_SetHardwareBreakPoint:
			return DebuggerHandler::handle_set_hardware_break_point(data.params);
		case RequestType::Debugger_DeleteHardwareBreakPoint:
			return DebuggerHandler::handle_delete_hardware_break_point(data.params);
		case RequestType::Debugger_GetRegister:
			return DebuggerHandler::handle_get_register(data.params);
		case RequestType::Debugger_GetEAX: return DebuggerHandler::handle_get_eax(data.params);
		case RequestType::Debugger_GetAX: return DebuggerHandler::handle_get_ax(data.params);
		case RequestType::Debugger_GetAH: return DebuggerHandler::handle_get_ah(data.params);
		case RequestType::Debugger_GetAL: return DebuggerHandler::handle_get_al(data.params);
		case RequestType::Debugger_GetEBX: return DebuggerHandler::handle_get_ebx(data.params);
		case RequestType::Debugger_GetBX: return DebuggerHandler::handle_get_bx(data.params);
		case RequestType::Debugger_GetBH: return DebuggerHandler::handle_get_bh(data.params);
		case RequestType::Debugger_GetBL: return DebuggerHandler::handle_get_bl(data.params);
		case RequestType::Debugger_GetECX: return DebuggerHandler::handle_get_ecx(data.params);
		case RequestType::Debugger_GetCX: return DebuggerHandler::handle_get_cx(data.params);
		case RequestType::Debugger_GetCH: return DebuggerHandler::handle_get_ch(data.params);
		case RequestType::Debugger_GetCL: return DebuggerHandler::handle_get_cl(data.params);
		case RequestType::Debugger_GetEDX: return DebuggerHandler::handle_get_edx(data.params);
		case RequestType::Debugger_GetDX: return DebuggerHandler::handle_get_dx(data.params);
		case RequestType::Debugger_GetDH: return DebuggerHandler::handle_get_dh(data.params);
		case RequestType::Debugger_GetDL: return DebuggerHandler::handle_get_dl(data.params);
		case RequestType::Debugger_GetEDI: return DebuggerHandler::handle_get_edi(data.params);
		case RequestType::Debugger_GetDI: return DebuggerHandler::handle_get_di(data.params);
		case RequestType::Debugger_GetESI: return DebuggerHandler::handle_get_esi(data.params);
		case RequestType::Debugger_GetSI: return DebuggerHandler::handle_get_si(data.params);
		case RequestType::Debugger_GetEBP: return DebuggerHandler::handle_get_ebp(data.params);
		case RequestType::Debugger_GetBP: return DebuggerHandler::handle_get_bp(data.params);
		case RequestType::Debugger_GetESP: return DebuggerHandler::handle_get_esp(data.params);
		case RequestType::Debugger_GetSP: return DebuggerHandler::handle_get_sp(data.params);
		case RequestType::Debugger_GetEIP: return DebuggerHandler::handle_get_eip(data.params);
		case RequestType::Debugger_GetDR0: return DebuggerHandler::handle_get_dr0(data.params);
		case RequestType::Debugger_GetDR1: return DebuggerHandler::handle_get_dr1(data.params);
		case RequestType::Debugger_GetDR2: return DebuggerHandler::handle_get_dr2(data.params);
		case RequestType::Debugger_GetDR3: return DebuggerHandler::handle_get_dr3(data.params);
		case RequestType::Debugger_GetDR6: return DebuggerHandler::handle_get_dr6(data.params);
		case RequestType::Debugger_GetDR7: return DebuggerHandler::handle_get_dr7(data.params);
		case RequestType::Debugger_GetCAX: return DebuggerHandler::handle_get_cax(data.params);
		case RequestType::Debugger_GetCBX: return DebuggerHandler::handle_get_cbx(data.params);
		case RequestType::Debugger_GetCCX: return DebuggerHandler::handle_get_ccx(data.params);
		case RequestType::Debugger_GetCDX: return DebuggerHandler::handle_get_cdx(data.params);
		case RequestType::Debugger_GetCSI: return DebuggerHandler::handle_get_csi(data.params);
		case RequestType::Debugger_GetCDI: return DebuggerHandler::handle_get_cdi(data.params);
		case RequestType::Debugger_GetCBP: return DebuggerHandler::handle_get_cbp(data.params);
		case RequestType::Debugger_GetCSP: return DebuggerHandler::handle_get_csp(data.params);
		case RequestType::Debugger_GetCIP: return DebuggerHandler::handle_get_cip(data.params);
		case RequestType::Debugger_GetCFLAGS: return DebuggerHandler::handle_get_cflags(data.params);
		case RequestType::Debugger_GetZF: return DebuggerHandler::handle_get_zf(data.params);
		case RequestType::Debugger_GetOF: return DebuggerHandler::handle_get_of(data.params);
		case RequestType::Debugger_GetCF: return DebuggerHandler::handle_get_cf(data.params);
		case RequestType::Debugger_GetPF: return DebuggerHandler::handle_get_pf(data.params);
		case RequestType::Debugger_GetSF: return DebuggerHandler::handle_get_sf(data.params);
		case RequestType::Debugger_GetTF: return DebuggerHandler::handle_get_tf(data.params);
		case RequestType::Debugger_GetAF: return DebuggerHandler::handle_get_af(data.params);
		case RequestType::Debugger_GetDF: return DebuggerHandler::handle_get_df(data.params);
		case RequestType::Debugger_GetIF: return DebuggerHandler::handle_get_if(data.params);
		case RequestType::Debugger_GetFlagRegister: return DebuggerHandler::handle_get_flag_register(data.params);
		case RequestType::Debugger_SetRegister: return DebuggerHandler::handle_set_register(data.params);
		case RequestType::Debugger_SetEAX: return DebuggerHandler::handle_set_eax(data.params);
		case RequestType::Debugger_SetAX: return DebuggerHandler::handle_set_ax(data.params);
		case RequestType::Debugger_SetAH: return DebuggerHandler::handle_set_ah(data.params);
		case RequestType::Debugger_SetAL: return DebuggerHandler::handle_set_al(data.params);
		case RequestType::Debugger_SetEBX: return DebuggerHandler::handle_set_ebx(data.params);
		case RequestType::Debugger_SetBX: return DebuggerHandler::handle_set_bx(data.params);
		case RequestType::Debugger_SetBH: return DebuggerHandler::handle_set_bh(data.params);
		case RequestType::Debugger_SetBL: return DebuggerHandler::handle_set_bl(data.params);
		case RequestType::Debugger_SetECX: return DebuggerHandler::handle_set_ecx(data.params);
		case RequestType::Debugger_SetCX: return DebuggerHandler::handle_set_cx(data.params);
		case RequestType::Debugger_SetCH: return DebuggerHandler::handle_set_ch(data.params);
		case RequestType::Debugger_SetCL: return DebuggerHandler::handle_set_cl(data.params);
		case RequestType::Debugger_SetEDX: return DebuggerHandler::handle_set_edx(data.params);
		case RequestType::Debugger_SetDX: return DebuggerHandler::handle_set_dx(data.params);
		case RequestType::Debugger_SetDH: return DebuggerHandler::handle_set_dh(data.params);
		case RequestType::Debugger_SetDL: return DebuggerHandler::handle_set_dl(data.params);
		case RequestType::Debugger_SetEDI: return DebuggerHandler::handle_set_edi(data.params);
		case RequestType::Debugger_SetDI: return DebuggerHandler::handle_set_di(data.params);
		case RequestType::Debugger_SetESI: return DebuggerHandler::handle_set_esi(data.params);
		case RequestType::Debugger_SetSI: return DebuggerHandler::handle_set_si(data.params);
		case RequestType::Debugger_SetEBP: return DebuggerHandler::handle_set_ebp(data.params);
		case RequestType::Debugger_SetBP: return DebuggerHandler::handle_set_bp(data.params);
		case RequestType::Debugger_SetESP: return DebuggerHandler::handle_set_esp(data.params);
		case RequestType::Debugger_SetSP: return DebuggerHandler::handle_set_sp(data.params);
		case RequestType::Debugger_SetEIP: return DebuggerHandler::handle_set_eip(data.params);
		case RequestType::Debugger_SetDR0: return DebuggerHandler::handle_set_dr0(data.params);
		case RequestType::Debugger_SetDR1: return DebuggerHandler::handle_set_dr1(data.params);
		case RequestType::Debugger_SetDR2: return DebuggerHandler::handle_set_dr2(data.params);
		case RequestType::Debugger_SetDR3: return DebuggerHandler::handle_set_dr3(data.params);
		case RequestType::Debugger_SetDR6: return DebuggerHandler::handle_set_dr6(data.params);
		case RequestType::Debugger_SetDR7: return DebuggerHandler::handle_set_dr7(data.params);
		case RequestType::Debugger_SetCAX: return DebuggerHandler::handle_set_cax(data.params);
		case RequestType::Debugger_SetCBX: return DebuggerHandler::handle_set_cbx(data.params);
		case RequestType::Debugger_SetCCX: return DebuggerHandler::handle_set_ccx(data.params);
		case RequestType::Debugger_SetCDX: return DebuggerHandler::handle_set_cdx(data.params);
		case RequestType::Debugger_SetCSI: return DebuggerHandler::handle_set_csi(data.params);
		case RequestType::Debugger_SetCDI: return DebuggerHandler::handle_set_cdi(data.params);
		case RequestType::Debugger_SetCBP: return DebuggerHandler::handle_set_cbp(data.params);
		case RequestType::Debugger_SetCSP: return DebuggerHandler::handle_set_csp(data.params);
		case RequestType::Debugger_SetCIP: return DebuggerHandler::handle_set_cip(data.params);
		case RequestType::Debugger_SetCFlags: return DebuggerHandler::handle_set_cflags(data.params);
		case RequestType::Debugger_SetFlagRegister: return DebuggerHandler::handle_set_flag_register(data.params);
		case RequestType::Debugger_SetZF: return DebuggerHandler::handle_set_zf(data.params);
		case RequestType::Debugger_SetOF: return DebuggerHandler::handle_set_of(data.params);
		case RequestType::Debugger_SetCF: return DebuggerHandler::handle_set_cf(data.params);
		case RequestType::Debugger_SetPF: return DebuggerHandler::handle_set_pf(data.params);
		case RequestType::Debugger_SetSF: return DebuggerHandler::handle_set_sf(data.params);
		case RequestType::Debugger_SetTF: return DebuggerHandler::handle_set_tf(data.params);
		case RequestType::Debugger_SetAF: return DebuggerHandler::handle_set_af(data.params);
		case RequestType::Debugger_SetDF: return DebuggerHandler::handle_set_df(data.params);
		case RequestType::Debugger_SetIF: return DebuggerHandler::handle_set_if(data.params);

		case RequestType::Dissassembly_DisasmOneCode:
			return DissassemblyHandler::handle_disasm_one_code(data.params);
		case RequestType::Dissassembly_DisasmCountCode:
			return DissassemblyHandler::handle_disasm_count_code(data.params);
		case RequestType::Dissassembly_DisasmOperand:
			return DissassemblyHandler::handle_disasm_operand(data.params);
		case RequestType::Dissassembly_DisasmFastAtFunction:
			return DissassemblyHandler::handle_disasm_fast_at_function(data.params);
		case RequestType::Dissassembly_GetOperandSize:
			return DissassemblyHandler::handle_get_operand_size(data.params);
		case RequestType::Dissassembly_GetBranchDestination:
			return DissassemblyHandler::handle_get_branch_destination(data.params);
		case RequestType::Dissassembly_GuiGetDisassembly:
			return DissassemblyHandler::handle_gui_get_disassembly(data.params);
		case RequestType::Dissassembly_AssembleMemoryEx:
			return DissassemblyHandler::handle_assemble_memory_ex(data.params);
		case RequestType::Dissassembly_AssembleCodeSize:
			return DissassemblyHandler::handle_assemble_code_size(data.params);
		case RequestType::Dissassembly_AssembleCodeHex:
			return DissassemblyHandler::handle_assemble_code_hex(data.params);
		case RequestType::Dissassembly_AssembleAtFunctionEx:
			return DissassemblyHandler::handle_assemble_at_function_ex(data.params);

		case RequestType::Module_GetModuleBaseAddress:
			return ModuleHandler::handle_get_module_base_address(data.params);
		case RequestType::Module_GetModuleProcAddress:
			return ModuleHandler::handle_get_module_proc_address(data.params);
		case RequestType::Module_GetBaseFromAddr:
			return ModuleHandler::handle_get_base_from_addr(data.params);
		case RequestType::Module_GetBaseFromName:
			return ModuleHandler::handle_get_base_from_name(data.params);
		case RequestType::Module_GetSizeFromAddress:
			return ModuleHandler::handle_get_size_from_address(data.params);
		case RequestType::Module_GetSizeFromName:
			return ModuleHandler::handle_get_size_from_name(data.params);
		case RequestType::Module_GetOEPFromName:
			return ModuleHandler::handle_get_oep_from_name(data.params);
		case RequestType::Module_GetOEPFromAddr:
			return ModuleHandler::handle_get_oep_from_addr(data.params);
		case RequestType::Module_GetPathFromName:
			return ModuleHandler::handle_path_from_name(data.params);
		case RequestType::Module_GetPathFromAddr:
			return ModuleHandler::handle_path_from_addr(data.params);
		case RequestType::Module_GetNameFromAddr:
			return ModuleHandler::handle_name_from_addr(data.params);
		case RequestType::Module_GetMainModuleSectionCount:
			return ModuleHandler::handle_get_main_module_section_count(data.params);
		case RequestType::Module_GetMainModulePath:
			return ModuleHandler::handle_get_main_module_path(data.params);
		case RequestType::Module_GetMainModuleSize:
			return ModuleHandler::handle_get_main_module_size(data.params);
		case RequestType::Module_GetMainModuleName:
			return ModuleHandler::handle_get_main_module_name(data.params);
		case RequestType::Module_GetMainModuleEntry:
			return ModuleHandler::handle_get_main_module_entry(data.params);
		case RequestType::Module_GetMainModuleBase:
			return ModuleHandler::handle_get_main_module_base(data.params);
		case RequestType::Module_SectionCountFromName:
			return ModuleHandler::handle_section_count_from_name(data.params);
		case RequestType::Module_SectionCountFromAddr:
			return ModuleHandler::handle_section_count_from_addr(data.params);
		case RequestType::Module_GetModuleAt:
			return ModuleHandler::handle_get_module_at(data.params);
		case RequestType::Module_GetWindowHandle:
			return ModuleHandler::handle_get_window_handle(data.params);
		case RequestType::Module_GetInfoFromAddr:
			return ModuleHandler::handle_get_info_from_addr(data.params);
		case RequestType::Module_GetInfoFromName:
			return ModuleHandler::handle_get_info_from_name(data.params);
		case RequestType::Module_GetSectionFromAddr:
			return ModuleHandler::handle_get_section_from_addr(data.params);
		case RequestType::Module_GetSectionFromName:
			return ModuleHandler::handle_get_section_from_name(data.params);
		case RequestType::Module_GetSectionListFromAddr:
			return ModuleHandler::handle_get_section_list_from_addr(data.params);
		case RequestType::Module_GetSectionListFromName:
			return ModuleHandler::handle_get_section_list_from_name(data.params);
		case RequestType::Module_GetMainModuleInfoEx:
			return ModuleHandler::handle_get_main_module_info_ex(data.params);
		case RequestType::Module_GetSection:
			return ModuleHandler::handle_get_section(data.params);
		case RequestType::Module_GetAllModule:
			return ModuleHandler::handle_get_all_module(data.params);
		case RequestType::Module_GetImport:
			return ModuleHandler::handle_get_import(data.params);
		case RequestType::Module_GetExport:
			return ModuleHandler::handle_get_export(data.params);

		case RequestType::Memory_GetBase:
			return MemoryHandler::handle_get_memory_base(data.params);
		case RequestType::Memory_GetLocalBase:
			return MemoryHandler::handle_get_memory_local_base(data.params);
		case RequestType::Memory_GetSize:
			return MemoryHandler::handle_get_memory_size(data.params);
		case RequestType::Memory_GetLocalSize:
			return MemoryHandler::handle_get_memory_local_size(data.params);
		case RequestType::Memory_GetProtect:
			return MemoryHandler::handle_get_memory_protect(data.params);
		case RequestType::Memory_GetLocalProtect:
			return MemoryHandler::handle_get_memory_local_protect(data.params);
		case RequestType::Memory_GetLocalPageSize:
			return MemoryHandler::handle_get_memory_local_page_size(data.params);
		case RequestType::Memory_GetPageSize:
			return MemoryHandler::handle_get_memory_page_size(data.params);
		case RequestType::Memory_IsValidReadPtr:
			return MemoryHandler::handle_dbg_mem_is_valid_read_ptr(data.params);
		case RequestType::Memory_GetSectionMap:
			return MemoryHandler::handle_get_memory_section(data.params);
		case RequestType::Memory_SetProtect:
			return MemoryHandler::handle_set_memory_protect(data.params);
		case RequestType::Memory_GetXrefCountAt:
			return MemoryHandler::handle_memory_get_xref_count_at(data.params);
		case RequestType::Memory_GetXrefTypeAt:
			return MemoryHandler::handle_memory_get_xref_type_at(data.params);
		case RequestType::Memory_GetFunctionTypeAt:
			return MemoryHandler::handle_memory_get_function_type_at(data.params);
		case RequestType::Memory_IsJumpGoingToExecute:
			return MemoryHandler::handle_memory_is_jump_going_to_execute(data.params);
		case RequestType::Memory_RemoteAlloc:
			return MemoryHandler::handle_memory_remote_alloc(data.params);
		case RequestType::Memory_RemoteFree:
			return MemoryHandler::handle_memory_remote_free(data.params);
		case RequestType::Memory_StackPush:
			return MemoryHandler::handle_memory_stack_push(data.params);
		case RequestType::Memory_StackPop:
			return MemoryHandler::handle_memory_stack_pop(data.params);
		case RequestType::Memory_StackPeek:
			return MemoryHandler::handle_memory_stack_peek(data.params);
		case RequestType::Memory_ScanModule:
			return MemoryHandler::handle_memory_scan_module(data.params);
		case RequestType::Memory_ScanRange:
			return MemoryHandler::handle_memory_scan_range(data.params);
		case RequestType::Memory_ScanModuleAll:
			return MemoryHandler::handle_memory_scan_module_all(data.params);
		case RequestType::Memory_WritePattern:
			return MemoryHandler::handle_memory_write_pattern(data.params);
		case RequestType::Memory_ReplacePattern:
			return MemoryHandler::handle_memory_replace_pattern(data.params);
		case RequestType::Memory_ReadByte:
			return MemoryHandler::handle_read_memory_byte(data.params);
		case RequestType::Memory_ReadWord:
			return MemoryHandler::handle_read_memory_word(data.params);
		case RequestType::Memory_ReadDword:
			return MemoryHandler::handle_read_memory_dword(data.params);
#ifdef _WIN64
		case RequestType::Memory_ReadQword:
			return MemoryHandler::handle_read_memory_qword(data.params);
#endif
		case RequestType::Memory_ReadPtr:
			return MemoryHandler::handle_read_memory_ptr(data.params);
		case RequestType::Memory_WriteByte:
			return MemoryHandler::handle_write_memory_byte(data.params);
		case RequestType::Memory_WriteWord:
			return MemoryHandler::handle_write_memory_word(data.params);
		case RequestType::Memory_WriteDword:
			return MemoryHandler::handle_write_memory_dword(data.params);
#ifdef _WIN64
		case RequestType::Memory_WriteQword:
			return MemoryHandler::handle_write_memory_qword(data.params);
#endif
		case RequestType::Memory_WritePtr:
			return MemoryHandler::handle_write_memory_ptr(data.params);

		case RequestType::Process_GetThreadList:
			return ProcessHandler::handle_process_get_thread_list(data.params);
		case RequestType::Process_GetHandle:
			return ProcessHandler::handle_process_get_handle(data.params);
		case RequestType::Process_GetThreadHandle:
			return ProcessHandler::handle_process_get_thread_handle(data.params);
		case RequestType::Process_GetPid:
			return ProcessHandler::handle_process_get_pid(data.params);
		case RequestType::Process_GetTid:
			return ProcessHandler::handle_process_get_tid(data.params);
		case RequestType::Process_GetTeb:
			return ProcessHandler::handle_process_get_teb(data.params);
		case RequestType::Process_GetPeb:
			return ProcessHandler::handle_process_get_peb(data.params);
		case RequestType::Process_GetMainThreadId:
			return ProcessHandler::handle_process_get_main_thread_id(data.params);

		case RequestType::Script_RunCmd:
			return ScriptHandler::handle_script_run_cmd(data.params);
		case RequestType::Script_RunCmdRef:
			return ScriptHandler::handle_script_run_cmd_ref(data.params);
		case RequestType::Script_Load:
			return ScriptHandler::handle_script_load(data.params);
		case RequestType::Script_Unload:
			return ScriptHandler::handle_script_unload(data.params);
		case RequestType::Script_Run:
			return ScriptHandler::handle_script_run(data.params);
		case RequestType::Script_SetIp:
			return ScriptHandler::handle_script_set_ip(data.params);

		case RequestType::Gui_SetComment:
			return GuiHandler::handle_gui_set_comment(data.params);
		case RequestType::Gui_Log:
			return GuiHandler::handle_gui_log(data.params);
		case RequestType::Gui_AddStatusBarMessage:
			return GuiHandler::handle_gui_add_status_bar_message(data.params);
		case RequestType::Gui_ClearLog:
			return GuiHandler::handle_gui_clear_log(data.params);
		case RequestType::Gui_ShowCpu:
			return GuiHandler::handle_gui_show_cpu(data.params);
		case RequestType::Gui_UpdateAllViews:
			return GuiHandler::handle_gui_update_all_views(data.params);
		case RequestType::Gui_GetInput:
			return GuiHandler::handle_gui_get_input(data.params);
		case RequestType::Gui_Confirm:
			return GuiHandler::handle_gui_confirm(data.params);
		case RequestType::Gui_ShowMessage:
			return GuiHandler::handle_gui_show_message(data.params);
		case RequestType::Gui_AddArgumentBracket:
			return GuiHandler::handle_gui_add_argument_bracket(data.params);
		case RequestType::Gui_DelArgumentBracket:
			return GuiHandler::handle_gui_del_argument_bracket(data.params);
		case RequestType::Gui_AddFunctionBracket:
			return GuiHandler::handle_gui_add_function_bracket(data.params);
		case RequestType::Gui_DelFunctionBracket:
			return GuiHandler::handle_gui_del_function_bracket(data.params);
		case RequestType::Gui_AddLoopBracket:
			return GuiHandler::handle_gui_add_loop_bracket(data.params);
		case RequestType::Gui_DelLoopBracket:
			return GuiHandler::handle_gui_del_loop_bracket(data.params);
		case RequestType::Gui_SetLabel:
			return GuiHandler::handle_gui_set_label(data.params);
		case RequestType::Gui_ResolveLabel:
			return GuiHandler::handle_gui_resolve_label(data.params);
		case RequestType::Gui_ClearAllLabels:
			return GuiHandler::handle_gui_clear_all_labels(data.params);
		default:
			ResponseData response;
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown request type. Supported: Debugger.Wait, Debugger.Run");
			return response;
		}
	}
};

// È«¾Ö·þÎñÆ÷ÉÏÏÂÎÄ
static std::unique_ptr<ServerContext> g_server;

// ·þÎñÆ÷Ïß³Ìº¯Êý£¨¼ò»¯WindowsÊµÏÖ£©
static DWORD WINAPI server_thread_func(LPVOID param)
{
	// Ôö¼ÓÈ«¾ÖÉÏÏÂÎÄ¿ÕÖ¸ÕëÅÐ¶Ï£¬±ÜÃâ±ÀÀ£
	if (!g_server) return 1;

	while (g_server->running)
	{
		mg_mgr_poll(&g_server->mgr, 100);
	}
	return 0;
}

// ´¦ÀíPOSTÇëÇó£¨ÓÅ»¯JSON½âÎö´íÎóÌáÊ¾£©
static void handle_post_request(struct mg_http_message* http_msg, struct mg_connection* connection)
{
	// Ôö¼Ó²ÎÊý¿ÕÖ¸ÕëÅÐ¶Ï
	if (!http_msg || !connection) return;

	// ½âÎöJSONÇëÇó£¨Ê¹ÓÃ¸ü°²È«µÄ½âÎö·½Ê½£¬Ôö¼Ó´íÎóÌáÊ¾£©
	CJsonPtr req_json(cJSON_ParseWithLength(http_msg->body.buf, http_msg->body.len));
	if (!req_json)
	{
		const char* error = cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "Unknown parse error";
		mg_http_reply(connection, 400, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Invalid JSON: %s\", \"position\": \"%s\"}",
			error, cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown");
		return;
	}

	// ½âÎöÇëÇóÊý¾Ý
	RequestData req_data = RequestParser::parse(req_json.get());
	if (req_data.type == RequestType::Unknown)
	{
		mg_http_reply(connection, 400, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Invalid or unsupported request parameters\", \"supported_interfaces\": \"Debugger.Wait, Debugger.Run\"}");
		return;
	}

	// ´¦ÀíÇëÇó£¨Ôö¼ÓÈ«¾ÖÉÏÏÂÎÄ¿ÕÖ¸ÕëÅÐ¶Ï£©
	if (!g_server || !g_server->handler)
	{
		mg_http_reply(connection, 500, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Server context not initialized\"}");
		return;
	}
	ResponseData resp_data = g_server->handler->handle_request(req_data);

	// ¹¹½¨ÏìÓ¦JSON
	CJsonPtr resp_json(cJSON_CreateObject());
	cJSON_AddStringToObject(resp_json.get(), "status", resp_data.success ? "success" : "error");
	cJSON_AddItemToObject(resp_json.get(), "result", resp_data.result.release());
	cJSON_AddNumberToObject(resp_json.get(), "timestamp", static_cast<double>(mg_millis()));

	// ·¢ËÍÏìÓ¦
	char* resp_str = cJSON_PrintUnformatted(resp_json.get());
	if (resp_str)
	{
		mg_http_reply(connection, resp_data.success ? 200 : 400,
			"Content-Type: application/json\r\n", "%s", resp_str);
		free(resp_str);
	}
	else
	{
		mg_http_reply(connection, 500, "Content-Type: application/json\r\n",
			"{\"status\": \"error\", \"error\": \"Failed to generate response JSON\"}");
	}
}

// HTTPÊÂ¼þ»Øµ÷£¨ÐÞ¸´URIÆ¥ÅäÂß¼­£¬Ôö¼Ó²ÎÊýÐ£Ñé£©
static void ev_handler(struct mg_connection* connection, int ev, void* ev_data)
{
	// Ôö¼Ó²ÎÊý¿ÕÖ¸ÕëÅÐ¶Ï
	if (!connection || !ev_data) return;

	if (ev == MG_EV_HTTP_MSG)
	{
		struct mg_http_message* http_msg = static_cast<struct mg_http_message*>(ev_data);

		// ÑéÖ¤ÇëÇó·½·¨
		if (mg_strcmp(http_msg->method, mg_str("GET")) != 0 &&
			mg_strcmp(http_msg->method, mg_str("POST")) != 0)
		{
			mg_http_reply(connection, 405,
				"Content-Type: application/json\r\nAllow: GET, POST\r\n",
				"{\"status\": \"error\", \"error\": \"Method not allowed. Use GET or POST.\"}");
			return;
		}

		// ´¦ÀíGETÇëÇó - ²å¼þÐÅÏ¢£¨¸üÐÂsupported_apisÎªÊµ¼ÊÖ§³ÖµÄ½Ó¿Ú£©
		if (mg_strcmp(http_msg->method, mg_str("GET")) == 0 &&
			mg_strcmp(http_msg->uri, mg_str("/")) == 0)
		{
			// ¶¨Òå²å¼þÔªÐÅÏ¢£¨¹Ø¼ü£ºÍ¬²½supported_apisÓëÊµ¼Ê½Ó¿Ú£©
			const char* plugin_version = "2.0.0";
			const char* author = "WangRui";
			const char* description = "x64dbg HTTP Debugging Interface";
			const char* compile_date = __DATE__;
			const char* compile_time = __TIME__;
			const char* supported_apis = "Debugger.Wait, Debugger.Run"; // ÐÞ¸´£ºÉ¾³ýÔ­ÎÞÐ§½Ó¿Ú£¬Ìí¼ÓÊµ¼ÊÖ§³ÖµÄ½Ó¿Ú

			// ¹¹½¨ÏìÓ¦
			mg_http_reply(connection, 200, "Content-Type: application/json\r\n",
				"{"
				"\"status\": \"success\","
				"\"plugin_info\": {"
				"\"name\": \"%s\","
				"\"version\": \"%s\","
				"\"author\": \"%s\","
				"\"description\": \"%s\","
				"\"compile_date\": \"%s\","
				"\"compile_time\": \"%s\""
				"},"
				"\"server_info\": {"
				"\"api_version\": \"1.0.0\","
				"\"supported_interfaces\": \"%s\","
				"\"status\": \"running\""
				"}"
				"}",
				PLUGIN_NAME,
				plugin_version,
				author,
				description,
				compile_date,
				compile_time,
				supported_apis
				);
			return;
		}

		// ´¦ÀíPOSTÇëÇó - µ÷ÊÔÃüÁî£¨ÓÅ»¯URIÆ¥ÅäÂß¼­£¬Ôö¼Ó¿ÕÖ¸ÕëÅÐ¶Ï£©
		if (mg_strcmp(http_msg->method, mg_str("POST")) == 0 &&
			mg_strcmp(http_msg->uri, mg_str("/")) == 0)
		{
			handle_post_request(http_msg, connection);
		}
		else
		{
			// ÓÅ»¯404ÌáÊ¾£¬¸æÖªÕýÈ·µÄÇëÇóÂ·¾¶
			mg_http_reply(connection, 404, "Content-Type: application/json\r\n",
				"{\"status\": \"error\", \"error\": \"Resource not found\", \"hint\": \"Use POST /debug for commands, GET / for plugin info\"}");
		}
	}
}

// Æô¶¯·þÎñÆ÷£¨¼ò»¯WindowsÊµÏÖ£¬É¾³ýÈßÓà¿çÆ½Ì¨·ÖÖ§£©
static bool start_server()
{
	if (!g_server) return false;

	if (g_server->running)
	{
		_plugin_logprintf("[%s] HTTP server is already running on %s\n", PLUGIN_NAME, g_server->listen_addr.c_str());
		return true;
	}

	// ´´½¨¼àÌýÆ÷
	struct mg_connection* listener = mg_http_listen(&g_server->mgr,
		g_server->listen_addr.c_str(), ev_handler, nullptr);

	if (!listener)
	{
		char err_msg[256];
		strerror_s(err_msg, sizeof(err_msg), WSAGetLastError());
		_plugin_logprintf("[%s] Failed to start server on %s: %s\n", PLUGIN_NAME, g_server->listen_addr.c_str(), err_msg);
		return false;
	}

	// Æô¶¯·þÎñÆ÷Ïß³Ì£¨Windows×¨ÓÃÂß¼­£©
	g_server->running = true;
	g_server->thread = ThreadUtils::create_thread(server_thread_func);
	if (!g_server->thread)
	{
		g_server->running = false;
		_plugin_logprintf("[%s] Failed to create server thread\n", PLUGIN_NAME);
		return false;
	}

	_plugin_logprintf("[%s] Server started successfully on %s\n", PLUGIN_NAME, g_server->listen_addr.c_str());
	return true;
}

// ²å¼þ³õÊ¼»¯²¿·Ö
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
	if (!initStruct) return false;

	initStruct->pluginVersion = PLUGIN_VERSION;
	initStruct->sdkVersion = PLUG_SDKVERSION;
	strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
	pluginHandle = initStruct->pluginHandle;

	// ³õÊ¼»¯·þÎñÆ÷ÉÏÏÂÎÄ
	g_server = std::make_unique<ServerContext>();
	g_server->listen_addr = "http://0.0.0.0:8000";
	g_server->handler = new RequestHandler();

	// Æô¶¯·þÎñÆ÷
	if (!start_server())
	{
		_plugin_logprintf("[%s] Failed to start server during initialization\n", PLUGIN_NAME);
		return false;
	}

#define PLUGIN_NAME "LyScript AI"
#define PLUGIN_VERSION "2.0.0"
#define PLUGIN_AUTHOR "RuiWang"
#define PLUGIN_WEBSITE "https://lyscript.lyshark.com"
#define PLUGIN_COMPILE_DATE __DATE__ " " __TIME__

	// Êä³ö²å¼þ»ù±¾ÐÅÏ¢
	_plugin_logprintf("[%s] Version: %s\n", PLUGIN_NAME, PLUGIN_VERSION);
	_plugin_logprintf("[%s] Author: %s\n", PLUGIN_NAME, PLUGIN_AUTHOR);
	_plugin_logprintf("[%s] Official website: %s\n", PLUGIN_NAME, PLUGIN_WEBSITE);
	_plugin_logprintf("[%s] Compilation date: %s\n", PLUGIN_NAME, PLUGIN_COMPILE_DATE);
	_plugin_logprintf("[%s] Initialized successfully\n", PLUGIN_NAME);

	return true;
}

// ²å¼þ¹Ø±ÕºóÖ´ÐÐ
PLUG_EXPORT bool plugstop()
{
	if (g_server->running)
	{
		_plugin_logprintf("[%s] Stopping HTTP server...\n", PLUGIN_NAME);
		g_server->running = false;
		ThreadUtils::join_thread(g_server->thread);
		_plugin_logprintf("[%s] Server stopped\n", PLUGIN_NAME);
	}

	if (g_server->handler)
	{
		delete g_server->handler;
		g_server->handler = nullptr;
	}

	g_server.reset();
	_plugin_logprintf("[%s] Plugin terminated\n", PLUGIN_NAME);
	return true;
}

// ²å¼þ²Ëµ¥»æÖÆ²¿·Ö
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
	// ³õÊ¼»¯²å¼þ±äÁ¿
	hwndDlg = setupStruct->hwndDlg;
	hMenu = setupStruct->hMenu;
	hMenuDisasm = setupStruct->hMenuDisasm;
	hMenuDump = setupStruct->hMenuDump;
	hMenuStack = setupStruct->hMenuStack;

	if (!g_server->running)
	{
		start_server();
	}
	else
	{
		_plugin_logprintf("HTTP server is already running on %s\n", g_server->listen_addr.c_str());
	}
}
