#pragma once
#define INLINE inline
#define NOEXCEPT noexcept
#define SAFE_BUFFER __declspec(safebuffers)
#define LOAD_LIBRARY_NO_EXECUTE        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS*16
#define LOAD_LIBRARY_NO_CURRENT_PATH  LOAD_LIBRARY_NO_EXECUTE*2
#define GET_HEADER_DICTIONARY(pNtHeader, idx)  &(pNtHeader)->OptionalHeader.DataDirectory[idx]
#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif
#ifdef LOADER
#else
#include<Windows.h>
#include<vector>
#include<queue>
#include<mutex>
#include<functional>
#include<set>
#include<unordered_map>
#include<stack>
#include<Psapi.h>
#include<minwinbase.h>
#include<winternl.h>
#include<string>
#include<algorithm>
#include <cctype>
#include <locale>
#include<thread>
#include<stack>
#include <Dbghelp.h>
#include"CPeFile.h"
#pragma comment(lib,"Dbghelp.lib")

typedef struct _PEB_LDR_DATA_64 {
	UINT Length;
	UCHAR Initialized;
	UINT_PTR SsHandle;
	_LIST_ENTRY InLoadOrderModuleList;
	_LIST_ENTRY InMemoryOrderModuleList;
	_LIST_ENTRY InInitializationOrderModuleList;
}PEB_LDR_DATA64, * PPEB_LDR_DATA64, * PLDT, LDT;
namespace Win32 {
#if defined(_WIN64)
	typedef struct _LDR_DATA_TABLE_ENTRY64 {
		LIST_ENTRY64 InLoadOrderLinks;
		LIST_ENTRY64 InMemoryOrderLinks;
		LIST_ENTRY64 InInitializationOrderLinks;
		ULONG64 DllBase;//模块地址
		ULONG64 EntryPoint;//入口点
		ULONG64 SizeOfImage;//映像大小
		UNICODE_STRING FullDllName;//完整的dll路径
		UNICODE_STRING BaseDllName;//dll名
		ULONG Flags;//标志
		USHORT LoadCount;//加载次数
		USHORT TlsIndex;//tls索引
		LIST_ENTRY64 HashLinks;//hash链表
		ULONG64 SectionPointer;//区段指针
		ULONG64 CheckSum;//校验和
		ULONG64 TimeDateStamp;//时间戳 就是PE文件的时间戳
		ULONG64 LoadedImports;//加载的导入表
		ULONG64 EntryPointActivationContext;//激活上下文
		ULONG64 PatchInformation;//补丁信息
		LIST_ENTRY64 ForwarderLinks;//转发链表
		LIST_ENTRY64 ServiceTagLinks;//服务标签链表
		LIST_ENTRY64 StaticLinks;//静态链接
		ULONG64 ContextInformation;//上下文信息
		ULONG64 OriginalBase;//原始基址 重定位之前的基址 最佳装配地址
		LARGE_INTEGER LoadTime;//加载时间
	}LDR_DATA_TABLE_ENTRY_T, * PLDR_DATA_TABLE_ENTRY_T, LDRT;
	typedef struct _PEB_LDR_DATA_64 {
		UINT Length;
		UCHAR Initialized;
		UINT_PTR SsHandle;
		_LIST_ENTRY InLoadOrderModuleList;
		_LIST_ENTRY InMemoryOrderModuleList;
		_LIST_ENTRY InInitializationOrderModuleList;
	}PEB_LDR_DATA64, * PPEB_LDR_DATA64, * PLDT, LDT;
	typedef struct _PEB64 {
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR Spare;
		UCHAR Padding0[4];
		ULONG64 Mutant;
		ULONG64 ImageBaseAddress;
		PPEB_LDR_DATA64 Ldr;//dll 链表
	} PEB64, * PPEB64, UPEB;
#else
	typedef struct _PEB_LDR_DATA32 {
		ULONG Length;
		UCHAR Initialized;
		ULONG SsHandle;
		LIST_ENTRY32 InLoadOrderModuleList;
		LIST_ENTRY32 InMemoryOrderModuleList;
		LIST_ENTRY32 InInitializationOrderModuleList;
		ULONG EntryInProgress;
	} PEB_LDR_DATA32, * PPEB_LDR_DATA32, * PLDT, LDT;
	typedef struct _PEB32 {
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR Spare;
		ULONG Mutant;
		ULONG ImageBaseAddress;
		PPEB_LDR_DATA32 Ldr;
	} PEB32, * PPEB32, UPEB;
	typedef struct _UNICODE_STRING32 {
		uint16_t Length;
		uint16_t MaximumLength;
		uint32_t Buffer;
	} UNICODE_STRING32;
	typedef struct _LDR_DATA_TABLE_ENTRY32 {
		LIST_ENTRY32 InLoadOrderLinks;
		LIST_ENTRY32 InMemoryOrderLinks;
		LIST_ENTRY32 InInitializationOrderLinks;
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING32 FullDllName;
		UNICODE_STRING32 BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
		ULONG CheckSum;
		ULONG TimeDateStamp;
		ULONG LoadedImports;
		ULONG EntryPointActivationContext;
		ULONG PatchInformation;
		LIST_ENTRY32 ForwarderLinks;
		LIST_ENTRY32 ServiceTagLinks;
		LIST_ENTRY32 StaticLinks;
		ULONG ContextInformation;
		ULONG OriginalBase;
		LARGE_INTEGER LoadTime;
	} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32, LDRT;
#endif // (_WIN64)_
}
#include<chrono>
struct AutoLog {
	using Clock = std::chrono::high_resolution_clock;
	std::recursive_timed_mutex logmtx;
	Clock::time_point timepoint;
	std::string funcname;//存储函数名字
	SAFE_BUFFER inline AutoLog(const std::string& szName = "", const std::string& perfix = "") noexcept {
		timepoint = Clock::now();
		std::unique_lock<decltype(logmtx)> lock(logmtx);//加锁使得多线程下不会出现问题
		funcname = szName + " " + perfix;//函数的名字拼接上前缀
		std::cout << funcname << "---> Begin\n";//当构造的时候会自动打印函数开始

	}
	SAFE_BUFFER inline  ~AutoLog() noexcept {//当对象析构的时候会自动调用
		auto end = Clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - timepoint).count();
		std::unique_lock<decltype(logmtx)> lock(logmtx);//加锁使得多线程下不会出现问题
		std::cout << funcname << "---> End  Time:"<<duration<<"ms\n";//打印函数结束和函数运行时间
	}
};
#ifdef _DEBUG
#define AUTOLOG  AutoLog log(__FUNCTION__,"");//直接打印函数名字
#else
#define AUTOLOG
#endif
namespace libraryloader {
	const DWORD PDB70 = 0x53445352; // 'RSDS' in little endian
	const DWORD PDB20 = 0x3031424e;// '01BN'
	struct CV_HEADER {
		uint32_t Sig;         // 签名
		uint32_t Length;      // 内容长度
		uint16_t MjrVer;      // 主版本
		uint16_t MinVer;      // 次版本
		uint32_t PdbSig;      // PDB 签名
		uint32_t Age;         // 年龄
		char PdbFileName[1];  // PDB 文件名
	};
	typedef struct CV_INFO_PDB20_ {
		CV_HEADER Header;
		DWORD Signature;    // seconds since 01.01.1970
		DWORD Age;          // an always-incrementing value
		BYTE PdbFileName[1];// zero terminated string with the name of the PDB file
	} CV_INFO_PDB20, * PCV_INFO_PDB20;
	typedef struct _CV_INFO_PDB70 {
		DWORD CvSignature;
		GUID Signature;
		DWORD Age;
		BYTE PdbFileName[1];
	} CV_INFO_PDB70, * PCV_INFO_PDB70;
	static std::unordered_map<std::string, void*> SelfLoadModules;
	class NormalHandle {//阐明了句柄的关闭方式和句柄的无效值 clarify the handle close method and the invalid value of the handle
	public:
		INLINE  static void Close(HANDLE handle)NOEXCEPT { CloseHandle(handle); }
		INLINE static HANDLE InvalidHandle()NOEXCEPT { return INVALID_HANDLE_VALUE; }
		INLINE static bool IsValid(HANDLE handle)NOEXCEPT { return handle != InvalidHandle() && handle; }
		INLINE static DWORD Wait(HANDLE handle,DWORD millionsedcond) {
			return WaitForSingleObject(handle, millionsedcond);
		}
	};
	class FileHandle {
	public:
		INLINE  static void Close(HANDLE handle)NOEXCEPT { FindClose(handle); }
		INLINE static HANDLE InvalidHandle()NOEXCEPT { return INVALID_HANDLE_VALUE; }
		INLINE static bool IsValid(HANDLE handle)NOEXCEPT { return handle != InvalidHandle() && handle; }
	};
	template<typename T>
	struct HandleView :public T {
	public:
		INLINE static void Close(HANDLE handle) NOEXCEPT {}
	};
	template<class T, class Traits>
	class GenericHandle {//利用RAII机制管理句柄 use RAII mechanism to manage handle
	private:
		T m_handle = Traits::InvalidHandle();
		bool m_bOwner = false;//所有者 owner
		INLINE bool IsValid()NOEXCEPT { return Traits::IsValid(m_handle); }
	public:
		GenericHandle() {

		}
		GenericHandle(const T& handle, bool bOwner = true) :m_handle(handle), m_bOwner(bOwner) {}//构造 m_bOwner默认为true construct m_bOwner default is true
		~GenericHandle() {
			Close();
		}
		void Close() {
			if (m_bOwner && IsValid()) {//当句柄的所有者为true并且句柄有效时 When the handle owner is true and the handle is valid
				Traits::Close(m_handle);//关闭句柄 close handle
				m_handle = Traits::InvalidHandle();//设置句柄为无效值 set handle to invalid value
				m_bOwner = false;//设置句柄所有者为false set handle owner to false
			}
		}
		GenericHandle(GenericHandle&) = delete;//禁止拷贝构造函数 disable copy constructor
		GenericHandle& operator =(const GenericHandle&) = delete;//禁止拷贝赋值函数 disable copy assignment
		INLINE GenericHandle& operator =(GenericHandle&& other)NOEXCEPT {   //移动赋值 move assignment
			m_handle = other.m_handle;
			m_bOwner = other.m_bOwner;
			other.m_handle = Traits::InvalidHandle();
			other.m_bOwner = false;
			return *this;
		}
		INLINE GenericHandle(GenericHandle&& other)NOEXCEPT {//移动构造 move construct
			m_handle = other.m_handle;
			m_bOwner = other.m_bOwner;
			other.m_handle = Traits::InvalidHandle();
			other.m_bOwner = false;
		}
		INLINE operator T() NOEXCEPT {//将m_handle转换为T类型,实际就是句柄的类型 convert m_handle to T type,actually is the type of handle
			return m_handle;
		}
		T& GetHandle() {
			m_bOwner = true;
			return	m_handle;
		}
		INLINE HANDLE* operator&() NOEXCEPT {
			return &m_handle;
		}
		INLINE operator bool() NOEXCEPT {//重载bool类型,判断句柄是否有效 overload bool type, judge handle is valid
			return IsValid();
		}
		DWORD Wait(DWORD millionSecond = INFINITE) {
			return (IsValid())?Traits::Wait(m_handle, millionSecond): WAIT_FAILED;
		}
	};
	using THANDLE = GenericHandle<HANDLE, NormalHandle>;
	using FHANDLE = GenericHandle<HANDLE, FileHandle>;
	using _THANDLE = GenericHandle<HANDLE, HandleView<NormalHandle>>;
	bool EnableDebugPrivilege() {
		THANDLE thToken;
		LUID sedebugnameValue;
		TOKEN_PRIVILEGES tkp{};
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &thToken)) {
			std::cerr << "OpenProcessToken error: " << GetLastError();
			return false;
		}
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
			std::cerr << "LookupPrivilegeValue error: " << GetLastError();
			return false;
		}
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = sedebugnameValue;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(thToken, false, &tkp, sizeof(tkp), NULL, NULL)) {
			std::cerr << "AdjustTokenPrivileges error: " << GetLastError();
			return false;
		}
		return true;
	}
	static auto init = EnableDebugPrivilege();
	enum class EnumStatus {
		ENUMSTOP,
		ENUMCONTINUE,
	};
	template<typename Pre>
	SAFE_BUFFER INLINE void GetModules(Pre bin) {
		auto pLdr = (LDT*)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
		auto pData = (Win32::LDRT*)pLdr->InLoadOrderModuleList.Blink;
		auto pFirst = pData;
		do {
			if (EnumStatus::ENUMSTOP == bin(*pData))break;
			pData = (Win32::LDRT*)pData->InLoadOrderLinks.Blink;
		} while (pData != pFirst && pData->DllBase);
	}
	static inline std::vector<std::string> GetImportDirectory() {
		std::vector<std::string> PathList;//程序默认搜索目录
		PathList.reserve(0x1000);
		char szPath[MAX_PATH]{};
		std::ignore = GetSystemDirectoryA(szPath, MAX_PATH);
		PathList.push_back(szPath);
		std::ignore = GetWindowsDirectoryA(szPath, MAX_PATH);
		PathList.push_back(szPath);
		char* szEnvPath = nullptr;
		_dupenv_s(&szEnvPath, nullptr, "PATH");
		char* szEnvPathTemp = szEnvPath;
		while (szEnvPathTemp) {
			char* szEnvPathTemp2 = strchr(szEnvPathTemp, ';');
			if (szEnvPathTemp2) {
				*szEnvPathTemp2 = '\0';
				PathList.emplace_back(szEnvPathTemp);
				szEnvPathTemp = szEnvPathTemp2 + 1;
			}else {
				PathList.emplace_back(szEnvPathTemp);
				break;
			}
		}
		PathList.erase(std::remove_if(PathList.begin(), PathList.end(), [](std::string& path) {return path.length() == 0; }), PathList.end());
		std::sort(PathList.begin(), PathList.end());
		PathList.erase(std::unique(PathList.begin(), PathList.end()), PathList.end());
		std::sort(PathList.begin(), PathList.end(), [](std::string& path1, std::string& path2) {return path1.length() < path2.length(); });
		std::ignore = GetCurrentDirectoryA(MAX_PATH, szPath);
		PathList.push_back(szPath);
		return PathList;
	}

	template<typename Pre>SAFE_BUFFER INLINE void GetFiles(const std::string& path,Pre bin, bool recursion = true) {
		WIN32_FIND_DATAA findData{};
		std::stack<std::string> directories;
		directories.push(path);
		while (!directories.empty()) {
			std::string currentPath = directories.top();
			directories.pop();
			for (std::tuple<BOOL, FHANDLE> packet{ TRUE, FindFirstFileA((currentPath + "\\*").c_str(), &findData) }; std::get<0>(packet); std::get<0>(packet) = FindNextFileA(std::get<1>(packet), &findData)) {
				const std::string fileName = findData.cFileName;
				if (fileName != "." && fileName != "..") {
					const std::string fullPath = currentPath + "\\" + fileName;
					if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && recursion) {
						if(!fullPath.empty())directories.emplace(fullPath);
					}else {
						if (EnumStatus::ENUMSTOP == bin(fullPath))return;
					}
				}
			}
		}
	}
	class FileMap {
		THANDLE     m_hFileMap;
		LPVOID      m_lpFileBase;
		bool RAII;
	public:
		FileMap(HANDLE hFile,DWORD _Protect= PAGE_READONLY, DWORD dwDesiredAccess= FILE_MAP_READ,bool Raii=true){
			if (!NormalHandle::IsValid(hFile)) return;
			m_hFileMap=CreateFileMappingA(hFile, NULL, _Protect, 0, 0, NULL);
			m_lpFileBase = MapViewOfFile(m_hFileMap, dwDesiredAccess, 0, 0, 0);
			if (!m_lpFileBase) throw std::bad_alloc();
			RAII = Raii;
		}
		INLINE LPVOID GetMap()NOEXCEPT {
			return m_lpFileBase;
		}
		INLINE operator LPVOID()NOEXCEPT {
			return m_lpFileBase;
		}
		void NotClose() {
			RAII = false;
		}
		~FileMap() {
			if (m_lpFileBase&& RAII) {
				UnmapViewOfFile(m_lpFileBase);
			}
		}
	};
	std::string GetFileExtension(const std::string& filePath) {
		// 查找最后一个点的位置
		size_t dotPos = filePath.find_last_of(".");
		// 查找最后一个路径分隔符的位置
		size_t slashPos = filePath.find_last_of("/\\");
		// 确保点的位置在分隔符之后或者没有分隔符
		if (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos)) {
			return filePath.substr(dotPos + 1); // 返回扩展名
		}
		return ""; // 如果没有扩展名，返回空字符串
	}
	std::pair<std::string, std::string> GetFileNameAndPath(const std::string& fullPath) {
		size_t slashPos = fullPath.find_last_of("/\\");
		std::string fileName = (slashPos != std::string::npos) ? fullPath.substr(slashPos + 1) : fullPath;
		std::string directoryPath = (slashPos != std::string::npos) ? fullPath.substr(0, slashPos) : "";
		return { fileName, directoryPath }; // Return as a pair
	}
	std::string GetFullPath(const std::string& dllname) {
		auto ext = GetFileExtension(dllname);
		std::string returnstr;
		static auto dependenciesPath = GetImportDirectory();
		std::vector<std::string> extpaths;
		for (auto& path : dependenciesPath) {
			GetFiles(path, [&](const std::string& filepath)->EnumStatus {
				if (GetFileExtension(filepath) == ext) {
					extpaths.emplace_back(filepath);
				}
				return EnumStatus::ENUMCONTINUE;
			}, false);
		}
		std::unordered_map<std::string, std::string> extmap;
		for (auto& dllpath : extpaths) {
			auto pair = GetFileNameAndPath(dllpath);
			extmap.insert(pair);
		}
		auto iter=extmap.find(dllname);
		if (iter != extmap.end())returnstr = iter->second + "\\" + iter->first;
		return returnstr;
	}
	template<typename T>
	class SingleTon{
	protected:
		SingleTon() = default;
		~SingleTon() = default;
		SingleTon(const SingleTon&) = delete;
		SingleTon& operator=(const SingleTon&) = delete;
		SingleTon(SingleTon&&) = delete;
		SingleTon& operator=(SingleTon&&) = delete;
	public:
		static T& GetInstance() {
			static T instance;
			return instance;
		}
	};
	struct LastError:public SingleTon<LastError>{
		LastError& operator=(DWORD value) {
			SetLastError(value);
			return *this;
		}
		operator DWORD() {
			return GetLastError();
		}
		operator bool() {
			return GetLastError() == ERROR_SUCCESS;
		}
	};
	std::string getDllFileName(const std::string& dllPath) {
		size_t lastSlash = dllPath.find_last_of("\\/");
		if (lastSlash != std::string::npos) {
			return dllPath.substr(lastSlash + 1);
		}
		return dllPath; // 没有分隔符时返回原路径
	}
	bool caseInsensitiveCompare(const std::string& str, const std::wstring& wstr) {
		if (str.size() != wstr.size()) return false;
		return std::equal(str.begin(), str.end(), wstr.begin(),
			[](char a, wchar_t b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
	}
	static BOOL CheckSize(size_t size, size_t expected) {//判断大小
		if (size < expected) {
			SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}
		return TRUE;
	}
	static INLINE bool CheckAddrReadable(LPVOID Address) noexcept {
		if (reinterpret_cast<ULONG_PTR>(Address) < 0x00001000) return false;
#ifdef _WIN64
		bool isUserSpace = (reinterpret_cast<ULONG_PTR>(Address) <= 0x00007FFFFFFFFFFF);
#else
		bool isUserSpace = (reinterpret_cast<ULONG_PTR>(Address) < 0x80000000);
#endif
		if (!isUserSpace) return false;
		MEMORY_BASIC_INFORMATION mbi{};
		// 查询地址的内存信息
		if (VirtualQuery(Address, &mbi, sizeof(mbi)) == 0) {
			// VirtualQuery 失败
			return false;
		}
		// 确保地址有效并且是可读的
		return (mbi.State == MEM_COMMIT) &&
			(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
	}
	struct ThreadInitializer {
		static DWORD mainThreadId;
	};
	static ThreadInitializer initializer;
	DWORD ThreadInitializer::mainThreadId = GetCurrentThreadId();
	class MemoryPE {
		std::string& fileName;
		LPVOID fileImage;
		DWORD fileSize;
		PIMAGE_DOS_HEADER m_pDosHeader;
		PIMAGE_NT_HEADERS m_pNtHeader;
		PIMAGE_SECTION_HEADER m_pSectionHeader;
		void* m_VirtualAddress;
		INLINE unsigned int GetAlignedSize(unsigned int OriginalData, unsigned int Alignment) //OriginalData原始数据 Alignment对齐边界
		{
			//Alignment必须是2的幂
			if (Alignment & (Alignment - 1)) return -1;
			return (OriginalData + Alignment - 1) & ~(Alignment - 1);
		}
	public:
		MemoryPE(std::string _fileName, LPVOID _fileImage, DWORD _fileSize) :fileName(_fileName), fileImage(_fileImage), fileSize(_fileSize) {
			m_pDosHeader = (PIMAGE_DOS_HEADER)fileImage;
			m_pNtHeader = (PIMAGE_NT_HEADERS) & ((const unsigned char*)(fileImage))[m_pDosHeader->e_lfanew];
			m_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_pNtHeader + sizeof(IMAGE_NT_HEADERS));
		}
		~MemoryPE() {}
		INLINE int GetVirtualSize() {
			int MemoryAlign = m_pNtHeader->OptionalHeader.SectionAlignment;   //段对齐字节数
			auto sectionsum = GetAlignedSize(m_pNtHeader->OptionalHeader.SizeOfHeaders, MemoryAlign);
			auto pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_pNtHeader + sizeof(IMAGE_NT_HEADERS));
			for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; ++i) {
				int iTureCodeSize = pSectionHeader[i].Misc.VirtualSize;     //没有按照文件和内存粒度对齐
				int iFileAlignCodeSize = pSectionHeader[i].SizeOfRawData;   //按照文件粒度对齐
				int iMaxSize = (iFileAlignCodeSize > iTureCodeSize) ? (iFileAlignCodeSize) : (iTureCodeSize);
				int iSectionSize = GetAlignedSize(pSectionHeader[i].VirtualAddress + iMaxSize, MemoryAlign);
				if (sectionsum < (unsigned int)iSectionSize) {
					sectionsum = iSectionSize;   //Use the Max
				}
			}
			return sectionsum;
		}
		bool Run() {
			AUTOLOG
			auto& lasterror = LastError::GetInstance();
			lasterror = ERROR_SUCCESS;
			if (!IsDosHeaderValid()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//头不是dos格式
				std::cerr << "Dos header is not valid." << std::endl;
				return lasterror;
			}
			if (!IsNtHeaderValid()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//判断头部是不是pe
				std::cerr << "Nt header is not valid." << std::endl;
				return lasterror;
			}
			if (!IsDllFileFormat()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//文件不是dll
				std::cerr << "File is not a DLL." << std::endl;
				return lasterror;
			}
			if (!IsOptionalHeaderSizeCorrect()) {
				lasterror = ERROR_INCORRECT_SIZE;//文件可选头大小不符合
				std::cerr << "Optional header size is incorrect." << std::endl;
				return lasterror;
			}
			if (!HasExports()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//判断有无导出表
				std::cerr << "No exports found." << std::endl;
				return lasterror;
			}
			if (!AllocateVirtualMemory()) {
				lasterror = ERROR_NOT_ENOUGH_MEMORY;
				std::cerr << "Failed to allocate virtual memory." << std::endl;
				return lasterror;
			}
			if (!CopyDataSections()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//拷贝节区失败
				std::cerr << "Failed to copy data sections." << std::endl;
				return lasterror;
			}
			if (!FixImportTable()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//修正导入表失败 注意还有一个叫做导入指针表的	IAT （Import Address Table） 和这个不一样
				std::cerr << "Failed to fix import table." << std::endl;
				return lasterror;
			}
			if (!FixRelocationTable()) {
				lasterror = ERROR_ILLEGAL_DLL_RELOCATION;//修正重定位表失败
				std::cerr << "Failed to fix relocation table." << std::endl;
				return lasterror;
			}
			if (!FixTLSTable()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//修正TLS表失败
				std::cerr << "Failed to fix TLS table." << std::endl;
				return lasterror;
			}
			if (!Flush()) {
				lasterror = ERROR_INVALID_ADDRESS;//刷新指令缓存失败
				std::cerr << "Failed to flush instruction cache." << std::endl;
				return lasterror;
			}
			if (!ExecuteDLLMain()) {
				FreeVirtualMemory();//m_VirtualAddress = nullptr;
				lasterror = ERROR_BAD_DLL_ENTRYPOINT;//	执行dllmain失败
				std::cerr << "Failed to execute DLLMain." << std::endl;
				return lasterror;
			}
			return lasterror;
		}
		DWORD RvaToOffset(DWORD rva, IMAGE_SECTION_HEADER* sections, int numberOfSections) {
			for (int i = 0; i < numberOfSections; i++) {
				if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].SizeOfRawData) {
					return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
				}
			}
			return 0;
		}
		INLINE bool IsDosHeaderValid() {
			AUTOLOG
			if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {//判断头部魔数确定其为pe格式
				return false;
			}
			if (m_pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) == 0) {
				return false;
			}
			return true;
		}
		INLINE bool IsNtHeaderValid() {
			AUTOLOG
			if (m_pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
				return false;
			}
			if (m_pNtHeader->FileHeader.Machine != HOST_MACHINE) {
				return false;
			}
			if ((m_pNtHeader->OptionalHeader.SectionAlignment & 1)!=0) {
				return false;
			}
			return true;
		}
		INLINE bool IsDllFileFormat() {
			AUTOLOG
			if ((m_pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)return false;
			return true;
		}
		INLINE bool IsExecutableImage() {
			AUTOLOG
			if ((m_pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)return false;
			return true;
		}
		INLINE bool IsOptionalHeaderSizeCorrect() {
			AUTOLOG
			if (m_pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER)){
				return false;
			}
			return true;
		}
		INLINE void* AllocateVirtualMemory() {
			AUTOLOG
			auto ImageLength = GetVirtualSize();
			m_VirtualAddress= VirtualAlloc(NULL, ImageLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			return m_VirtualAddress;
		}
		INLINE bool FreeVirtualMemory() {
			AUTOLOG
			if (m_VirtualAddress) {
				VirtualFree(m_VirtualAddress, 0, MEM_RELEASE);
				m_VirtualAddress = nullptr;
				return true;
			}
			return false;
		}
		INLINE BOOL FixImportTable() {
			AUTOLOG
			ULONG ulOffset = m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_IMPORT))return TRUE;    // 没有导入表
			auto ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)m_VirtualAddress + ulOffset);
			std::stack<std::string> dllnames;
			// 遍历导入表，获取所有 DLL 名称
			while (ImageImportDescriptor->Characteristics != 0) {
				std::string szDllName((char*)((PBYTE)m_VirtualAddress + ImageImportDescriptor->Name));
				if (!szDllName.empty())dllnames.push(szDllName);
				ImageImportDescriptor++;
			}
			// 遍历 DLL 名称栈，修复 IAT
			while (!dllnames.empty()) {
				std::string dllname = dllnames.top();
				dllnames.pop();
				if (dllname.empty())continue;
				// 重新遍历 ImageImportDescriptor 来找到对应的 DLL
				ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)m_VirtualAddress + ulOffset);
				while (ImageImportDescriptor->Characteristics != 0) {
					std::string currentDllName((char*)((PBYTE)
						m_VirtualAddress + ImageImportDescriptor->Name));
					if (currentDllName == dllname)break; // 找到对应的 DLL
					ImageImportDescriptor++;
				}
				if (ImageImportDescriptor->Characteristics == 0)return FALSE;  // 如果没有找到对应的 DLL，返回错误
				auto hDll = GetModuleHandleA(dllname.c_str());
				if (hDll == NULL)hDll = LoadLibraryA(dllname.c_str());
				if (!hDll) return false;
				// 获取 FirstThunk 和 OriginalFirstThunk
				auto FirstThunkData = (PIMAGE_THUNK_DATA)((PBYTE)m_VirtualAddress + ImageImportDescriptor->FirstThunk);
				auto OriginalThunkData = (PIMAGE_THUNK_DATA)((PBYTE)m_VirtualAddress + ImageImportDescriptor->OriginalFirstThunk);
				for (int i = 0;; i++) {
					if (OriginalThunkData[i].u1.Function == 0)break; // 到达表的末尾
					FARPROC FunctionAddress = NULL;
					// 判断是按序号导出还是按名称导出
					if (OriginalThunkData[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						// 按序号导出
						DWORD ordinal = OriginalThunkData[i].u1.Ordinal & ~IMAGE_ORDINAL_FLAG;
						FunctionAddress = GetProcAddress(hDll, (char*)ordinal);
					}else {
						// 按名称导出
						auto ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)m_VirtualAddress + OriginalThunkData[i].u1.AddressOfData);
						FunctionAddress = GetProcAddress(hDll, (char*)ImageImportByName->Name);
					}
					// 如果找到了函数地址，则修复 IAT
					if (FunctionAddress != NULL) {
#ifdef _WIN64
						FirstThunkData[i].u1.Function = (ULONGLONG)FunctionAddress;
#else
						FirstThunkData[i].u1.Function = (DWORD)FunctionAddress;
#endif
					}else {
						return FALSE;  // 如果函数地址为空，返回错误
					}
				}
			}
			LastError::GetInstance()=ERROR_SUCCESS;
			return TRUE;  // 成功修复 IT
		}
		INLINE bool FixExceptionTable() {
			AUTOLOG
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_EXCEPTION)) return true;//如果没有一场表就不做后续处理
			

		}
		INLINE bool FixRelocationTable(){
			AUTOLOG
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_BASERELOC)) return true;
			//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
			//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
			auto BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)m_VirtualAddress +
				m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			if (!BaseRelocation) return false;
			while ((BaseRelocation->VirtualAddress + BaseRelocation->SizeOfBlock) != 0){
				auto RelocationData = (WORD*)((PBYTE)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
				//计算本节需要修正的重定位项(地址)的数目
				int NumberOfRelocation = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				for (int i = 0; i < NumberOfRelocation; i++)
				{
					// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
					// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。
					if ((DWORD)(RelocationData[i] & 0xF000) == 0x0000A000){
						//64位Dll重定位，IMAGE_REL_BASED_DIR64
						//对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的
#ifdef _WIN64
						auto Address = (ULONGLONG*)((PBYTE)m_VirtualAddress + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
						auto  ulDelta = (ULONGLONG)m_VirtualAddress - m_pNtHeader->OptionalHeader.ImageBase;
						*Address += ulDelta;
#endif
					}else if ((DWORD)(RelocationData[i] & 0xF000) == 0x00003000){
						//32位dll重定位，IMAGE_REL_BASED_HIGHLOW
						//对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
#ifndef _WIN64
						DWORD* Address = (DWORD*)((PBYTE)ImageData + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
						DWORD  dwDelta = (DWORD)ImageData - m_NtHeader->OptionalHeader.ImageBase;
						*Address += dwDelta;
#endif
					}
				}
				//转移到下一个节进行处理
				BaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseRelocation + BaseRelocation->SizeOfBlock);
			}
			return true;
		}
		INLINE bool CopyDataSections(){
			AUTOLOG
			//计算需要复制的PE头+段表字节数
			int HeaderLength = m_pNtHeader->OptionalHeader.SizeOfHeaders;
			//复制头和段信息
			if(!HeaderLength) return false;
			if (!m_VirtualAddress)	return false;
			memcpy(m_VirtualAddress, fileImage, HeaderLength);
			//复制每个节
			for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; ++i){
				if (m_pSectionHeader[i].VirtualAddress == 0 || m_pSectionHeader[i].SizeOfRawData == 0)continue;
				//定义该节在内存中的位置
				auto SectionMemoryAddress = (VOID*)((PBYTE)m_VirtualAddress + m_pSectionHeader[i].VirtualAddress);
				//复制段数据到虚拟内存
				memcpy((VOID*)SectionMemoryAddress, (VOID*)((PBYTE)fileImage + m_pSectionHeader[i].PointerToRawData),
					m_pSectionHeader[i].SizeOfRawData);
			}
			//修正指针，指向新分配的内存
			//新的DOS头
			m_pDosHeader = (PIMAGE_DOS_HEADER)m_VirtualAddress;
			//新的PE头
			m_pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)m_VirtualAddress + (m_pDosHeader->e_lfanew));
			//新的节表地址
			m_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_pNtHeader + sizeof(IMAGE_NT_HEADERS));
			return true;
		}
		INLINE bool Flush() {
			AUTOLOG
			ULONG ulOld;
			if (m_VirtualAddress) {
				VirtualProtect(m_VirtualAddress, GetVirtualSize(), PAGE_EXECUTE_READWRITE, &ulOld);
				FlushInstructionCache(GetCurrentProcess(), m_VirtualAddress, GetVirtualSize());
				return true;
			}
			return false;
		}
		INLINE bool FixTLSTable() {
			AUTOLOG
			auto TLSdirectory = (PIMAGE_DATA_DIRECTORY) & (m_pNtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_TLS)) return true;
			auto tlsAddr = (PIMAGE_TLS_DIRECTORY)((PBYTE)m_VirtualAddress + TLSdirectory->VirtualAddress);
			auto callback = (PIMAGE_TLS_CALLBACK*)tlsAddr->AddressOfCallBacks;
			if (callback) {
				while (*callback) {
					(*callback)(m_VirtualAddress, DLL_PROCESS_ATTACH, NULL);
					callback++;
				}
			}
			return true;
		}
		// 更新PE文件的加载基地址
		BOOL UpdateImageBase(){
			AUTOLOG
			m_pNtHeader->OptionalHeader.ImageBase = (ULONG_PTR)m_VirtualAddress;
			return TRUE;
		}
		PIMAGE_DATA_DIRECTORY GetHeader(DWORD dwindex) {
			return &m_pNtHeader->OptionalHeader.DataDirectory[dwindex];
		}
		bool CheckHeader(DWORD nIndex) {
			AUTOLOG
			auto exportDir = GetHeader(nIndex);
			return !(exportDir->Size == 0 || exportDir->VirtualAddress == 0);
		}
		bool HasExports() {
			AUTOLOG
			return CheckHeader(IMAGE_DIRECTORY_ENTRY_EXPORT);
		}
		
		INLINE bool ExecuteDLLMain() {
			AUTOLOG
			typedef   BOOL(*ProcDllMain)(HINSTANCE, DWORD, LPVOID);
			auto pDllMain = (ProcDllMain)(m_pNtHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)m_VirtualAddress);
			if (pDllMain&&IsExecutableImage()) {
				auto ExcuteDll = [=]()->bool	 {
					if (pDllMain((HINSTANCE)m_VirtualAddress, DLL_PROCESS_ATTACH, 0) == FALSE) {
						pDllMain((HINSTANCE)m_VirtualAddress, DLL_PROCESS_DETACH, 0);
						return false;
					}
					return true;
				};
				if (GetCurrentThreadId() != ThreadInitializer::mainThreadId) {
					 return ExcuteDll();
				}else {
					std::thread(ExcuteDll).detach();
					return true;
				}
			}
			return true;
		}
		INLINE HMODULE GetModuleInstance() {
			AUTOLOG
			return (HMODULE)m_VirtualAddress;
		}
		
	};
	HMODULE LoadExcuteMemory(const std::string& filename, LPVOID fileImage,DWORD filesize) {
		AUTOLOG
		if (!fileImage || !filesize || filename.empty()) return nullptr;
		auto ModuleHandle = GetModuleHandleA(filename.c_str());
		if (ModuleHandle) return ModuleHandle;
		LastError& lasterror = LastError::GetInstance();
		MemoryPE pe(filename, fileImage, filesize);
		pe.Run();
		ModuleHandle = (HMODULE)pe.GetModuleInstance();
		return ModuleHandle;
	}
	std::string wideStringToString(const std::wstring& wideStr) {
		if (wideStr.empty()) {
			return std::string();
		}

		int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), (int)wideStr.size(), NULL, 0, NULL, NULL);
		std::string str(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), (int)wideStr.size(), &str[0], size_needed, NULL, NULL);
		return str;
	}
	std::vector<std::string> getSafeDirectories() {
		AUTOLOG
		static std::vector<std::string> safeDirs;
		if (safeDirs.empty()) {
#ifdef _WIN32
			wchar_t systemRoot[MAX_PATH];
			GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
			safeDirs.push_back(wideStringToString(std::wstring(systemRoot) + L"\\System32"));
			wchar_t programFiles[MAX_PATH];
			GetEnvironmentVariableW(L"ProgramFiles", programFiles, MAX_PATH);
			safeDirs.push_back(wideStringToString(std::wstring(programFiles) + L"\\SomeApp"));
			wchar_t programFilesX86[MAX_PATH];
			GetEnvironmentVariableW(L"ProgramFiles(x86)", programFilesX86, MAX_PATH);
			safeDirs.push_back(wideStringToString(std::wstring(programFilesX86) + L"\\SomeApp"));
#else
			// 其他平台的安全目录
			safeDirs.push_back("/usr/lib");
			safeDirs.push_back("/usr/local/lib");
#ifdef __APPLE__
			safeDirs.push_back("/usr/local/lib");
#endif
#endif
		}
		return safeDirs;
	}
	HMODULE LibraryLoadExA(LPCSTR lpLibFileName, HANDLE  hFile, DWORD   dwFlags) {
		AUTOLOG
		if (!lpLibFileName) return NULL;
		HMODULE returnmodule = NULL;
		if (hFile != NULL) return returnmodule;
		LastError& lasterror = LastError::GetInstance();
		bool Resolve = true;
		std::string FilePath= lpLibFileName;
		if (FilePath.find_first_of("\\") == std::string::npos){
			auto ext = GetFileExtension(FilePath);
			std::string returnstr;
			std::vector<std::string> PathList;//程序默认搜索目录
			PathList.reserve(0x1000);
			char szPath[MAX_PATH]{};
			switch (dwFlags)
			{
			case LOAD_LIBRARY_SEARCH_SYSTEM32:
				std::ignore = GetSystemDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				break;
			case LOAD_LIBRARY_SEARCH_USER_DIRS:
				std::ignore = GetWindowsDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				break;
			case LOAD_WITH_ALTERED_SEARCH_PATH:
				std::ignore = GetSystemDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				std::ignore = GetWindowsDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				break;
			case LOAD_LIBRARY_SEARCH_APPLICATION_DIR:
				std::ignore = GetCurrentDirectoryA(MAX_PATH, szPath);
				PathList.push_back(szPath);
				break;
			case LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: {
				std::ignore = GetSystemDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				std::ignore = GetWindowsDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				char* szEnvPath = nullptr;
				_dupenv_s(&szEnvPath, nullptr, "PATH");
				char* szEnvPathTemp = szEnvPath;
				while (szEnvPathTemp) {
					char* szEnvPathTemp2 = strchr(szEnvPathTemp, ';');
					if (szEnvPathTemp2) {
						*szEnvPathTemp2 = '\0';
						PathList.emplace_back(szEnvPathTemp);
						szEnvPathTemp = szEnvPathTemp2 + 1;
					}else {
						PathList.emplace_back(szEnvPathTemp);
						break;
					}
				}
				std::ignore = GetCurrentDirectoryA(MAX_PATH, szPath);
				PathList.push_back(szPath);
			}
			break;
			#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
			case LOAD_LIBRARY_SAFE_CURRENT_DIRS:
				PathList = getSafeDirectories();
				break;
			#endif
			case LOAD_LIBRARY_NO_CURRENT_PATH: {
				std::ignore = GetSystemDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				std::ignore = GetWindowsDirectoryA(szPath, MAX_PATH);
				PathList.push_back(szPath);
				char* szEnvPath = nullptr;
				_dupenv_s(&szEnvPath, nullptr, "PATH");
				char* szEnvPathTemp = szEnvPath;
				while (szEnvPathTemp) {
					auto szEnvPathTemp2 = strchr(szEnvPathTemp, ';');
					if (szEnvPathTemp2) {
						*szEnvPathTemp2 = '\0';
						PathList.emplace_back(szEnvPathTemp);
						szEnvPathTemp = szEnvPathTemp2 + 1;
					}else {
						PathList.emplace_back(szEnvPathTemp);
						break;
					}
				}
			}
				break;
			default: {
				std::ignore = GetCurrentDirectoryA(MAX_PATH, szPath);
				PathList.push_back(szPath);
			}
			break;
			}
			PathList.erase(std::remove_if(PathList.begin(), PathList.end(), [](std::string& path) {return path.length() == 0; }), PathList.end());
			std::sort(PathList.begin(), PathList.end());
			PathList.erase(std::unique(PathList.begin(), PathList.end()), PathList.end());
			std::sort(PathList.begin(), PathList.end(), [](std::string& path1, std::string& path2) {return path1.length() < path2.length(); });
			static auto dependenciesPath = PathList;
			std::vector<std::string> extpaths;
			extpaths.reserve(dependenciesPath.size());
			for (auto& path : dependenciesPath) {
				GetFiles(path, [&](const std::string& filepath)->EnumStatus {
					if (GetFileExtension(filepath) == ext)extpaths.emplace_back(filepath);
					return EnumStatus::ENUMCONTINUE;
				}, false);
			}
			std::unordered_map<std::string, std::string> extmap;
			extmap.reserve(extpaths.size());
			for (auto& filepath : extpaths)extmap.insert(GetFileNameAndPath(filepath));
			auto iter = extmap.find(FilePath);
			if (iter != extmap.end())returnstr = iter->second + "\\" + iter->first;
			FilePath = returnstr;
		}
		auto pair = GetFileNameAndPath(FilePath);
		auto iter = SelfLoadModules.find(pair.first);
		if (iter != SelfLoadModules.end())return (HMODULE)iter->second;
		if (FilePath.empty()){
			lasterror = ERROR_PATH_NOT_FOUND;//设置错误码
			return returnmodule;
		}
		lasterror = ERROR_SUCCESS;
		std::cout << "文件名:" << FilePath << std::endl;
		THANDLE hfile= CreateFileA(FilePath.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if (!hfile||!lasterror) return returnmodule;
		LARGE_INTEGER filesize{};
		GetFileSizeEx(hfile, &filesize);
		if(filesize.QuadPart==0) return returnmodule;
		FileMap mapview(hfile);
		auto fileImage = mapview.GetMap();
		bool bExcuteDLLmain = true;
		switch (dwFlags)
		{
		case DONT_RESOLVE_DLL_REFERENCES:
			mapview.NotClose();
			returnmodule = (HMODULE)fileImage;
			Resolve = false;
			break;
		case LOAD_LIBRARY_NO_EXECUTE:
			bExcuteDLLmain = false;
			break;
		default:
			break;
		}
		if(Resolve)returnmodule=LoadExcuteMemory(pair.first,fileImage, filesize.QuadPart);
		if(returnmodule)SelfLoadModules[pair.first]=returnmodule;
		return returnmodule;
	}
	HMODULE LibraryLoadA(LPCSTR lpLibFileName) {
		//智能解析
		return LibraryLoadExA(lpLibFileName, NULL, NULL);
	}
}
#endif // !LOADER
