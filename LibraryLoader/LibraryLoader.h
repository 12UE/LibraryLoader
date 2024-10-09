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
		ULONG64 DllBase;//ģ���ַ
		ULONG64 EntryPoint;//��ڵ�
		ULONG64 SizeOfImage;//ӳ���С
		UNICODE_STRING FullDllName;//������dll·��
		UNICODE_STRING BaseDllName;//dll��
		ULONG Flags;//��־
		USHORT LoadCount;//���ش���
		USHORT TlsIndex;//tls����
		LIST_ENTRY64 HashLinks;//hash����
		ULONG64 SectionPointer;//����ָ��
		ULONG64 CheckSum;//У���
		ULONG64 TimeDateStamp;//ʱ��� ����PE�ļ���ʱ���
		ULONG64 LoadedImports;//���صĵ����
		ULONG64 EntryPointActivationContext;//����������
		ULONG64 PatchInformation;//������Ϣ
		LIST_ENTRY64 ForwarderLinks;//ת������
		LIST_ENTRY64 ServiceTagLinks;//�����ǩ����
		LIST_ENTRY64 StaticLinks;//��̬����
		ULONG64 ContextInformation;//��������Ϣ
		ULONG64 OriginalBase;//ԭʼ��ַ �ض�λ֮ǰ�Ļ�ַ ���װ���ַ
		LARGE_INTEGER LoadTime;//����ʱ��
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
		PPEB_LDR_DATA64 Ldr;//dll ����
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
	std::string funcname;//�洢��������
	SAFE_BUFFER inline AutoLog(const std::string& szName = "", const std::string& perfix = "") noexcept {
		timepoint = Clock::now();
		std::unique_lock<decltype(logmtx)> lock(logmtx);//����ʹ�ö��߳��²����������
		funcname = szName + " " + perfix;//����������ƴ����ǰ׺
		std::cout << funcname << "---> Begin\n";//�������ʱ����Զ���ӡ������ʼ

	}
	SAFE_BUFFER inline  ~AutoLog() noexcept {//������������ʱ����Զ�����
		auto end = Clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - timepoint).count();
		std::unique_lock<decltype(logmtx)> lock(logmtx);//����ʹ�ö��߳��²����������
		std::cout << funcname << "---> End  Time:"<<duration<<"ms\n";//��ӡ���������ͺ�������ʱ��
	}
};
#ifdef _DEBUG
#define AUTOLOG  AutoLog log(__FUNCTION__,"");//ֱ�Ӵ�ӡ��������
#else
#define AUTOLOG
#endif
namespace libraryloader {
	const DWORD PDB70 = 0x53445352; // 'RSDS' in little endian
	const DWORD PDB20 = 0x3031424e;// '01BN'
	struct CV_HEADER {
		uint32_t Sig;         // ǩ��
		uint32_t Length;      // ���ݳ���
		uint16_t MjrVer;      // ���汾
		uint16_t MinVer;      // �ΰ汾
		uint32_t PdbSig;      // PDB ǩ��
		uint32_t Age;         // ����
		char PdbFileName[1];  // PDB �ļ���
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
	class NormalHandle {//�����˾���Ĺرշ�ʽ�;������Чֵ clarify the handle close method and the invalid value of the handle
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
	class GenericHandle {//����RAII���ƹ����� use RAII mechanism to manage handle
	private:
		T m_handle = Traits::InvalidHandle();
		bool m_bOwner = false;//������ owner
		INLINE bool IsValid()NOEXCEPT { return Traits::IsValid(m_handle); }
	public:
		GenericHandle() {

		}
		GenericHandle(const T& handle, bool bOwner = true) :m_handle(handle), m_bOwner(bOwner) {}//���� m_bOwnerĬ��Ϊtrue construct m_bOwner default is true
		~GenericHandle() {
			Close();
		}
		void Close() {
			if (m_bOwner && IsValid()) {//�������������Ϊtrue���Ҿ����Чʱ When the handle owner is true and the handle is valid
				Traits::Close(m_handle);//�رվ�� close handle
				m_handle = Traits::InvalidHandle();//���þ��Ϊ��Чֵ set handle to invalid value
				m_bOwner = false;//���þ��������Ϊfalse set handle owner to false
			}
		}
		GenericHandle(GenericHandle&) = delete;//��ֹ�������캯�� disable copy constructor
		GenericHandle& operator =(const GenericHandle&) = delete;//��ֹ������ֵ���� disable copy assignment
		INLINE GenericHandle& operator =(GenericHandle&& other)NOEXCEPT {   //�ƶ���ֵ move assignment
			m_handle = other.m_handle;
			m_bOwner = other.m_bOwner;
			other.m_handle = Traits::InvalidHandle();
			other.m_bOwner = false;
			return *this;
		}
		INLINE GenericHandle(GenericHandle&& other)NOEXCEPT {//�ƶ����� move construct
			m_handle = other.m_handle;
			m_bOwner = other.m_bOwner;
			other.m_handle = Traits::InvalidHandle();
			other.m_bOwner = false;
		}
		INLINE operator T() NOEXCEPT {//��m_handleת��ΪT����,ʵ�ʾ��Ǿ�������� convert m_handle to T type,actually is the type of handle
			return m_handle;
		}
		T& GetHandle() {
			m_bOwner = true;
			return	m_handle;
		}
		INLINE HANDLE* operator&() NOEXCEPT {
			return &m_handle;
		}
		INLINE operator bool() NOEXCEPT {//����bool����,�жϾ���Ƿ���Ч overload bool type, judge handle is valid
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
		std::vector<std::string> PathList;//����Ĭ������Ŀ¼
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
		// �������һ�����λ��
		size_t dotPos = filePath.find_last_of(".");
		// �������һ��·���ָ�����λ��
		size_t slashPos = filePath.find_last_of("/\\");
		// ȷ�����λ���ڷָ���֮�����û�зָ���
		if (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos)) {
			return filePath.substr(dotPos + 1); // ������չ��
		}
		return ""; // ���û����չ�������ؿ��ַ���
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
		return dllPath; // û�зָ���ʱ����ԭ·��
	}
	bool caseInsensitiveCompare(const std::string& str, const std::wstring& wstr) {
		if (str.size() != wstr.size()) return false;
		return std::equal(str.begin(), str.end(), wstr.begin(),
			[](char a, wchar_t b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
	}
	static BOOL CheckSize(size_t size, size_t expected) {//�жϴ�С
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
		// ��ѯ��ַ���ڴ���Ϣ
		if (VirtualQuery(Address, &mbi, sizeof(mbi)) == 0) {
			// VirtualQuery ʧ��
			return false;
		}
		// ȷ����ַ��Ч�����ǿɶ���
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
		INLINE unsigned int GetAlignedSize(unsigned int OriginalData, unsigned int Alignment) //OriginalDataԭʼ���� Alignment����߽�
		{
			//Alignment������2����
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
			int MemoryAlign = m_pNtHeader->OptionalHeader.SectionAlignment;   //�ζ����ֽ���
			auto sectionsum = GetAlignedSize(m_pNtHeader->OptionalHeader.SizeOfHeaders, MemoryAlign);
			auto pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_pNtHeader + sizeof(IMAGE_NT_HEADERS));
			for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; ++i) {
				int iTureCodeSize = pSectionHeader[i].Misc.VirtualSize;     //û�а����ļ����ڴ����ȶ���
				int iFileAlignCodeSize = pSectionHeader[i].SizeOfRawData;   //�����ļ����ȶ���
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
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//ͷ����dos��ʽ
				std::cerr << "Dos header is not valid." << std::endl;
				return lasterror;
			}
			if (!IsNtHeaderValid()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//�ж�ͷ���ǲ���pe
				std::cerr << "Nt header is not valid." << std::endl;
				return lasterror;
			}
			if (!IsDllFileFormat()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//�ļ�����dll
				std::cerr << "File is not a DLL." << std::endl;
				return lasterror;
			}
			if (!IsOptionalHeaderSizeCorrect()) {
				lasterror = ERROR_INCORRECT_SIZE;//�ļ���ѡͷ��С������
				std::cerr << "Optional header size is incorrect." << std::endl;
				return lasterror;
			}
			if (!HasExports()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//�ж����޵�����
				std::cerr << "No exports found." << std::endl;
				return lasterror;
			}
			if (!AllocateVirtualMemory()) {
				lasterror = ERROR_NOT_ENOUGH_MEMORY;
				std::cerr << "Failed to allocate virtual memory." << std::endl;
				return lasterror;
			}
			if (!CopyDataSections()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//��������ʧ��
				std::cerr << "Failed to copy data sections." << std::endl;
				return lasterror;
			}
			if (!FixImportTable()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//���������ʧ�� ע�⻹��һ����������ָ����	IAT ��Import Address Table�� �������һ��
				std::cerr << "Failed to fix import table." << std::endl;
				return lasterror;
			}
			if (!FixRelocationTable()) {
				lasterror = ERROR_ILLEGAL_DLL_RELOCATION;//�����ض�λ��ʧ��
				std::cerr << "Failed to fix relocation table." << std::endl;
				return lasterror;
			}
			if (!FixTLSTable()) {
				lasterror = ERROR_DLL_MIGHT_BE_INCOMPATIBLE;//����TLS��ʧ��
				std::cerr << "Failed to fix TLS table." << std::endl;
				return lasterror;
			}
			if (!Flush()) {
				lasterror = ERROR_INVALID_ADDRESS;//ˢ��ָ���ʧ��
				std::cerr << "Failed to flush instruction cache." << std::endl;
				return lasterror;
			}
			if (!ExecuteDLLMain()) {
				FreeVirtualMemory();//m_VirtualAddress = nullptr;
				lasterror = ERROR_BAD_DLL_ENTRYPOINT;//	ִ��dllmainʧ��
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
			if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {//�ж�ͷ��ħ��ȷ����Ϊpe��ʽ
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
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_IMPORT))return TRUE;    // û�е����
			auto ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)m_VirtualAddress + ulOffset);
			std::stack<std::string> dllnames;
			// �����������ȡ���� DLL ����
			while (ImageImportDescriptor->Characteristics != 0) {
				std::string szDllName((char*)((PBYTE)m_VirtualAddress + ImageImportDescriptor->Name));
				if (!szDllName.empty())dllnames.push(szDllName);
				ImageImportDescriptor++;
			}
			// ���� DLL ����ջ���޸� IAT
			while (!dllnames.empty()) {
				std::string dllname = dllnames.top();
				dllnames.pop();
				if (dllname.empty())continue;
				// ���±��� ImageImportDescriptor ���ҵ���Ӧ�� DLL
				ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)m_VirtualAddress + ulOffset);
				while (ImageImportDescriptor->Characteristics != 0) {
					std::string currentDllName((char*)((PBYTE)
						m_VirtualAddress + ImageImportDescriptor->Name));
					if (currentDllName == dllname)break; // �ҵ���Ӧ�� DLL
					ImageImportDescriptor++;
				}
				if (ImageImportDescriptor->Characteristics == 0)return FALSE;  // ���û���ҵ���Ӧ�� DLL�����ش���
				auto hDll = GetModuleHandleA(dllname.c_str());
				if (hDll == NULL)hDll = LoadLibraryA(dllname.c_str());
				if (!hDll) return false;
				// ��ȡ FirstThunk �� OriginalFirstThunk
				auto FirstThunkData = (PIMAGE_THUNK_DATA)((PBYTE)m_VirtualAddress + ImageImportDescriptor->FirstThunk);
				auto OriginalThunkData = (PIMAGE_THUNK_DATA)((PBYTE)m_VirtualAddress + ImageImportDescriptor->OriginalFirstThunk);
				for (int i = 0;; i++) {
					if (OriginalThunkData[i].u1.Function == 0)break; // ������ĩβ
					FARPROC FunctionAddress = NULL;
					// �ж��ǰ���ŵ������ǰ����Ƶ���
					if (OriginalThunkData[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						// ����ŵ���
						DWORD ordinal = OriginalThunkData[i].u1.Ordinal & ~IMAGE_ORDINAL_FLAG;
						FunctionAddress = GetProcAddress(hDll, (char*)ordinal);
					}else {
						// �����Ƶ���
						auto ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)m_VirtualAddress + OriginalThunkData[i].u1.AddressOfData);
						FunctionAddress = GetProcAddress(hDll, (char*)ImageImportByName->Name);
					}
					// ����ҵ��˺�����ַ�����޸� IAT
					if (FunctionAddress != NULL) {
#ifdef _WIN64
						FirstThunkData[i].u1.Function = (ULONGLONG)FunctionAddress;
#else
						FirstThunkData[i].u1.Function = (DWORD)FunctionAddress;
#endif
					}else {
						return FALSE;  // ���������ַΪ�գ����ش���
					}
				}
			}
			LastError::GetInstance()=ERROR_SUCCESS;
			return TRUE;  // �ɹ��޸� IT
		}
		INLINE bool FixExceptionTable() {
			AUTOLOG
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_EXCEPTION)) return true;//���û��һ����Ͳ�����������
			

		}
		INLINE bool FixRelocationTable(){
			AUTOLOG
			if (!CheckHeader(IMAGE_DIRECTORY_ENTRY_BASERELOC)) return true;
			//����NewBase��0x600000,���ļ������õ�ȱʡImageBase��0x400000,������ƫ��������0x200000
			//ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ
			auto BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)m_VirtualAddress +
				m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			if (!BaseRelocation) return false;
			while ((BaseRelocation->VirtualAddress + BaseRelocation->SizeOfBlock) != 0){
				auto RelocationData = (WORD*)((PBYTE)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
				//���㱾����Ҫ�������ض�λ��(��ַ)����Ŀ
				int NumberOfRelocation = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				for (int i = 0; i < NumberOfRelocation; i++)
				{
					// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��
					// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�
					if ((DWORD)(RelocationData[i] & 0xF000) == 0x0000A000){
						//64λDll�ض�λ��IMAGE_REL_BASED_DIR64
						//����IA-64�Ŀ�ִ���ļ����ض�λ�ƺ�����IMAGE_REL_BASED_DIR64���͵�
#ifdef _WIN64
						auto Address = (ULONGLONG*)((PBYTE)m_VirtualAddress + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
						auto  ulDelta = (ULONGLONG)m_VirtualAddress - m_pNtHeader->OptionalHeader.ImageBase;
						*Address += ulDelta;
#endif
					}else if ((DWORD)(RelocationData[i] & 0xF000) == 0x00003000){
						//32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW
						//����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�
#ifndef _WIN64
						DWORD* Address = (DWORD*)((PBYTE)ImageData + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x0FFF));
						DWORD  dwDelta = (DWORD)ImageData - m_NtHeader->OptionalHeader.ImageBase;
						*Address += dwDelta;
#endif
					}
				}
				//ת�Ƶ���һ���ڽ��д���
				BaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseRelocation + BaseRelocation->SizeOfBlock);
			}
			return true;
		}
		INLINE bool CopyDataSections(){
			AUTOLOG
			//������Ҫ���Ƶ�PEͷ+�α��ֽ���
			int HeaderLength = m_pNtHeader->OptionalHeader.SizeOfHeaders;
			//����ͷ�Ͷ���Ϣ
			if(!HeaderLength) return false;
			if (!m_VirtualAddress)	return false;
			memcpy(m_VirtualAddress, fileImage, HeaderLength);
			//����ÿ����
			for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; ++i){
				if (m_pSectionHeader[i].VirtualAddress == 0 || m_pSectionHeader[i].SizeOfRawData == 0)continue;
				//����ý����ڴ��е�λ��
				auto SectionMemoryAddress = (VOID*)((PBYTE)m_VirtualAddress + m_pSectionHeader[i].VirtualAddress);
				//���ƶ����ݵ������ڴ�
				memcpy((VOID*)SectionMemoryAddress, (VOID*)((PBYTE)fileImage + m_pSectionHeader[i].PointerToRawData),
					m_pSectionHeader[i].SizeOfRawData);
			}
			//����ָ�룬ָ���·�����ڴ�
			//�µ�DOSͷ
			m_pDosHeader = (PIMAGE_DOS_HEADER)m_VirtualAddress;
			//�µ�PEͷ
			m_pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)m_VirtualAddress + (m_pDosHeader->e_lfanew));
			//�µĽڱ��ַ
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
		// ����PE�ļ��ļ��ػ���ַ
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
			// ����ƽ̨�İ�ȫĿ¼
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
			std::vector<std::string> PathList;//����Ĭ������Ŀ¼
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
			lasterror = ERROR_PATH_NOT_FOUND;//���ô�����
			return returnmodule;
		}
		lasterror = ERROR_SUCCESS;
		std::cout << "�ļ���:" << FilePath << std::endl;
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
		//���ܽ���
		return LibraryLoadExA(lpLibFileName, NULL, NULL);
	}
}
#endif // !LOADER
