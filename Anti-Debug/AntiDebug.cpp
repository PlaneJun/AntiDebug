#include "AntiDebug.h"
#include"xorstr.hpp"
#include<Shlwapi.h>
#include<string>
#include<chrono>
#include <imagehlp.h>
#pragma  comment (lib, "imagehlp")
#pragma comment(lib,"Shlwapi.lib")

BOOL g_bDebug = false;
AntiDebug* AntiDebug::m_Instance = NULL;

__declspec(naked) _PEB* getpeb()
{
    __asm {
        mov eax, fs: [0x30]
        ret
    }
}

void AntiDebug::Init()
{
    //修改为自定义的值
    if (getpeb()->BeingDebugged)
        *(BYTE*)&getpeb()->BeingDebugged = 0x10;
    else
        *(BYTE*)&getpeb()->BeingDebugged = 0x20;

    if (getpeb()->NtGlobalFlag & 0x70)
        getpeb()->NtGlobalFlag = 0x50;
    else
        getpeb()->NtGlobalFlag = 0x20;
}
AntiDebug* AntiDebug::GetInstance()
{
    if (!m_Instance)
    {
        m_Instance = new AntiDebug();
        auto ntdll = m_Instance->_LoadLibrary(xorstr_(L"ntdll.dll"));
        if (ntdll)
        {
            m_Instance->winapi.lpRtlFreeHeap = reinterpret_cast<decltype(m_Instance->winapi.lpRtlFreeHeap)>(m_Instance->_GetProcAddress(ntdll, xorstr_("RtlFreeHeap")));
            m_Instance->winapi.lpRtlAllocateHeap = reinterpret_cast<decltype(m_Instance->winapi.lpRtlAllocateHeap)>(m_Instance->_GetProcAddress(ntdll, xorstr_("RtlAllocateHeap")));
            m_Instance->winapi.lpNtSetDebugFilterState = reinterpret_cast<decltype(m_Instance->winapi.lpNtSetDebugFilterState)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtSetDebugFilterState")));
            m_Instance->winapi.lpNtQueryInformationProcess = reinterpret_cast<decltype(m_Instance->winapi.lpNtQueryInformationProcess)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtQueryInformationProcess")));
            m_Instance->winapi.lpNtQueryInformationThread = reinterpret_cast<decltype(m_Instance->winapi.lpNtQueryInformationThread)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtQueryInformationThread")));
            m_Instance->winapi.lpNtQueryObject = reinterpret_cast<decltype(m_Instance->winapi.lpNtQueryObject)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtQueryObject")));
            m_Instance->winapi.lpNtQuerySystemInformation = reinterpret_cast<decltype(m_Instance->winapi.lpNtQuerySystemInformation)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtQuerySystemInformation")));
            m_Instance->winapi.lpNtCreateDebugObject = reinterpret_cast<decltype(m_Instance->winapi.lpNtCreateDebugObject)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtCreateDebugObject")));
            m_Instance->winapi.lpNtClose = reinterpret_cast<decltype(m_Instance->winapi.lpNtClose)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtClose")));
            m_Instance->winapi.lpZwSetInformationThread = reinterpret_cast<decltype(m_Instance->winapi.lpZwSetInformationThread)>(m_Instance->_GetProcAddress(ntdll, xorstr_("ZwSetInformationThread")));
            m_Instance->winapi.lpNtGetContextThread = reinterpret_cast<decltype(m_Instance->winapi.lpNtGetContextThread)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtGetContextThread")));
            m_Instance->winapi.lpNtSetContextThread = reinterpret_cast<decltype(m_Instance->winapi.lpNtSetContextThread)>(m_Instance->_GetProcAddress(ntdll, xorstr_("NtSetContextThread")));
        }

        auto kernel = m_Instance->_LoadLibrary(xorstr_(L"kernel32.dll"));
        if (kernel)
        {
            
            m_Instance->winapi.lpLoadLibraryA = reinterpret_cast<decltype(m_Instance->winapi.lpLoadLibraryA)>(m_Instance->_GetProcAddress(kernel, xorstr_("LoadLibraryA")));
            m_Instance->winapi.lpSleep = reinterpret_cast<decltype(m_Instance->winapi.lpSleep)>(m_Instance->_GetProcAddress(kernel, xorstr_("Sleep")));
            m_Instance->winapi.lpCreateThread = reinterpret_cast<decltype(m_Instance->winapi.lpCreateThread)>(m_Instance->_GetProcAddress(kernel, xorstr_("CreateThread")));
            m_Instance->winapi.lpWriteProcessMemory = reinterpret_cast<decltype(m_Instance->winapi.lpWriteProcessMemory)>(m_Instance->_GetProcAddress(kernel, xorstr_("WriteProcessMemory")));
            m_Instance->winapi.lpVirtualProtect = reinterpret_cast<decltype(m_Instance->winapi.lpVirtualProtect)>(m_Instance->_GetProcAddress(kernel, xorstr_("VirtualProtect")));
            m_Instance->winapi.lpGetLastError = reinterpret_cast<decltype(m_Instance->winapi.lpGetLastError)>(m_Instance->_GetProcAddress(kernel, xorstr_("GetLastError")));
            m_Instance->winapi.lpHeapSetInformation  = reinterpret_cast<decltype(m_Instance->winapi.lpHeapSetInformation)>(m_Instance->_GetProcAddress(kernel, xorstr_("HeapSetInformation")));
            m_Instance->winapi.lpGetProcessHeap = reinterpret_cast<decltype(m_Instance->winapi.lpGetProcessHeap)>(m_Instance->_GetProcAddress(kernel, xorstr_("GetProcessHeap")));
            m_Instance->winapi.lpCreateMutexA = reinterpret_cast<decltype(m_Instance->winapi.lpCreateMutexA)>(m_Instance->_GetProcAddress(kernel, xorstr_("CreateMutexA")));
            m_Instance->winapi.lpSetHandleInformation = reinterpret_cast<decltype(m_Instance->winapi.lpSetHandleInformation)>(m_Instance->_GetProcAddress(kernel, xorstr_("SetHandleInformation")));
            m_Instance->winapi.lpRaiseException = reinterpret_cast<decltype(m_Instance->winapi.lpRaiseException)>(m_Instance->_GetProcAddress(kernel, xorstr_("RaiseException")));
            m_Instance->winapi.lpUnhandledExceptionFilter = reinterpret_cast<decltype(m_Instance->winapi.lpUnhandledExceptionFilter)>(m_Instance->_GetProcAddress(kernel, xorstr_("UnhandledExceptionFilter")));
            m_Instance->winapi.lpSetUnhandledExceptionFilter = reinterpret_cast<decltype(m_Instance->winapi.lpSetUnhandledExceptionFilter)>(m_Instance->_GetProcAddress(kernel, xorstr_("SetUnhandledExceptionFilter")));
            m_Instance->winapi.lpGetModuleHandleA = reinterpret_cast<decltype(m_Instance->winapi.lpGetModuleHandleA)>(m_Instance->_GetProcAddress(kernel, xorstr_("GetModuleHandleA")));
            m_Instance->winapi.lpGetCurrentThread =  reinterpret_cast<decltype(m_Instance->winapi.lpGetCurrentThread)>(m_Instance->_GetProcAddress(kernel, xorstr_("GetCurrentThread")));
            m_Instance->winapi.lpVirtualAlloc = reinterpret_cast<decltype(m_Instance->winapi.lpVirtualAlloc)>(m_Instance->_GetProcAddress(kernel, xorstr_("VirtualAlloc")));
            m_Instance->winapi.lpVirtualFree = reinterpret_cast<decltype(m_Instance->winapi.lpVirtualFree)>(m_Instance->_GetProcAddress(kernel, xorstr_("VirtualFree")));
            m_Instance->winapi.lpGetCurrentProcess = reinterpret_cast<decltype(m_Instance->winapi.lpGetCurrentProcess)>(m_Instance->_GetProcAddress(kernel, xorstr_("GetCurrentProcess")));
            m_Instance->winapi.lpIsDebuggerPresent = reinterpret_cast<decltype(m_Instance->winapi.lpIsDebuggerPresent)>(m_Instance->_GetProcAddress(kernel, xorstr_("IsDebuggerPresent")));
            m_Instance->winapi.lpOutputDebugStringA = reinterpret_cast<decltype(m_Instance->winapi.lpOutputDebugStringA)>(m_Instance->_GetProcAddress(kernel, xorstr_("OutputDebugStringA")));
            m_Instance->winapi.lpCheckRemoteDebuggerPresent = reinterpret_cast<decltype(m_Instance->winapi.lpCheckRemoteDebuggerPresent)>(m_Instance->_GetProcAddress(kernel, xorstr_("CheckRemoteDebuggerPresent")));
        }

        auto userdll = m_Instance->_LoadLibrary(xorstr_(L"User32.dll"));
        if (!userdll)
            userdll= m_Instance->winapi.lpLoadLibraryA(xorstr_("User32.dll"));
        if (userdll)
        {
            m_Instance->winapi.lpIsWindow = reinterpret_cast<decltype(m_Instance->winapi.lpIsWindow)>(m_Instance->_GetProcAddress(userdll, xorstr_("IsWindow")));
            m_Instance->winapi.lpGetMessageA = reinterpret_cast<decltype(m_Instance->winapi.lpGetMessageA)>(m_Instance->_GetProcAddress(userdll, xorstr_("GetMessageA")));
            m_Instance->winapi.lpCloseWindow = reinterpret_cast<decltype(m_Instance->winapi.lpCloseWindow)>(m_Instance->_GetProcAddress(userdll, xorstr_("CloseWindow")));
        }

        auto advapi32 = m_Instance->_LoadLibrary(xorstr_(L"Advapi32.dll"));
        if (!advapi32)
            advapi32= m_Instance->winapi.lpLoadLibraryA(xorstr_("Advapi32.dll"));
        if (advapi32)
        {
            m_Instance->winapi.lpGetUserNameA = reinterpret_cast<decltype(m_Instance->winapi.lpGetUserNameA)>(m_Instance->_GetProcAddress(advapi32, xorstr_("GetUserNameA")));
            m_Instance->winapi.lpRegOpenKeyExA = reinterpret_cast<decltype(m_Instance->winapi.lpRegOpenKeyExA)>(m_Instance->_GetProcAddress(advapi32, xorstr_("RegOpenKeyExA")));
            m_Instance->winapi.lpRegCloseKey = reinterpret_cast<decltype(m_Instance->winapi.lpRegCloseKey)>(m_Instance->_GetProcAddress(advapi32, xorstr_("RegCloseKey")));
            m_Instance->winapi.lpRegGetValueA = reinterpret_cast<decltype(m_Instance->winapi.lpRegGetValueA)>(m_Instance->_GetProcAddress(advapi32, xorstr_("RegGetValueA")));
        }
            
    }  
    return m_Instance;
}
_declspec(naked) void AntiDebug::_ExitProcess()
{
    _asm {
        push 0
        ret
    }
}
HMODULE AntiDebug::_LoadLibrary(const wchar_t* image_name)
{
	PLIST_ENTRY Head, Cur;
	PPEB_LDR_DATA ldr;
	PLDR_MODULE ldm;

	//获取Ldr地址
	__asm
	{
		mov eax, fs: [0x30]   //PEB
		mov ecx, [eax + 0xC]  //Ldr
		mov ldr, ecx
	}

	Head = &(ldr->InLoadOrderModuleList);
	Cur = Head->Flink;
	do
	{
		ldm = CONTAINING_RECORD(Cur, LDR_MODULE, InLoadOrderModuleList);  //计算首地址
		if (StrStrIW(std::wstring(ldm->BaseDllName.Buffer).c_str(),image_name))
			return (HMODULE)ldm->BaseAddress;
		Cur = Cur->Flink;  //指向下一个
	} while (Head != Cur);
	return 0;
}
DWORD AntiDebug::_GetProcAddress(HMODULE hModule, const char* procName) {
    int i = 0;
    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
    PIMAGE_NT_HEADERS pImageNtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + pImageDosHeader->e_lfanew);
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (DWORD)hModule);
    DWORD* pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (DWORD)hModule);
    DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
    DWORD dwBase = (DWORD)(pImageExportDirectory->Base);

    WORD* pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (DWORD)hModule);

    //这个是查一下是按照什么方式（函数名称or函数序号）来查函数地址的   
    DWORD dwName = (DWORD)procName;
    if ((dwName & 0xFFFF0000) == 0)
    {
        goto xuhao;
    }
    for (i = 0; i < (int)dwNumberOfNames; i++)
    {
        char* strFunction = (char*)(pAddressOfNames[i] + (DWORD)hModule);
        if (lstrcmp(procName, strFunction) == 0)
        {
            return (pAddressOfFunction[pAddressOfNameOrdinals[i]] + (DWORD)hModule);
        }
    }
    return 0;
    //这个是通过以序号的方式来查函数地址的  
xuhao:
    if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
    {
        return 0;
    }
    return (pAddressOfFunction[dwName - dwBase] + (DWORD)hModule);

}


BOOL AntiDebug::EatHook(LPCWCH szDllName, LPCTSTR szFunName, LPVOID NewFun, DWORD* OriginFun) {

    DWORD addr = 0;
    DWORD index = 0;
    DWORD dwProtect;
    HMODULE hMod = _LoadLibrary(szDllName);
    if (NULL == hMod)
        return(FALSE);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)hMod + pDosHeader->e_lfanew + 24);
    PIMAGE_EXPORT_DIRECTORY pExpDes = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hMod + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)hMod + pExpDes->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)hMod + pExpDes->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)hMod + pExpDes->AddressOfNameOrdinals);

    for (int i = 0; i < pExpDes->NumberOfNames; ++i) {
        index = pAddressOfNameOrdinals[i];
        LPCTSTR pFuncName = (LPTSTR)((PBYTE)hMod + pAddressOfNames[i]);
        if (strstr((LPCTSTR)pFuncName, szFunName)) {
            addr = pAddressOfFunctions[index];
            break;
        }
    }
    if (addr)
    {
        if (this->winapi.lpVirtualProtect(&pAddressOfFunctions[index], 0x100, PAGE_READWRITE, &dwProtect))
        {
            *OriginFun = pAddressOfFunctions[index] + (DWORD)hMod;
            auto offset = (DWORD)NewFun - (DWORD)hMod;
            pAddressOfFunctions[index] = offset;
            this->winapi.lpVirtualProtect(&pAddressOfFunctions[index], 0x100, dwProtect, NULL);
            return(TRUE);
        }
    }
    return false;
}
BOOL AntiDebug::IatHook(LPCWCH szDLLName, LPCTSTR szName, LPVOID NewFun, DWORD* OriginFun)
{
    DWORD Protect;
    HMODULE hMod = this->_LoadLibrary(szDLLName);
    DWORD RealAddr = (DWORD)this->_GetProcAddress(hMod, szName);
    *OriginFun = RealAddr;
    hMod = this->winapi.lpGetModuleHandleA(NULL);
    IMAGE_DOS_HEADER* DosHeader = (PIMAGE_DOS_HEADER)hMod;
    IMAGE_OPTIONAL_HEADER* Opthdr = (PIMAGE_OPTIONAL_HEADER)((DWORD)hMod + DosHeader->e_lfanew + 24);
    IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)DosHeader + Opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (pImport == NULL)
    {
        return FALSE;
    }
    while (pImport->Characteristics && pImport->FirstThunk != NULL)
    {
        IMAGE_THUNK_DATA32* Pthunk = (IMAGE_THUNK_DATA32*)((DWORD)hMod + pImport->FirstThunk);
        while (Pthunk->u1.Function)
        {
            if (RealAddr == Pthunk->u1.Function)
            {
                this->winapi.lpVirtualProtect(&Pthunk->u1.Function, 0x1000, PAGE_READWRITE, &Protect);
                Pthunk->u1.Function = (DWORD)NewFun;
                break;
            }
            Pthunk++;
        }
        pImport++;
    }

    
    return TRUE;
}

BOOL AntiDebug::BasicDebugDetect()
{
    if (*(BYTE*)&getpeb()->BeingDebugged != 0x20)
        return true;
    if (getpeb()->NtGlobalFlag != 0x20)
        return true;
    BOOL debug = false;
    this->winapi.lpCheckRemoteDebuggerPresent(this->winapi.lpGetCurrentProcess(), &debug);
    if (debug)
        return true;
    return false;

}
BOOL AntiDebug::QueryInfoDetect()
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION sysInfo{};
    this->winapi.lpNtQuerySystemInformation(SystemProcessorStatistics, &sysInfo, sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION), NULL);
    if (sysInfo.KernelDebuggerEnabled)
        return true;
    //-----------------------------------------------------------------------------------------------------------------------------------------------------
    DWORD dwDebugPort{};
    this->winapi.lpNtQueryInformationProcess(this->winapi.lpGetCurrentProcess(), ProcessDebugPort, &dwDebugPort, sizeof(dwDebugPort), NULL);
    if (dwDebugPort != 0)
        return true;
    //-----------------------------------------------------------------------------------------------------------------------------------------------------
    DWORD dwObjectHandle{};
    this->winapi.lpNtQueryInformationProcess(this->winapi.lpGetCurrentProcess(), ProcessDebugObjectHandle, &dwObjectHandle, sizeof(dwObjectHandle), NULL);
    if (dwObjectHandle != 0)
        return true;
    //-----------------------------------------------------------------------------------------------------------------------------------------------------
    DWORD dwDebugFlags{};
    this->winapi.lpNtQueryInformationProcess(this->winapi.lpGetCurrentProcess(), ProcessDebugFlags, &dwDebugFlags, sizeof(dwDebugFlags), NULL);
    if (dwDebugFlags == 0)
        return true;
    //-----------------------------------------------------------------------------------------------------------------------------------------------------
    WOW64_CONTEXT ctx{};
    this->winapi.lpNtQueryInformationThread(this->winapi.lpGetCurrentThread(), ThreadWow64Context, &ctx, sizeof(WOW64_CONTEXT), NULL);
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7)
        return true;
    return false;
}
BOOL AntiDebug::DebugObejctDetect_All() {
    ULONG objSize{};
    this->winapi.lpNtQueryObject(NULL, ObjectAllInformation, &objSize, sizeof(ULONG), &objSize);
    // 分配内存
    PVOID p_Memory = this->winapi.lpVirtualAlloc(NULL, objSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p_Memory == NULL) {
        return false;
    }
    // 遍历对象信息
    if (this->winapi.lpNtQueryObject(NULL, ObjectAllInformation, p_Memory, objSize, NULL) != 0) {
        this->winapi.lpVirtualFree(p_Memory, 0, MEM_RELEASE);
        return true;
    }
    POBJECT_ALL_INFORMATION p_ObjectAllInfo = (POBJECT_ALL_INFORMATION)p_Memory;
    PUCHAR  p_ObjInfoLocation = (PUCHAR)p_ObjectAllInfo->ObjectTypeInformation;
    for (UINT i = 0; i < p_ObjectAllInfo->NumberOfObjects; i++) {
        POBJECT_TYPE_INFORMATION p_ObjectTypeInfo = (POBJECT_TYPE_INFORMATION)p_ObjInfoLocation;
        if (wcscmp(xorstr_(L"DebugObject"), p_ObjectTypeInfo->TypeName.Buffer) == 0) {
            if (p_ObjectTypeInfo->TotalNumberOfObjects > 0) {
                return true;
            }
        }
        p_ObjInfoLocation = (PUCHAR)p_ObjectTypeInfo->TypeName.Buffer;
        p_ObjInfoLocation += p_ObjectTypeInfo->TypeName.MaximumLength;
        ULONG_PTR tmp = ((ULONG_PTR)p_ObjInfoLocation) & -(int)sizeof(void*);
        if ((ULONG_PTR)tmp != (ULONG_PTR)p_ObjInfoLocation) {
            tmp += sizeof(void*);
        }
        p_ObjInfoLocation = ((unsigned char*)tmp);
    }
    if (p_Memory)   this->winapi.lpVirtualFree(p_Memory, 0, MEM_RELEASE);
    return false;
}
BOOL AntiDebug::DebugObejctDetect_Create()
{
    BOOL ret = true;
    OBJECT_ATTRIBUTES objAttr{};
    InitializeObjectAttributes(&objAttr, 0, 0, 0, 0);
    auto hDebugObject = HANDLE(INVALID_HANDLE_VALUE);
    BYTE pMemory[0x1000] = { 0 };
    if (this->winapi.lpNtCreateDebugObject(&hDebugObject, DEBUG_ALL_ACCESS, &objAttr, 0) == 0)
    {
        auto pObjectType = reinterpret_cast<POBJECT_TYPE_INFORMATION>(pMemory);
        if (this->winapi.lpNtQueryObject(hDebugObject, ObjectTypeInformation, pObjectType, sizeof(pMemory), 0) == 0)
        {
            if (pObjectType->TotalNumberOfObjects == 1)
                ret = false;
        }
    } 
    this->winapi.lpNtClose(hDebugObject); //不知道为啥报无效句柄
    return ret;
}
void AntiDebug::CrashOD()
{
    this->winapi.lpOutputDebugStringA(xorstr_("%s%s%s%s%s%s%s%s%s"));
}
BOOL AntiDebug::CloseInvaildHandleDetect()
{
    __try {
        this->winapi.lpNtClose((HANDLE)672368);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
    return false;
}
BOOL AntiDebug::CloseProtectHandleDetect()
{
    static HANDLE hMutex{};
    if (!hMutex)
    {
        hMutex = this->winapi.lpCreateMutexA(NULL, FALSE, xorstr_("System"));
        if (!this->winapi.lpSetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE))
        {
            this->winapi.lpNtClose(hMutex);
            hMutex = NULL;
        }
    }
    if(hMutex)
    {
        __try
        {
            this->winapi.lpNtClose(hMutex);
        }
        __except (HANDLE_FLAG_PROTECT_FROM_CLOSE)
        {
            return true;
        }
    }
    return false;
}
BOOL AntiDebug::HideThread()
{
    BOOLEAN bIsHidden = FALSE;
    if (this->winapi.lpNtQueryInformationThread(this->winapi.lpGetCurrentThread(), ThreadHideFromDebugger, &bIsHidden, sizeof(bIsHidden), NULL)==0)
    {
        if (!bIsHidden)
        {
            bIsHidden = true;
            this->winapi.lpZwSetInformationThread(this->winapi.lpGetCurrentThread(), ThreadHideFromDebugger, NULL, NULL);
            return bIsHidden;
        }  
    }
    return bIsHidden;
}
BOOL AntiDebug::NtGlobalClearDetect()
{
    auto pImageBase = (PBYTE)this->winapi.lpGetModuleHandleA(NULL);
    if (!pImageBase)
        return false;

    auto pIDH = (PIMAGE_DOS_HEADER)pImageBase;
    if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto pINH = (PIMAGE_NT_HEADERS)(pImageBase + pIDH->e_lfanew);
    if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
        return false;

    auto pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (pImageLoadConfigDirectory->GlobalFlagsClear)
    {
        return true;
    }
    return false;
}
LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers) {
    g_bDebug = FALSE;
    return EXCEPTION_CONTINUE_EXECUTION;
}
BOOL AntiDebug::SehDetect()
{
    if(!m_top)
        m_top = this->winapi.lpSetUnhandledExceptionFilter(UnhandledExcepFilter); //注册异常
    this->winapi.lpRaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
    if (g_bDebug)
        return true;
    return false;
}
BOOL AntiDebug::HeapTailDetect()
{
    DWORD flag[] = { 0xabababab, 0xabababab };
    auto pProcessHeap = this->winapi.lpGetProcessHeap();
    DWORD_PTR pMem = (DWORD_PTR)this->winapi.lpRtlAllocateHeap(pProcessHeap, HEAP_ZERO_MEMORY, 32);
    strcpy((char*)pMem, "");
    auto temp = pMem + 32;
    auto dwRet = memcmp((LPVOID)temp, (LPVOID)flag, 8);
    this->winapi.lpRtlFreeHeap(pProcessHeap,0, (LPVOID)pMem);
    return dwRet == 0;
}
BOOL AntiDebug::HeapSetInformationDetect()
{
    ULONG uHeapInfo = 2; /* HEAP_LFH */
    if (!this->winapi.lpHeapSetInformation(m_Instance->winapi.lpGetProcessHeap(), HeapCompatibilityInformation, &uHeapInfo, sizeof(uHeapInfo)))
        return true;
    return false;
}
BOOL AntiDebug::CloseInvaildWindowDetect()
{
    auto dwRet = this->winapi.lpCloseWindow((HWND)0x13371337);
    if (dwRet != 0 || this->winapi.lpGetLastError() != ERROR_INVALID_WINDOW_HANDLE)
        return true;
    return false;
}
BOOL AntiDebug::TimeDetect()
{
    auto tStart = std::chrono::high_resolution_clock::now();

    this->winapi.lpGetCurrentProcess();
    this->winapi.lpGetCurrentProcess();
    this->winapi.lpGetCurrentProcess();
    this->winapi.lpGetCurrentProcess();

    auto tDiff = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - tStart).count();

    if (tDiff > 100)
    {
        return true;
    }
    return false;
}
BOOL AntiDebug::SystemBootDetect()
{
    auto hKey = HKEY(nullptr);
    auto dwRegOpenRet = this->winapi.lpRegOpenKeyExA(HKEY_LOCAL_MACHINE, xorstr_("System\\CurrentControlSet\\Control"), 0, KEY_READ, &hKey);
    if (dwRegOpenRet != ERROR_SUCCESS)
    {
        return false;
    }
    char szBootOptions[1024] = { 0 };
    auto dwLen = DWORD(sizeof(szBootOptions) - sizeof(CHAR));
    auto dwRegGetRet = this->winapi.lpRegGetValueA(hKey, NULL, xorstr_("SystemStartOptions"), RRF_RT_REG_SZ, NULL, szBootOptions, &dwLen);
    if (dwRegGetRet != ERROR_SUCCESS)
    {
        this->winapi.lpRegCloseKey(hKey);
        return false;
    }

    if (StrStrIA(szBootOptions, xorstr_("debug")))
    {
        this->winapi.lpRegCloseKey(hKey);
        return true;
    }

    this->winapi.lpRegCloseKey(hKey);
    return false;
}
BOOL AntiDebug::DebugFilterStateDetect()
{
    auto ntStatus = this->winapi.lpNtSetDebugFilterState(0, 0, TRUE);
    if (ntStatus == 0 )
        return true;
    return false;
}
BOOL AntiDebug::VehDetect()
{
    if (getpeb()->CrossProcessFlags & 0x4)
        return true;
    return false;
}
void AntiDebug::DrClear()
{
    CONTEXT ctx{};
    this->winapi.lpNtGetContextThread(GetCurrentThread(), &ctx);
    ctx.Dr0 = 0; //清空
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0;
    this->winapi.lpNtSetContextThread(GetCurrentThread(), &ctx);
}