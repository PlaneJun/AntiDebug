#pragma once
#include<Windows.h>
#include"def.h"



typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtCreateDebugObject)(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);
typedef  NTSTATUS(NTAPI* fnNtClose)(HANDLE Handle);
typedef NTSYSAPI NTSTATUS(NTAPI* fnZwSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
typedef NTSTATUS(NTAPI* fnNtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef NTSTATUS(NTAPI* fnNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef BOOL(WINAPI* fnIsDebuggerPresent)(void);
typedef HANDLE (WINAPI* fnGetCurrentProcess)(void); 
typedef HANDLE(WINAPI* fnGetCurrentThread)(void);
typedef void(WINAPI* fnOutputDebugStringA)(LPCSTR str);
typedef BOOL (WINAPI* fnCheckRemoteDebuggerPresent)(HANDLE hProcess,PBOOL pbDebuggerPresent);
typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flAllocationType,DWORD  flProtect);
typedef BOOL (WINAPI* fnVirtualFree)(LPVOID lpAddress,SIZE_T dwSize,DWORD  dwFreeType);
typedef HMODULE (WINAPI* fnGetModuleHandleA)(LPCTSTR lpModuleName);
typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI* fnSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
typedef LONG (WINAPI* fnUnhandledExceptionFilter)(_EXCEPTION_POINTERS* ExceptionInfo);
typedef void (WINAPI* fnRaiseException)(DWORD dwExceptionCode,DWORD dwExceptionFlags,DWORD nNumberOfArguments,const ULONG_PTR* lpArguments);
typedef BOOL (WINAPI* fnSetHandleInformation)(HANDLE hObject,DWORD  dwMask,DWORD  dwFlags);
typedef HANDLE (WINAPI* fnCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName);
typedef HANDLE (WINAPI* fnGetProcessHeap)();
typedef PVOID (WINAPI* fnRtlAllocateHeap)(PVOID  HeapHandle,ULONG  Flags,SIZE_T Size);
typedef PVOID(WINAPI* fnRtlFreeHeap)(PVOID  HeapHandle, ULONG  Flags, PVOID BaseAddress);
typedef BOOL (WINAPI* fnHeapSetInformation)(HANDLE HeapHandle,HEAP_INFORMATION_CLASS HeapInformationClass,PVOID HeapInformation,SIZE_T HeapInformationLength);
typedef BOOL (WINAPI* fnCloseWindow)(HWND hWnd);
typedef DWORD (WINAPI* fnGetLastError)();
typedef LSTATUS (WINAPI* fnRegOpenKeyExA)(HKEY hKey,LPCSTR lpSubKey,DWORD  ulOptions,REGSAM samDesired,PHKEY  phkResult);
typedef LSTATUS (WINAPI* fnRegGetValueA)(HKEY hkey,LPCSTR  lpSubKey,LPCSTR  lpValue,DWORD   dwFlags,LPDWORD pdwType,PVOID   pvData,LPDWORD pcbData);
typedef LONG (WINAPI* fnRegCloseKey)(HKEY hKey);
typedef NTSTATUS(NTAPI* fnNtSetDebugFilterState)(ULONG ComponentId, unsigned int Level, char State);
typedef BOOL(WINAPI* fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef BOOL(WINAPI* fnGetMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
typedef BOOL(WINAPI* fnIsWindow)(HWND hWnd);
typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef BOOL(WINAPI* fnGetUserNameA)(LPSTR   lpBuffer, LPDWORD pcbBuffer);
typedef DWORD(WINAPI* fnCreateThread)(LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef void (WINAPI* fnSleep)(DWORD dwMilliseconds);
typedef HMODULE(WINAPI* fnLoadLibraryA)(_In_opt_ LPCSTR lpFileName);

typedef struct _APITABLE
{
	fnNtQueryInformationProcess lpNtQueryInformationProcess;
	fnNtQueryInformationThread lpNtQueryInformationThread;
	fnNtQueryObject  lpNtQueryObject;
	fnNtQuerySystemInformation lpNtQuerySystemInformation;
	fnNtCreateDebugObject lpNtCreateDebugObject;
	fnNtClose lpNtClose;
	fnZwSetInformationThread lpZwSetInformationThread;
	fnNtGetContextThread lpNtGetContextThread;
	fnNtSetContextThread lpNtSetContextThread;
	fnIsDebuggerPresent lpIsDebuggerPresent;
	fnOutputDebugStringA lpOutputDebugStringA;
	fnCheckRemoteDebuggerPresent lpCheckRemoteDebuggerPresent;
	fnGetCurrentProcess lpGetCurrentProcess;
	fnGetCurrentProcess lpGetCurrentThread;
	fnVirtualAlloc lpVirtualAlloc;
	fnVirtualFree lpVirtualFree;
	fnGetModuleHandleA lpGetModuleHandleA;
	fnSetUnhandledExceptionFilter lpSetUnhandledExceptionFilter;
	fnUnhandledExceptionFilter lpUnhandledExceptionFilter;
	fnRaiseException lpRaiseException;
	fnSetHandleInformation lpSetHandleInformation;
	fnCreateMutexA lpCreateMutexA;
	fnGetProcessHeap lpGetProcessHeap;
	fnRtlAllocateHeap lpRtlAllocateHeap;
	fnRtlFreeHeap lpRtlFreeHeap;
	fnHeapSetInformation lpHeapSetInformation;
	fnCloseWindow lpCloseWindow;
	fnGetLastError lpGetLastError;
	fnRegOpenKeyExA lpRegOpenKeyExA;
	fnRegGetValueA lpRegGetValueA;
	fnRegCloseKey lpRegCloseKey;
	fnNtSetDebugFilterState lpNtSetDebugFilterState;
	fnVirtualProtect lpVirtualProtect;
	fnGetMessageA lpGetMessageA;
	fnIsWindow lpIsWindow;
	fnWriteProcessMemory lpWriteProcessMemory;
	fnGetUserNameA lpGetUserNameA;
	fnCreateThread lpCreateThread;
	fnSleep lpSleep;
	fnLoadLibraryA lpLoadLibraryA;
}APITABLE;

class AntiDebug
{
private:
	static AntiDebug*	m_Instance;
public:
	static AntiDebug* GetInstance();
	void Init();
	HMODULE _LoadLibrary(const wchar_t* image_name);
	DWORD _GetProcAddress(HMODULE hModule,const char* procName);
	void _ExitProcess();
	LPTOP_LEVEL_EXCEPTION_FILTER m_top;
	APITABLE winapi;

	friend LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers);

	BOOL IatHook(LPCWCH szDLLName, LPCTSTR szName, LPVOID NewFun, DWORD* OriginFun);
	BOOL EatHook(LPCWCH szDllName, LPCTSTR szFunName, LPVOID NewFun,DWORD* OriginFun);

	BOOL BasicDebugDetect();
	BOOL QueryInfoDetect();
	BOOL DebugObejctDetect_All();
	BOOL DebugObejctDetect_Create();
	BOOL CloseInvaildHandleDetect();
	BOOL CloseProtectHandleDetect();
	BOOL NtGlobalClearDetect();
	BOOL HideThread();
	BOOL HeapTailDetect();
	BOOL HeapSetInformationDetect();
	BOOL CloseInvaildWindowDetect();
	BOOL TimeDetect();
	BOOL SystemBootDetect();
	BOOL DebugFilterStateDetect();
	BOOL SehDetect();
	BOOL VehDetect();

	void CrashOD();
	void DrClear();
};
