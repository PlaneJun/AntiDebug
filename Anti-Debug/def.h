#pragma once


//0x8 bytes (sizeof)
struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    WCHAR* Buffer;                                                          //0x4
};




//0x480 bytes (sizeof)
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;

    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN SpareBits : 1;
        };
    };

    HANDLE Mutant;
    PVOID ImageBaseAddress;
    void* LoaderData;
    void* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };

        ULONG EnvironmentUpdateCount;
    };

    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    void** ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    void** ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    ULONG GdiHandleBuffer;
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    _UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
    void** FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };

    ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA
{
    DWORD Length;  //0x00
    bool Initialized;    //0x04
    PVOID SsHandle;  //0x08
    LIST_ENTRY InLoadOrderModuleList;  // 0x0C                模块加载顺序
    LIST_ENTRY InMemoryOrderModuleList;  //0x14            模块在内存中的顺序
    LIST_ENTRY InInitiallizationOrderModuleList; // 0x1C     模块初始化装载顺序
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_MODULE
{
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG               SizeOfImage;
    _UNICODE_STRING   FullDllName;
    _UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    HANDLE              SectionHandle;
    ULONG               CheckSum;
    ULONG               TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;


typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, 					// 0x0
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,							// 0x7
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information, 					// 0x1A
    ProcessImageFileName, 						// 0x1B
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,					// 0x1E
    ProcessDebugFlags, 							// 0x1F
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessResourceManagement,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    ProcessHandleInformation,
    ProcessMitigationPolicy,
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode,
    ProcessKeepAliveCount,
    ProcessRevokeFileHandles,
    ProcessWorkingSetControl,
    ProcessHandleTable,
    ProcessCheckStackExtentsMode,
    ProcessCommandLineInformation,
    ProcessProtectionInformation,
    ProcessMemoryExhaustion,
    ProcessFaultInformation,
    ProcessTelemetryIdInformation,
    ProcessCommitReleaseInformation,
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation,
    ProcessInPrivate,
    ProcessRaiseUMExceptionOnInvalidHandleClose,
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation,
    ProcessHighGraphicsPriorityInformation,
    ProcessSubsystemInformation,
    ProcessEnergyValues,
    ProcessActivityThrottleState,
    ProcessActivityThrottlePolicy,
    ProcessWin32kSyscallFilterInformation,
    ProcessDisableSystemAllowedCpuSets,
    ProcessWakeInformation,
    ProcessEnergyTrackingState,
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,   // Obsolete
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,          // Obsolete
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,      // UMS
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    MaxThreadInfoClass
} THREADINFOCLASS;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,// 0 Y N
    SystemProcessorInformation,// 1 Y N
    SystemPerformanceInformation,// 2 Y N
    SystemTimeOfDayInformation,// 3 Y N
    SystemNotImplemented1,// 4 Y N // SystemPathInformation
    SystemProcessesAndThreadsInformation,// 5 Y N
    SystemCallCounts,// 6 Y N
    SystemConfigurationInformation,// 7 Y N
    SystemProcessorTimes,// 8 Y N
    SystemGlobalFlag,// 9 Y Y
    SystemNotImplemented2,// 10 YN // SystemCallTimeInformation
    SystemModuleInformation,// 11 YN
    SystemLockInformation,// 12 YN
    SystemNotImplemented3,// 13 YN // SystemStackTraceInformation
    SystemNotImplemented4,// 14 YN // SystemPagedPoolInformation
    SystemNotImplemented5,// 15 YN // SystemNonPagedPoolInformation
    SystemHandleInformation,// 16 YN
    SystemObjectInformation,// 17 YN
    SystemPagefileInformation,// 18 YN
    SystemInstructionEmulationCounts,// 19 YN
    SystemInvalidInfoClass1,// 20
    SystemCacheInformation,// 21 YY
    SystemPoolTagInformation,// 22 YN
    SystemProcessorStatistics,// 23 YN
    SystemDpcInformation,// 24 YY
    SystemNotImplemented6,// 25 YN // SystemFullMemoryInformation
    SystemLoadImage,// 26 NY // SystemLoadGdiDriverInformation
    SystemUnloadImage,// 27 NY
    SystemTimeAdjustment,// 28 YY
    SystemNotImplemented7,// 29 YN // SystemSummaryMemoryInformation
    SystemNotImplemented8,// 30 YN // SystemNextEventIdInformation
    SystemNotImplemented9,// 31 YN // SystemEventIdsInformation
    SystemCrashDumpInformation,// 32 YN
    SystemExceptionInformation,// 33 YN
    SystemCrashDumpStateInformation,// 34 YY/N
    SystemKernelDebuggerInformation,// 35 YN
    SystemContextSwitchInformation,// 36 YN
    SystemRegistryQuotaInformation,// 37 YY
    SystemLoadAndCallImage,// 38 NY // SystemExtendServiceTableInformation
    SystemPrioritySeparation,// 39 NY
    SystemNotImplemented10,// 40 YN // SystemPlugPlayBusInformation
    SystemNotImplemented11,// 41 YN // SystemDockInformation
    SystemInvalidInfoClass2,// 42 // SystemPowerInformation
    SystemInvalidInfoClass3,// 43 // SystemProcessorSpeedInformation
    SystemTimeZoneInformation,// 44 YN
    SystemLookasideInformation,// 45 YN
    SystemSetTimeSlipEvent,// 46 NY
    SystemCreateSession,// 47 NY
    SystemDeleteSession,// 48 NY
    SystemInvalidInfoClass4,// 49
    SystemRangeStartInformation,// 50 YN
    SystemVerifierInformation,// 51 YY
    SystemAddVerifier,// 52 NY
    SystemSessionProcessesInformation// 53 YN
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION {
    _UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
}OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION {
    ULONG NumberOfObjects;
    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
}OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    _UNICODE_STRING *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES,* POBJECT_ATTRIBUTES;


#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


#define DEBUG_OBJECT_KILLONCLOSE	0x1
#define DEBUG_READ_EVENT			0x0001
#define DEBUG_PROCESS_ASSIGN		0x0002
#define DEBUG_SET_INFORMATION		0x0004
#define DEBUG_QUERY_INFORMATION		0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE |  DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | DEBUG_QUERY_INFORMATION)