#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstring>

// make sure to disable all optimisations to make stubfunc appear in asm i think? projectsettings->c++->advanced->optimisations->disabled

void xormem(ULONG64 StartAddr, ULONG64 dwSize)
{
    // x64 xormem, no inline asm
    UCHAR* ecx = reinterpret_cast<UCHAR*>(StartAddr + dwSize);
    UCHAR* eax = reinterpret_cast<UCHAR*>(StartAddr);

    // crypt_loop
    for (; eax < ecx; eax+=sizeof(UCHAR))
    {
        *eax ^= 0xb3;
    }
}

/*    __asm // inline asm only for x86 i hate microsoft
    {
        push eax
        push ecx
        mov ecx, StartAddr
        add ecx, dwSize
        mov eax, StartAddr

        crypt_loop :
        xor byte ptr ds : [eax] , 0xb3
            inc eax
            cmp eax, ecx
            jl crypt_loop;

        pop ecx
        pop eax
    }
*/


ULONG64 GetProcSize(ULONG64* Function, ULONG64* StubFunction)
{
    ULONG64 dwFunctionSize = 0;
    ULONG64* fnA = 0, * fnB = 0;
    DWORD dwOldProtect;

    fnA = (ULONG64*)Function;
    fnB = (ULONG64*)StubFunction;
    dwFunctionSize = (fnB - fnA); // the address of the end of the function minus the address start of the function

    // disable memory protection so that we can modify it later (i think)
    VirtualProtect(fnA, dwFunctionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    return dwFunctionSize;
}

// dumps bytes in memory
void hexDump(void* addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char* pc = (unsigned char*)addr;

    printf("\n");

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        }
        else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s", buff);
}

// the test function that we will be encrypting
void TestFunc()
{
    MessageBoxA(0, "MR WHITE!", "it seems to be working mr white", 0);
} void StubFunc() { } // this marks the end of the function, so that we can calculate the size of it. Make sure optimization is diabled for this to work

ULONG64 funcSize = GetProcSize((ULONG64*)&TestFunc, (ULONG64*)&StubFunc);


int main()
{

    TestFunc();
    hexDump(&TestFunc, funcSize);
    std::cout << "    the bytes of the function normally";

    xormem((ULONG64)&TestFunc, funcSize);
    hexDump(&TestFunc, funcSize);
    std::cout << "    the bytes of the function encrypted";

    // calling testfunc here will crash the program because it is encrypted 
    // TestFunc();

    xormem((ULONG64)&TestFunc, funcSize);
    hexDump(&TestFunc, funcSize);
    std::cout << "    the bytes of the function restored";
    TestFunc();
}