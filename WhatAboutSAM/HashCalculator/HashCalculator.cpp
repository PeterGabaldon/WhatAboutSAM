// Took from Maldev-Academy. Take a look https://maldevacademy.com/

// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>


#define     STR                 "_RFDT"

CONST CHAR* g_StringsArray[] = {
    // Syscalls
    "NtOpenKey",
    "NtQueryKey",
    "NtEnumerateKey",
    "NtQueryValueKey",
    "NtEnumerateValueKey",
    "NtClose",

    // Proxy Call
    "TpAllocWork",
    "TpPostWork",
    "TpReleaseWork",

    // Utility
    "RtlInitUnicodeString",
    NULL
};


DWORD HashString2A(IN LPCSTR String)
{
    ULONG Hash = 6485;
    INT c = 0;

    while (c = *String++)
        Hash = ((Hash << 5) + Hash) + c;

    return Hash;
}


#define HASH(STR)    ( HashString2A( (LPCSTR)STR ) )


int main() {

    DWORD ii = 0;

    while (g_StringsArray[ii]) {
        printf("#define %s%s \t 0x%0.8X \n", g_StringsArray[ii], STR, HASH(g_StringsArray[ii]));
        ii++;
    }

    // Used in UnhookAllLoadedDlls
    //printf("\n#define %s%s \t 0x%0.8X \n", "text", STR, HASH(".text"));
    // Used in FetchWin32uSyscallInst
    //printf("#define %s%s \t 0x%0.8X \n", "win32udll", STR, HASH("win32u.dll"));

    // Used with GetModuleHandleH
    //printf("\n#define %s%s \t 0x%0.8X \n", "kernel32dll", STR, HASH("kernel32.dll"));
    printf("#define %s%s \t 0x%0.8X \n", "ntdlldll", STR, HASH("NTDLL.DLL"));

}