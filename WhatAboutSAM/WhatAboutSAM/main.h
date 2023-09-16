#pragma once

#include <windef.h>
#include "ntdll.h"

#define MAX_KEY_LENGTH 255
#define MAX_KEY_VALUE_LENGTH 1000
#define MAX_VALUE_NAME 16383
#define MAX_SAM_ENTRIES 100
#define STR_TO_KEY_LEN 8

typedef FARPROC(WINAPI* myMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
typedef NTSTATUS(WINAPI* myNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* myNtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
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

void getSAM(PSAM samRegEntries[], PULONG size);
void getClasses(PSAM samRegEntry);
void getBootKey(PSAM samRegEntry, PBYTE bootKeyRet);
void strToKey(PBYTE s, PBYTE keyRet);
void decryptSAM(PSAM samRegEntries[], int entries);