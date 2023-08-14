#pragma once

#include <windef.h>
#include "ntdll.h"

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_SAM_ENTRIES 100

typedef FARPROC(WINAPI* myMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
typedef NTSTATUS(WINAPI* myNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* myNtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateValueKey)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef VOID(WINAPI* myRtlInitUnicodeString)(PUNICODE_STRING, __drv_aliasesMem PCWSTR);

typedef struct _sam {
	PCHAR rid;
	PBYTE v;
	PBYTE f;
	PCHAR classes;
} *PSAM, SAM;

void getSAM(PSAM samRegEntries[], PULONG len);
void getClasses(PSAM samRegEntry);
void getBootKey(PSAM samRegEntry, int* bootKeyRet);