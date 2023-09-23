// Thanks Paranoid Ninja: https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <windef.h>

#include "ntdll.h"

typedef NTSTATUS(NTAPI* myTpAllocWork)(PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef VOID(NTAPI* myTpPostWork)(PTP_WORK);
typedef VOID(NTAPI* myTpReleaseWork)(PTP_WORK);

typedef struct _NTOPENKEY_ARGS {
    FARPROC pNtOpenKey;                    // pointer to NtOpenKey - rax
	PHANDLE KeyHandle;                     // rcx
    ACCESS_MASK DesiredAccess;             // rdx 
    POBJECT_ATTRIBUTES ObjectAttributes;   // r8
} NTOPENKEY_ARGS, * PNTOPENKEY_ARGS;

typedef struct _NTQUERYKEY_ARGS {
    FARPROC pNtQueryKey;                                            // pointer to NtQueryKey - rax
    HANDLE KeyHandle;                                               // rcx
    KEY_INFORMATION_CLASS KeyInformationClass;                      // rdx
    PVOID KeyInformation;                                           // r8 
    ULONG Length;                                                   // r9
    PULONG ResultLength;                                            // RSP + 0x28
} NTQUERYKEY_ARGS, * PNTQUERYKEY_ARGS;

typedef struct _NTENUMERATEKEY_ARGS {
    FARPROC pNtEnumerateKey;                                        // pointer to NtEnumerateKey - rax
    HANDLE KeyHandle;                                               // rcx
    ULONG Index;                                                    // rdx
    KEY_INFORMATION_CLASS KeyInformationClass;                      // r8 
    PVOID KeyInformation;                                           // r9
    ULONG Length;                                                   // RSP + 0x28
    PULONG ResultLength;                                            // RSP + 0x2c
} NTENUMERATEKEY_ARGS, * PNTENUMERATEKEY_ARGS;

typedef struct _NTQUERYVALUEKEY_ARGS {
    FARPROC pNtQueryValueKey;                                       // pointer to NtQueryValueKey - rax
    HANDLE KeyHandle;                                               // rcx
    PUNICODE_STRING ValueName;                                      // rdx
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass;           // r8 
    PVOID KeyValueInformation;                                      // r9
    ULONG Length;                                                   // RSP + 0x28
    PULONG ResultLength;                                            // RSP + 0x2c
} NTQUERYVALUEKEY_ARGS, * PNTQUERYVALUEKEY_ARGS;

typedef struct _NTENUMERATEVALUEKEY_ARGS {
    FARPROC pNtEnumerateValueKey;                                   // pointer to NtEnumerateValueKey - rax
    HANDLE KeyHandle;                                               // rcx
    ULONG Index;                                                    // rdx
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass;           // r8 
    PVOID KeyValueInformation;                                      // r9
    ULONG Length;                                                   // RSP + 0x28
    PULONG ResultLength;                                            // RSP + 0x30
} NTENUMERATEVALUEKEY_ARGS, * PNTENUMERATEVALUEKEY_ARGS;

typedef struct _NTCLOSE_ARGS {
    FARPROC pNtCloseKey;                                            // pointer to pNtCloseKey - rax
    HANDLE KeyHandle;                                               // rcx
} NTCLOSE_ARGS, * PNTCLOSE_ARGS;

typedef struct _RTLINITUNICODESTRING_ARGS {
    FARPROC pRltInitUnicodeString;                                  // pointer to RltInitUnicodeString - rax
    PUNICODE_STRING DestinationString;                              // rcx
    __drv_aliasesMem PCWSTR SourceString;                           // rdx
} RTLINITUNICODESTRING_ARGS, * PRTLINITUNICODESTRING_ARGS;