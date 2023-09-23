// Thanks Paranoid Ninja: https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <windef.h>

#include "ntdll.h"

typedef struct _NTOPENKEY_ARGS {
    UINT_PTR pNtOpenKey;                   // pointer to NtOpenKey - rax
	PHANDLE KeyHandle;                     // rcx
    ACCESS_MASK DesiredAccess;             // rdx 
    POBJECT_ATTRIBUTES ObjectAttributes;   // r8
} NTOPENKEY_ARGS, * PNTOPENKEY_ARGS;

typedef struct _NTQUERYKEY_ARGS {
    UINT_PTR pNtQueryKey;                                           // pointer to NtQueryKey - rax
    HANDLE KeyHandle;                                               // rcx
    KEY_INFORMATION_CLASS KeyInformationClass;                      // rdx
    PVOID KeyInformation;                                           // r8 
    ULONG Length;                                                   // r9
    PULONG ResultLength;                                            // RSP + 0x28
} NTQUERYKEY_ARGS, * PNTQUERYKEY_ARGS;

typedef struct _NTENUMERATEKEY_ARGS {
    UINT_PTR pNtEnumerateKey;                                       // pointer to NtEnumerateKey - rax
    HANDLE KeyHandle;                                               // rcx
    ULONG Index;                                                    // rdx
    KEY_INFORMATION_CLASS KeyInformationClass;                      // r8 
    PVOID KeyInformation;                                           // r9
    ULONG Length;                                                   // RSP + 0x28
    PULONG ResultLength;                                            // RSP + 0x2c
} NTENUMERATEKEY_ARGS, * PNTENUMERATEKEY_ARGS;

typedef struct _NTQUERYVALUEKEY_ARGS {
    UINT_PTR pNtQueryValueKey;                                      // pointer to NtQueryValueKey - rax
    HANDLE KeyHandle;                                               // rcx
    PUNICODE_STRING ValueName;                                      // rdx
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass;           // r8 
    PVOID KeyValueInformation;                                      // r9
    ULONG Length;                                                   // RSP + 0x28
    PULONG ResultLength;                                            // RSP + 0x2c
} NTQUERYVALUEKEY_ARGS, * PNTQUERYVALUEKEY_ARGS;

typedef struct _NTENUMERATEVALUEKEY_ARGS {
    UINT_PTR pNtEnumerateValueKey;                                  // pointer to NtEnumerateValueKey - rax
    HANDLE KeyHandle;                                               // rcx
    ULONG Index;                                                    // rdx
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass;           // r8 
    PVOID KeyValueInformation;                                      // r9
    ULONG Length;                                                   // RSP + 0x28
    PULONG ResultLength;                                            // RSP + 0x30
} NTENUMERATEVALUEKEY_ARGS, * PNTENUMERATEVALUEKEY_ARGS;

typedef struct _NTCLOSE_ARGS {
    UINT_PTR pNtCloseKey;                                           // pointer to pNtCloseKey - rax
    HANDLE KeyHandle;                                               // rcx
} NTCLOSE_ARGS, * PNTCLOSE_ARGS;

typedef struct _RTLINITUNICODESTRING_ARGS {
    UINT_PTR pRltInitUnicodeString;                                 // pointer to RltInitUnicodeString - rax
    PUNICODE_STRING DestinationString;                              // rcx
    __drv_aliasesMem PCWSTR SourceString;                           // rdx
} RTLINITUNICODESTRING_ARGS, * PRTLINITUNICODESTRING_ARGS;