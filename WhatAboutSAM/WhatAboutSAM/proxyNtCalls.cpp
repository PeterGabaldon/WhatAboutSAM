// Thanks Paranoid Ninja: https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/

#include "proxyNtCalls.h"
#include "main.h"

myTpAllocWork pMyTpAllocWork = (myTpAllocWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpAllocWork");
myTpPostWork pMyTpPostWork = (myTpPostWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpPostWork");
myTpReleaseWork pMyTpReleaseWork = (myTpReleaseWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpReleaseWork");

NTSTATUS proxyNtOpenKey (FARPROC pNtOpenKey, PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
	extern VOID CALLBACK WorkCallbackNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

	NTOPENKEY_ARGS ntOpenKeyArgs = {};
	ntOpenKeyArgs.pNtOpenKey = pNtOpenKey;
	ntOpenKeyArgs.KeyHandle = KeyHandle;
	ntOpenKeyArgs.DesiredAccess = DesiredAccess;
	ntOpenKeyArgs.ObjectAttributes = ObjectAttributes;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtOpenKey, &ntOpenKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}

NTSTATUS proxyNtQueryKey(FARPROC pNtQueryKey, HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);

	NTQUERYKEY_ARGS ntQueryKeyArgs = {};
	ntQueryKeyArgs.pNtQueryKey = pNtQueryKey;
	ntQueryKeyArgs.KeyHandle = KeyHandle;
	ntQueryKeyArgs.KeyInformationClass = KeyInformationClass;
	ntQueryKeyArgs.KeyInformation = KeyInformation;
	ntQueryKeyArgs.Length = Length;
	ntQueryKeyArgs.ResultLength = ResultLength;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtQueryKey, &ntQueryKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}

NTSTATUS proxyNtEnumerateKey(FARPROC pNtEnumerateKey, HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);

	NTENUMERATEKEY_ARGS ntEnumerateKeyArgs = {};
	ntEnumerateKeyArgs.pNtEnumerateKey = pNtEnumerateKey;
	ntEnumerateKeyArgs.KeyHandle = KeyHandle;
	ntEnumerateKeyArgs.Index = Index;
	ntEnumerateKeyArgs.KeyInformationClass = KeyInformationClass;
	ntEnumerateKeyArgs.KeyInformation = KeyInformation;
	ntEnumerateKeyArgs.Length = Length;
	ntEnumerateKeyArgs.ResultLength = ResultLength;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtEnumerateKey, &ntEnumerateKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}

NTSTATUS proxyNtQueryValueKey(FARPROC pNtQueryValueKey, HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

	NTQUERYVALUEKEY_ARGS ntQueryValueKeyArgs = {};
	ntQueryValueKeyArgs.pNtQueryValueKey = pNtQueryValueKey;
	ntQueryValueKeyArgs.KeyHandle = KeyHandle;
	ntQueryValueKeyArgs.ValueName = ValueName;
	ntQueryValueKeyArgs.KeyValueInformationClass = KeyValueInformationClass;
	ntQueryValueKeyArgs.KeyValueInformation = KeyValueInformation;
	ntQueryValueKeyArgs.Length = Length;
	ntQueryValueKeyArgs.ResultLength = ResultLength;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtQueryValueKey, &ntQueryValueKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}

NTSTATUS proxyNtEnumerateValueKey(FARPROC pNtEnumerateValueKey, HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

	NTENUMERATEVALUEKEY_ARGS ntEnumerateValueKeyArgs = {};
	ntEnumerateValueKeyArgs.pNtEnumerateValueKey = pNtEnumerateValueKey;
	ntEnumerateValueKeyArgs.KeyHandle = KeyHandle;
	ntEnumerateValueKeyArgs.Index = Index;
	ntEnumerateValueKeyArgs.KeyValueInformationClass = KeyValueInformationClass;
	ntEnumerateValueKeyArgs.KeyValueInformation = KeyValueInformation;
	ntEnumerateValueKeyArgs.Length = Length;
	ntEnumerateValueKeyArgs.ResultLength = ResultLength;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtEnumerateValueKey, &ntEnumerateValueKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}

NTSTATUS proxyNtCloseKey(FARPROC pNtCloseKey, HANDLE KeyHandle) {
	extern VOID CALLBACK WorkCallbackNtCloseKey(HANDLE KeyHandle);

	NTCLOSE_ARGS ntCloseKeyArgs = {};
	ntCloseKeyArgs.pNtCloseKey = pNtCloseKey;
	ntCloseKeyArgs.KeyHandle = KeyHandle;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtCloseKey, &ntCloseKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}

NTSTATUS proxyRtlInitUnicodeString(FARPROC pRtlInitUnicodeString, PUNICODE_STRING DestinationString, __drv_aliasesMem PCWSTR SourceString) {
	extern VOID CALLBACK WorkCallbackRtlInitUnicodeString(PUNICODE_STRING DestinationString, __drv_aliasesMem PCWSTR SourceString);

	RTLINITUNICODESTRING_ARGS rtlInitUnicodeStringArgs = {};
	rtlInitUnicodeStringArgs.pRltInitUnicodeString = pRtlInitUnicodeString;
	rtlInitUnicodeStringArgs.DestinationString = DestinationString;
	rtlInitUnicodeStringArgs.SourceString = SourceString;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackRtlInitUnicodeString, &rtlInitUnicodeStringArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}