// Thanks Paranoid Ninja: https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/

#include "proxyNtCalls.h"
#include "main.h"

myTpAllocWork pMyTpAllocWork = (myTpAllocWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpAllocWork");
myTpPostWork pMyTpPostWork = (myTpPostWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpPostWork");
myTpReleaseWork pMyTpReleaseWork = (myTpReleaseWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpReleaseWork");

NTSTATUS proxyNtOpenKey (FARPROC pNtOpenKey, PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
	extern VOID CALLBACK WorkCallbackNtOpenKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

	NTOPENKEY_ARGS ntOpenKeyArgs = {};
	ntOpenKeyArgs.pNtOpenKey = pNtOpenKey;
	ntOpenKeyArgs.KeyHandle = KeyHandle;
	ntOpenKeyArgs.DesiredAccess = DesiredAccess;
	ntOpenKeyArgs.ObjectAttributes = ObjectAttributes;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtOpenKey, &ntOpenKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	return 0;
}

NTSTATUS proxyNtQueryKey(FARPROC pNtQueryKey, HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtQueryKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

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

	return 0;
}

NTSTATUS proxyNtEnumerateKey(FARPROC pNtEnumerateKey, HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtEnumerateKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

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

	return 0;
}

NTSTATUS proxyNtQueryValueKey(FARPROC pNtQueryValueKey, HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtQueryValueKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

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

	return 0;
}

NTSTATUS proxyNtEnumerateValueKey(FARPROC pNtEnumerateValueKey, HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	extern VOID CALLBACK WorkCallbackNtEnumerateValueKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

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

	return 0;
}

NTSTATUS proxyNtCloseKey(FARPROC pNtCloseKey, HANDLE KeyHandle) {
	extern VOID CALLBACK WorkCallbackNtCloseKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

	NTCLOSE_ARGS ntCloseKeyArgs = {};
	ntCloseKeyArgs.pNtCloseKey = pNtCloseKey;
	ntCloseKeyArgs.KeyHandle = KeyHandle;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtCloseKey, &ntCloseKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	return 0;
}

NTSTATUS proxyRtlInitUnicodeString(FARPROC pRtlInitUnicodeString, PUNICODE_STRING DestinationString, __drv_aliasesMem PCWSTR SourceString) {
	extern VOID CALLBACK WorkCallbackRtlInitUnicodeString(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

	RTLINITUNICODESTRING_ARGS rtlInitUnicodeStringArgs = {};
	rtlInitUnicodeStringArgs.pRltInitUnicodeString = pRtlInitUnicodeString;
	rtlInitUnicodeStringArgs.DestinationString = DestinationString;
	rtlInitUnicodeStringArgs.SourceString = SourceString;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackRtlInitUnicodeString, &rtlInitUnicodeStringArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	return 0;
}