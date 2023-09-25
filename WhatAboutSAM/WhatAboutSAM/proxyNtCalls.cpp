// Thanks Paranoid Ninja: https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/

#include "proxyNtCalls.h"
#include "main.h"

myTpAllocWork pMyTpAllocWork = (myTpAllocWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpAllocWork");
myTpPostWork pMyTpPostWork = (myTpPostWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpPostWork");
myTpReleaseWork pMyTpReleaseWork = (myTpReleaseWork)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"TpReleaseWork");

extern "C" VOID CALLBACK WorkCallbackNtOpenKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" VOID CALLBACK WorkCallbackNtQueryKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" VOID CALLBACK WorkCallbackNtEnumerateKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" VOID CALLBACK WorkCallbackNtQueryValueKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" VOID CALLBACK WorkCallbackNtEnumerateValueKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" VOID CALLBACK WorkCallbackNtCloseKey(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern "C" VOID CALLBACK WorkCallbackRtlInitUnicodeString(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

NTSTATUS proxyNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
	NTOPENKEY_ARGS ntOpenKeyArgs = {};
	ntOpenKeyArgs.pNtOpenKey = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtOpenKey");
	ntOpenKeyArgs.KeyHandle = KeyHandle;
	ntOpenKeyArgs.DesiredAccess = DesiredAccess;
	ntOpenKeyArgs.ObjectAttributes = ObjectAttributes;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtOpenKey, &ntOpenKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);

	return 0;
}

NTSTATUS proxyNtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
	NTQUERYKEY_ARGS ntQueryKeyArgs = {};
	ntQueryKeyArgs.pNtQueryKey = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtQueryKey");
	ntQueryKeyArgs.KeyHandle = KeyHandle;
	ntQueryKeyArgs.KeyInformationClass = KeyInformationClass;
	ntQueryKeyArgs.KeyInformation = KeyInformation;
	ntQueryKeyArgs.Length = Length;
	ntQueryKeyArgs.ResultLength = ResultLength;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtQueryKey, &ntQueryKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);

	return 0;
}

NTSTATUS proxyNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
	NTENUMERATEKEY_ARGS ntEnumerateKeyArgs = {};
	ntEnumerateKeyArgs.pNtEnumerateKey = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtEnumerateKey");
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

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);

	return 0;
}

NTSTATUS proxyNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	NTQUERYVALUEKEY_ARGS ntQueryValueKeyArgs = {};
	ntQueryValueKeyArgs.pNtQueryValueKey = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtQueryValueKey");
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

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);

	return 0;
}

NTSTATUS proxyNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	NTENUMERATEVALUEKEY_ARGS ntEnumerateValueKeyArgs = {};
	ntEnumerateValueKeyArgs.pNtEnumerateValueKey = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtEnumerateValueKey");
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

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);

	return 0;
}

NTSTATUS proxyNtCloseKey(HANDLE KeyHandle) {
	NTCLOSE_ARGS ntCloseKeyArgs = {};
	ntCloseKeyArgs.pNtCloseKey = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtClose");
	ntCloseKeyArgs.KeyHandle = KeyHandle;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtCloseKey, &ntCloseKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);

	return 0;
}

VOID proxyRtlInitUnicodeString(PUNICODE_STRING DestinationString, __drv_aliasesMem PCWSTR SourceString) {
	RTLINITUNICODESTRING_ARGS rtlInitUnicodeStringArgs = {};
	rtlInitUnicodeStringArgs.pRltInitUnicodeString = myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"RtlInitUnicodeString");
	rtlInitUnicodeStringArgs.DestinationString = DestinationString;
	rtlInitUnicodeStringArgs.SourceString = SourceString;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackRtlInitUnicodeString, &rtlInitUnicodeStringArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);

	WaitForSingleObject(GetCurrentProcess(), THREAD_WAIT);
}
