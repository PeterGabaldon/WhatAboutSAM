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
	ntOpenKeyArgs.KeyHandle = KeyHandle;
	ntOpenKeyArgs.DesiredAccess = DesiredAccess;
	ntOpenKeyArgs.ObjectAttributes = ObjectAttributes;

	PTP_WORK WorkReturn = NULL;
	pMyTpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallbackNtOpenKey, &ntOpenKeyArgs, NULL);
	pMyTpPostWork(WorkReturn);
	pMyTpReleaseWork(WorkReturn);
}