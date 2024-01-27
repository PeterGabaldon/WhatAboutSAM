// Peter Gabaldon. https://pgj11.com/.
// Perform a Shadow Snapshot to read SAM and SYSTEM
// from this newly created SS instead of reading them from the registry

// For this method, we need to parse the whole SAM and SYSTEM using the REGF format.
// https://github.com/fortra/impacket/blob/master/impacket/winregistry.py#L46
// https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/winbase/vss/vshadow/shadow.cpp
// https://github.com/PeterUpfold/ShadowDuplicator
// https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-reference
//#define _CRT_SECURE_NO_WARNINGS

#include "shadowMethod.h"

BOOL createSS() {
	HRESULT result;
	IVssBackupComponents * backupComponents = NULL;
	IVssAsync * vssAsync = NULL;
	HRESULT asyncResult = E_FAIL;
	VSS_ID * snapshotSetId = NULL;
	VSS_ID * snapshotId = NULL;
	VSS_SNAPSHOT_PROP snapshotProp{};
	// For now, we presuppose C:

	// Not necessary right now. Later, when using args is better to use GetVolumePathNameW(); before GetVolumeNameForVolumeMountPointW 

	WCHAR volumeName[MAX_PATH] = {};
	if (!GetVolumeNameForVolumeMountPointW(L"C:\\", volumeName, MAX_PATH)) {
		return FALSE;
	}

	// Init COM
	result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	if (result != S_OK) {
		exit(result);
	}
	
	result = CreateVssBackupComponents(&backupComponents);

	if (result != S_OK) {
		exit(result);
	}

	result = backupComponents->InitializeForBackup();

	if (result != S_OK) {
		exit(result);
	}

	result = backupComponents->GatherWriterMetadata(&vssAsync);

	if (result != S_OK) {
		exit(result);
	}

	while (asyncResult != VSS_S_ASYNC_CANCELLED && asyncResult != VSS_S_ASYNC_FINISHED) {
		Sleep(SLEEP_VSS_SYNC);
		result = vssAsync->QueryStatus(&asyncResult, NULL);
		if (result != S_OK) {
			vssAsync->Release();
			vssAsync = NULL;
		}
	}

	if (asyncResult == VSS_S_ASYNC_CANCELLED) {
		vssAsync->Release();
		vssAsync = NULL;
	}

	vssAsync->Release();
	vssAsync = NULL;

	asyncResult = E_FAIL;

	result = backupComponents->SetBackupState(false, false, VSS_BT_FULL, false);

	snapshotSetId = (VSS_ID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VSS_ID));

	result = backupComponents->StartSnapshotSet(snapshotSetId);

	// from StartSnapshotSet until backup completion, if we fail, we must call AbortBackup inside bail
	BOOL shouldAbortBackupOnBail = FALSE;

	snapshotId = (VSS_ID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VSS_ID));

	result = backupComponents->AddToSnapshotSet(volumeName, GUID_NULL, snapshotId);

	result = backupComponents->PrepareForBackup(&vssAsync);

	while (asyncResult != VSS_S_ASYNC_CANCELLED && asyncResult != VSS_S_ASYNC_FINISHED) {
		Sleep(SLEEP_VSS_SYNC);
		result = vssAsync->QueryStatus(&asyncResult, NULL);
		if (result != S_OK) {
			vssAsync->Release();
			vssAsync = NULL;
		}
	}

	if (asyncResult == VSS_S_ASYNC_CANCELLED) {
		vssAsync->Release();
		vssAsync = NULL;
	}

	asyncResult = E_FAIL;
	vssAsync->Release();
	vssAsync = NULL;

	// verify all VSS writers are in the correct state
	// TODO
	// VerifyWriterStatus();

	result = backupComponents->DoSnapshotSet(&vssAsync);

	while (asyncResult != VSS_S_ASYNC_CANCELLED && asyncResult != VSS_S_ASYNC_FINISHED) {
		Sleep(SLEEP_VSS_SYNC);
		result = vssAsync->QueryStatus(&asyncResult, NULL);
		if (result != S_OK) {
			vssAsync->Release();
			vssAsync = NULL;
		}
	}

	if (asyncResult == VSS_S_ASYNC_CANCELLED) {
		vssAsync->Release();
		vssAsync = NULL;
	}

	asyncResult = E_FAIL;
	vssAsync->Release();
	vssAsync = NULL;

	// verify all VSS writers are in the correct state
	// TODO
	// VerifyWriterStatus();

	result = backupComponents->GetSnapshotProperties(*snapshotId, &snapshotProp);

	// TO BE CONTINUED :)
}