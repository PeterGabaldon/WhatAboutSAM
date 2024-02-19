// Thanks to impacket
// https://github.com/fortra/impacket/blob/master/impacket/winregistry.py

// Disclaimer: This is not a fully REGF parser. The objective is not to write a REGF parser. The objetive is to get the necessary fields for decrypting SAM entries. 
// Id est, we need to fill the proper SAM structure (main.h)

#include "include/regfParser.h"

void getSAMData(PBYTE regfSAM, ULONG regfSAMLen, PBYTE * block) {
	// This procedure loops over HBINS. For each HBIN tries to locate "Users" key. If found then loop over "Users" keys to get V and F vector of each user.

	REG_HBIN * hBinHeader;
	PBYTE hBinData;
	ULONG i = 4096; // Ignore first 4KB, REGF header
	// Loop over HBINS and parse them.
	while (i <= regfSAMLen) {
		hBinHeader = (PREG_HBIN) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
		CopyMemory(hBinHeader, regfSAM + i, 0x20);

		if (strncmp(hBinHeader->Magic, "hbin", 4) != 0) {
			continue;
		}

		ULONG hBinDataLength = hBinHeader->SizeOfHbin - 0x20;

		hBinData = (PBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hBinDataLength);
		CopyMemory(hBinData, regfSAM + i + 0x20, hBinDataLength);

		// Process Data blocks (of HBIN).
		// When we find "Users" key, loop over subkeys to extract info
		if (findUsersKey(hBinData, hBinDataLength)) {
			// Get Users V and F

		}

		HeapFree(GetProcessHeap(), NULL, hBinHeader);
		HeapFree(GetProcessHeap(), NULL, hBinData);
		i += hBinHeader->SizeOfHbin;
	}
}

// Find "Users" Key under which there are each user Key with V and F, which processed and decrypted get local credentials
BOOL findUsersKey(PBYTE hBinData, ULONG hbinDataLength) {
	// We should be at a NK block
	LONG datablockSize; 
	PREG_NK nk;
	PCHAR keyName;
	DWORD totalRead = 0;

	while (totalRead < hbinDataLength) {
		datablockSize = -((LONG)hBinData - 4);
		if (datablockSize > 0) {
			// Check if signature is 'nk'
			if (hBinData[0] == 0x6e && hBinData[1] == 0x6b) {
				nk = (PREG_NK)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, datablockSize - 4);
				CopyMemory(nk, hBinData, datablockSize - 4);

				keyName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nk->NameLength + 1);
				CopyMemory(keyName, nk->KeyName, nk->NameLength);

				// We check if are at "Users"
				if (strncmp(keyName, "Users", nk->NameLength) == 0) {
					return TRUE;
				}
			}
		}
		totalRead += datablockSize;
		HeapFree(GetProcessHeap(), NULL, nk);
		HeapFree(GetProcessHeap(), NULL, keyName);
	}
	// Presuppose False
	return FALSE;
}

// Get Only V and F for each user and return a SAM structure array. We need to pass whole regf because need to follow LF
void getVandF() {

}