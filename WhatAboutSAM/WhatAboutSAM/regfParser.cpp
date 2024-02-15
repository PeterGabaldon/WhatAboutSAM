// Thanks to impacket
// https://github.com/fortra/impacket/blob/master/impacket/winregistry.py

// Disclaimer: This is not a fully REGF parser. The objective is not to write a REGF parser. The objetive is to get the necessary fields for decrypting SAM entries. 
// Id est, we need to fill the proper SAM structure (main.h)

#include "include/regfParser.h"

void getSAMData(PBYTE regfSAM, ULONG regfSAMLen, PBYTE * block) {
	REG_HBIN * hBinHeader;
	PBYTE hBinData;
	ULONG i = 4096; // Ignore first 4KB, REGF header
	// Loop over HBINS and parse them.
	while (i <= regfSAMLen) {
		hBinHeader = (PREG_HBIN) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
		CopyMemory(regfSAM + i, hBinHeader, 0x20);

		if (strncmp(hBinHeader->Magic, "hbin", 4) != 0) {
			continue;
		}

		ULONG hBinDataLength = hBinHeader->SizeOfHbin - 0x20;

		hBinData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hBinDataLength);
		CopyMemory(regfSAM + i + 0x20, hBinData, hBinDataLength);

		// Process Data blocks (of HBIN)
		// When we find a user, F, V and RID are get. 
		findUsersKeys(hBinData, hBinDataLength);

		HeapFree(GetProcessHeap(), NULL, hBinHeader);
		HeapFree(GetProcessHeap(), NULL, hBinData);
		i += hBinHeader->SizeOfHbin;
	}
}

BOOL findUsersKeys(PBYTE hBinData, ULONG hbinDataLength) {
	// We should be at a NK block
	LONG datablockSize = -((LONG)hBinData - 4);

	if (datablockSize <= 0) {
		return 0;
	}
}