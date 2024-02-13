// Thanks to impacket
// https://github.com/fortra/impacket/blob/master/impacket/winregistry.py

#include "include/regfParser.h"

void findRootKey(PBYTE regf, ULONG regfLen, PBYTE * block) {
	REG_HBIN * hbin;
	PBYTE spure;
	ULONG i = 4096; // Ignore first 4KB, REGF header
	while (i <= regfLen) {
		hbin = (PREG_HBIN) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
		CopyMemory(regf + i, hbin, 0x20);

		spure = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hbin->OffsetNextHBin - 0x20);
		CopyMemory(regf + i + 0x20, spure, hbin->OffsetNextHBin - 0x20);

		// Process Data blocks

		HeapFree(GetProcessHeap(), NULL, hbin);
		HeapFree(GetProcessHeap(), NULL, spure);
		i += hbin->OffsetNextHBin;
	}
}