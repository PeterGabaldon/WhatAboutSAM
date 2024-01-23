// Peter Gabaldon. https://pgj11.com/.
// Perform a Shadow Snapshot to read SAM and SYSTEM
// from this newly created SS instead of reading them from the registry

// For this, we need to parse the whole SAM and SYSTEM using the REGF format.
// https://github.com/fortra/impacket/blob/master/impacket/winregistry.py#L46
// https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/winbase/vss/vshadow/shadow.cpp
// https://github.com/PeterUpfold/ShadowDuplicator
// https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-reference
//#define _CRT_SECURE_NO_WARNINGS

#include "shadowMethod.h"

BOOL createSS() {
	// For now, we presuppose C:

	// Not necessary right now. Later, when using args is better to use GetVolumePathNameW(); before GetVolumeNameForVolumeMountPointW 

	WCHAR volumeName[MAX_PATH] = {};
	if (!GetVolumeNameForVolumeMountPointW(L"C:\\", volumeName, MAX_PATH)) {
		return FALSE;
	}



}