#pragma once

#define SLEEP_VSS_SYNC 500

#include <Windows.h>

#include "main.h"

BOOL createSS(WCHAR sourcePathFileSAM[MAX_PATH * sizeof(WCHAR)], WCHAR sourcePathFileSYSTEM[MAX_PATH * sizeof(WCHAR)]);
void getSAMfromRegf(PSAM samRegEntries[], PULONG size, WCHAR SAMPath[MAX_PATH], WCHAR SYSTEMPath[MAX_PATH]);
void getClassesfromRegf(PSAM samRegEntry, WCHAR SYSTEMPath[MAX_PATH]);
