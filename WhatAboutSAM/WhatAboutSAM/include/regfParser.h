#pragma once

#include <Windows.h>

#define REG_NONE        0x00
#define REG_SZ          0x01
#define REG_EXPAND_SZ   0x02
#define REG_BINARY      0x03
#define REG_DWORD       0x04
#define REG_MULTISZ     0x07
#define REG_QWORD       0x0b
#define ROOT_KEY        0x2c

using namespace std;

struct REG_REGF {
    CHAR Magic[4];
    ULONG Unknown;
    ULONG Unknown2;
    ULONGLONG lastChange;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG _0;
    ULONG _11;
    ULONG OffsetFirstRecord;
    ULONG DataSize;
    ULONG _1111;
    CHAR Name[48];
    CHAR Remaining1[411];
    ULONG CheckSum;
    CHAR Remaining2[3585];
};

struct REG_HBIN {
    CHAR Magic[4];
    ULONG OffsetFirstHBin;
    ULONG OffsetNextHBin;
    ULONG BlockSize;
};

struct REG_HBINBLOCK {
    LONG DataBlockSize;
    CHAR Data[];
};

struct REG_NK {
    CHAR Magic[2];
    ULONGLONG lastChange;
    ULONG Unknown;
    LONG OffsetParent;
    ULONG NumSubKeys;
    ULONG Unknown2;
    LONG OffsetSubKeyLf;
    ULONG Unknown3;
    ULONG NumValues;
    LONG OffsetValueList;
    LONG OffsetSkRecord;
    LONG OffsetClassName;
    CHAR UnUsed[20];
    SHORT NameLength;
    SHORT ClassNameLength;
    CHAR KeyName[];
};

struct REG_VK {
    CHAR Magic[2];
    SHORT NameLength;
    LONG DataLen;
    ULONG OffsetData;
    ULONG ValueType;
    SHORT Flag;
    SHORT UnUsed;
    CHAR Name[];
};

struct REG_LF {
    CHAR Magic[2];
    SHORT NumKeys;
    CHAR HashRecords[];
};

struct REG_LH {
    CHAR Magic[2];
    SHORT NumKeys;
    CHAR HashRecords[];
};

struct REG_RI {
    CHAR Magic[2];
    SHORT NumKeys;
    CHAR HashRecords[];
};

struct REG_SK {
    CHAR Magic[2];
    USHORT UnUsed;
    LONG OffsetPreviousSk;
    LONG OffsetNextSk;
    ULONG UsageCounter;
    ULONG SizeSk;
    CHAR Data[];
};

struct REG_HASH {
    ULONG OffsetNk;
    CHAR KeyName[4];
};


