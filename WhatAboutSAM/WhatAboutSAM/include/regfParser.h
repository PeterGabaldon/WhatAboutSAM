#pragma once

#include <Windows.h>

// Constants
#define REG_NONE        0x00
#define REG_SZ          0x01
#define REG_EXPAND_SZ   0x02
#define REG_BINARY      0x03
#define REG_DWORD       0x04
#define REG_MULTISZ     0x07
#define REG_QWORD       0x0b
#define ROOT_KEY        0x2c

// Structs
typedef struct _REG_REGF {
    BYTE Magic[4];
    DWORD Unknown;
    DWORD Unknown2;
    ULONGLONG lastChange;
    DWORD MajorVersion;
    DWORD MinorVersion;
    DWORD _0;
    DWORD _11;
    DWORD OffsetFirstRecord;
    DWORD DataSize;
    DWORD _1111;
    BYTE Name[48];
    BYTE Remaining1[411];
    DWORD CheckSum;
    BYTE Remaining2[3585];
} REG_REGF, *PREG_REGF;

typedef struct _REG_HBIN {
    BYTE Magic[4];
    DWORD OffsetFirstHBin;
    DWORD OffsetNextHBin;
    DWORD BlockSize;
} REG_HBIN, *PREG_HBIN;

typedef struct _REG_HBINBLOCK {
    LONG DataBlockSize;
    BYTE Data[];
} REG_HBINBLOCK, *PREG_HBINBLOCK;

typedef struct _REG_NK {
    BYTE Magic[2];
    USHORT Type;
    ULONGLONG lastChange;
    DWORD Unknown;
    LONG OffsetParent;
    DWORD NumSubKeys;
    DWORD Unknown2;
    LONG OffsetSubKeyLf;
    DWORD Unknown3;
    DWORD NumValues;
    LONG OffsetValueList;
    LONG OffsetSkRecord;
    LONG OffsetClassName;
    BYTE UnUsed[20];
    USHORT NameLength;
    USHORT ClassNameLength;
    BYTE KeyName[];
} REG_NK, *PREG_NK;

typedef struct _REG_VK {
    BYTE Magic[2];
    USHORT NameLength;
    LONG DataLen;
    DWORD OffsetData;
    DWORD ValueType;
    USHORT Flag;
    USHORT UnUsed;
    BYTE Name[];
} REG_VK, *PREG_VK;

typedef struct _REG_LF {
    BYTE Magic[2];
    USHORT NumKeys;
    BYTE HashRecords[];
} REG_LF, *PREG_LF;

typedef struct _REG_LH {
    BYTE Magic[2];
    USHORT NumKeys;
    BYTE HashRecords[];
} REG_LH, *PREG_LH;

typedef struct _REG_RI {
    BYTE Magic[2];
    USHORT NumKeys;
    BYTE HashRecords[];
} REG_RI, *PREG_RI;

typedef struct _REG_SK {
    BYTE Magic[2];
    USHORT UnUsed;
    LONG OffsetPreviousSk;
    LONG OffsetNextSk;
    DWORD UsageCounter;
    DWORD SizeSk;
    BYTE Data[];
} REG_SK, *PREG_SK;

typedef struct _REG_HASH {
    DWORD OffsetNk;
    BYTE KeyName[4];
} REG_HASH, *PREG_HASH;
