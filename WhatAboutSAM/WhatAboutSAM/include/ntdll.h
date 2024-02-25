#pragma once

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation, // KEY_BASIC_INFORMATION
	KeyNodeInformation, // KEY_NODE_INFORMATION
	KeyFullInformation, // KEY_FULL_INFORMATION
	KeyNameInformation, // KEY_NAME_INFORMATION
	KeyCachedInformation, // KEY_CACHED_INFORMATION
	KeyFlagsInformation, // KEY_FLAGS_INFORMATION
	KeyVirtualizationInformation, // KEY_VIRTUALIZATION_INFORMATION
	KeyHandleTagsInformation, // KEY_HANDLE_TAGS_INFORMATION
	KeyLayerInformation, // KEY_LAYER_INFORMATION
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_FULL_INFORMATION {
	LARGE_INTEGER LastWriteTime;
	ULONG         TitleIndex;
	ULONG         ClassOffset;
	ULONG         ClassLength;
	ULONG         SubKeys;
	ULONG         MaxNameLen;
	ULONG         MaxClassLen;
	ULONG         Values;
	ULONG         MaxValueNameLen;
	ULONG         MaxValueDataLen;
	WCHAR         Class[1];
} KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
	LARGE_INTEGER LastWriteTime;
	ULONG         TitleIndex;
	ULONG         NameLength;
	WCHAR         Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, * PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;

