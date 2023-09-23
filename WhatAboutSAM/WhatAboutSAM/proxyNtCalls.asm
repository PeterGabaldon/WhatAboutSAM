section .text

global WorkCallbackNtOpenKey
global WorkCallbackNtQueryKey
global WorkCallbackNtEnumerateKey
global WorkCallbackNtQueryValueKey
global WorkCallbackNtEnumerateValueKey
global WorkCallbackNtCloseKey
global WorkCallbackRtlInitUnicodeString

WorkCallbackNtOpenKey:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtOpenKey
    mov rcx, [rbx + 0x8]        ; PHANDLE KeyHandle
    mov rdx, [rbx + 0x10]       ; ACCESS_MASK DesiredAccess
    mov r8, [rbx + 0x14]        ; POBJECT_ATTRIBUTES ObjectAttributes
    jmp rax

WorkCallbackNtQueryKey:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtQueryKey
    mov rcx, [rbx + 0x8]        ; PHANDLE KeyHandle
    mov rdx, [rbx + 0x10]       ; KEY_INFORMATION_CLASS KeyInformationClass
    mov r8, [rbx + 0x14]        ; PVOID KeyInformation
    mov r9, [rbx + 0x1c]        ; ULONG Length
    mov r10, [rbx + 0x20]     
    mov [rsp+0x28], r10         ; PULONG ResultLength
    jmp rax

WorkCallbackNtEnumerateKey:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtEnumerateKey
    mov rcx, [rbx + 0x8]        ; PHANDLE KeyHandle
    mov rdx, [rbx + 0x10]       ; ULONG Index
    mov r8, [rbx + 0x14]        ; KEY_INFORMATION_CLASS KeyInformationClass
    mov r9, [rbx + 0x18]        ; PVOID KeyInformation
    mov r10, [rbx + 0x20]       ; ULONG Length
    mov [rsp+0x28], r10         ; PULONG ResultLength
    mov r10, [rbx + 0x24]     
    mov [rsp+0x2c], r10         
    jmp rax

WorkCallbackNtQueryValueKey:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtQueryValueKey
    mov rcx, [rbx + 0x8]        ; PHANDLE KeyHandle
    mov rdx, [rbx + 0x10]       ; PUNICODE_STRING ValueName; 
    mov r8, [rbx + 0x18]        ; KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass
    mov r9, [rbx + 0x1c]        ; PVOID KeyValueInformation
    mov r10, [rbx + 0x24]       ; ULONG Length
    mov [rsp+0x28], r10         
    mov r10, [rbx + 0x28]       ; PULONG ResultLength
    mov [rsp+0x2c], r10         
    jmp rax

WorkCallbackNtEnumerateValueKey:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtEnumerateValueKey
    mov rcx, [rbx + 0x8]        ; PHANDLE KeyHandle
    mov rdx, [rbx + 0x10]       ; ULONG Index; 
    mov r8, [rbx + 0x14]        ; KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass
    mov r9, [rbx + 0x18]        ; PVOID KeyValueInformation
    mov r10, [rbx + 0x20]       ; ULONG Length
    mov [rsp+0x28], r10         
    mov r10, [rbx + 0x24]       ; PULONG ResultLength
    mov [rsp+0x2c], r10         
    jmp rax

WorkCallbackNtCloseKey:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtCloseKey
    mov rcx, [rbx + 0x8]        ; PHANDLE KeyHandle
    jmp rax

WorkCallbackRtlInitUnicodeString:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; RtlInitUnicodeString
    mov rcx, [rbx + 0x8]        ; UINT_PTR pRltInitUnicodeString
    mov rcx, [rbx + 0x10]        ; PUNICODE_STRING DestinationString
    jmp rax