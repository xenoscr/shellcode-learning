; This assembly code should spawn cmd.exe using the CreateProcess() Windows API

section .text
	global _start

_start:

;------------------------------------------------------------------------------------------------------------
; This section will find the base address of kernel32.dll and store
; the value in ESI.
;
; A great explaination of this code can be found here:
; - https://web.archive.org/web/20090728193835/http://skypher.com/wiki/index.php/Hacking/Shellcode/kernel32
;
; 1. PEB is located at an offset of 0x30 from of the FS register.
;    - https://docs.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-_peb
; 2. LoaderData is located at an offset of 0xc of the PEB.
; 3. her
;------------------------------------------------------------------------------------------------------------

find_kernel32:
	push esi
	xor ecx, ecx
	mov esi, [fs:esi+0x30]
	mov esi, [esi+0x0C]
	mov esi, [esi+0x1C]
next_module:
	mov ebp, [esi+0x08]
	mov edi, [esi+0x20]
	mov esi, [esi]
	cmp [edi+12*2], cl
	jne next_module
	
	mov eax, ebp
;----------------------------------------------------------------------------------------
