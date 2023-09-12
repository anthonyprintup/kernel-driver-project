extern ?returnAddress@Syscalls@Globals@Miscellaneous@KM@@3_KA:QWORD

.code
returnStatus proc
	mov edi, eax
	jmp ?returnAddress@Syscalls@Globals@Miscellaneous@KM@@3_KA
returnStatus endp
end
