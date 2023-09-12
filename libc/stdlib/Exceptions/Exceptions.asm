.code

__EH_prolog proc
	pop rax
	push rbp
	mov rbp, rsp
	jmp rax
__EH_prolog endp

__EH_prolog3_catch proc
	pop rax
	push rbp
	mov rbp, rsp
	jmp rax
__EH_prolog3_catch endp

__EH_epilog3 proc
	mov rsp, rbp
	pop rbp
	ret
__EH_epilog3 endp

__EH_epilog3_catch proc
	mov rsp, rbp
	pop rbp
	ret
__EH_epilog3_catch endp

_wassert proc
	int 3
	xor rax, rax
	ret
_wassert endp

__InternalCxxFrameHandler proc
	int 3
	ret
__InternalCxxFrameHandler endp

__hypot proc
	ret
__hypot endp

__invalid_parameter proc
	ret
__invalid_parameter endp

__CxxFrameHandler3 proc
__CxxThrowException proc
	int 3
	ret
__CxxFrameHandler3 endp
__CxxThrowException endp

end