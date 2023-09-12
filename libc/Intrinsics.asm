.code
_byteswap_uint64 PROC
	mov   rax, rcx
	bswap rax
	ret
_byteswap_uint64 ENDP
_byteswap_ulong PROC
	mov   eax, ecx
	bswap eax
	ret
_byteswap_ulong ENDP
_byteswap_ushort PROC
	mov eax, ecx
	rol ax, 8
	ret
_byteswap_ushort ENDP
end
