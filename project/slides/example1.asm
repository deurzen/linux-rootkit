	BITS 64
	global _start
	section .text
_start:
	mov rdi, memfrobbed
	mov cl, 0x18
	call _my_memfrob

;	do something interesting ...

	mov rdi, memfrobbed
	mov cl, 0x18
	call _my_memfrob
	ret

_my_memfrob:
	xor byte [rdi+rcx-1], 0x42
	loop _my_memfrob
	ret
	;db "53cr3t_p4yl04d_g035_h3r3", 0
	section .data
memfrobbed:
	db 0x77, 0x71, 0x21, 0x30,
	db 0x71, 0x36, 0x1d, 0x32,
	db 0x76, 0x3b, 0x2e, 0x72,
	db 0x76, 0x26, 0x1d, 0x25,
	db 0x72, 0x71, 0x77, 0x1d,
	db 0x2a, 0x71, 0x30, 0x71