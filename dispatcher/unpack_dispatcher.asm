[bits 64]
; nasm

; backup registers
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15

call $+5
pop rdx
mov rdi, rdx

add rdi, -0x551d     ; dst to unpack off

add rdx, 67          ; src, packed code off

mov rsi, strict dword 15 ; unpacked_len

push rsi
mov rsi, rsp
mov rcx, strict dword 29  ; packed_len

call $+1337         ; call unpack_code

pop rsi


; restore registers
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax

jmp $-2000 ; jmp back to the original code
