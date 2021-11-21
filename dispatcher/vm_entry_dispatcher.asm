[bits 64]


; construct ctx
; backup registers
push rsp
sub rsp, 224
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
add rdi, -0x551d ; ctx.registers.rip: addr of code
push rdi

pushfq ; push rflags


mov rdi, rsp ; CTX ADDR


call $+1337 ; call vm_entry 


popfq ; pop rflags


pop rdi ; rip


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
add rsp, 224
add rsp, 8


jmp $-2000 ;jmp back to the original code
