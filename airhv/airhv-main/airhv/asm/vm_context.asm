.CODE                                                                                                                                                                            
extern ?vmexit_handler@@YA_NPEAU__vmexit_guest_registers@@@Z : proc
extern ?init_logical_processor@@YAXPEAX@Z : proc
extern ?return_rsp_for_vmxoff@@YA_KXZ : proc
extern ?return_rip_for_vmxoff@@YA_KXZ : proc

PUBLIC ?vmm_entrypoint@@YAXXZ
PUBLIC ?vmx_restore_state@@YAXXZ
PUBLIC ?vmx_save_state@@YAXXZ

SAVE_GP macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -01h ; placeholder for rsp
        push    rbp 
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
endm
RESTORE_GP macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx ; placeholder for rsp
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
endm

?vmm_entrypoint@@YAXXZ proc
    SAVE_GP
    sub     rsp ,60h
    movdqa  xmmword ptr [rsp], xmm0
    movdqa  xmmword ptr [rsp+10h], xmm1
    movdqa  xmmword ptr [rsp+20h], xmm2
    movdqa  xmmword ptr [rsp+30h], xmm3
    movdqa  xmmword ptr [rsp+40h], xmm4
    movdqa  xmmword ptr [rsp+50h], xmm5
    mov     rcx, rsp
    sub     rsp,  20h
    call    ?vmexit_handler@@YA_NPEAU__vmexit_guest_registers@@@Z
    add     rsp, 20h
    movdqa  xmm0, xmmword ptr [rsp]
    movdqa  xmm1, xmmword ptr [rsp+10h]
    movdqa  xmm2, xmmword ptr [rsp+20h]
    movdqa  xmm3, xmmword ptr [rsp+30h]
    movdqa  xmm4, xmmword ptr [rsp+40h]
    movdqa  xmm5, xmmword ptr [rsp+50h]
    add     rsp,  60h
    cmp     al, 1
    jnz      exit
    RESTORE_GP
    vmresume
exit:
    sub rsp, 20h
    call ?return_rsp_for_vmxoff@@YA_KXZ
    add rsp, 20h

    push rax

    sub rsp, 20h
    call ?return_rip_for_vmxoff@@YA_KXZ
    add rsp, 20h

    push rax

    mov rcx,rsp
    mov rsp,[rcx+8h]
    mov rax,[rcx]
    push rax

    mov r15,[rcx+10h]
    mov r14,[rcx+18h]
    mov r13,[rcx+20h]
    mov r12,[rcx+28h]
    mov r11,[rcx+30h]
    mov r10,[rcx+38h]
    mov r9,[rcx+40h]
    mov r8,[rcx+48h]
    mov rdi,[rcx+50h]
    mov rsi,[rcx+58h]
    mov rbp,[rcx+60h]
    mov rbx,[rcx+70h]
    mov rdx,[rcx+78h]
    mov rax,[rcx+88h]
    mov rcx,[rcx+80h]

    ret
?vmm_entrypoint@@YAXXZ endp

?vmx_save_state@@YAXXZ PROC
    pushfq
    SAVE_GP
    sub rsp, 020h
    mov rcx, rsp
    call ?init_logical_processor@@YAXPEAX@Z
    int 3 ; we should never be here

?vmx_save_state@@YAXXZ ENDP

?vmx_restore_state@@YAXXZ PROC
	add rsp, 020h
	RESTORE_GP
    popfq
	ret
?vmx_restore_state@@YAXXZ ENDP

END