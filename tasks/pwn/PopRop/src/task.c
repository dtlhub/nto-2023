#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
char message[0x100];
void pop(int reg){
    switch(reg){
        case 1: 
            asm("pop %rax");
        break;
        case 2:
            asm("pop %rbx");
        break;
        case 3:
            asm("pop %rcx");
        break;
        case 4:
            asm("pop %rdx");
        break;
        case 5:
            asm("pop %rdi");
        break;
        case 6:
            asm("pop %rsi");
        break;
        case 7:
            asm("pop %rbp");
        break;
        case 8:
            asm("pop %rsp");
        break;
        default:
        break;
    }
    return;
}
int main(){
    int option;

    char buf[8];
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stdout,0,_IONBF,0);
    setvbuf(stderr,0,_IONBF,0);

    system("echo [POP ROP]");
    
    puts("ENTER YOUR MESSAGE: \n");
    
    read(STDIN_FILENO,buf,0x28);

    while(1){

        puts("Enter reg to pop it or 0 to exit.[=)]\n");

        read(STDIN_FILENO,&option,4);

        option = atoi(&option);

        if(option==0)
            break;
        else if(option<1 || option >8){
            puts("NET TAKOGO REGISTRA\n");
            continue;
        }
        pop(option);

    }
    puts("please write \n");

    read(STDIN_FILENO,message,0x100);

    return 0;
}
