#include "heap/heap.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
wonderful_pointer passwords[0x10]={0};
size_t delsym(char* str,char sym){
    int i=0;
    while(str[i]!=sym){
        i++;
    }
    str[i]='\0';
    return i;
}
int get_idx(){

    char buf[10];

    memset(buf,0,10);

    fgets(buf,10,stdin);

    int index = atoi(buf);

    if(index<0 || index >=0x10){

        puts("Out of bounds e\n");

        exit(228);
    }

    return index;
}
void add_password(){

    char buf[1024];

    memset(buf,0,1024);

    puts("Enter index of password to add (less than 16)\n");

    int index = get_idx();

    puts("Enter password to safe\n");

    fgets(buf,500,stdin);

    size_t len = delsym(buf,'\n');

    if(passwords[index]==0){

        passwords[index] = wonderful_malloc(len);

        safe_write(passwords[index],buf,len);

        puts("Succesfully saved\n");

    }
   
    return;

}
void delete_passwd(){

    puts("Inter index of deleted element");

    int index = get_idx();

    if(passwords[index]!=0){

        wonderful_free(passwords[index]);
    
        puts("Succesfully freed\n");
    }

    return;
}
void print_passwd(){

    char buf[1024] = {0};

    printf("Enter index to print");
    
    int index = get_idx();
    if(passwords[index]!=0){

        safe_read(passwords[index],buf,1024);

        printf("Password is: %s\n",buf);
    }

    return;
}
void edit_password(){
    
    char buf[1024];
    puts("Enter index of element");

    int index = get_idx();

    fgets(buf,500,stdin);

    int len = delsym(buf,'\n');

    buf[len] = '\0';

    if(passwords[index]!=0){

        safe_write(passwords[index],buf,len);

        puts("Successfully edited");
    }
    return;
}
void menu(){
    puts("Enter 1 to add password");
    puts("Enter 2 to delete password");
    puts("Enter 3 to print password");
    puts("Enter 4 to edit password");
    puts("Enter 5 to exit");
    return;
}
int get_num(){
     char buf[10];

    fgets(buf,10,stdin);

    int num = atoi(buf);

    return num;
}
int main(){

    setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
    int option=0;
    while(1){
        menu();
        option = get_num();
        switch(option){
            case 1:
                add_password();
            break;
            case 2:
                delete_passwd();
            break;
            case 3:
                print_passwd();
            break;
            case 4:
                edit_password();
            break;
            case 5:
                exit(0x0);
            break;

            default:
                printf("Error\n");
            break;

        }
    
    }
}
