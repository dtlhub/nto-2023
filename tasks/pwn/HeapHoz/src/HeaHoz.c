#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct hehe{
    char* name;
    int allocated;
}hehe;

hehe hehes[16]={0};

char* command = 0;

int get_num(){

    char buf[10];

    int num=0;
    puts("Enter index:");

    read(STDIN_FILENO,buf,10);

    num = atoi(buf);

    return num;

}
void add(){

    int index = get_num();

    if(index<0 || index>=16)
        return;

    hehes[index].allocated = 1;

    hehes[index].name = malloc(0x50);

    puts("Enter hehe:");
    
    read(STDIN_FILENO,hehes[index].name,0x50);

    return;
}
void delete(){
    
    int index = get_num();

    if(index<0 || index>=16)
        return;

    if(hehes[index].allocated==1){
        hehes[index].allocated = 0;
        free(hehes[index].name);
        puts("Deleted");
    }
    return;
}
void edit(){

    int index = get_num();

    if(index<0 || index>=16)
        return;

    puts("Enter new hehe:");

    read(STDIN_FILENO,hehes[index].name,0x50);

    return;
}
void print(){
    
    for(int i=0;i<16;i++){
        if(hehes[i].allocated==1)
            printf("Hehe %d is: %s\n",i,hehes[i].name);
    }
    return;
}
void ahaha(){
    if(command==NULL)
        command = malloc(0x50);

    int index = get_num();

    if(index<0 || index>=16)
        return;
    if(hehes[index].allocated==1){
        memcpy(command,hehes[index].name,0x50);
        command[0x50-1]='\0';
    }
    if(strcmp(command,"echo Mua-ha-ha")==0)
        system(hehes[index].name);
    return;
}
void menu(){

    puts("Menushka");
    puts("1 to add phah");
    puts("2 to delete heahea");
    puts("3 to print ehehe");
    puts("4 to edit hihihi");
    puts("5 to ahaha");
    puts("0 to not ahaha");
    return;
}
int main(){

    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stdout,0,_IONBF,0);
    setvbuf(stderr,0,_IONBF,0);
    while(1){
        menu();
        int option = get_num();
        switch(option){
            case 1:
                add();
            break;
            case 2:
                delete();
            break;
            case 3:
                print();
            break;
            case 4:
                edit();
            break;
            case 5:
                ahaha();
            break;
            case 0:
                exit(0);
            break;
        }

    }
    return 0;
}
