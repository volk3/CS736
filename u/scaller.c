#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv){
    for(;;){
        sleep(1); // even sleep requires a syscall
        printf("a syscall is required\n");
    }
}
