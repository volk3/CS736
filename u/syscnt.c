#include "syscnt.h"
#include <stdio.h>
#include <string.h>

const char* sstart = "start";
const char* sstop = "stop";
const char* sget = "get";

int main(int argc, char** argv) {
  if(argc < 3){
    printf("usage: [cmd] [pid] - get syscnt info for given pid using a cmd\n");
    printf("       [cmd] start, stop, or get\n");
    printf("       [pid] pid of running process\n");
    return -1;
  }

  int pid = atoi(argv[2]);

  if(strcmp(argv[1], sstart) == 0){
    return syscnt_s(SYSCNT_START, pid);
  } else if(strcmp(argv[1], sstop) == 0) {
    return syscnt_s(SYSCNT_STOP, pid);
  } else if(strcmp(argv[1], sget) == 0) {
    int ressize = 330;
    int res[ressize];
    int r = syscnt(SYSCNT_GET, pid, res);

    if(r == -1){
      printf("error calling syscnt get\n");
      return -1;
    } else {
      for(int i = 0; i < syscall_length && i < ressize; i++) {
        if(res[i] != 0)
          printf("%-20s: %10d\n", syscall_defs[i], res[i]);
      }
      printf("\n");
    }
  } else {
    printf("unrecognized command: %s\n", argv[1]);
    return -1;
  }
}