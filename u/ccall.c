#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

// this should probably be defined
// somewhere else
#define __NR_scallinfo 323
#define SCI_GET   0
#define SCI_START 1
#define SCI_STOP  2

const char * syscall_defs[] = {"read","write","open","close","stat","fstat","lstat","poll","lseek",
"mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64",
"readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise",
"shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer",
"getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown",
"bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork",
"execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget",
"msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents",
"getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink",
"readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage",
"sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid",
"setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid",
"setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait",
"rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs",
"sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval",
"mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl",
"adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff",
"reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module",
"quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr",
"lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr",
"fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents",
"io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address",
"restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime",
"clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy",
"get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key",
"request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat",
"mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat",
"faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice",
"move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4",
"signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open",
"recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns",
"getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat2","seccomp","getrandom",
"memfd_create","kexec_file_load","bpf","execveat","scallinfo"};

int forked_pid = -1;

long scallinfo_s(int scinum, int pid) {
    if(scinum == SCI_GET)
        return -1;
    return syscall(__NR_scallinfo, scinum, pid, (int*) NULL, NULL,NULL);
}

long scallinfo(int scinum, int pid, int nreq, int *req, int *res) {
    return syscall(__NR_scallinfo, scinum, pid, nreq, req, res);
}


void exec_parent(int rpid) {
    // continuously send the same request
    int i, r, nreq = 320;
    int req[nreq];
    int res[nreq];
    for(i = 0; i < nreq; i++)
        req[i] = i;
    for(;;) {
        r = scallinfo(SCI_GET, rpid, nreq, req, res);

        if(r == -1){
            int e = errno;
            printf("scallinfo error no %d\n", e);
            int rret = raise(SIGINT);
            if(rret != 0){
                printf("Failed to exit cleanly\n");
                exit(-1);
            }
        } else {
            for(i = 0; i < nreq; i++)
                if(res[i] != 0)
                    printf("%s: %d\n", syscall_defs[req[i]], res[i]);
        }
        printf("\n");
        sleep(1);
    }
}

int monitorpid(int pid){
    int r = scallinfo_s(SCI_START, pid);
    if(r != 0){
        return -1;
    }
    exec_parent(pid);
    return 0;
}

void parent_sig_handler(int sig) {
    if(sig == SIGKILL){
        scallinfo_s(SCI_STOP,forked_pid);
        exit(0);
    } else if (sig == SIGUSR1) {
        exec_parent(forked_pid);
    }
}

int main(int argc, char** argv){
    if(argc < 2){
        printf("usage: %s -p pid\n", argv[0]);
        printf("alter: %s program to launch\n", argv[0]);
        return 0;
    }

    if(argv[1][0] == '-' && argv[1][1] == 'p'){
        return monitorpid(atoi(argv[2]));
    }
    
    signal(SIGKILL, parent_sig_handler);
    char rbuf[2];
    char *msg = "s";
    int fd[2];
    pipe(fd);

    int cpid = fork();
    if(cpid == 0){

        // read this pipe to know when to begin operation
        // (parent has begun monitoring the child)
        close(fd[1]);
        read(fd[0], rbuf, sizeof(rbuf));
        char *args[argc - 1]; // leave space for NULL
        memcpy(args, (argv + 2), (argc - 2) * sizeof(char*));
        args[argc-2] = NULL;
        execv(argv[1], args);

        printf("failed to exec child\n");
        return -1;
     } else if(cpid != -1) {
        scallinfo_s(SCI_START, cpid);
        close(fd[0]);
        write(fd[1], msg, 2);
        exec_parent(cpid);

        exit(-1); // should not return
     } else {
         return -1;
     }
}
