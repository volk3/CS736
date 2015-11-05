#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/sched.h>

/* Returns information about how many system calls the requested
 * process is using.
 *
 * pid: the pid of the process we're interested in
 * nreq: the number of requests
 * reqs: pointer to array of syscall numbers we're interested in
 * res: pointer to array which the call returns results
 */
asmlinkage long sys_scallinfo(int pid, int nreq, int *reqs, int *res) {
    struct task_struct *ts;
    int r_ok, w_ok, i;
    long total;
    ts = find_task_by_vpid(pid);

    if(ts == NULL){
        printk("scallinfo: find by vpid NULL\n");
        return -1;
    }

    if(ts->pid != pid){
        printk("scallinfo: find by vpid returned incorrect process: %d\n", ts->pid);
        return -1;
    }

    r_ok = access_ok(VERIFY_READ, reqs, nreq * sizeof(int));

    if(r_ok == 0){
        printk("scallinfo: req pointed to invalid memory\n");
        return -1;
    }

    w_ok = access_ok(VERIFY_WRITE, res, nreq * sizeof(int));

    if(w_ok == 0){
        printk("scallinfo: res pointed to invalid memory\n");
        return -1;
    }
        
    total = 0;
    for(i = 0; i < 500; i++){
        total += ts->syscalltable[i];
    }
    return total;
}
