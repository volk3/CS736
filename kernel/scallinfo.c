#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/sched.h>

asmlinkage long sys_scallinfo(int scnum) {
	printk("called scallinfo arg: %d\n", scnum);
    struct task_struct* ts;
    // ts = find_task_by_vpid(scnum);
    ts = find_task_by_vpid(scnum);
    if(ts == NULL)
        return -1;
    long total;
    total = 0;
    int i;
    for(i = 0; i < 500; i++){
        total += ts->syscalltable[i];
    }
    printk("total: %d\n", total);
    return total;
}
