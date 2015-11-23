#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/sched.h>
#include <linux/slab.h>

// the following is brittle and needs to actually be based on the
// number of system calls in a specific system
#define NSYSCALL 324

int syscnt_get(struct task_struct *ts, int *res){
    int w_ok, i, cr, *ures;

    if(ts->syscnt_table == NULL) {
        printk("syscnt: tried to access syscnt infomation on unallocated table\n");
        return -1;
    }

    w_ok = access_ok(VERIFY_WRITE, res, NSYSCALL * sizeof(int));

    if(w_ok == 0){
        printk("syscnt: result pointed to invalid memory\n");
        return -1;
    }

    // ! need to dynamically allocate large portions
    ures = (int*) kmalloc(sizeof(int) * NSYSCALL, GFP_KERNEL);
    if(ures == NULL){
        printk("syscnt: kmalloc failed\n");
        return -1;
    }

    for(i = 0; i < NSYSCALL; i++)
        ures[i] = ts->syscnt_table[i];

    cr = copy_to_user(res, ures, sizeof(int) * NSYSCALL);
    
    if(cr != 0){
        printk("syscnt: failed copy back %d bytes\n", cr);
        goto free_and_die;
    }

    kfree(ures);
    return 0;

free_and_die:

    kfree(ures);
    return -1;
}

int syscnt_start(struct task_struct *ts) {
    int i;
    if(ts->syscnt_table != NULL){
        printk("syscnt: error on start, table already allocated\n");
        return -1;
    }
    
    ts->syscnt_table = kmalloc(sizeof(int) * NSYSCALL, GFP_KERNEL);
    if(ts->syscnt_table == NULL){
        printk("syscnt: error mallocing table\n");
        return -1;
    }

    // zero
    for(i = 0; i < NSYSCALL; i++)
        ts->syscnt_table[i] = 0;

    return 0;
}

/* 
 * Given a task struct, does deallocation of syscnt counters
 */
int syscnt_stop(struct task_struct *ts) {
    if(ts->syscnt_table == NULL)
        return 0;

    kfree(ts->syscnt_table);
    ts->syscnt_table = NULL;

    return 0;
}


/* Returns information about how many system calls the requested
 * process is using.
 *
 * sctype:
 *      0 GET_SYSCNT, retrieve tracing information
 * 		1 START_SYSCNT, start tracing this process
 *		2 STOP_SYSCNT, stop tracing this process
 * pid:  The pid of the process we're interested in. 
 *       Only used in GET_TRACE, STOP_TRACE
 * res:  Pointer to array which the call returns results. 
 *       Used in GET_TRACE
 */
asmlinkage long sys_syscnt(int sctype, int pid, int *res){
    struct task_struct *ts;

    ts = find_task_by_vpid(pid);

    if(ts == NULL){
        printk("syscnt: find by vpid NULL\n");
        return -1;
    }

    if(ts->pid != pid){
        printk("syscnt: find by vpid returned incorrect process: %d\n", ts->pid);
        return -1;
    }

    switch(sctype){
    case 0: // GET
        return syscnt_get(ts, res);
    case 1: // START
        return syscnt_start(ts);
    case 2: // STOP
        return syscnt_stop(ts);
    default:
        printk("syscnt: unrecognized enum input, options are 0,1,2\n");
        return -1;
    }   
}
