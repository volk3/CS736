#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/sched.h>
#include <linux/slab.h>

/* Returns information about how many system calls the requested
 * process is using.
 *
 * scitype:
 *      0 GET_TRACE, retrieve tracing information
 * 		1 START_TRACE, start tracing this process
 *		2 STOP_TRACE, stop tracing this process
 * pid:  The pid of the process we're interested in. 
 *       Only used in GET_TRACE, STOP_TRACE
 * nreq: The number of requests. 
 * 	     Used in GET_TRACE
 * reqs: Pointer to array of syscall numbers we're interested in. 
 * 	     Used in GET_TRACE
 * res:  Pointer to array which the call returns results. 
 *       Used in GET_TRACE
 */
asmlinkage long sys_scallinfo(int scitype, int pid, int nreq, int *reqs, int *res) {
    struct task_struct *ts;
    int r_ok, w_ok, i, *ureq, cr, *ures, req;

    ts = find_task_by_vpid(pid);

    if(ts == NULL){
        printk("scallinfo: find by vpid NULL\n");
        return -1;
    }

    if(ts->pid != pid){
        printk("scallinfo: find by vpid returned incorrect process: %d\n", ts->pid);
        return -1;
    }

    switch(scitype){
    case 0: 
        return sci_trace_get(ts, nreq, reqs, res);
    case 1:
        return sci_trace_start(ts);
    case 2:
        return sci_trace_stop(ts);
    default:
        printk("scallinfo: unrecognized enum input, options are 0,1,2\n");
        return -1;
    }
    
}

int sci_trace_get(task_struct *ts, int nreq, int *reqs, int *res){
    int r_ok, w_ok, i, *ureq, cr, *ures, req;

    if(ts->scinfo_table == NULL) {
        printk("scallinfo: tried to access scall infomation on unallocated table\n");
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

    ureq = (int*) kmalloc(sizeof(int) * nreq, GFP_KERNEL);
    ures = (int*) kmalloc(sizeof(int) * nreq, GFP_KERNEL);
    if(ureq == NULL || ures == NULL){
        printk("scallinfo: kmalloc failed\n");
        return -1;
    }

    cr = copy_from_user(ureq, reqs, sizeof(int) * nreq);
    if(cr != 0){
        printk("scallinfo: copy from user failed to copy %d bytes\n", cr);
        goto free_and_die;
    }

    for(i = 0; i < nreq; i++){
        req = ureq[i];
        if(req > -1 && req < 500){
            ures[i] = ts->syscalltable[req];
        } else {
            printk("scallinfo: requested invalid syscall: %d\n", req);
            goto free_and_die;
        }
    }

    cr = copy_to_user(res, ures, sizeof(int) * nreq);
    if(cr != 0){
        printk("scallinfo: failed copy back %d bytes\n", cr);
        goto free_and_die;
    }

    kfree(ureq);
    kfree(ures);

    return 0;

    free_and_die:

    kfree(ureq);
    kfree(ures);
    return -1;
}

int sci_trace_start(struct task_struct *ts) {
    int num_calls = 500, i;
    if(ts->scinfo_table != NULL){
        printk("scallinfo: error on start, table already allocated\n");
        return -1;
    }
    
    ts->scinfo_table = kmalloc(sizeof(int) * num_calls); // TODO: magic
    if(ts->scinfo_table == NULL){
        printk("scallinfo: error mallocing table\n");
        return -1;
    }

    // zero
    for(i = 0; i < num_calls; i++)
        ts->scinfo_table[i] = 0;

    return 0;
}

int sci_trace_stop(struct task_struct *ts) {
    if(ts->scinfo_table == NULL)
        return 0;

    kfree(ts->scinfo_table);
    ts->scinfo_table = NULL;

    return 0;
}


