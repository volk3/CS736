#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>

struct syscall_struct *head = NULL;
struct syscall_struct *tail = NULL;
int count = 0;

DEFINE_SPINLOCK(lock);

void __init scallist_init(void) {
	spin_lock_init(&lock);
}

int flush_syscall_list(struct task_struct *task) {
	int i;
	struct syscall_struct *node;
	
	if(task->scinfo_table == NULL)
		return 0;

	node = kmalloc(sizeof(struct syscall_struct), GFP_KERNEL);
	node->scinfo_table = task->scinfo_table;
	task->scinfo_table = kmalloc(500*sizeof(int), GFP_KERNEL);
	for(i = 0; i < TASK_COMM_LEN; i++)
		(node->comm)[i] = (task->comm)[i];
	node->pid = task->pid;

	spin_lock(&lock);	
	if(head == NULL) {
		node -> prev = node;
		node -> next = node;
		head = node;
		tail = node;
	}
	else {
		node -> next = head;
		node -> prev = tail;
		tail -> next = node;
		head -> prev = node;
		head = node;
	}
	spin_unlock(&lock);

	spin_lock(&lock);
	count++;
	if(count == 20) {  //a limit of 19 nodes allowed
		node = tail;
		tail = tail -> prev;
		head -> prev = tail;
		tail -> next = head;
		
		kfree(node -> scinfo_table);
		kfree(node);
		count--;
	}	
	spin_unlock(&lock);

	return 0;
}
