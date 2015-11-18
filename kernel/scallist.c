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
//struct syscall_struct *current = NULL;
//int count = 0;

DEFINE_SPINLOCK(lock);

void __init scallist_init(void) {
	spin_lock_init(&lock);
}

struct syscall_struct* find_match(struct task_struct *task) {
	struct syscall_struct *node;
	int i;
	int match;
	
	node = head;

	while(node != NULL) {
		match = 1;
		for(i = 0; i < TASK_COMM_LEN; i++)
			if((node->comm)[i] != (task->comm)[i]) {
				match = 0;
				break;
			}
		if(match == 1)
			break;

		node = node->next;
		
		if(node == head)
			node = NULL;
	}

	return node;
}

int flush_syscall_list(struct task_struct *task) {
	int i;
	struct syscall_struct *node;
	
	if(task->scinfo_table == NULL)
		return 0;

	spin_lock(&lock);
	node = find_match(task);

	if(node == NULL) {
		node = kmalloc(sizeof(struct syscall_struct), GFP_KERNEL);
		node->scinfo_table = task->scinfo_table;
		task->scinfo_table = kzalloc(500*sizeof(int), GFP_KERNEL);
		for(i = 0; i < TASK_COMM_LEN; i++)
			(node->comm)[i] = (task->comm)[i];
		node->pid = task->pid;
			
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

		/*spin_lock(&lock);
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
		spin_unlock(&lock);*/
	}
	else {
		for(i = 0; i < 500; i++) {
			(node->scinfo_table)[i] += (task->scinfo_table)[i];
			(task->scinfo_table)[i] = 0;
		}
	}
	spin_unlock(&lock);

	return 0;
}

/*int next_flush(int *res, char *comm) {
	int cr;

	spin_lock(&lock);
	current = tail;
	if(current == NULL)
		spin_unlock(&lock);
		return 1;
	else {
		if(head == tail) {
			head = NULL;
			tail = NULL;
		}
		else {
			tail = tail -> prev;
			head -> prev = tail;
			tail -> next = head;
		}
		
		cr = copy_to_user(res, current->scinfo_table, sizeof(int) * 500);
    		if(cr != 0){
        		printk("scallist: failed copy back %d bytes\n", cr);
			spin_unlock(&lock);
        		return -1;
    		}
		cr = copy_to_user(comm, current->comm, sizeof(char) * 16);
		if(cr != 0){
			printk("scallist: failed copy back %d bytes\n", cr);
			spin_unlock(&lock);
        		return -1;
		}
		
		kfree(current->scinfo_table);
		kfree(current);
	}
	spin_unlock(&lock);
	return 0;
}*/
