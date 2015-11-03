#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>

asmlinkage long sys_scallinfo(int scnum) {
	printk(KERN_EMERG "service running");
	return 0;
}
