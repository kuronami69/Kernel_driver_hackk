#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#define DEVICE_NAME "HY"

static DEFINE_MUTEX(dispatch_mutex);

int dispatch_open(struct inode *node, struct file *file)
{
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	return 0;
}

static long handle_init_key(unsigned long arg, bool *is_verified, char *key)
{
	if (!(*is_verified)) {
		if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) != 0) {
			return -EFAULT;
		}
		*is_verified = true;
		printk("[+] Key initialized: %s\n", key);
	}
	return 0;
}

static long handle_read_mem(unsigned long arg)
{
	COPY_MEMORY cm;
	if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) {
		return -EFAULT;
	}
	if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
		return -EIO;
	}
	return 0;
}

static long handle_write_mem(unsigned long arg)
{
	COPY_MEMORY cm;
	if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) {
		return -EFAULT;
	}
	if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
		return -EIO;
	}
	return 0;
}

static long handle_module_base(unsigned long arg)
{
	MODULE_BASE mb;
	char name[0x100] = {0};

	if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0) {
		return -EFAULT;
	}
	if (copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0) {
		return -EFAULT;
	}
	mb.base = get_module_base(mb.pid, name);
	if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0) {
		return -EFAULT;
	}
	return 0;
}

long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	static char key[0x100] = {0};
	static bool is_verified = false;
	long ret = 0;

	mutex_lock(&dispatch_mutex);

	switch (cmd) {
	case OP_INIT_KEY:
		ret = handle_init_key(arg, &is_verified, key);
		break;
	case OP_READ_MEM:
		ret = handle_read_mem(arg);
		break;
	case OP_WRITE_MEM:
		ret = handle_write_mem(arg);
		break;
	case OP_MODULE_BASE:
		ret = handle_module_base(arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	mutex_unlock(&dispatch_mutex);
	return ret;
}

struct file_operations dispatch_functions = {
	.owner = THIS_MODULE,
	.open = dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &dispatch_functions,
};

int __init driver_entry(void)
{
	int ret;
	printk(KERN_INFO "[+] Driver entry\n");
	ret = misc_register(&misc);
	if (ret) {
		printk(KERN_ERR "[-] Failed to register misc device\n");
	}
	return ret;
}

void __exit driver_unload(void)
{
	printk(KERN_INFO "[+] Driver unload\n");
	misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Memory Module.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("HYLAB");
