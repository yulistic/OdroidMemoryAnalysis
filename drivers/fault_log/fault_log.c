#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/circ_buf.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include <asm/uaccess.h>

/*
 * logging
 */ 
#include <linux/circ_buf.h>
struct circ_buf fault_log;
spinlock_t	fault_log_enqueue_lock;
spinlock_t	fault_log_dequeue_lock;
#define FAULT_LOG_SIZE (1<<20)
typedef struct fault_log_struct {
	struct timeval 	tv;
	unsigned long	pfn;
	pid_t pid;
	char comm[TASK_COMM_LEN];

} fault_log_t;
DECLARE_WAIT_QUEUE_HEAD(fault_log_wq);

EXPORT_SYMBOL(fault_log);
#define FL_DEVICE_NAME "fault_log"
static int 		fl_major = 0;
static struct class	*fl_class;
static char		*fl_buf;
static DEFINE_MUTEX(fl_open_mutex);
static DEFINE_MUTEX(fl_close_mutex);
static DEFINE_MUTEX(fl_read_mutex);

void fault_log_enqueue(unsigned long pfn, struct timeval *tv)
{
	unsigned long head;
	unsigned long tail;
	int ret;
	fault_log_t *f;

	spin_lock(&fault_log_enqueue_lock);

	do {
		head = fault_log.head;
		tail = ACCESS_ONCE(fault_log.tail);
		if (CIRC_SPACE(head, tail, FAULT_LOG_SIZE) >= 1)
			break;

		spin_unlock(&fault_log_enqueue_lock);
		ret = wait_event_interruptible(fault_log_wq,
			CIRC_SPACE(head, tail, FAULT_LOG_SIZE) >= 1);
		spin_lock(&fault_log_enqueue_lock);
	} while (ret == -ERESTARTSYS);

	f = (fault_log_t *)fault_log.buf + head;
	f->pfn = pfn;
	f->tv = *tv;
	f->pid = current->pid;
	snprintf(f->comm, TASK_COMM_LEN, "%s", current->comm);

	smp_wmb();
	fault_log.head = (head + 1) & (FAULT_LOG_SIZE - 1);

	ret = 1;

	spin_unlock(&fault_log_enqueue_lock);
}

int fault_log_dequeue(fault_log_t *fault)
{
	unsigned long head;
	unsigned long tail;
	int ret;
	fault_log_t *f;

	spin_lock(&fault_log_dequeue_lock);

	head = fault_log.head;
	tail = fault_log.tail;
	if (CIRC_CNT(head, tail, FAULT_LOG_SIZE) < 1) {
		spin_unlock(&fault_log_dequeue_lock);
		return 0;
	}
	smp_read_barrier_depends();

	f = (fault_log_t *)fault_log.buf + tail;
	fault->pfn = f->pfn;
	fault->tv = f->tv;
	fault->pid = f->pid;
	snprintf(fault->comm, TASK_COMM_LEN, "%s", f->comm);

	smp_mb();
	fault_log.tail = (tail + 1) & (FAULT_LOG_SIZE - 1);
	wake_up(&fault_log_wq);

	ret = CIRC_CNT(head, tail, FAULT_LOG_SIZE);

	spin_unlock(&fault_log_dequeue_lock);
	return ret;
}

static int fl_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	printk("fault logger open\n");

	mutex_lock(&fl_open_mutex);
	fl_buf = kmalloc(4096, GFP_KERNEL);
	if (!fl_buf)
		ret = -ENOMEM;
	mutex_unlock(&fl_open_mutex);
	return ret;
}

static int fl_release(struct inode *inode, struct file *filp)
{
	printk("fault logger release\n");
	mutex_lock(&fl_close_mutex);
	if (fl_buf)
		kfree(fl_buf);
	mutex_unlock(&fl_close_mutex);
	return 0;
}

static ssize_t fl_read(struct file *filp, char __user *buf, 
			size_t count, loff_t *ppos)
{
	ssize_t bytes = 0;
	int err = 0, ret, offset;
	unsigned long remained_bytes;
	fault_log_t f;

	mutex_lock(&fl_read_mutex);
	
	do {
		ret = fault_log_dequeue(&f);
		if (ret == 0)
			break;
		bytes += snprintf(fl_buf + bytes, 4096 - bytes, 
				"%d %s 0x%lx %ld.%06ld\n",
				f.pid, f.comm, f.pfn, f.tv.tv_sec, f.tv.tv_usec);
	} while (bytes < 4000);

	remained_bytes = bytes;
	do {
		offset = bytes - remained_bytes;
		remained_bytes = copy_to_user(buf + offset, 
					fl_buf + offset, remained_bytes);
	} while (remained_bytes > 0);

	mutex_unlock(&fl_read_mutex);

	return bytes?bytes:err;
}

static ssize_t fl_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *ppos)
{
	extern bool WDP_ON;
	WDP_ON = true;
	/*struct timeval tv;*/
	/*static unsigned long pfn = 0;*/

	/*do_gettimeofday(&tv);*/
	/*printk("%s 0x%lx %ld.%06ld\n", __func__, */
				/*pfn, tv.tv_sec, tv.tv_usec);*/
	/*fault_log_enqueue(pfn++, &tv);*/

	return count;
}

static const struct file_operations fault_log_fops = {
	.open =		fl_open,
	.release = 	fl_release,
	.read =		fl_read,
	.write = 	fl_write,
};

static int __init fault_log_init(void)
{
	struct device *err_dev;
	extern void (*fault_logger_enqueue)
				(unsigned long, struct timeval *);

	fl_major = register_chrdev(0, FL_DEVICE_NAME, &fault_log_fops);
	if (fl_major < 0) {
		printk(KERN_ERR "failed to register a device %s\n", 
			FL_DEVICE_NAME);
		return -1;
	}

	fl_class = class_create(THIS_MODULE, FL_DEVICE_NAME);
	if (fl_class == NULL) {
		printk(KERN_ERR "failed to create a class\n");
		unregister_chrdev(fl_major, FL_DEVICE_NAME);
	}

	err_dev = device_create(fl_class, NULL, MKDEV(fl_major,0),
				NULL, FL_DEVICE_NAME);
	if (err_dev == NULL) {
		printk(KERN_ERR "failed to create a device\n");
		class_unregister(fl_class);
		class_destroy(fl_class);
		unregister_chrdev(fl_major, FL_DEVICE_NAME);
	}

	fault_log.buf = vmalloc(sizeof(fault_log_t) * FAULT_LOG_SIZE);
	if (!fault_log.buf)
		printk("failed to allocate memory for fault_log\n");
	fault_log.head = fault_log.tail = 0;
	spin_lock_init(&fault_log_enqueue_lock);
	spin_lock_init(&fault_log_dequeue_lock);

	// register the en/dequeue functions
	fault_logger_enqueue = fault_log_enqueue;
	
	printk("fault logger initialized\n");

	return 0;
}

static void __exit fault_log_exit(void)
{
	extern void (*fault_logger_enqueue)
				(unsigned long, struct timeval *);

	fault_logger_enqueue = NULL;

	device_destroy(fl_class, MKDEV(fl_major, 0));
	class_unregister(fl_class);
	class_destroy(fl_class);
	unregister_chrdev(fl_major, FL_DEVICE_NAME);
}

module_init(fault_log_init)
module_exit(fault_log_exit)
MODULE_LICENSE("GPL");
