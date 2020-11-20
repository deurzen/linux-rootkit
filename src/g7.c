#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "ioctl.h"

#define BUFLEN 4096


static int  __init g7_init(void);
static void __exit g7_exit(void);

static int     g7_open(struct inode *, struct file *);
static int     g7_release(struct inode *, struct file *);
static ssize_t g7_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t g7_write(struct file *, const char *, size_t, loff_t *);
static long    g7_ioctl(struct file *, unsigned int, unsigned long);


static struct mutex lock;
static char buf[BUFLEN];

static struct file_operations g7_fops =
{
    .owner          = THIS_MODULE,
    .read           = g7_read,
    .write          = g7_write,
    .open           = g7_open,
    .unlocked_ioctl = g7_ioctl,
    .release        = g7_release,
};



static int
g7_open(struct inode *inode, struct file *file)
{
        printk(KERN_INFO "g7_open\n");
        return 0;
}

static int
g7_release(struct inode *inode, struct file *file)
{
        printk(KERN_INFO "g7_release\n");
        return 0;
}

static ssize_t
g7_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        printk(KERN_INFO "g7_read\n");
        return 0;
}

static ssize_t
g7_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        printk(KERN_INFO "g7_write\n");
        return 0;
}

static long
g7_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case G7_PING: handle_ping(arg); break;
    default: break;
    }

    return 0;
}


static int
g7_init(void)
{
    mutex_init(&lock);
    proc_create_data(G7_DEVICE, S_IRUSR | S_IWUSR, 0, &g7_fops, buf);

    printk(KERN_INFO "g7 initialized\n");

    return 0;
}

static void
g7_exit(void)
{
    remove_proc_entry(G7_DEVICE, 0);
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group 7");
MODULE_DESCRIPTION("Assignment 3");

module_init(g7_init);
module_exit(g7_exit);
