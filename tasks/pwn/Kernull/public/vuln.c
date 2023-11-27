#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME "kernull"
#define MAX_SIZE 0x400

static int module_open(struct inode *inode, struct file *file);
static ssize_t module_read(struct file *file, char __user *buf, size_t count, loff_t *f_pos);
static ssize_t module_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos);
static int module_lock(struct file *, int, struct file_lock *);
static int module_close(struct inode *inode, struct file *file);

char *globalBuffer = 0x0;
static int lock = 1;
static dev_t dev_id;
static struct cdev c_dev;

struct file_operations module_fops =
  {
   owner:   THIS_MODULE,
   read:    module_read,
   write:   module_write,
   open:    module_open,
   release: module_close,
   lock:    module_lock,
  };

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }
  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

static int module_open(struct inode *inode, struct file *file) {
  printk(KERN_INFO "module_open called\n");
  globalBuffer = kmalloc(MAX_SIZE, GFP_KERNEL);

  if (!globalBuffer) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }
  return 0;
}

static ssize_t module_read(struct file *file, char __user *buf, size_t count, loff_t *f_pos) {
  char kbuf[MAX_SIZE] = { 0 };
  printk(KERN_INFO "module_read called\n");

  if (count >= MAX_SIZE) {
    memcpy(kbuf, globalBuffer, MAX_SIZE);
  } else {
      memcpy(kbuf, globalBuffer, count);
  }

  if (lock) {
      printk(KERN_INFO "ERROR: reading failed");
      return -EINVAL;
  }

  if (_copy_to_user(buf, kbuf, count)) {
    printk(KERN_INFO "ERROR: copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos) {
    char kbuf[MAX_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (count > MAX_SIZE && !lock) {
      printk(KERN_INFO "ERROR: writing failed");
      return -EINVAL;
  }
//
  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "ERROR: copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(globalBuffer, kbuf, MAX_SIZE);

  return count;
}

static int module_lock(struct file *, int, struct file_lock *) {
    pr_info("Lock state: %d", lock);
    lock = lock != 1;
    return 0;
}

static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(globalBuffer);
  return 0;
}



module_init(module_initialize);
module_exit(module_cleanup);

MODULE_LICENSE("GPL");
