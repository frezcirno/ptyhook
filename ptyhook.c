#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/tty.h>

MODULE_LICENSE("GPL");

static int hook_write(struct tty_struct *tty, const unsigned char *buf, int c) {
  struct tty_driver *driver;

  if (!c)
    return 0;

  if (tty->flow.stopped)
    return 0;

  driver = tty->driver;

  if (driver->type != TTY_DRIVER_TYPE_PTY)
    return 0;

  if (driver->name_base == 0)
    // don't repeat self
    return 0;

  char print_buf[512];
  char *p = print_buf;
  for (int i = 0; i < c && i < 100; i++) {
    if (isprint(buf[i]))
      *p++ = buf[i];
    else
      // %02x prints the hex value of the character
      p += sprintf(p, "\\x%02x", buf[i]);
  }
  *p = '\0';

  pr_info("hook_write: in hook_write function %s %s %d buf %d %s\n",
          driver->driver_name, driver->name, driver->name_base, c, print_buf);
  return 0;
}

static int kprobes_pre(struct kprobe *t_kp, struct pt_regs *regs) {
  hook_write(regs->di, regs->si, regs->dx);

  return 0;
}

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
    .symbol_name = "pty_write",
    .pre_handler = kprobes_pre,
};

static int __init kprobe_init(void) {
  int ret;

  ret = register_kprobe(&kp);
  if (ret < 0) {
    pr_err("register_kprobe failed, returned % d\n", ret);
    return ret;
  }
  pr_info("Planted kprobe at % p\n", kp.addr);
  return 0;
}

static void __exit kprobe_exit(void) {
  unregister_kprobe(&kp);
  pr_info("kprobe at % p unregistered\n", kp.addr);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
