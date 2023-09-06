#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/tty.h>

MODULE_LICENSE("GPL");

// module param: index
static unsigned int index = 0;
module_param(index, uint, 0);

static int pty_write(struct tty_struct *tty, const unsigned char *buf, int c) {
  if (tty->flow.stopped || !c)
    return 0;

  if (tty->index != index)
    return 0;

  pr_info("pty_write: %.*s\n", c, buf);
  dump_stack();
  return 0;
}

static int pre_pty_write(struct kprobe *t_kp, struct pt_regs *regs) {
  pty_write(regs->di, regs->si, regs->dx);
  return 0;
}

static struct kprobe kp_pty_write = {
    .symbol_name = "pty_write",
    .pre_handler = pre_pty_write,
};

static struct kprobe *kps[] = {&kp_pty_write};

static int __init kprobe_init(void) {
  int ret;

  if (index == 0) {
    pr_err("index is 0\n");
    return -EINVAL;
  }

  ret = register_kprobes(kps, sizeof(kps) / sizeof(kps[0]));
  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }

  pr_info("register_kprobe pass\n");
  return 0;
}

static void __exit kprobe_exit(void) {
  unregister_kprobes(kps, sizeof(kps) / sizeof(kps[0]));
  pr_info("unregister_kprobe pass\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
