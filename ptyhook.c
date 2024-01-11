#include <linux/init.h>
#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/kprobes.h>
#include <linux/module.h>  /* Specifically, a module */
#include <linux/proc_fs.h> /* Necessary because we use the proc fs */
#include <linux/tty.h>
#include <linux/uaccess.h> /* for copy_from_user */
#include <linux/version.h>

#define PTYHOOK_CTRL_NAME "ptyhook"
#define PTYHOOK_DATA_NAME "ptyhook_data"

static unsigned int tty_index = 0;
module_param(tty_index, uint, 0);

static struct proc_dir_entry *ph_ctrl;
static struct proc_dir_entry *ph_data;

static int hooked = 0;

/* The ring buffer used to store character for this module
 * [            ************     ]
 *              |          |
 *             tail       head
 * [***********               ***]
 *            |               |
 *           head            tail
 */
static char ph_buf[1024 * 1024];
static size_t ph_buf_head = 0;
static size_t ph_buf_tail = 0;

// return the number of bytes in ph_buf
static inline size_t ph_buf_size(void) {
  ssize_t x = ph_buf_head - ph_buf_tail;
  if (x >= 0)
    return x;
  return sizeof(ph_buf) + x;
}

/* put a length of `len` of buf to ph_buf
 * if the space is not enough, put as much as possible
 */
static size_t ph_buf_put(const char *buf, size_t len) {
  size_t size = ph_buf_size();

  // put as much as possible
  if (size + len > sizeof(ph_buf))
    len = sizeof(ph_buf) - size;

  if (ph_buf_head + len > sizeof(ph_buf)) {
    size_t first = sizeof(ph_buf) - ph_buf_head;
    memcpy(ph_buf + ph_buf_head, buf, first);
    memcpy(ph_buf, buf + first, len - first);
    ph_buf_head = len - first;
  } else {
    memcpy(ph_buf + ph_buf_head, buf, len);
    ph_buf_head += len;
  }

  return len;
}

/* get a length of `len` of ph_buf to buf
 * if the space is not enough, get as much as possible
 */
static size_t ph_buf_get(char *buf, size_t len) {
  size_t size = ph_buf_size();

  // get as much as possible
  if (size < len)
    len = size;

  if (ph_buf_tail + len > sizeof(ph_buf)) {
    size_t first = sizeof(ph_buf) - ph_buf_tail;
    memcpy(buf, ph_buf + ph_buf_tail, first);
    memcpy(buf + first, ph_buf, len - first);
    ph_buf_tail = len - first;
  } else {
    memcpy(buf, ph_buf + ph_buf_tail, len);
    ph_buf_tail += len;
  }

  return len;
}

static int start_hook(void);
static void stop_hook(void);

/* fetch a length of `len` of ph_buf to user
 * return the number of bytes read
 */
static ssize_t ph_data_read(struct file *file, char __user *ubuf, size_t len,
                            loff_t *off) {
  int ret;
  char kbuf[512];
  size_t val = len;

  // offset is not supported
  if (*off != 0)
    return -EINVAL;

  while (len > 0) {
    size_t get_size = min(len, sizeof(kbuf));
    size_t got = ph_buf_get(kbuf, get_size);
    if (got == 0)
      break;

    if (copy_to_user(ubuf, kbuf, got)) {
      ret = -EFAULT;
      goto out;
    }

    ubuf += got;
    len -= got;
  }

  return val - len;
out:
  return ret;
}

/* read line by line
 * if 0 -> stop hook
 * if positive number -> start hook
 */
static ssize_t ph_ctrl_write(struct file *file, const char __user *ubuf,
                             size_t len, loff_t *off) {
  int ret = 0;
  int val = 0;
  char kbuf[10];

  if (len == 0)
    return 0;

  if (len > sizeof(kbuf))
    return -EINVAL;

  if (copy_from_user(kbuf, ubuf, len)) {
    ret = -EFAULT;
    goto out;
  }
  kbuf[len] = '\0';

  ret = kstrtoint(kbuf, 10, &val);
  if (ret < 0) {
    ret = -EINVAL;
    goto out;
  }

  if (val == 0) {
    stop_hook();
  } else {
    tty_index = val;
    start_hook();
  }

out:
  return ret ? ret : len;
}

static const struct proc_ops ph_ctrl_fops =
                                 {
                                     .proc_write = ph_ctrl_write,
},
                             ph_data_fops = {
                                 .proc_read = ph_data_read,
};

static int pre_pty_write(struct kprobe *t_kp, struct pt_regs *regs) {
  struct tty_struct *tty = (struct tty_struct *)regs->di;
  const unsigned char *buf = (const unsigned char *)regs->si;
  int c = regs->dx;

  if (tty->flow.stopped || !c)
    return 0;

  if (tty->index != tty_index)
    return 0;

  ph_buf_put(buf, c);

  return 0;
}

static struct kprobe kp_pty_write = {
    .symbol_name = "pty_write",
    .pre_handler = pre_pty_write,
};

static struct kprobe *kps[] = {&kp_pty_write};

static int start_hook(void) {
  int ret;

  if (hooked)
    return 0;

  ret = register_kprobes(kps, sizeof(kps) / sizeof(kps[0]));
  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }

  hooked = 1;
  return 0;
}

static void stop_hook(void) {
  if (!hooked)
    return;
  unregister_kprobes(kps, sizeof(kps) / sizeof(kps[0]));
  hooked = 0;
}

static int __init kprobe_init(void) {
  int ret;

  ph_ctrl = proc_create(PTYHOOK_CTRL_NAME, 0644, NULL, &ph_ctrl_fops);
  if (ph_ctrl == NULL) {
    pr_err("Could not initialize /proc/%s\n", PTYHOOK_CTRL_NAME);
    ret = -ENOMEM;
    goto err_ctrl;
  }

  ph_data = proc_create(PTYHOOK_DATA_NAME, 0644, NULL, &ph_data_fops);
  if (ph_data == NULL) {
    pr_err("Could not initialize /proc/%s\n", PTYHOOK_DATA_NAME);
    ret = -ENOMEM;
    goto err_data;
  }

  if (tty_index > 0) {
    ret = start_hook();
    if (ret < 0)
      goto err_reg;
  }

  return 0;

err_reg:
  remove_proc_entry(PTYHOOK_DATA_NAME, NULL);

err_data:
  remove_proc_entry(PTYHOOK_CTRL_NAME, NULL);

err_ctrl:
  return ret;
}

static void __exit kprobe_exit(void) {
  stop_hook();
  remove_proc_entry(PTYHOOK_DATA_NAME, NULL);
  remove_proc_entry(PTYHOOK_CTRL_NAME, NULL);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
