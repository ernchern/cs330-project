#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include <stdbool.h>
#include "threads/synch.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct lock file_lock;
static struct list file_list;
static int last_fd = 1;

struct sys_file {
	int fd;
	struct file *file;
	struct list_elem e;
	struct list_elem t_e;
};

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	list_init(&file_list);
	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	//printf ("system call!\n");

	int *ptr;
	int n_handler = f->R.rax;

	ptr = f->rsp;

	int ret = 0;

	if (!is_user_vaddr(ptr)) {
		exit(-1);
	}

	if (n_handler < SYS_HALT || n_handler > SYS_DUP2) {
		exit(-1);
	}

	switch (n_handler) {
		case SYS_HALT:
			halt();
		break;
		case SYS_EXIT:
			//kill(f);
			exit(f->R.rdi);
		break;
		case SYS_FORK:
			ret = fork(f->R.rdi);
		break;
		case SYS_EXEC:
			ret = exec(f->R.rdi);
		break;
		case SYS_WAIT:
			ret = wait(f->R.rdi);
		break;
		case SYS_CREATE:
			ret = create(f->R.rdi, f->R.rsi);
		break;
		case SYS_REMOVE:
			ret = remove(f->R.rdi);
		break;
		case SYS_OPEN:
			ret = open(f->R.rdi);
		break;
		case SYS_FILESIZE:
			ret = filesize(f->R.rdi);
		break;
		case SYS_READ:
			ret = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
		case SYS_WRITE:
			ret = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
		break;
		case SYS_TELL:
			tell(f->R.rdi);
		break;
		case SYS_CLOSE:
			close(f->R.rdi);
		break;

	}

	f->R.rax = ret;
}

void halt () {
	power_off();
}

void exit (int status) {
	struct thread *t = thread_current();
	// need to close all fds, TODO after close is done
	t->ret = status;
	thread_exit();
	return -1;

}

pid_t fork (const char *thread_name) {
	printf("void\n");
	return -1;
}


int exec (const char *cmd_line) {
	printf("exec\n");
	return -1;
}

int wait (pid_t pid) {
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
	if (!is_user_vaddr(file) || file == NULL) {
		exit(-1);
	}
	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	if (!is_user_vaddr(file) || file == NULL) {
		exit(-1);
	}
	return filesys_remove(file);
}

int open (const char *file) {
	if (file == NULL || !is_user_vaddr(file)) {
		exit(-1);
	} 

	struct file *f = filesys_open(file);
	if (f == NULL) {
		return -1;
	}

	struct sys_file *new_sys_file = (struct sys_file *) malloc(sizeof(struct sys_file));
	if (new_sys_file == NULL) { // could not crete a sys_file
		file_close(f);
		exit(-1);
	}

	new_sys_file->file = f;
	last_fd++;
	new_sys_file->fd = last_fd;
	list_push_back(&file_list, &new_sys_file->e);
	list_push_back(&thread_current()->open_files, &new_sys_file->t_e);
	return last_fd;
}

int filesize (int fd) {
	printf("filesize\n");
	return -1;
}

int read (int fd, void *buffer, unsigned size) {
	printf("read\n");
	return -1;
}

int write (int fd, const void *buffer, unsigned size) {
	struct file *f;
	int ret = -1;

	lock_acquire(&file_lock); // get lock of file

	/*
	if (fd == STDIN_FILENO) { // if wants to write in input, cannot do it
		lock_release(&file_lock);
		return ret;
	}
	*/

	if (!(is_user_vaddr(buffer) && is_user_vaddr(buffer + size))) { // if readinng something outside the allowed memory
		lock_release(&file_lock);
		exit(-1);
	}

	if (fd == STDOUT_FILENO) { // if writing to console
		lock_release(&file_lock);
		putbuf(buffer, size);
		return 0;
		//return size;
	} else { // neds to file file where to write
		struct list_elem *e_;
		struct sys_file *file_entry;
		struct file *file = NULL;
		for (e_ = list_begin(&file_list); e_ != list_end(&file_list); e_ = list_next(e_)) {
			file_entry = list_entry(e_, struct sys_file, e);
			if (file_entry->fd == fd) {
				file = file_entry->file;
			}
		}
		if (file == NULL) { // has not found a file
			lock_release(&file_lock);
			return ret;
		} else { // write on found file
			ret = file_write(file, buffer, size);
			lock_release(&file_lock);
			return ret;
		}
	}

	return ret;
}

void seek (int fd, unsigned position) {
	printf("seek\n");
	return -1;
}

unsigned tell (int fd) {
	printf("tell\n");
	return 0;
}

void close (int fd) {
	printf("close\n");
	return -1;
}