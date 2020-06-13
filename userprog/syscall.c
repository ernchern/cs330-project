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
#include "filesys/filesys.h"

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
//static struct list file_list;
//static int last_fd = 1;
//static struct intr_frame *f_;

// struct sys_file {
// 	int fd;
// 	struct file *file;
// 	struct list_elem e;
// 	struct list_elem t_e;
// };

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

	//list_init(&file_list);
	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
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
			exit(f->R.rdi);
		break;
		case SYS_FORK:
			thread_current()->fork_f = f;
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
		case SYS_MMAP:
			ret = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
		break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
		break; 

	}

	f->R.rax = ret;
}

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset){
	int file_len = filesize(fd);
	if (file_len == 0 || length == 0 || offset > length) {
		return NULL;
	}

	if (addr != pg_round_down(addr) || addr == NULL) {
		return NULL;
	}

	// for (int i = (int) addr; i < ((int) addr + (int) length); i += (int) PGSIZE) {
	// 	if (spt_find_page(&thread_current()->spt, i) != NULL) {
	// 		return NULL;
	// 	}
	// }

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
		return NULL;
	}

	struct sys_file *file = get_sys_file(fd);
	if (file == NULL) {
		return NULL;
	}

	if (!is_user_vaddr(addr) || !is_user_vaddr(addr + length) || addr + length == 0) {
		return NULL;
	}

	struct file *file_ = file->file;
	file_ = file_reopen(file_);
	return do_mmap (addr, length, writable, file_, offset);
}

void munmap (void *addr) {
	struct page *page = spt_find_page(&thread_current()->spt, addr);
	if (page->type != VM_FILE) {
		exit(-1);
	}

	do_munmap(addr);


}

void halt () {
	power_off();
}

void exit (int status) {
	struct thread *t = thread_current();
	t->ret = status;
	thread_exit();
	return -1;

}

pid_t fork (const char *thread_name) {
	struct thread *t = thread_current();
	pid_t ret = process_fork(thread_name, t->fork_f);
	return ret;
}


int exec (const char *cmd_line) {
	if (cmd_line == NULL || !is_user_vaddr(cmd_line) || pml4_get_page(thread_current()->pml4, cmd_line) == NULL) {
		exit(-1);
	}
	char *ptr;
	struct file *file;
	int len = strlen(cmd_line)+1;
	char *newcmd = malloc(len);
	memcpy(newcmd, cmd_line, len);     
	
	char *new = strtok_r(cmd_line, " ", &ptr);   //i could not tokenize newcmd, why
	file = filesys_open(new);
	if (file == NULL) {
		printf ("load: %s: open failed\n", cmd_line);
		exit(-1);
	}

	return process_exec(newcmd);
}

int wait (pid_t pid) {
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
	if (!is_user_vaddr(file) || file == NULL || pml4_get_page(thread_current()->pml4,file) == NULL) {
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
	if (file == NULL || !is_user_vaddr(file) || pml4_get_page(thread_current()->pml4,file) == NULL) {
		exit(-1);
	} 

	struct sys_file *new_sys_file = (struct sys_file *) malloc(sizeof(struct sys_file));
	if (new_sys_file == NULL) {
		return -1;
	}

	struct thread *t = thread_current();

	struct file *f = filesys_open(file);
	if (f == NULL) {
		free(new_sys_file);
		return -1;
	}

	if (strcmp(file, t->name) == 0) {
		file_deny_write(f);
	}


	new_sys_file->file = f;

	int n_fds = list_size(&t->open_files);
	new_sys_file->fd = 2 + n_fds;

	list_push_back(&t->open_files, &new_sys_file->t_e);
	return 2 + n_fds;
}

int filesize (int fd) {
	struct list_elem *e_;
	struct sys_file *file_entry = get_sys_file(fd);
	if (file_entry == NULL) {
		return -1;
	}
	struct file *file = file_entry->file;
	if (file == NULL) {
		return -1;
	}

	return file_length(file);

}

int read (int fd, void *buffer, unsigned size) {
	int ret = -1;
	if (((int) buffer >> 20) == 4) {
		exit(-1);
	}
	if (fd != STDOUT_FILENO) {
		lock_acquire(&file_lock); // get lock of file

		if (!(is_user_vaddr(buffer) && is_user_vaddr(buffer + size))) { // if readinng something outside the allowed memory
			lock_release(&file_lock);
			exit(-1);
		}

		// if (!(pml4_get_page(thread_current()->pml4, buffer) && pml4_get_page(thread_current()->pml4,(buffer + size)))) {
		// 	lock_release(&file_lock);
		// 	exit(-1);
		// }

		if (fd == STDIN_FILENO) { // if reading from console
			uint8_t read = input_getc();
			ret = 0;
			while(read != NULL) {
				*(char *)(buffer + ret) = read;
				ret++;
				read = input_getc();
			}
			lock_release(&file_lock);
			return ret;
		} else { // neds to file file where to write
			struct list_elem *e_;
			struct sys_file *file_entry = get_sys_file(fd);
			if (file_entry == NULL) {
				lock_release(&file_lock);
				return -1;
			}
			struct file *file = file_entry->file;
			if (file == NULL) { // has not found a file
				lock_release(&file_lock);
				return -1;
			} else { // read from found file
				ret = file_read(file, buffer, size);
				lock_release(&file_lock);
				return ret;
			}
		}
	}
	return ret;
}

int write (int fd, const void *buffer, unsigned size) {
	struct file *f;
	int ret = -1;
	if (fd != STDIN_FILENO) {
		lock_acquire(&file_lock); // get lock of file

		if (!(is_user_vaddr(buffer) && is_user_vaddr(buffer + size))) { // if readinng something outside the allowed memory
			lock_release(&file_lock);
			exit(-1);
		}

		if (!pml4_get_page(thread_current()->pml4,buffer) && !pml4_get_page(thread_current()->pml4,(buffer + size))) {
			lock_release(&file_lock);
			exit(-1);
		}

		if (fd == STDOUT_FILENO) { // if writing to console
			putbuf(buffer, size);
			lock_release(&file_lock);
			return 0;
		} else { // neds to file file where to write
			struct list_elem *e_;
			struct sys_file *file_entry = get_sys_file(fd);
			if (file_entry == NULL) {
				lock_release(&file_lock);
				return -1;
			}
			struct file *file = file_entry->file;
			if (file == NULL) { // has not found a file
				lock_release(&file_lock);
				return -1;
			}
			ret = file_write(file, buffer, size);
			lock_release(&file_lock);
			return ret;
		}
	}
	return ret;
}

void seek (int fd, unsigned position) {
	struct sys_file *file_entry = get_sys_file(fd);
	if (file_entry == NULL) {
		return -1;
	}

	file_seek(file_entry->file, position);
}

unsigned tell (int fd) {
	struct sys_file *file_entry = get_sys_file(fd);
	if (file_entry == NULL) {
		return -1;
	}

	return file_tell(file_entry->file);
}

void close (int fd) {
	struct sys_file *file_entry = get_sys_file(fd);

	if (file_entry == NULL) {
		return;
	}

	file_close(file_entry->file);
	//list_remove(&file_entry->e);
	list_remove(&file_entry->t_e);
	free(file_entry);
}

struct sys_file *get_sys_file(int fd) {
	struct list_elem *e_;
	struct thread *t = thread_current();
	struct sys_file *file_entry;

	for (e_ = list_begin(&t->open_files); e_ != list_end(&t->open_files); e_ = list_next(e_)) {
		file_entry = list_entry(e_, struct sys_file, t_e);
		if (file_entry->fd == fd) {
			return file_entry;
		}
	}
	return NULL;
}