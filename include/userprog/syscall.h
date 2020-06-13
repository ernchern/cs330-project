#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/vaddr.h"
#include <stdbool.h>
#include "threads/synch.h"


void syscall_init (void);

typedef int pid_t;

struct sys_file {
	int fd;
	struct file *file;
	struct list_elem t_e;
};

void halt(void);
void exit(int status);
pid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
struct sys_file *get_sys_file(int fd);
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

#endif /* userprog/syscall.h */
