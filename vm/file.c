/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static bool file_map_swap_in (struct page *page, void *kva);
static bool file_map_swap_out (struct page *page);
static void file_map_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_map_swap_in,
	.swap_out = file_map_swap_out,
	.destroy = file_map_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file mapped page */
bool
file_map_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	page->type = type;

	struct file_page *file_page = &page->file;
	// file_page->has_modified = false;
	//page->file->has_modified = false;
}

/* Swap in the page by read contents from the file. */
static bool
file_map_swap_in (struct page *page, void *kva) {
	//struct file_page *file_page UNUSED = &page->file;
	struct aux_vm *aux_vm = page->aux_vm;

	struct file *f = file_reopen(aux_vm->file);

	file_seek(f, aux_vm->ofs);

	int read = file_read(f, kva, aux_vm->read_bytes);
	if (read != aux_vm->read_bytes) {
		return false;
	}

	memset(page->frame->kva + aux_vm->read_bytes, 0, aux_vm->zero_bytes);

	page->spt = &thread_current()->spt;
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_map_swap_out (struct page *page) {
	//struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(&thread_current()->pml4, page->va)) {
		struct file* f = file_reopen(page->aux_vm->file);
		file_write(f, page->frame->kva, page->aux_vm->read_bytes);
		pml4_set_dirty(&thread_current()->pml4, page->va, false);
	}
			
}

/* Destory the file mapped page. PAGE will be freed by the caller. */
static void
file_map_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	int file_len = file_length(file);
	int past_read = offset;
	for (int i = (int) addr; i < ((int) addr + (int) length); i += (int) PGSIZE) {
		if (spt_find_page(&thread_current()->spt, i) != NULL) {
			return NULL;
		}
		void *upage = (void *) i;
		struct aux_vm *aux_vm = (struct aux_vm*) malloc(sizeof(struct aux_vm));
		aux_vm->file = file;
		aux_vm->ofs = past_read;
		aux_vm->upage = upage;
		aux_vm->writable = writable;
		aux_vm->read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
		aux_vm->read_bytes = aux_vm->read_bytes < 0 ? 0 : aux_vm->read_bytes;
		past_read += aux_vm->read_bytes;
		aux_vm->zero_bytes = PGSIZE - aux_vm->read_bytes;
		aux_vm->owner = thread_current();
		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_segment_mmap, aux_vm))
			return NULL;
		file_len -= aux_vm->read_bytes;
	}

	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	struct file *file = file_reopen(page->aux_vm->file);

	while(page != NULL) {
		if (page->type == VM_FILE) {
			file_seek(file, page->aux_vm->ofs);
			struct file_page *file_page = &page->file;
			if (pml4_is_dirty(thread_current()->pml4, addr))
				file_write(file, page->frame->kva, page->aux_vm->read_bytes);
			spt_remove_page(spt, page);
			page = spt_find_page(&thread_current()->spt, addr + PGSIZE);
		} else {
			if (page->type == VM_UNINIT) {
				struct uninit_page *uninit = &page->uninit;
				if (uninit->type == VM_FILE) {
					spt_remove_page(spt, page);
					page = spt_find_page(&thread_current()->spt, addr + PGSIZE);
				}
			}
		}
		
	}
}
