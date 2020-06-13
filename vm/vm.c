/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <list.h>
#include "threads/vaddr.h"
#include "userprog/process.h"

static unsigned vm_hash(struct hash_elem *, void * UNUSED);
static bool vm_less(struct hash_elem *, struct hash_elem *, void * UNUSED);
static struct lock vm_lock;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&vm_lock);
	// lock_acquire(&vm_lock);
	// lock_release(&vm_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	if (init != NULL) {
		ASSERT (VM_TYPE(type) != VM_UNINIT)
	}

	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page* page;

	/* Check wheter the upage is already occupied or not. */
	page = spt_find_page (spt, upage);
	if (page == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		page = (struct page *) malloc(sizeof(struct page));
		
		if (page == NULL) {
			return false;
		}
	} else {
		page = spt_find_page (spt, upage);
		spt_do_remove_page(spt, page);
	}

	bool (*init_func)(struct page*, enum vm_type, void*);

	/* TODO: Insert the page into the spt. */
	switch(VM_TYPE(type)) {
		case VM_ANON:
			init_func = anon_initializer;
			break;
		case VM_FILE:
			init_func = file_map_initializer;
			break;
		case VM_PAGE_CACHE:
			goto err;
		default:
			init_func = anon_initializer;
			break;
	}

	uninit_new(page, upage, init, type, aux, init_func);
	page->use_count = 0;

	if (init == NULL) {
		if (!(vm_do_claim_page(page) && swap_in(page, page->frame->kva))) {
			goto err;
		}
	}

	spt_insert_page(spt, page);
	page->aux_vm = aux;
	
	return true;
		
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// struct page *
// spt_find_page (struct supplemental_page_table *spt, void *va) {
// 	struct page *page = NULL;
// 	/* TODO: Fill this function. */
// 	struct page *tmp = NULL;
// 	struct list_elem *e;
	
// 	if (!list_empty(&spt->page_list)) {
// 		e = list_begin(&spt->page_list);
// 		while (e != list_end(&spt->page_list)) {
// 			tmp = list_entry(e, struct page, elem);
// 			if (tmp->va == pg_round_down(va)) {
// 				page = tmp;
// 				break;
// 			}
// 			e = list_next(e);

// 		}
// 	}

// 	return page;
// }

/* Insert PAGE into spt with validation. */
// bool
// spt_insert_page (struct supplemental_page_table *spt,
// 		struct page *page) {
// 	int succ = false;
// 	/* TODO: Fill this function. */
// 	if (spt_find_page(spt, page->va) == NULL) {
// 		list_push_back(&spt->page_list, &page->elem);
// 		page->spt = spt;
// 		return true;
// 	} else {
// 		return false;
// 	}
// }

struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page page;
	/* TODO: Fill this function. */
	page.va = pg_round_down(va);
	//lock_acquire(&vm_lock);

	struct hash_elem *e = hash_find(&spt->page_hash, &page.hash_elem);
	//lock_release(&vm_lock);

	if (e == NULL) {
		return NULL;
	} else {
		return hash_entry(e, struct page, hash_elem);
	}
}


bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	//lock_acquire(&vm_lock);
	struct hash_elem *e = hash_insert(&spt->page_hash, &page->hash_elem);
	//lock_release(&vm_lock);
	if (e == NULL) {
		page->spt = spt;
	}

	return e == NULL;

}



void spt_do_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct list_elem *e;
	struct page *tmp = NULL;

	lock_acquire(&vm_lock);
	hash_delete(&spt->page_hash, &page->hash_elem);
	lock_release(&vm_lock);
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	spt_do_remove_page(spt, page);
	
	vm_dealloc_page (page);
	
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	struct list_elem *e;
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page;
	int max = -1;
	bool has_victim = false;
	struct hash_iterator i;
	lock_acquire(&vm_lock);
	hash_first(&i, &spt->page_hash);
	while (hash_next(&i)) { 
		page = hash_entry (hash_cur(&i), struct page, hash_elem);
		if (pml4_is_dirty(&thread_current()->pml4, page->va) || page->type == VM_UNINIT || ((int) page->va >> 20) == 4 || ((int) page->va >> 20) == 26) {
			page->use_count = 0;
		} else {
			page->use_count++;

			// save max in spt and get first? 
			if (page->use_count >= max && page->frame != NULL) {
				victim = page->frame;
				has_victim = true;
				max = page->use_count;
				break;
			}
		}
	}

	lock_release(&vm_lock);

	ASSERT(victim != NULL);
	victim->page->use_count = 0;
	victim->page->type = 64;

	pml4_clear_page(thread_current()->pml4, victim->page->va);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	uint8_t *kva = palloc_get_page(PAL_USER);
	if (kva != NULL) {
		frame = (struct frame *) malloc(sizeof(struct frame));
		frame->page = NULL;
		frame->kva = kva;
	} else {
		frame = vm_evict_frame();
		frame->page = NULL;
	}


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *rounded_addr = pg_round_down(addr);

	bool success = vm_alloc_page(32, rounded_addr, true);
	if (success) {
		struct aux_vm *aux_vm = (struct aux_vm*) malloc(sizeof(struct aux_vm));
		aux_vm->writable = true;
		aux_vm->upage = rounded_addr;
		aux_vm->owner = thread_current();
		spt_find_page(&thread_current()->spt, rounded_addr)->aux_vm = aux_vm;
	}
	
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	page = spt_find_page(spt, addr);

	if (not_present) {
		//bool test = !is_user_vaddr(addr);
		if (user && !is_user_vaddr(addr)) {
			return false;
		}

		// stack growth
		void *max_size = 1 << 20;
		void *rounded_addr = pg_round_down(addr);
		int diff = USER_STACK - (int) rounded_addr;
		if (diff < (int) max_size && diff >= 0) {
			if (user) {
				if (write) {
					vm_stack_growth(addr);
					return true;
				} else {
					return false;
				}
			} else {
				if (f->rsp >= (uint8_t) addr && diff <= 2 * PGSIZE) {
					return false;
				}
				if (write) {
					vm_stack_growth(addr);
					return true;
				} else {
					return false;
				}
			}


		}

		// normal
		if (page != NULL) {
			if(vm_do_claim_page(page)) {
				return swap_in(page, page->frame->kva);
			}
		} else {
			return false;
		}
	}

	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = (struct page *) malloc(sizeof(struct page));
	if (page == NULL) {
		return false;
	}
	page->use_count = 0;
	page->va = va;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *t = thread_current();

	bool get = pml4_get_page (t->pml4, page->va) == NULL;
	bool set;
	if (page->aux_vm == NULL) {
		set = pml4_set_page(t->pml4, page->va, frame->kva, true);
	} else {
		set = pml4_set_page(t->pml4, page->va, frame->kva, page->aux_vm->writable);
	}

	return (get && set);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	//list_init(&spt->page_list);
	hash_init(&spt->page_hash, vm_hash, vm_less, NULL);
	spt->type = VM_UNINIT;
	spt->t = thread_current();
}

static unsigned vm_hash (struct hash_elem *elem, void *aux UNUSED) {
	struct page *p = hash_entry (elem, struct page, hash_elem);
  	return hash_bytes (&p->va, sizeof p->va);
}

static bool vm_less(struct hash_elem *elem1, struct hash_elem *elem2, void *aux UNUSED) {
	return hash_entry(elem1, struct page, hash_elem)->va < hash_entry(elem2, struct page, hash_elem)->va;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	dst->type = src->type;
	dst->t = thread_current();
	struct list_elem *e;
	struct page *new_page, *old_page;
	struct hash_iterator i;
	lock_acquire(&vm_lock);
	hash_first(&i, &src->page_hash);
	while (hash_next(&i)) { 
		old_page = hash_entry (hash_cur(&i), struct page, hash_elem);
		if (!vm_alloc_page(old_page->type, old_page->va, old_page->aux_vm->writable))
			return false;

		new_page = spt_find_page(dst, old_page->va);
		if (old_page->frame != NULL)
			memcpy(new_page->frame->kva, old_page->frame->kva, PGSIZE);

		new_page->spt = dst;
		new_page->aux_vm = old_page->aux_vm;
		if (new_page->type == VM_ANON) {
			struct anon_page *new_anon = &new_page->anon;
			struct anon_page *old_anon = &old_page->anon;
			new_anon->disk_sector = old_anon->disk_sector;

		}

	}
	lock_release(&vm_lock);

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct list_elem *e;
	struct hash_iterator i;
	lock_acquire(&vm_lock);
	if (!hash_empty(&spt->page_hash)) {
		hash_first(&i, &spt->page_hash);
		struct page *page;
		while (hash_next(&i)) { 
			//vm_dealloc_page(hash_entry (hash_cur(&i), struct page, hash_elem));
			page = hash_entry (hash_cur(&i), struct page, hash_elem);
			if (page->type == VM_FILE) {
				struct file *file = file_reopen(page->aux_vm->file);
				file_seek(file, page->aux_vm->ofs);
				struct file_page *file_page = &page->file;
				if (pml4_is_dirty(thread_current()->pml4, page->va))
					file_write(file, page->frame->kva, page->aux_vm->read_bytes);
			}
		}
	}
	lock_release(&vm_lock);
	//destroy(page);
}
