/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <list.h>
#include "threads/vaddr.h"

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

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page* page = (struct page *) malloc(sizeof(struct page));

		if (page == NULL) {
			return false;
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

		if (init == NULL) {
			if (!(vm_do_claim_page(page) && swap_in(page, page->frame->kva))) {
				goto err;
			}
		}

		spt_insert_page(spt, page);

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page *tmp = NULL;
	struct list_elem *e;
	
	if (!list_empty(&spt->page_list)) {
		e = list_begin(&spt->page_list);
		while (e != list_end(&spt->page_list)) {
			tmp = list_entry(e, struct page, elem);
			if (tmp->va == pg_round_down(va)) {
				page = tmp;
				break;
			}
			e = list_next(e);

		}
	}

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
	if (spt_find_page(spt, page->va) == NULL) {
		list_push_back(&spt->page_list, &page->elem);
		page->spt = spt;
		return true;
	} else {
		return false;
	}
}

void spt_do_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct list_elem *e;
	struct page *tmp = NULL;

	e = list_begin (&spt->page_list);
	while(e != list_end (&spt->page_list)) {
		if (list_entry(e, struct page, elem) == page) {
			tmp = list_entry(e, struct page, elem);
			break;
		}
		e = list_next(e);
	}
	
	if (tmp != NULL) {
		list_remove(&tmp->elem);
	}
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

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
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
		//evict
		PANIC("todo: evict");
	}


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
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

	if (not_present) {
		struct page *page = spt_find_page(spt, addr);
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
	//spt_insert_page(&t->spt, page);

	return (pml4_get_page (t->pml4, page->va) == NULL 
		&& pml4_set_page(t->pml4, page->va, frame->kva, true));

	//return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	list_init(&spt->page_list);
	spt->type = VM_UNINIT;
	spt->t = thread_current();
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
