/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include <bitmap.h>
#include "threads/vaddr.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *disk_bitmap;
static struct semaphore sem;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	disk_bitmap = bitmap_create(disk_size(swap_disk));
	bitmap_set_all(disk_bitmap, false);
	//sema_init(&sem, 1);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;

	anon_page->disk_sector = NULL;
	page->use_count = 0;

	page->type = type;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	//sema_down(&sem);

	size_t first_index = anon_page->disk_sector;

	if (!bitmap_test(disk_bitmap, first_index)) {
		return false;
	}

	int i = 0;
	for (i; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
		disk_read(swap_disk, first_index + i, page->frame->kva + i * DISK_SECTOR_SIZE);
		bitmap_set(disk_bitmap, first_index + i, false);
	}

	anon_page->disk_sector = NULL;

	//sema_up(&sem);

	return pml4_set_page(thread_current()->pml4, page->va, kva, page->aux_vm->writable);

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//sema_down(&sem);

	// if (page->va == 0xaba000) {
	// 	printf("%p\n", page->va);
	// }

	//size_t size = bitmap_size(disk_bitmap);
	//bool test = bitmap_contains(disk_bitmap, 0, 8, true);
	size_t first_index = bitmap_scan(disk_bitmap, 0, 1, false);
	if (first_index == BITMAP_ERROR) {
		return false;
	}

	int i = 0;
	int j = 0;
	for (i; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
		j = first_index + i;
		disk_write(swap_disk, j, page->frame->kva + i * DISK_SECTOR_SIZE);
		bitmap_set(disk_bitmap, j, true);
	}
	anon_page->disk_sector = first_index;

	//sema_up(&sem);

	return true;

}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//destroy(page->anon);
}
