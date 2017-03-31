#include "config.h"
#include "wmem_iarray.h"
#include <glib.h>
#include <assert.h>
#include <stdio.h>
struct entry {
	range_admin_t range;
	unsigned value;
};

gboolean equal(gconstpointer _a, gconstpointer _b) {
	const struct entry *a = (const struct entry*)_a,
	                   *b = (const struct entry*)_b;
	return a->value == b->value;
}

int main(void) {
	epl_wmem_iarray_t *iarr;
	int i;
	struct entry *pentry;
	struct entry entry = {
		{ 0, 0 },
		0
	};

	iarr = epl_wmem_iarray_new(NULL, sizeof (struct entry), equal);
	assert(iarr);

	entry.value = 1;
	epl_wmem_iarray_insert(iarr, 0, &entry.range);

	entry.value = 1;
	epl_wmem_iarray_insert(iarr, 0, &entry.range);

	entry.value = 1;
	epl_wmem_iarray_insert(iarr, 1, &entry.range);


	entry.value = 2;
	epl_wmem_iarray_insert(iarr, 10, &entry.range);

	entry.value = 2;
	epl_wmem_iarray_insert(iarr, 11, &entry.range);

	epl_wmem_print_iarr(iarr);

	epl_wmem_iarray_sort(iarr);
	puts("------");

	epl_wmem_print_iarr(iarr);

	puts("------");

	for (i = 0; i < 20; i++) {
		pentry = (struct entry*)epl_wmem_iarray_find(iarr, i);
		printf("%02d: ", i);
		if (pentry) {
			printf("[value=%2u, low =%2u, high=%2u]\n",
					pentry->value, pentry->range.low, pentry->range.high
			);
		} else {
			puts("doesn't exist");
		}
	}

	return 0;
}



guint wmem_register_callback (wmem_allocator_t *allocator _U_, wmem_user_cb_t callback _U_, void *user_data _U_) {

	return 0;
}
void *wmem_alloc(wmem_allocator_t *allocator _U_, const size_t size) {
	return g_malloc(size);
}

