#include "wmem_iarray.h"
#include "wmem_iarray_int.h"

#include <epan/wmem/wmem.h>
#include <stdlib.h>
#include <stdio.h>

#include "config.h"

static gboolean
free_garray(wmem_allocator_t *scope _U_, wmem_cb_event_t event _U_, void *data)
{
	GArray *arr = (GArray*)data;
	g_array_free(arr, TRUE);
	return FALSE;
}

epl_wmem_iarray_t *
epl_wmem_iarray_new(wmem_allocator_t *scope, const guint elem_size, GEqualFunc equal)
{
	epl_wmem_iarray_t *iarr;

	if (elem_size < sizeof(range_t)) return NULL;

	iarr = wmem_new(scope, epl_wmem_iarray_t);
	if (!iarr) return NULL;
	iarr->equal = equal;
	iarr->scope = scope;
	iarr->arr = g_array_new(FALSE, FALSE, elem_size);
	iarr->flags.dirty = 0;

	wmem_register_callback(scope, free_garray, iarr->arr);

	return iarr;
}


gboolean
epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr)
{
	return iarr->arr->len == 0;
}

void
epl_wmem_iarray_insert(epl_wmem_iarray_t *iarr, guint32 where, range_admin_t *data)
{
	data->high = data->low = where;
	g_array_append_vals(iarr->arr, data, 1);
}

static int
cmp(const void *_a, const void *_b)
{
	const guint32 a = *(const guint32*)_a,
	              b = *(const guint32*)_b;

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

void
epl_wmem_iarray_lock(epl_wmem_iarray_t *iarr)
{
	range_admin_t *elem, *prev = NULL;
	guint i, len;
	len = iarr->arr->len;
	if (len <= 1) return;
	g_array_sort(iarr->arr, cmp);
	prev = elem = (range_admin_t*)iarr->arr->data;
	for (i = 1; i < len; i++)
	{
		elem = (range_admin_t*)((char*)elem + g_array_get_element_size(iarr->arr));

again:
			if (ABS(elem->low - prev->high) <= 1
				&& iarr->equal(elem, prev)) {
			prev->high = elem->high;
			g_array_remove_index(iarr->arr, i);
			len--;
			if (i < len)
				goto again;
		} else {
			prev = elem;
		}
	}

}

static int
find_in_range(const void *_a, const void *_b)
{
	const range_admin_t *a = (const range_admin_t*)_a,
	                    *b = (const range_admin_t*)_b;

	if (a->low == a->high) {
		if (b->low <= a->low && a->low <= b->high)
			return 0;
		else if (a->low < b->low)
			return -1;
		else if (a->high > b->high)
			return 1;
	} else {
		if (a->low <= b->low && b->low <= a->high)
			return 0;
		else if (b->low < a->low)
			return 1;
		else if (b->high > a->high)
			return -1;
	}

	/* unreachable */
	return 0;
}

static void*
bsearch_garray(const void *key, GArray *arr, int (*cmp)(const void*, const void*))
{
	return bsearch(key, arr->data, arr->len, g_array_get_element_size(arr), cmp);
}

range_admin_t *
epl_wmem_iarray_find(epl_wmem_iarray_t *iarr, guint32 value) {
	range_admin_t needle;
	needle.low  = value;
	needle.high = value;
	return (range_admin_t*)bsearch_garray(&needle, iarr->arr, find_in_range);
}

void
epl_wmem_print_iarr(epl_wmem_iarray_t *iarr)
{
	range_admin_t *elem;
	guint i, len;
	elem = (range_admin_t*)iarr->arr->data;
	len = iarr->arr->len;
	for (i = 0; i < len; i++)
	{

		printf("Range: low=%" G_GUINT32_FORMAT " high=%" G_GUINT32_FORMAT "\n",
				elem->low, elem->high);

		elem = (range_admin_t*)((char*)elem + g_array_get_element_size(iarr->arr));
	}
}
