#ifndef EPL_WMEM_IARRAY_INT
#define EPL_WMEM_IARRAY_INT
#include <glib.h>
#include <epan/wmem/wmem.h>
struct _epl_wmem_iarray {
	GEqualFunc equal;
	wmem_allocator_t *scope;
	GArray *arr;
	guint cb_id;
	struct {
		unsigned dirty:1;
	} flags;
};
#endif
