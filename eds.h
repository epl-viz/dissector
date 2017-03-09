#ifndef WIRESHARK_EPL_EDS_H_
#define WIRESHARK_EPL_EDS_H_

#include <glib.h>
#include <epan/wmem/wmem.h>

void eds_init(void);
void eds_free(void);

struct profile *eds_load(wmem_allocator_t*parent_pool, guint16 id, const char *eds_file);

#endif
