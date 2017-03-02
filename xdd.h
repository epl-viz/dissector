#ifndef WIRESHARK_EPL_XDD_H_
#define WIRESHARK_EPL_XDD_H_

#include <glib.h>
#include <epan/wmem/wmem.h>

void xdd_init(void);
void xdd_free(void);

struct profile *xdd_load(wmem_allocator_t*, guint16 id, const char *xml_file);

#endif
