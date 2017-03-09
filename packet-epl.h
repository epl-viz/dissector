/* packet-epl.h
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 */

#ifndef WIRESHARK_PACKET_EPL_H_
#define WIRESHARK_PACKET_EPL_H_

#include <glib.h>
#include <epan/wmem/wmem.h>
#include "wmem_iarray.h"

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wmissing-braces"
#endif

/* copied from <wiretap/wtap-int.h> */
#ifndef phtolell
#define phtolell(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);     \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 16);    \
        (p)[3] = (guint8)((v) >> 24);    \
        (p)[4] = (guint8)((v) >> 32);    \
        (p)[5] = (guint8)((v) >> 40);    \
        (p)[6] = (guint8)((v) >> 48);    \
        (p)[7] = (guint8)((v) >> 56);    \
    }
#endif


gboolean epl_g_int16_equal(gconstpointer v1, gconstpointer v2);
guint epl_g_int16_hash(gconstpointer v);

struct dataTypeMap_in;
const struct dataTypeMap_in *epl_type_to_hf(const char *name);

struct profile {
	guint16 id;
	wmem_map_t *objects;
	wmem_allocator_t *scope, *parent_scope;
	char *name;
	char *path;
	void *data;
    guint cb_id;
    wmem_array_t *TPDO; /* CN->MN */
    wmem_array_t *RPDO; /* MN->CN */
};

#define OD_ENTRY_NO_SUBINDICES 7
struct od_entry {
	guint16 idx;
	guint8 kind; /* object type, is it aggregate or plain and so, FIXME needs better name */
	char name[64];
	const struct dataTypeMap_in *type;
	guint64 value;
};

struct subobject {
	range_admin_t range;
	struct od_entry info;
};
gboolean subobject_equal(gconstpointer, gconstpointer);
struct object {
	struct od_entry info;
	epl_wmem_iarray_t *subindices;
};


struct profile *profile_new(wmem_allocator_t *parent_pool, guint16 id);
void profile_del(struct profile *profile);
struct object *profile_object_add(struct profile *profile, guint16 idx);
struct object *profile_object_lookup_or_add(struct profile *profile, guint16 idx);
gboolean profile_object_mapping_add(struct profile *profile, guint16 idx, guint8 subindex, guint64 mapping);
gboolean profile_object_mappings_update(struct profile *profile);
struct object * object_lookup(struct profile *profile, guint16 idx);

#define CHECK_OVERLAP(x, x_len, y, y_len) ((x) <= (y) + ((y_len)-1) && (y) <= (x) + ((x_len)-1))

#endif

