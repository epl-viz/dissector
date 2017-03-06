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

gboolean epl_g_int16_equal(gconstpointer v1, gconstpointer v2);
guint epl_g_int16_hash(gconstpointer v);

struct dataTypeMap_in;
const struct dataTypeMap_in *epl_type_to_hf(const char *name);

struct profile {
	guint16 id;
	wmem_map_t *objects;
	wmem_allocator_t *scope;
	const char *name;
	const char *path;
	void *data;
};

struct od_entry {
	guint16 index;
	guint8 kind; /* object type, is it aggregate or plain and so, FIXME needs better name */
	char name[64];
	const struct dataTypeMap_in *type;
};

struct subobject {
	range_admin_t range;
	struct od_entry info;
};
struct object {
	struct od_entry info;
	epl_wmem_iarray_t *subindices;
};


struct profile *profile_new(wmem_allocator_t *scope, guint16 id);
struct object *profile_object_add(struct profile *profile, guint16 index);

#define CHECK_OVERLAP(x, x_len, y, y_len) ((x) <= (y) + ((y_len)-1) && (y) <= (x) + ((x_len)-1))

#endif

