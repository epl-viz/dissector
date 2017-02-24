/* packet-epl.h
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 */

#ifndef WIRESHARK_PACKET_EPL_H_
#define WIRESHARK_PACKET_EPL_H_

#include <glib.h>

gboolean epl_g_int16_equal(gconstpointer v1, gconstpointer v2);
guint epl_g_int16_hash(gconstpointer v);

gint *epl_type_to_hf(const char *name);

struct profile {
	guint16 id;
	GHashTable *objects;
    void *data;
};

struct subobject {
	/*range_string *range;*/
	const char *name;
};
struct object {
    guint16 index;
    guint8 type;
    const char *name;
    gint *hf;
    GArray *subindices;
};


struct profile *profile_new(guint16 id);
struct object *profile_object_add(struct profile *profile, guint16 index);

#endif

