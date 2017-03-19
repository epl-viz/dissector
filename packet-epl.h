/* packet-epl.h
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
	guint8 nodeid;
	guint32 VendorId;
	guint32 ProductCode;
	
	wmem_map_t *objects;
	wmem_allocator_t *scope, *parent_scope;
	wmem_map_t *parent_map;

	char *name;
	char *path;
	void *data;
	guint cb_id;
	wmem_array_t *TPDO; /* CN->MN */
	wmem_array_t *RPDO; /* MN->CN */

	struct profile *next;
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


struct object *profile_object_add(struct profile *profile, guint16 idx);
struct object *profile_object_lookup_or_add(struct profile *profile, guint16 idx);
gboolean profile_object_mapping_add(struct profile *profile, guint16 idx, guint8 subindex, guint64 mapping);
gboolean profile_object_mappings_update(struct profile *profile);
struct object * object_lookup(struct profile *profile, guint16 idx);

#define CHECK_OVERLAP_ENDS(x1, x2, y1, y2) ((x1) < (y2) && (y1) < (x2))
#define CHECK_OVERLAP_LENGTH(x, x_len, y, y_len) \
	CHECK_OVERLAP_ENDS((x), (x) + (x_len), (y), (y) + (y_len))

#if GLIB_CHECK_VERSION(2, 40, 0)
#define EPL_INFO(...) g_info(__VA_ARGS__)
#else
#define EPL_INFO(...) 
#endif

#endif

