/* eds.c
 * Routines for reading in Ethernet POWERLINK EDS profiles
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "xdd.h"

#include "packet-epl.h"

#include "config.h"

#include "xdd.h"

#include "packet-epl.h"

#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <epan/wmem/wmem.h>
#include <errno.h>

#include "wmem_iarray.h"

static gboolean
epl_ishex(const char *num)
{
	if (g_str_has_prefix(num, "0x"))
		return TRUE;

	for (; isxdigit(*num); num++)
		;

	if (tolower(*num) == 'h')
		return TRUE;

	return FALSE;
}

static guint16
epl_strtou16(const char * str, char **endptr, int base)
{
	unsigned long val = strtoul(str, endptr, base);
	if (val > G_MAXUINT16)
	{
		val = G_MAXUINT16;
		errno = ERANGE;
	}
	return val;
}

static guint16
epl_g_key_file_get_uint16(GKeyFile *gkf, const gchar *group_name, const gchar *key, GError **error)
{
	guint32 ret = 0;
	char *val, *endptr;
	val = g_key_file_get_string(gkf, group_name, key, error);
	if (val) /* We need to support XXh, but no octals (is that right?) */
		ret = epl_strtou16(val, &endptr, epl_ishex(val) ? 16 : 10);
	g_free(val);
	return ret;
}

static char *
epl_strchrnul(const char *s, int c)
{
	const char *end;
	if (!s) return NULL;
	for (end = s; *end && *end != c; end++)
		;
	return (char*)end;
}

static char *
epl_wmem_strdup_till(wmem_allocator_t *allocator, const char *str, char ch)
{
	if (!str) return NULL;
	return wmem_memdup(allocator, str, epl_strchrnul(str, ch) - str);
}

static void
lock_subindices(void *key _U_, void *value, void *user_data _U_)
{
	epl_wmem_iarray_t *subindices = ((struct object*)value)->subindices;
	if (subindices)
		epl_wmem_iarray_lock(subindices);
}

struct dataTypeMap {
	guint16 id;
	const char *name;
	struct dataTypeMap_in *type;
} dataTypeMap_in[] = {
	{0x0001, "Boolean",        NULL},
	{0x0002, "Integer8",       NULL},
	{0x0003, "Integer16",      NULL},
	{0x0004, "Integer32",      NULL},
	{0x0005, "Unsigned8",      NULL},
	{0x0006, "Unsigned16",     NULL},
	{0x0007, "Unsigned32",     NULL},
	{0x0008, "Real32",         NULL},
	{0x0009, "Visible_String", NULL},
	{0x0010, "Integer24",      NULL},
	{0x0011, "Real64",         NULL},
	{0x0012, "Integer40",      NULL},
	{0x0013, "Integer48",      NULL},
	{0x0014, "Integer56",      NULL},
	{0x0015, "Integer64",      NULL},
	{0x000A, "Octet_String",   NULL},
	{0x000B, "Unicode_String", NULL},
	{0x000C, "Time_of_Day",    NULL},
	{0x000D, "Time_Diff",      NULL},
	{0x000F, "Domain",         NULL},
	{0x0016, "Unsigned24",     NULL},
	{0x0018, "Unsigned40",     NULL},
	{0x0019, "Unsigned48",     NULL},
	{0x001A, "Unsigned56",     NULL},
	{0x001B, "Unsigned64",     NULL},
	{0x0401, "MAC_ADDRESS",    NULL},
	{0x0402, "IP_ADDRESS",     NULL},
	{0x0403, "NETTIME",        NULL},
	{0x0000, NULL,		   NULL}
};

wmem_map_t *dataTypeMap;


void
eds_init(void)
{
	struct dataTypeMap *entry;
	dataTypeMap = wmem_map_new(wmem_epan_scope(), epl_g_int16_hash, epl_g_int16_equal);
	for (entry = dataTypeMap_in; entry->name; entry++)
	{
		const struct dataTypeMap_in *type = epl_type_to_hf(entry->name);
		wmem_map_insert(dataTypeMap, &entry->id, (void*)type);
	}
}

void
eds_free(void)
{
}

struct profile *
eds_load(wmem_allocator_t *parent_pool, guint16 id, const char *eds_file)
{
	struct profile *profile = NULL;
	GKeyFile* gkf;
	GError *err;
	char **group, **groups;
	char *val;
	gsize groups_count;

	gkf = g_key_file_new();

	/* Load EDS document */
	if (!g_key_file_load_from_file(gkf, eds_file, G_KEY_FILE_NONE, &err)){
		g_warning("Error: unable to parse file \"%s\"\n", eds_file);
	    goto cleanup;
	}

	/* Allocate profile */
	profile = profile_new(parent_pool, id);
	profile->path = wmem_strdup(profile->scope, eds_file);

	val = g_key_file_get_string(gkf, "FileInfo", "Description", NULL);
	profile->name = epl_wmem_strdup_till(profile->scope, val, '#');
	g_free(val);

	groups = g_key_file_get_groups(gkf, &groups_count);
	for (group = groups; *group; group++)
	{
		char *endptr, *name;
		guint16 idx, DataType;
		struct object *obj = NULL;
		struct od_entry tmpobj = {0};
		gboolean is_object = TRUE;
		
		if (!isxdigit(**group))
			continue;

		idx = epl_strtou16(*group, &endptr, 16);
		if (*endptr == '\0')
		{ /* index */
			tmpobj.idx = idx;
		}
		else if (g_str_has_prefix(endptr, "sub"))
		{ /* subindex */
			tmpobj.idx = epl_strtou16(endptr + 3, &endptr, 16);
			if (tmpobj.idx > 0xFF) continue;
			is_object = FALSE;
		}
		else continue;
		
		tmpobj.kind = epl_g_key_file_get_uint16(gkf, *group, "ObjectType", NULL);
		if (!tmpobj.kind) continue; 

		DataType = epl_g_key_file_get_uint16(gkf, *group, "DataType", NULL);
		if (DataType)
			tmpobj.type = wmem_map_lookup(dataTypeMap, &DataType);

		if ((name = g_key_file_get_string(gkf, *group, "ParameterName", NULL)))
		{
			gsize count = epl_strchrnul(name, '#') - name + 1;
			g_strlcpy(
					tmpobj.name,
					name,
					count > sizeof tmpobj.name ? sizeof tmpobj.name : count
			);
			g_free(name);
		}

		obj = profile_object_lookup_or_add(profile, idx);

		if (is_object)
		{ /* Let's add a new object! Exciting! */
			obj->info = tmpobj;
		}
		else
		{ /* Object already there, let's add subindices */
			struct subobject subobj = {0};
			if (!obj->subindices)
			{
				obj->subindices = epl_wmem_iarray_new(
						profile->scope,
						sizeof (struct subobject),
						subobject_equal
				);
			}

			subobj.info = tmpobj;
			epl_wmem_iarray_insert(obj->subindices, subobj.info.idx, &subobj.range);
		}
	}

	/* Unlike with XDDs, subindices might interleave with others, so let's sort them now */
	wmem_map_foreach(profile->objects, lock_subindices, NULL);

	/* We don't read object mappings from EDS files */
	/*   profile_object_mappings_update(profile);   */

cleanup:
	g_key_file_free(gkf);
	return profile;
}

void
eds_unload()
{
}

/*
 * Editor modelines  -	http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
