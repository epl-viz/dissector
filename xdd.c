/* xdd.c
 * Routines for reading in Ethernet POWERLINK XDD profiles
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

#include <glib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <errno.h>

#include "wmem_iarray.h"

static guint16
epl_strtou16(const char * str, char ** endptr, int base)
{
	unsigned long val = strtoul(str, endptr, base);
	if (val > G_MAXUINT16)
	{
		val = G_MAXUINT16;
		errno = ERANGE;
	}
	return val;
}


void
xdd_init(void)
{
	xmlInitParser();
	LIBXML_TEST_VERSION;
}

void
xdd_free(void)
{
	xmlCleanupParser();
}

/* XXX: do this in build system instead? */
#if !defined(LIBXML_XPATH_ENABLED) \
||  !defined(LIBXML_SAX1_ENABLED)  \
||  !defined(LIBXML_TREE_ENABLED)
#error "libxml needs XPATH, SAX1 and TREE support compiled in!"
#endif

typedef int xpath_handler(xmlNodeSetPtr, void*);
static xpath_handler populate_objectList, populate_dataTypeList, populate_profileName;

struct namespace {
	const xmlChar *prefix, *href;
} namespaces[] = {
	{ BAD_CAST "x",   BAD_CAST "http://www.ethernet-powerlink.org" },
	{ BAD_CAST "xsi", BAD_CAST "http://www.w3.org/2001/XMLSchema-instance" },
	{ NULL, NULL }
};

struct xpath {
	const xmlChar *expr;
	xpath_handler *handler;
} xpaths[] = {
	{
		BAD_CAST "//x:ISO15745Profile[x:ProfileHeader/x:ProfileIdentification='Powerlink_Communication_Profile']/x:ProfileHeader/x:ProfileName",
		populate_profileName
	},
	{
		BAD_CAST "//x:ProfileBody[@xsi:type='ProfileBody_CommunicationNetwork_Powerlink']/x:ApplicationLayers/x:DataTypeList/x:defType",
		populate_dataTypeList
	},
	{
		BAD_CAST "//x:ProfileBody[@xsi:type='ProfileBody_CommunicationNetwork_Powerlink']/x:ApplicationLayers/x:ObjectList/x:Object",
		populate_objectList
	},
	{ NULL, NULL }
};

struct profile *
xdd_load(wmem_allocator_t *parent_pool, guint16 id, const char *xml_file)
{
	struct profile *profile = NULL;
	xmlXPathContextPtr xpathCtx = NULL;
	xmlDoc *doc = NULL;
	struct namespace *ns = NULL;
	struct xpath *xpath = NULL;

	/* Load XML document */
	doc = xmlParseFile(xml_file);
	if (!doc)
	{
		g_warning("Error: unable to parse file \"%s\"\n", xml_file);
		goto fail;
	}


	/* Create xpath evaluation context */
	xpathCtx = xmlXPathNewContext(doc);
	if(!xpathCtx)
	{
		g_warning("Error: unable to create new XPath context\n");
		goto fail;
	}

	/* Register namespaces from list */
	for (ns = namespaces; ns->href; ns++)
	{
		if(xmlXPathRegisterNs(xpathCtx, ns->prefix, ns->href) != 0)
		{
			g_warning("Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", ns->prefix, ns->href);
			goto fail;
		}
	}

	/* Allocate profile */
	profile = profile_new(parent_pool, id);
	profile->path = wmem_strdup(profile->scope, xml_file);

	/* mapping type ids to &hf_s */
	profile->data = g_hash_table_new_full(epl_g_int16_hash, epl_g_int16_equal, NULL, g_free);

	/* Evaluate xpath expressions */
	for (xpath = xpaths; xpath->expr; xpath++)
	{
		xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(xpath->expr, xpathCtx);
		if (!xpathObj || !xpathObj->nodesetval)
		{
			g_warning("Error: unable to evaluate xpath expression \"%s\"\n", xpath->expr);
			xmlXPathFreeObject(xpathObj);
			goto fail;
		}

		/* run handler */
		if (xpath->handler && xpathObj->nodesetval->nodeNr)
			xpath->handler(xpathObj->nodesetval, profile);
		xmlXPathFreeObject(xpathObj);
	}

	/* We create ObjectMappings while reading the XML, this is makes it likely,
	 * that we won't be able to reference a mapped object in the ObjectMapping
	 * as we didn't reach its XML tag yet. Therefore, after reading the XDD
	 * completely, we update mappings in the profile
	 */
	profile_object_mappings_update(profile);

	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);
	return profile;

fail:
	if (profile && profile->data)
	{
		g_hash_table_destroy(profile->data);
		profile_del(profile);
	}

	if (xpathCtx)
		xmlXPathFreeContext(xpathCtx);
	if (doc)
		xmlFreeDoc(doc);

	return NULL;
}

void
xdd_unload()
{
}

static int
populate_profileName(xmlNodeSetPtr nodes, void *_profile)
{
	struct profile *profile = _profile;
	if (nodes->nodeNr == 1
	&&  nodes->nodeTab[0]->type == XML_ELEMENT_NODE
	&&  nodes->nodeTab[0]->children)
	{
		profile->name = wmem_strdup(profile->scope, (char*)nodes->nodeTab[0]->children->content);
		return 0;
	}

	return -1;
}

struct dataType {
	guint16 id;
	const struct dataTypeMap_in *ptr;
};

static int
populate_dataTypeList(xmlNodeSetPtr nodes, void *_profile)
{
	xmlNodePtr cur;
	int i;
	struct profile *profile = _profile;

	for(i = 0; i < nodes->nodeNr; ++i)
	{
		xmlAttrPtr attr;

		if(!nodes->nodeTab[i] || nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
			return -1;

		cur = nodes->nodeTab[i];


		for(attr = cur->properties; attr; attr = attr->next)
		{
			char *endptr;
			const char *key = (char*)attr->name, *val = (char*)attr->children->content;

			if (g_str_equal("dataType", key))
			{
				xmlNode *subnode;
				guint16 idx = epl_strtou16(val, &endptr, 16);
				if (endptr == val) continue;

				for (subnode = cur->children; subnode; subnode = subnode->next)
				{
					if (subnode->type == XML_ELEMENT_NODE)
					{
						/* FIXME cast */
						struct dataType *type;
						const struct dataTypeMap_in *ptr = epl_type_to_hf((char*)subnode->name);
						if (!ptr)
						{
							g_info("Skipping unknown type '%s'\n", subnode->name);
							continue;
						}
						type = g_new(struct dataType, 1);
						type->id = idx;
						type->ptr = ptr;
						g_hash_table_insert(profile->data, &type->id, type);
						continue;
					}
				}

			}
		}
	}

	return 0;
}

static gboolean
parse_obj_tag(xmlNode *cur, struct od_entry *out, struct profile *profile) {
		xmlAttrPtr attr;
		const char *defaultValue = NULL, *actualValue = NULL, *value;
		char *endptr;

		for(attr = cur->properties; attr; attr = attr->next)
		{
			const char *key = (char*)attr->name,
				  *val = (char*)attr->children->content;

			if (g_str_equal("index", key))
			{
				out->idx = epl_strtou16(val, &endptr, 16);
				if (val == endptr) return FALSE;

			} else if (g_str_equal("subIndex", key)) {
				out->idx = epl_strtou16(val, &endptr, 16);
				if (val == endptr) return FALSE;

			} else if (g_str_equal("name", key)) {
				g_strlcpy(out->name, val, sizeof out->name);

			} else if (g_str_equal("objectType", key)) {
				out->kind = epl_strtou16(val, &endptr, 16);

			} else if (g_str_equal("dataType", key)) {
				guint16 id = epl_strtou16(val, &endptr, 16);
				if (endptr != val)
				{
					struct dataType *type = g_hash_table_lookup(profile->data, &id);
					if (type) out->type = type->ptr;
				}

			} else if (g_str_equal("defaultValue", key)) {
				defaultValue = val;

			} else if (g_str_equal("actualValue", key)) {
				actualValue = val;
			}
			/*else if (g_str_equal("PDOmapping", key)) {
			  obj.PDOmapping = get_index(ObjectPDOmapping_tostr, val);
			  assert(obj.PDOmapping >= 0);
			  }*/
		}

		value = actualValue ? actualValue
		      : defaultValue ? defaultValue
		      : NULL;

		out->value = value ? g_ascii_strtoull(value, &endptr, 0) : 0;

		return TRUE;
}

static int
populate_objectList(xmlNodeSetPtr nodes, void *data)
{
	int i;
	struct profile *profile = data;

	for(i = 0; i < nodes->nodeNr; ++i)
	{
		xmlNodePtr cur = nodes->nodeTab[i];
		struct od_entry tmpobj = {0};

		if (!nodes->nodeTab[i] || nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
			continue;

		parse_obj_tag(cur, &tmpobj, data);

		if (tmpobj.idx)
		{
			struct object *obj = profile_object_add(profile, tmpobj.idx);
			obj->info = tmpobj;

			if (tmpobj.kind == 8 || tmpobj.kind == 9)
			{
				xmlNode *subcur;
				struct subobject subobj = {0};

				obj->subindices = epl_wmem_iarray_new(profile->scope, sizeof (struct subobject), subobject_equal);

				for (subcur = cur->children; subcur; subcur = subcur->next)
				{
					if (subcur->type != XML_ELEMENT_NODE)
						continue;

					if (parse_obj_tag(subcur, &subobj.info, profile))
					{
						epl_wmem_iarray_insert(obj->subindices,
								subobj.info.idx, &subobj.range);
					}
					if (subobj.info.value && profile_object_mapping_add(profile, obj->info.idx, subobj.info.idx, subobj.info.value))
					{
						g_info("Loaded mapping from XDC %s:%s", obj->info.name, subobj.info.name);
					}
				}
				epl_wmem_iarray_lock(obj->subindices);
			}
		}
	}

	return 0;
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
