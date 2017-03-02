#include "xdd.h"

#include "packet-epl.h"

#include <glib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <errno.h>

static guint16
strtou16(const char * str, char ** endptr, int base)
{
	unsigned long val = strtoul(str, endptr, base);
	if (val >= G_MAXUINT16 && errno == ERANGE)
		val = G_MAXUINT16;
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
#if !defined(LIBXML_XPATH_ENABLED) || !defined(LIBXML_SAX1_ENABLED)
#error "No XPATH support"
#endif

typedef int xpath_handler(xmlNodeSetPtr, void*);
static xpath_handler populate_objectList, populate_dataTypeList;

struct namespace {
	const xmlChar *prefix, *href;
} namespaces[] = {
	{ BAD_CAST "x",   BAD_CAST "http://www.ethernet-powerlink.org" },
	{ BAD_CAST "xsi", BAD_CAST "http://www.w3.org/2001/XMLSchema-instance" },
	{ NULL, NULL }
};

struct xpath {
	const xmlChar *expr;
	int (*handler)(xmlNodeSet *node_set, void *data);
} xpaths[] = {
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
xdd_load(wmem_allocator_t *scope, guint16 id, const char *xml_file)
{
	/*int ret;*/
	struct profile *profile = NULL;
	xmlXPathContextPtr xpathCtx = NULL;
	xmlDoc *doc = NULL;
	struct namespace *ns = NULL;
	struct xpath *xpath = NULL;

	/* Load XML document */
	doc = xmlParseFile(xml_file);
	if (!doc) {
		fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
		goto fail;
	}


	/* Create xpath evaluation context */
	xpathCtx = xmlXPathNewContext(doc);
	if(!xpathCtx) {
		fprintf(stderr, "Error: unable to create new XPath context\n");
		goto fail;
	}

	/* Register namespaces from list */
	for (ns = namespaces; ns->href; ns++) {
		if(xmlXPathRegisterNs(xpathCtx, ns->prefix, ns->href) != 0) {
			fprintf(stderr, "Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", ns->prefix, ns->href);
			goto fail;
		}
	}

	/* Allocate profile */
	profile = profile_new(scope, id);

	/* mapping type ids to &hf_s */
	profile->data = g_hash_table_new_full(epl_g_int16_hash, epl_g_int16_equal, NULL, g_free);

	/* Evaluate xpath expressions */
	for (xpath = xpaths; xpath->expr; xpath++) {
		xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(xpath->expr, xpathCtx);
		if (!xpathObj) {
			fprintf(stderr,"Error: unable to evaluate xpath expression \"%s\"\n", xpath->expr);
			xmlXPathFreeObject(xpathObj);
			goto fail;
		}

		/* run handler */
		if (xpath->handler && xpathObj->nodesetval->nodeNr)
			xpath->handler(xpathObj->nodesetval, profile);
		xmlXPathFreeObject(xpathObj);
	}

	return profile;
fail:
	if (profile->data) {
		g_hash_table_destroy(profile->data);
		profile->data = NULL;
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

	for(i = 0; i < nodes->nodeNr; ++i) {
		xmlAttrPtr attr;

		if(!nodes->nodeTab[i] || nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
			return -1;

		cur = nodes->nodeTab[i];


		for(attr = cur->properties; attr; attr = attr->next) {
			char *endptr;
			const char *key = (char*)attr->name, *val = (char*)attr->children->content;

			if (strcmp("dataType", key) == 0) {
				xmlNode *subnode;
				guint16 index = strtou16(val, &endptr, 16);
				if (endptr == val) continue;

				for (subnode = cur->children; subnode; subnode = subnode->next) {
					if (subnode->type == XML_ELEMENT_NODE) {
						/* FIXME cast */
						struct dataType *type;
						const struct dataTypeMap_in *ptr = epl_type_to_hf((char*)subnode->name);
						if (!ptr) {
							fprintf(stderr, "Skipping unknown type '%s'\n", subnode->name);
							continue;
						}
						type = g_new(struct dataType, 1);
						type->id = index;
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

static int
populate_objectList(xmlNodeSetPtr nodes, void *data)
{
	xmlNodePtr cur;
	int i;
	struct profile *profile = data;

	for(i = 0; i < nodes->nodeNr; ++i) {
		xmlAttrPtr attr;
		struct object obj = {0};

		if(!nodes->nodeTab[i] || nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
			return -1;

		cur = nodes->nodeTab[i];

		for(attr = cur->properties; attr; attr = attr->next) {
			char *endptr;
			const char *key = (char*)attr->name,
				  *val = (char*)attr->children->content;

			if (strcmp("index", key) == 0) {
				obj.index = strtou16(val, &endptr, 16);
				if (val == endptr) break;

			} else if (strcmp("name", key) == 0) {
				g_strlcpy(obj.name, val, sizeof obj.name);

			} else if (strcmp("objectType", key) == 0) {
				obj.kind = strtou16(val, &endptr, 16);
				/*assert((7 <= obj.kind && obj.kind <= 9) && endptr != val);*/

			} else if (strcmp("dataType", key) == 0) {
				guint16 id = strtou16(val, &endptr, 16);
				if (endptr != val) {
					struct dataType *type = g_hash_table_lookup(profile->data, &id);
					if (type)
						obj.type = type->ptr;
				}
			}
			/*else if (strcmp("PDOmapping", key) == 0) {
			  obj.PDOmapping = get_index(ObjectPDOmapping_tostr, val);
			  assert(obj.PDOmapping >= 0);
			  }*/
		}

		if (obj.index)
			*profile_object_add(profile, obj.index) = obj;

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
