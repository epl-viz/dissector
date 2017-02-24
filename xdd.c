#include "xdd.h"

#include "packet-epl.h"

#include <glib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <assert.h>

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

void xdd_init(void) {
    xmlInitParser();
    LIBXML_TEST_VERSION;
}
void xdd_free(void) {
    xmlCleanupParser();
}

/* XXX: do this in build system instead? */
#if !defined(LIBXML_XPATH_ENABLED) || !defined(LIBXML_SAX1_ENABLED)
#error "No XPATH support"
#endif

typedef int xpath_handler(xmlNodeSetPtr, void*);
xpath_handler print_xpath_nodes, populate_objectList, populate_dataTypeList;

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

struct profile *xdd_load(guint16 id, const char *xml_file) {
    /*int ret;*/
    struct profile *profile;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlDoc *doc = NULL;
    struct namespace *ns;
    struct xpath *xpath;

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
    profile = profile_new(id);

    /* mapping type ids to &hf_s */
    profile->data = g_hash_table_new(epl_g_int16_hash, epl_g_int16_equal);

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
    if (xpathCtx)
        xmlXPathFreeContext(xpathCtx);
    if (doc)
        xmlFreeDoc(doc);

    return NULL;
}

struct dataType {
    guint16 index;
    gint *hf;
};

int populate_dataTypeList(xmlNodeSetPtr nodes, void *_profile) {
    xmlNodePtr cur;
    int i;
    struct profile *profile = _profile;

    for(i = 0; i < nodes->nodeNr; ++i) {
        xmlAttrPtr attr;
        assert(nodes->nodeTab[i]);

        if(nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
            return -1;

        cur = nodes->nodeTab[i];


        for(attr = cur->properties; attr; attr = attr->next) {
            char *endptr;
            const char *key = (char*)attr->name, *val = (char*)attr->children->content;

            if (strcmp("dataType", key) == 0) {
                xmlNode *subnode;
                guint16 index = strtol(val, &endptr, 16);
                assert((index & ~0xffff) == 0 && endptr != val);
                
                for (subnode = cur->children; subnode; subnode = subnode->next) {
                    if (subnode->type == XML_ELEMENT_NODE) {
                        /* FIXME cast */
                        struct dataType *type;
                        gint *hf = epl_type_to_hf((char*)subnode->name);
                        if (!hf) {
                            fprintf(stderr, "Skipping unknown type '%s'\n", subnode->name);
                            continue;
                        }
                        type = g_new0(struct dataType, 1);
                        type->index = index;
                        type->hf = hf;
                        g_hash_table_insert(profile->data, &type->index, type);
                        continue;
                    }
                }

            }
        }
    }

    return 0;
}

int populate_objectList(xmlNodeSetPtr nodes, void *data) {
    xmlNodePtr cur;
    int i;
    struct profile *profile = data;

    for(i = 0; i < nodes->nodeNr; ++i) {
        xmlAttrPtr attr;
        struct object obj = {0};
        assert(nodes->nodeTab[i]);

        if(nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
            return -1;

        cur = nodes->nodeTab[i];

        for(attr = cur->properties; attr; attr = attr->next) {
            char *endptr;
            const char *key = (char*)attr->name,
                        *val = (char*)attr->children->content;

            if (strcmp("index", key) == 0) {
                obj.index = strtol(val, &endptr, 16);
                assert((obj.index & ~0xffff) == 0 && endptr != val);

            } else if (strcmp("name", key) == 0) {
                obj.name = strdup(val);

            } else if (strcmp("objectType", key) == 0) {
                obj.type = strtol(val, &endptr, 16);
                assert((7 <= obj.type && obj.type <= 9) && endptr != val);

            } else if (strcmp("dataType", key) == 0) {
                long index = strtol(val, &endptr, 16);
                assert(endptr != val);
                obj.hf = g_hash_table_lookup(profile->data, &index);
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

