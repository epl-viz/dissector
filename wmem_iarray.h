/* wmem_iarray.h
 * Sorted arrays keyed by intervals - Public defines
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

#ifndef EPL_WMEM_INTERVAL_ARRAY_H_
#define EPL_WMEM_INTERVAL_ARRAY_H_

#include <glib.h>
#include <epan/wmem/wmem.h>
#include <epan/range.h>

/**
 * A sorted array keyed by intervals
 * You keep inserting items, then lock the array.
 * Locking the arrays sorts it and combines items that compare equal into one
 * And adjust the interval accordingly. find uses binary search to find the item
 *
 * This is particularly useful, if you got many similar items,
 * e.g. ObjectMapping subindices in the XDD.
 *
 * Intervall Trees didn't work, because they didn't allow expanding
 * existing intervals. Using an array instead of a tree, additionally offers
 * a possible performance advantage, but it's not that critical here,
 * as finding should only happen in the async frames
 *
 * Much room for optimization in the creation process of the array,
 * but it doesn't matter much, as they aren't created frequently.
 * Finding speed is what matters
 *
 */

typedef struct _epl_wmem_iarray epl_wmem_iarray_t;

/** Creates a new interval array where each element is of size elem_size.
 *  Elements must have range_admin_t as their first element
 *  The GEqualFunc is used to establish equality in order to combine elements
 *  at lock-time
 */

epl_wmem_iarray_t *
epl_wmem_iarray_new(wmem_allocator_t *allocator, const guint elem_size, GEqualFunc cmp)
G_GNUC_MALLOC;


/** Returns true if the iarr is empty. */

gboolean
epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr);


/**
 *  Inserts a new element
 */

void
epl_wmem_iarray_insert(epl_wmem_iarray_t *iarr, guint32 where, range_admin_t *data);

/**
 *  Makes array suitable for searching
 */

void
epl_wmem_iarray_lock(epl_wmem_iarray_t *iarr);

/*
 * Finds an element in the interval array. Returns NULL if it doesn't exist
 * Calling this is unspecified if the array wasn't locked before
 */

range_admin_t *
epl_wmem_iarray_find(epl_wmem_iarray_t *arr, guint32 value);


/**
 * Print ranges within the iarr
 */
void
epl_wmem_print_iarr(epl_wmem_iarray_t *iarr);

#endif

