/* wmem_iarray_uint.h
 * Sorted arrays keyed by intervals - Private defines
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

#ifndef EPL_WMEM_IARRAY_INT
#define EPL_WMEM_IARRAY_INT
#include <glib.h>
#include <epan/wmem/wmem.h>
struct _epl_wmem_iarray {
	GEqualFunc equal;
	wmem_allocator_t *scope;
	GArray *arr;
	guint cb_id;
	struct {
		unsigned dirty:1;
	} flags;
};
#endif
