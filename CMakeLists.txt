# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(epl_plus_xdd 0 0 3 0)

## XXX Remove when libxml2 is added as optional dependency to Wireshark ##
set(HAVE_LIBXML 1)
add_definitions(-DHAVE_LIBXML=1)
##########################################################################


set(DISSECTOR_SRC
	packet-epl.c
	eds.c
	wmem_iarray.c
)
if(HAVE_LIBXML)
	set(DISSECTOR_SRC
		xdd.c
		${DISSECTOR_SRC}
	)
endif(HAVE_LIBXML)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if(WERROR_COMMON_FLAGS)
  set_source_files_properties(
  	${CLEAN_FILES}
  	PROPERTIES
  	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
  )
endif(WERROR_COMMON_FLAGS)

if(HAVE_LIBXML)
	set(LibXml2_ROOT ${CMAKE_CURRENT_LIST_DIR})
	find_package(LibXml2 REQUIRED )

	include_directories(${LIBXML2_INCLUDE_DIR})
	set(LIBS ${LIBS} ${LIBXML2_LIBRARIES})
endif(HAVE_LIBXML)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})


register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(epl_plus_xdd)
target_link_libraries(epl_plus_xdd ${LIBS})

install(TARGETS epl_plus_xdd
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  epl_plus_xdd
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
