# - Try to find zlib library.
# Once done this will define
#
#  ZLIB_FOUND - system has zlib
#  ZLIB_INCLUDE_DIR - the zlib include directory
#  ZLIB_LIBRARIES - Link these to use zlib
#  ZLIB_DEFINITIONS - Compiler switches required for using zlib

find_package(PkgConfig)
pkg_check_modules(PC_ZLIB QUIET zlib)

set(ZLIB_FOUND ${PC_ZLIB_FOUND})
set(ZLIB_DEFINITIONS ${PC_ZLIB_CFLAGS_OTHER})

find_path(ZLIB_INCLUDE_DIR NAMES zlib.h
  PATHS
  ${PC_ZLIB_INCLUDEDIR}
  ${PC_ZLIB_INCLUDE_DIRS}
)

find_library(ZLIB_LIBRARY
  NAMES
    libz.a
  PATHS
    ${PC_ZLIB_LIBDIR}
    ${PC_ZLIB_LIBRARY_DIRS}
)

set(ZLIB_LIBRARIES ${ZLIB_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zlib DEFAULT_MSG
  ZLIB_LIBRARIES
  ZLIB_INCLUDE_DIR)

mark_as_advanced(ZLIB_INCLUDE_DIR ZLIB_LIBRARIES)