# - Try to find libelf library.
# Once done this will define
#
#  LIBELF_FOUND - system has libelf
#  LIBELF_INCLUDE_DIR - the libelf include directory
#  LIBELF_LIBRARIES - Link these to use libelf
#  LIBELF_DEFINITIONS - Compiler switches required for using libelf

find_package(PkgConfig)
pkg_check_modules(PC_LIBELF QUIET libelf)

set(LIBELF_FOUND ${PC_LIBELF_FOUND})
set(LIBELF_DEFINITIONS ${PC_LIBELF_CFLAGS_OTHER})

find_path(LIBELF_INCLUDE_DIR NAMES libelf.h
  PATHS
  ${PC_LIBELF_INCLUDEDIR}
  ${PC_LIBELF_INCLUDE_DIRS}
)

find_library(LIBELF_LIBRARY
  NAMES
    libelf.a
  PATHS
    ${PC_LIBELF_LIBDIR}
    ${PC_LIBELF_LIBRARY_DIRS}
)

set(LIBELF_LIBRARIES ${LIBELF_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibELF DEFAULT_MSG
  LIBELF_LIBRARIES
  LIBELF_INCLUDE_DIR)

mark_as_advanced(LIBELF_INCLUDE_DIR LIBELF_LIBRARIES)