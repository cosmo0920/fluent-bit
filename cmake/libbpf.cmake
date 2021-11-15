# This file provides 'libbpf' target for both UNIX and Windows.
#
# To enable libbpf, include this file and link the build target:
#
#    include(cmake/libbpf.cmake)
#    target_link_libraries(fluent-bit libbpf)


add_library(libbpf STATIC IMPORTED GLOBAL)

# Global Settings
set(LIBBPF_SRC "${PROJECT_SOURCE_DIR}/lib/libbpf-0.5.0/src")
set(LIBBPF_DEST "${CMAKE_CURRENT_BINARY_DIR}")
# We are on -fPIC for all libraries.
set(LIBBPF_CFLAGS "-g -O2 -Werror -Wall -fPIC")

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(bpf
  PREFIX libbpf
  SOURCE_DIR ${LIBBPF_SRC}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND $(MAKE)
    BUILD_STATIC_ONLY=1
    OBJDIR=${LIBBPF_DEST}/libbpf
    DESTDIR=${LIBBPF_DEST}/lib
    PREFIX=${LIBBPF_DEST}
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    CFLAGS=${LIBBPF_CFLAGS}
    install
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND $(MAKE) DESTDIR=${LIBBPF_DEST} install
  STEP_TARGETS build
)

add_dependencies(libbpf bpf)
set(LIBBPF_STATIC_LIB "${LIBBPF_DEST}/lib/libbpf.a")
set(LIBBPF_INCLUDE_DIR "${LIBBPF_DEST}/lib/")

set_target_properties(libbpf PROPERTIES IMPORTED_LOCATION ${LIBBPF_STATIC_LIB})
include_directories("${LIBBPF_DEST}/lib/")
