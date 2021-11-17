set(src
  ebpf.c)
# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)

find_package(BpfObject REQUIRED)

bpf_object(vfsstat vfsstat.bpf.c)
FLB_PLUGIN(in_ebpf "${src}" "libbpf")
target_link_libraries(flb-plugin-in_ebpf ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES} vfsstat_skel)
