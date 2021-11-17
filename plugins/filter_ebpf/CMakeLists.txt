set(src
  ebpf.c)
# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)

find_package(BpfObject REQUIRED)

bpf_object(minimal minimal.bpf.c)
FLB_PLUGIN(filter_ebpf "${src}" "libbpf")
target_link_libraries(flb-plugin-filter_ebpf ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES} minimal_skel)
