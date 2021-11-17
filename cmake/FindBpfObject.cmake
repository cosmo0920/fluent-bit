# This cmake file is heavily based on
# https://github.com/libbpf/libbpf-bootstrap/blob/master/tools/cmake/FindBpfObject.cmake

if(NOT FLB_EBPF_BPFTOOL_EXE)
  find_program(FLB_EBPF_BPFTOOL_EXE NAMES bpftool DOC "Path to bpftool executable")
endif()

if(FLB_EBPF_BPFTOOL_EXE)
  message(STATUS "BPFTOOL is found in: ${BPFOBJECT_BPFTOOL_EXE}")
endif()

if(NOT FLB_EBPF_CLANG_EXE)
  find_program(FLB_EBPF_CLANG_EXE NAMES clang DOC "Path to clang executable")
endif()

if(FLB_EBPF_CLANG_EXE)
  execute_process(COMMAND ${FLB_EBPF_CLANG_EXE} --version
    OUTPUT_VARIABLE CLANG_version_output
    ERROR_VARIABLE CLANG_version_error
    RESULT_VARIABLE CLANG_version_result
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if(${CLANG_version_result} EQUAL 0)
    if("${CLANG_version_output}" MATCHES "clang version ([^\n]+)\n")
      set(CLANG_VERSION "${CMAKE_MATCH_1}")
      string(REPLACE "." ";" CLANG_VERSION_LIST ${CLANG_VERSION})
      list(GET CLANG_VERSION_LIST 0 CLANG_VERSION_MAJOR)
      list(GET CLANG_VERSION_LIST 1 CLANG_VERSION_MINOR)
      list(GET CLANG_VERSION_LIST 2 CLANG_VERSION_PATCH)

      string(COMPARE LESS ${CLANG_VERSION_MAJOR} 10 CLANG_VERSION_MAJOR_LESS_THAN_10)
      if(${CLANG_VERSION_MAJOR_LESS_THAN_10})
        message(FATAL_ERROR "clang ${CLANG_VERSION} is too old for eBPF on Fluent Bit")
      endif()

      message(STATUS "Found clang version: ${CLANG_VERSION}")
    else()
      message(FATAL_ERROR "Failed to parse clang version string: ${CLANG_version_output}")
    endif()
  else()
    message(FATAL_ERROR "Command \"${FLB_EBPF_CLANG_EXE} --version\" failed with output:\n${CLANG_version_error}")
  endif()
endif()

if(FLB_EBPF_BPFTOOL_EXE)
  set(GENERATED_VMLINUX_DIR ${CMAKE_CURRENT_BINARY_DIR})
  set(FLB_EBPF_VMLINUX_H ${GENERATED_VMLINUX_DIR}/vmlinux.h)
  execute_process(COMMAND ${FLB_EBPF_BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c
    OUTPUT_FILE ${FLB_EBPF_VMLINUX_H}
    ERROR_VARIABLE VMLINUX_error
    RESULT_VARIABLE VMLINUX_result)
  if(${VMLINUX_result} EQUAL 0)
    set(VMLINUX ${FLB_EBPF_VMLINUX_H})
  else()
    message(FATAL_ERROR "Failed to dump vmlinux.h from Kernel BTF: ${VMLINUX_error}")
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BpfObject
  REQUIED_VARS
  FLB_EBPF_BPFTOOL_EXE
  FLB_EBPF_CLANG_EXE
  GENERATED_VMLINUX_DIR)

# Get clang bpf system includes
execute_process(
  COMMAND bash -c "${FLB_EBPF_CLANG_EXE} -v -E - < /dev/null 2>&1 |
          sed -n '/<...> search starts here:/,/End of search list./{ s| \\(/.*\\)|-idirafter \\1|p }'"
  OUTPUT_VARIABLE CLANG_SYSTEM_INCLUDES_output
  ERROR_VARIABLE CLANG_SYSTEM_INCLUDES_error
  RESULT_VARIABLE CLANG_SYSTEM_INCLUDES_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${CLANG_SYSTEM_INCLUDES_result} EQUAL 0)
  string(REPLACE "\n" " " CLANG_SYSTEM_INCLUDES ${CLANG_SYSTEM_INCLUDES_output})
  message(STATUS "BPF system include flags: ${CLANG_SYSTEM_INCLUDES}")
else()
  message(FATAL_ERROR "Failed to determine BPF system includes: ${CLANG_SYSTEM_INCLUDES_error}")
endif()

# Get target arch
execute_process(COMMAND uname -m
  COMMAND sed "s/x86_64/x86/"
  OUTPUT_VARIABLE ARCH_output
  ERROR_VARIABLE ARCH_error
  RESULT_VARIABLE ARCH_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${ARCH_result} EQUAL 0)
  set(ARCH ${ARCH_output})
  message(STATUS "BPF target arch: ${ARCH}")
else()
  message(FATAL_ERROR "Failed to determine target architecture: ${ARCH_error}")
endif()

execute_process(COMMAND uname -m
  OUTPUT_VARIABLE ACTUAL_ARCH_output
  ERROR_VARIABLE ACTUAL_ARCH_error
  RESULT_VARIABLE ACTUAL_ARCH_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${ARCH_result} EQUAL 0)
  set(ACTUAL_ARCH ${ACTUAL_ARCH_output})
  message(STATUS "Actual target arch: ${ACTUAL_ARCH}")
else()
  message(FATAL_ERROR "Failed to obtain actual architecture: ${ACTUAL_ARCH_error}")
endif()

macro(bpf_object name input)
  set(BPF_C_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${input})
  set(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
  set(BPF_SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h)
  set(OUTPUT_TARGET ${name}_skel)

  add_custom_command(OUTPUT ${BPF_O_FILE}
    COMMAND ${FLB_EBPF_CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_${ARCH}
    ${CLANG_SYSTEM_INCLUDES} -I${GENERATED_VMLINUX_DIR} -I/usr/include/${ACTUAL_ARCH}-linux-gnu
    -isystem ${LIBBPF_INCLUDE_DIR} -c ${BPF_C_FILE} -o ${BPF_O_FILE}
    COMMENT "[clang] building bpf object: ${name}"
    )

  add_custom_command(OUTPUT ${BPF_SKEL_FILE}
    COMMAND bash -c "${FLB_EBPF_BPFTOOL_EXE} gen skeleton ${BPF_O_FILE} > ${BPF_SKEL_FILE}"
    VERBATIM
    DEPENDS ${BPF_O_FILE}
    COMMENT "[skel] building bpf skeleton: ${name}"
    )

  add_library(${OUTPUT_TARGET} INTERFACE)
  target_sources(${OUTPUT_TARGET} INTERFACE ${BPF_SKEL_FILE})
  target_include_directories(${OUTPUT_TARGET} INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
  target_include_directories(${OUTPUT_TARGET} SYSTEM INTERFACE ${LIBBPF_INCLUDE_DIR})
endmacro()