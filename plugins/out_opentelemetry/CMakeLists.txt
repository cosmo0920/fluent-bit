add_subdirectory(libopentelemetry_proto EXCLUDE_FROM_ALL)
include_directories(libopentelemetry_proto)

set(src
  opentelemetry.c
  opentelemetry_conf.c
  )

FLB_PLUGIN(out_opentelemetry "${src}" "opentelemetry_proto")
