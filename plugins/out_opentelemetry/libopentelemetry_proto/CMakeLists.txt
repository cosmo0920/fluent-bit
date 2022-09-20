project(opentelemetry_proto
  LANGUAGES C
)

set(src
  ${src}
  opentelemetry_logs.pb-c.c
  opentelemetry_logs_service.pb-c.c
  )

add_library(opentelemetry_proto
  ${src}
)
target_include_directories(opentelemetry_proto PRIVATE ${FLB_PATH_LIB_CMETRICS}/include)
target_link_libraries(opentelemetry_proto cmetrics-static)

set(CMAKE_SHARED_LIBRARY_PREFIX lib)
set(CMAKE_STATIC_LIBRARY_PREFIX lib)
