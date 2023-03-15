set(src
  lf_textfile.c
  lf_utils.c
  lf_config.c
  lf.c
  )

FLB_PLUGIN(in_local_file_exporter_metrics "${src}" "")
