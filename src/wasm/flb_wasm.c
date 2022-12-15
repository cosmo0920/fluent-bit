/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* Don't use and expose bh_ prefixed headers in flb_wasm.h.
   Their definitions are tightly coupled in wasm-micro-runtime library. */
#include "bh_read_file.h"
#include "bh_getopt.h"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/wasm/flb_wasm.h>

#ifdef FLB_SYSTEM_WINDOWS
#define STDIN_FILENO (_fileno( stdin ))
#define STDOUT_FILENO (_fileno( stdout ))
#define STDERR_FILENO (_fileno( stderr ))
#else
#include <unistd.h>
#endif

void flb_wasm_init(struct flb_config *config)
{
    mk_list_init(&config->wasm_list);
}

static int flb_wasm_load_wasm_binary(const char *wasm_path, int8_t **out_buf, uint32_t *out_size)
{
    char *buffer;
    uint32_t buf_size;
    buffer = bh_read_file_to_buffer(wasm_path, &buf_size);
    if (!buffer) {
        flb_error("Open wasm file [%s] failed.", wasm_path);
        goto error;
    }

#if defined(FLB_WAMR_DISABLE_AOT_LOADING)
    if ((get_package_type((const uint8_t *)buffer, buf_size) != Wasm_Module_Bytecode)) {
        flb_error("WASM bytecode is expected but other file format");
        goto error;
    }
#else
    if ((get_package_type((const uint8_t *)buffer, buf_size) != Wasm_Module_Bytecode) &&
        (get_package_type((const uint8_t *)buffer, buf_size) != Wasm_Module_AoT)) {
        flb_error("WASM bytecode or AOT object is expected but other file format");
        goto error;
    }
#endif

    *out_buf = buffer;
    *out_size = buf_size;

    return buffer != NULL;

error:

    return -1;
}

#ifdef FLB_WASI_SOCKETS
static int set_address_pool(struct flb_wasm *wasm, wasm_module_t module, struct mk_list *address_pool)
{
    char **addr_pool;
    int i = 0;
    struct mk_list *head;
    struct flb_slist_entry *entry;


    addr_pool = flb_calloc(mk_list_size(address_pool), sizeof(char *));
    if (addr_pool == NULL) {
        return 1;
    }

    wasm->addr_pool = addr_pool;

    mk_list_foreach(head, address_pool) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        addr_pool[i] = entry->str;
        flb_debug("add %s to the address pool", entry->str);
        i++;
    }

    wasm_runtime_set_wasi_addr_pool(module, (const char **)addr_pool, 1);

    flb_debug("succesfully set the address pool");
    return 0;
}
#endif // FLB_WASI_SOCKETS

struct flb_wasm *flb_wasm_instantiate(struct flb_config *config, const char *wasm_path,
                                      struct mk_list *accessible_dir_list,
                                      struct mk_list *address_pool,
                                      int stdinfd, int stdoutfd, int stderrfd)
{
    struct flb_wasm *fw;
    uint32_t buf_size, stack_size = 8 * 1024, heap_size = 8 * 1024;
    int8_t *buffer = NULL;
    char error_buf[128];
#if WASM_ENABLE_LIBC_WASI != 0
    struct mk_list *head;
    struct flb_slist_entry *wasi_dir;
    const size_t accessible_dir_list_size = mk_list_size(accessible_dir_list);
    const char **wasi_dir_list = NULL;
    size_t dir_index = 0;
#endif

#ifdef FLB_WASI_SOCKETS
    const char **default_address_pool = {"127.0.0.1"};
#endif

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;

    RuntimeInitArgs wasm_args;

    fw = flb_calloc(1, sizeof(struct flb_wasm));
    if (!fw) {
        flb_errno();
        return NULL;
    }

#if WASM_ENABLE_LIBC_WASI != 0
    wasi_dir_list = flb_malloc(sizeof(char *) * accessible_dir_list_size);
    if (!wasi_dir_list) {
        flb_errno();
        return NULL;
    }
    mk_list_foreach(head, accessible_dir_list) {
        wasi_dir = mk_list_entry(head, struct flb_slist_entry, _head);
        wasi_dir_list[dir_index] = wasi_dir->str;
        dir_index++;
    }
#endif

    fw->config = config;

    memset(&wasm_args, 0, sizeof(RuntimeInitArgs));

    wasm_args.mem_alloc_type = Alloc_With_Allocator;
    wasm_args.mem_alloc_option.allocator.malloc_func = flb_malloc;
    wasm_args.mem_alloc_option.allocator.realloc_func = flb_realloc;
    wasm_args.mem_alloc_option.allocator.free_func = flb_free;

    if (!wasm_runtime_full_init(&wasm_args)) {
        flb_error("Init runtime environment failed.");
        return NULL;
    }

    if(!flb_wasm_load_wasm_binary(wasm_path, &buffer, &buf_size)) {
        goto error;
    }

    module = wasm_runtime_load((uint8_t *)buffer, buf_size, error_buf, sizeof(error_buf));
    if (!module) {
        flb_error("Load wasm module failed. error: %s", error_buf);
        goto error;
    }

#ifdef FLB_WASI_SOCKETS
    // the address pool must be set before running wasm_runtime_set_wasi_args_ex
    // otherwise it will be ignored.
    if (address_pool) {
        set_address_pool(fw, module, address_pool);
    } else {
        flb_warn("setting address pool to default with 127.0.0.1.");
        wasm_runtime_set_wasi_addr_pool(module, default_address_pool, 1);
    }
#endif

#if WASM_ENABLE_LIBC_WASI != 0
    wasm_runtime_set_wasi_args_ex(module, wasi_dir_list, accessible_dir_list_size, NULL, 0,
                                  NULL, 0, NULL, 0,
                                  (stdinfd != -1) ? stdinfd : STDIN_FILENO,
                                  (stdoutfd != -1) ? stdoutfd : STDOUT_FILENO,
                                  (stderrfd != -1) ? stderrfd : STDERR_FILENO);
#endif

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));
    if (!module_inst) {
        flb_error("Instantiate wasm module failed. error: %s", error_buf);
        goto error;
    }

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        flb_error("Create wasm execution environment failed.");
        goto error;
    }

    fw->buffer = buffer;
    fw->module = module;
    fw->module_inst = module_inst;
    fw->exec_env = exec_env;

    mk_list_add(&fw->_head, &config->wasm_list);

#if WASM_ENABLE_LIBC_WASI != 0
    flb_free(wasi_dir_list);
#endif

    return fw;

error:
#if WASM_ENABLE_LIBC_WASI != 0
    if (wasi_dir_list != NULL) {
        flb_free(wasi_dir_list);
    }
#endif
    if (exec_env) {
        wasm_runtime_destroy_exec_env(exec_env);
    }
    if (module_inst) {
        wasm_runtime_deinstantiate(module_inst);
    }
    if (module) {
        wasm_runtime_unload(module);
    }
    if (buffer != NULL) {
        BH_FREE(buffer);
    }

    wasm_runtime_destroy();

    return NULL;
}

char *flb_wasm_call_function_format_json(struct flb_wasm *fw, const char *function_name,
                                         const char* tag_data, size_t tag_len,
                                         struct flb_time t,
                                         const char* record_data, size_t record_len)
{
    const char *exception;
    uint8_t *func_result;
    wasm_function_inst_t func = NULL;
    /* We should pass the length that is null terminator included into
     * WASM runtime. This is why we add +1 for tag_len and record_len.
     */
    fw->tag_buffer = wasm_runtime_module_dup_data(fw->module_inst, tag_data, tag_len+1);
    fw->record_buffer = wasm_runtime_module_dup_data(fw->module_inst, record_data, record_len+1);
    uint32_t func_args[6] = {fw->tag_buffer, tag_len,
                             t.tm.tv_sec, t.tm.tv_nsec,
                             fw->record_buffer, record_len};
    size_t args_size = sizeof(func_args) / sizeof(uint32_t);

    if (!(func = wasm_runtime_lookup_function(fw->module_inst, function_name, NULL))) {
        flb_error("The %s wasm function is not found.", function_name);
        return NULL;
    }

    if (!wasm_runtime_call_wasm(fw->exec_env, func, args_size, func_args)) {
        exception = wasm_runtime_get_exception(fw->module_inst);
        flb_error("Got exception running wasm code: %s", exception);
        wasm_runtime_clear_exception(fw->module_inst);
        return NULL;
    }

    // The return value is stored in the first element of the function argument array.
    // It's a WASM pointer to null-terminated c char string.
    // WAMR allows us to map WASM pointers to native pointers.
    if (!wasm_runtime_validate_app_str_addr(fw->module_inst, func_args[0])) {
        flb_warn("[wasm] returned value is invalid");
        return NULL;
    }
    func_result = wasm_runtime_addr_app_to_native(fw->module_inst, func_args[0]);

    return (char *)flb_strdup(func_result);
}

int flb_wasm_call_wasi_main(struct flb_wasm *fw, struct mk_list *wasi_args)
{
#if WASM_ENABLE_LIBC_WASI != 0
    wasm_function_inst_t func = NULL;
    int i = 0, len = 0;
    int arg_num = 0;
    uint32_t *args = {0};
    struct mk_list *head;
    struct flb_slist_entry *entry;
    char *buffer = NULL;

    if (wasi_args != NULL && mk_list_size(wasi_args) > 0) {
        args = (uint32_t *)flb_calloc(mk_list_size(wasi_args), sizeof(uint32_t *));
        if (!args) {
            flb_warn("[wasm] could not allocate memory");
            return -1;
        }

        mk_list_foreach(head, wasi_args) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            len = strlen(entry->str)+1;
            args[arg_num] = wasm_runtime_module_dup_data(fw->module_inst, entry->str, len);
            flb_debug("add %s to WASI program's commandline argument(s)", entry->str);
            arg_num++;
        }
    }

    if (!(func = wasm_runtime_lookup_wasi_start_function(fw->module_inst))) {
        const char *exception = wasm_runtime_get_exception(fw->module_inst);
        flb_error("The wasi mode main function is not found with error: %s", exception);
        wasm_runtime_clear_exception(fw->module_inst);

        goto error;
    }

    if (!wasm_runtime_call_wasm(fw->exec_env, func, arg_num, args)) {
        const char *exception = wasm_runtime_get_exception(fw->module_inst);
        flb_error("The wasi mode main function is not called properly with error: %s", exception);
        wasm_runtime_clear_exception(fw->module_inst);

        goto error;
    }

    for (i = 0; i < arg_num; i++) {
        wasm_runtime_module_free(fw->module_inst, args[i]);
    }
    if (args != NULL) {
        flb_free(args);
    }

    return 0;
error:
    for (i = 0; i < arg_num; i++) {
        wasm_runtime_module_free(fw->module_inst, args[i]);
    }
    if (args != NULL) {
        flb_free(args);
    }

    return -2;
#else
    return -1;
#endif
}

void flb_wasm_buffer_free(struct flb_wasm *fw)
{
    if (fw->tag_buffer) {
        wasm_runtime_module_free(fw->module_inst, fw->tag_buffer);
    }
    if (fw->record_buffer) {
        wasm_runtime_module_free(fw->module_inst, fw->record_buffer);
    }
}

void flb_wasm_destroy(struct flb_wasm *fw)
{
    if (fw->exec_env) {
        wasm_runtime_destroy_exec_env(fw->exec_env);
    }
    if (fw->module_inst) {
        flb_wasm_buffer_free(fw);
        wasm_runtime_deinstantiate(fw->module_inst);
    }
    if (fw->module) {
        wasm_runtime_unload(fw->module);
    }
    if (fw->buffer) {
        BH_FREE(fw->buffer);
    }
#ifdef FLB_WASI_SOCKETS
    if (fw->addr_pool) {
        flb_free(fw->addr_pool);
    }
#endif
    wasm_runtime_destroy();

    mk_list_del(&fw->_head);
    flb_free(fw);
}

int flb_wasm_destroy_all(struct flb_config *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_wasm *fw;

    mk_list_foreach_safe(head, tmp, &ctx->wasm_list) {
        fw = mk_list_entry(head, struct flb_wasm, _head);
        flb_wasm_destroy(fw);
        c++;
    }

    return c;
}
