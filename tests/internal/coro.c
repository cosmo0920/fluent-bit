/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_input.h>

#include "flb_tests_internal.h"

static void nop_cb(void) {};

static void basic_coro()
{
    size_t stack_size;
    struct flb_coro *coro;
    struct flb_input_coro *input_coro;

    flb_coro_init();
    flb_coro_thread_init();

    /* input_coro context */
    input_coro = (struct flb_input_coro *) flb_calloc(1,
                                                      sizeof(struct flb_input_coro));
    if (!input_coro) {
        flb_errno();
        return;
    }

    /* coroutine context */
    coro = flb_coro_create(input_coro);
    if (!coro) {
        flb_free(input_coro);
        return;
    }

    input_coro->id         = 1;
    input_coro->ins        = NULL;
    input_coro->coro       = coro;
    input_coro->start_time = time(NULL);
    input_coro->config     = NULL;

    coro->caller = co_active();
    coro->callee = co_create(FLB_CORO_STACK_SIZE_BYTE,
                             nop_cb, &stack_size);

    flb_coro_destroy(input_coro->coro);
    flb_free(input_coro);
}

TEST_LIST = {
    { "basic_coro" , basic_coro },
    { 0 }
};
