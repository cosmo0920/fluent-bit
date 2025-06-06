/*-------------------------------------------------------------------------
 *
 *	  BIG5 <--> UTF8
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/mb/conversion_procs/utf8_and_big5/utf8_and_big5.c
 *
 *-------------------------------------------------------------------------
 */

#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>
#include "maps/big5_to_utf8.map"
#include "maps/utf8_to_big5.map"

/* ----------
 * Returns the number of bytes successfully converted.
 * ----------
 */
int
flb_big5_to_utf8(const unsigned char *src, unsigned char **dest,
                 size_t len, bool no_error, int encoding)

{
    int converted = -1;

    converted = LocalToUtf(src, len, *dest,
                           &big5_to_unicode_tree,
                           NULL, 0,
                           NULL,
                           FLB_BIG5,
                           no_error);

    return converted;
}

int
flb_utf8_to_big5(const unsigned char *src, unsigned char **dest,
                 size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = UtfToLocal(src, len, *dest,
                           &big5_from_unicode_tree,
                           NULL, 0,
                           NULL,
                           FLB_BIG5,
                           no_error);

    return converted;
}
struct flb_unicode_converter big5_converter = {
    .name = "BIG5",
    .aliases = {NULL},
    .desc = "BIG5 encoding converter",
    .encoding = FLB_BIG5,
    .max_width = 3,
    .cb_to_utf8 = flb_big5_to_utf8,
    .cb_from_utf8 = flb_utf8_to_big5,
};
