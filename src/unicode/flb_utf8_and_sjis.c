/*-------------------------------------------------------------------------
 *
 *	  SJIS <--> UTF8
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/mb/conversion_procs/utf8_and_sjis/utf8_and_sjis.c
 *
 *-------------------------------------------------------------------------
 */

#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>
#include "maps/sjis_to_utf8.map"
#include "maps/utf8_to_sjis.map"

/*
 * Returns the number of bytes successfully converted.
 * ----------
 */
int
flb_sjis_to_utf8(const unsigned char *src, unsigned char **dest,
                 size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = LocalToUtf(src, len, *dest,
                           &sjis_to_unicode_tree,
                           NULL, 0,
                           NULL,
                           FLB_SJIS,
                           no_error);

    return converted;
}

int
flb_utf8_to_sjis(const unsigned char *src, unsigned char **dest,
                 size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = UtfToLocal(src, len, *dest,
                           &sjis_from_unicode_tree,
                           NULL, 0,
                           NULL,
                           FLB_SJIS,
                           no_error);

    return converted;
}

struct flb_unicode_converter sjis_converter = {
    .name = "SHIFTJIS",
    .aliases = {"SJIS", "CP932", "Windows-31J", NULL},
    .desc = "SHIFTJIS encoding converter",
    .max_width = 3,
    .encoding = FLB_SJIS,
    .cb_to_utf8 = flb_sjis_to_utf8,
    .cb_from_utf8 = flb_utf8_to_sjis,
};
