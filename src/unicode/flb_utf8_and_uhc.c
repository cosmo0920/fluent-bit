/*-------------------------------------------------------------------------
 *
 *	  UHC <--> UTF8
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/mb/conversion_procs/utf8_and_uhc/utf8_and_uhc.c
 *
 *-------------------------------------------------------------------------
 */

#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>
#include "maps/uhc_to_utf8.map"
#include "maps/utf8_to_uhc.map"

/* ----------
 * Returns the number of bytes successfully converted.
 * ----------
 */
int
flb_uhc_to_utf8(const unsigned char *src, unsigned char **dest,
                size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = LocalToUtf(src, len, *dest,
                           &uhc_to_unicode_tree,
                           NULL, 0,
                           NULL,
                           FLB_UHC,
                           no_error);

    return converted;
}

int
flb_utf8_to_uhc(const unsigned char *src, unsigned char **dest,
                size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = UtfToLocal(src, len, *dest,
                           &uhc_from_unicode_tree,
                           NULL, 0,
                           NULL,
                           FLB_UHC,
                           no_error);

    return converted;
}

struct flb_unicode_converter uhc_converter = {
    .name = "UHC",
    .aliases = {"CP949", "Windows-949", NULL},
    .desc = "UHC encoding converter",
    .encoding = FLB_UHC,
    .max_width = 3,
    .cb_to_utf8 = flb_uhc_to_utf8,
    .cb_from_utf8 = flb_utf8_to_uhc,
};
