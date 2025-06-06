/*-------------------------------------------------------------------------
 *
 * flb_wchar.h
 *    multibyte-character support for flb_conv converter.
 * Based on pg_wchar.h
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/mb/pg_wchar.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef FLB_WCHAR_H
#define FLB_WCHAR_H

#include <stddef.h>
#include <stdbool.h>

#include <fluent-bit/flb_log.h>

/* msb for char */
#define HIGHBIT                     (0x80)
#define IS_HIGHBIT_SET(ch)      ((unsigned char)(ch) & HIGHBIT)

/*
 * The FLB_wchar type
 */
typedef unsigned int flb_wchar;

/*
 * Maximum byte length of multibyte characters in any backend encoding
 */
#define MAX_MULTIBYTE_CHAR_LEN  4

/*
 * SJIS validation macros
 */
#define ISSJISHEAD(c) (((c) >= 0x81 && (c) <= 0x9f) || ((c) >= 0xe0 && (c) <= 0xfc))
#define ISSJISTAIL(c) (((c) >= 0x40 && (c) <= 0x7e) || ((c) >= 0x80 && (c) <= 0xfc))

#include <fluent-bit/flb_macros.h>

/*
 * Encoding identifiers
 */
typedef enum flb_enc
{
    FLB_STR_ASCII = 0,          /* STR/ASCII */
    FLB_UTF8,                   /* Unicode UTF8 */
    FLB_WIN1256,                    /* windows-1256 */
    FLB_WIN866,                     /* (MS-DOS CP866) */
    FLB_WIN874,                     /* windows-874 */
    FLB_WIN1251,                    /* windows-1251 */
    FLB_WIN1252,                    /* windows-1252 */
    FLB_WIN1250,                    /* windows-1250 */
    FLB_WIN1253,                    /* windows-1253 */
    FLB_WIN1254,                    /* windows-1254 */
    FLB_WIN1255,                    /* windows-1255 */
    /* FLB_ENCODING_BE_LAST points to the above entry */

    /* followings are for client encoding only */
    FLB_SJIS,                   /* Shift JIS (Windows-932) */
    FLB_BIG5,                   /* Big5 (Windows-950) */
    FLB_GBK,                        /* GBK (Windows-936) */
    FLB_UHC,                        /* UHC (Windows-949) */
    FLB_GB18030,                    /* GB18030 */
    _FLB_LAST_ENCODING_             /* mark only */

} flb_enc;

#define FLB_ENCODING_BE_LAST FLB_WIN1255

/*
 * Please use these tests before access to flb_enc2name_tbl[]
 * or to other places...
 */

#define FLB_VALID_ENCODING(_enc) \
        ((_enc) >= 0 && (_enc) < _FLB_LAST_ENCODING_)

/* On FE are possible all encodings */
#define FLB_VALID_FE_ENCODING(_enc)     FLB_VALID_ENCODING(_enc)

/*
 * flb_wchar stuff
 */
typedef int (*mb2wchar_with_len_converter) (const unsigned char *from,
                                            flb_wchar *to,
                                            int len);

typedef int (*wchar2mb_with_len_converter) (const flb_wchar *from,
                                            unsigned char *to,
                                            int len);

typedef int (*mblen_converter) (const unsigned char *mbstr);
typedef int (*mbdisplaylen_converter) (const unsigned char *mbstr);
typedef bool (*mbcharacter_incrementer) (unsigned char *mbstr, int len);
typedef int (*mbchar_verifier) (const unsigned char *mbstr, int len);
typedef int (*mbstr_verifier) (const unsigned char *mbstr, int len);

typedef struct
{
    mb2wchar_with_len_converter mb2wchar_with_len;  /* convert a multibyte
                                                     * string to a wchar */
    wchar2mb_with_len_converter wchar2mb_with_len;  /* convert a wchar string
                                                     * to a multibyte */
    mblen_converter mblen;      /* get byte length of a char */
    mbdisplaylen_converter dsplen;  /* get display width of a char */
    mbchar_verifier mbverifychar;   /* verify multibyte character */
    mbstr_verifier mbverifystr; /* verify multibyte string */
    int             maxmblen;       /* max bytes for a char in this encoding */
} flb_wchar_tbl;

extern const flb_wchar_tbl flb_wchar_table[];

/*
 * Data structures for conversions between UTF-8 and other encodings
 * (UtfToLocal() and LocalToUtf()).  In these data structures, characters of
 * either encoding are represented by uint32_t words; hence we can only support
 * characters up to 4 bytes long.  For example, the byte sequence 0xC2 0x89
 * would be represented by 0x0000C289, and 0xE8 0xA2 0xB4 by 0x00E8A2B4.
 *
 * There are three possible ways a character can be mapped:
 *
 * 1. Using a radix tree, from source to destination code.
 * 2. Using a sorted array of source -> destination code pairs. This
 *    method is used for "combining" characters. There are so few of
 *    them that building a radix tree would be wasteful.
 * 3. Using a conversion function.
 */

/*
 * Radix tree for character conversion.
 *
 * Logically, this is actually four different radix trees, for 1-byte,
 * 2-byte, 3-byte and 4-byte inputs. The 1-byte tree is a simple lookup
 * table from source to target code. The 2-byte tree consists of two levels:
 * one lookup table for the first byte, where the value in the lookup table
 * points to a lookup table for the second byte. And so on.
 *
 * Physically, all the trees are stored in one big array, in 'chars16' or
 * 'chars32', depending on the maximum value that needs to be represented. For
 * each level in each tree, we also store lower and upper bound of allowed
 * values - values outside those bounds are considered invalid, and are left
 * out of the tables.
 *
 * In the intermediate levels of the trees, the values stored are offsets
 * into the chars[16|32] array.
 *
 * In the beginning of the chars[16|32] array, there is always a number of
 * zeros, so that you safely follow an index from an intermediate table
 * without explicitly checking for a zero. Following a zero any number of
 * times will always bring you to the dummy, all-zeros table in the
 * beginning. This helps to shave some cycles when looking up values.
 */
typedef struct {
    /*
     * Array containing all the values. Only one of chars16 or chars32 is
     * used, depending on how wide the values we need to represent are.
     */
    const uint16_t *chars16;
    const uint32_t *chars32;

    /* Radix tree for 1-byte inputs */
    uint32_t        b1root;             /* offset of table in the chars[16|32] array */
    uint8_t         b1_lower;       /* min allowed value for a single byte input */
    uint8_t         b1_upper;       /* max allowed value for a single byte input */

    /* Radix tree for 2-byte inputs */
    uint32_t        b2root;             /* offset of 1st byte's table */
    uint8_t         b2_1_lower;         /* min/max allowed value for 1st input byte */
    uint8_t         b2_1_upper;
    uint8_t         b2_2_lower;         /* min/max allowed value for 2nd input byte */
    uint8_t         b2_2_upper;

    /* Radix tree for 3-byte inputs */
    uint32_t        b3root;             /* offset of 1st byte's table */
    uint8_t         b3_1_lower;         /* min/max allowed value for 1st input byte */
    uint8_t         b3_1_upper;
    uint8_t         b3_2_lower;         /* min/max allowed value for 2nd input byte */
    uint8_t         b3_2_upper;
    uint8_t         b3_3_lower;         /* min/max allowed value for 3rd input byte */
    uint8_t         b3_3_upper;

    /* Radix tree for 4-byte inputs */
    uint32_t        b4root;             /* offset of 1st byte's table */
    uint8_t         b4_1_lower;         /* min/max allowed value for 1st input byte */
    uint8_t         b4_1_upper;
    uint8_t         b4_2_lower;         /* min/max allowed value for 2nd input byte */
    uint8_t         b4_2_upper;
    uint8_t         b4_3_lower;         /* min/max allowed value for 3rd input byte */
    uint8_t         b4_3_upper;
    uint8_t         b4_4_lower;         /* min/max allowed value for 4th input byte */
    uint8_t         b4_4_upper;

} flb_mb_radix_tree;

/*
 * UTF-8 to local code conversion map (for combined characters)
 */
typedef struct {
    uint32_t        utf1;           /* UTF-8 code 1 */
    uint32_t        utf2;           /* UTF-8 code 2 */
    uint32_t        code;           /* local code */
} flb_utf_to_local_combined;

/*
 * local code to UTF-8 conversion map (for combined characters)
 */
typedef struct {
    uint32_t        code;           /* local code */
    uint32_t        utf1;           /* UTF-8 code 1 */
    uint32_t        utf2;           /* UTF-8 code 2 */
} flb_local_to_utf_combined;

/*
 * callback function for algorithmic encoding conversions (in either direction)
 *
 * if function returns zero, it does not know how to convert the code
 */
typedef uint32_t (*utf_local_conversion_func) (uint32_t code);

extern void flb_encoding_set_invalid(int encoding, char *dst);
extern int  flb_encoding_mblen(int encoding, const char *mbstr);
extern int  flb_encoding_mblen_or_incomplete(int encoding, const char *mbstr,
                                            size_t remaining);
extern int  flb_encoding_mblen_bounded(int encoding, const char *mbstr);
extern int  flb_encoding_dsplen(int encoding, const char *mbstr);
extern int  flb_encoding_verifymbchar(int encoding, const char *mbstr, int len);
extern int  flb_encoding_verifymbstr(int encoding, const char *mbstr, int len);
extern int  flb_encoding_max_length(int encoding);

extern bool flb_utf8_islegal(const unsigned char *source, int length);
extern int  flb_utf_mblen(const unsigned char *s);

extern int  UtfToLocal(const unsigned char *utf, int len,
                       unsigned char *iso,
                       const flb_mb_radix_tree *map,
                       const flb_utf_to_local_combined *cmap, int cmapsize,
                       utf_local_conversion_func conv_func,
                       int encoding, bool noError);
extern int  LocalToUtf(const unsigned char *iso, int len,
                       unsigned char *utf,
                       const flb_mb_radix_tree *map,
                       const flb_local_to_utf_combined *cmap, int cmapsize,
                       utf_local_conversion_func conv_func,
                       int encoding, bool noError);

extern bool flb_verifymbstr(const char *mbstr, int len, bool noError);
extern bool flb_verify_mbstr(int encoding, const char *mbstr, int len,
                            bool noError);
extern int  flb_verify_mbstr_len(int encoding, const char *mbstr, int len,
                                bool noError);

extern void flb_report_invalid_encoding(int encoding, const char *mbstr, int len);
extern void flb_report_untranslatable_char(int src_encoding, int dest_encoding,
                                           const char *mbstr, int len);

#endif                          /* FLB_WCHAR_H */
