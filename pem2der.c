/*
 *  Convert PEM to DER
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "polarssl/error.h"
#include "polarssl/base64.h"

#define DFL_FILENAME            "file.pem"
#define DFL_OUTPUT_FILENAME     "file.der"

#if !defined(POLARSSL_BASE64_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_BASE64_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else
/*
 * global options
 */
struct options
{
    const char *filename;       /* filename of the input file             */
    const char *output_file;    /* where to store the output              */
} opt;

int convert_pem_to_der( const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen )
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr( (const char *) input, "-----BEGIN" );
    if( s1 == NULL )
        return( -1 );

    s2 = (unsigned char *) strstr( (const char *) input, "-----END" );
    if( s2 == NULL )
        return( -1 );

    s1 += 10;
    while( s1 < end && *s1 != '-' )
        s1++;
    while( s1 < end && *s1 == '-' )
        s1++;
    if( *s1 == '\r' ) s1++;
    if( *s1 == '\n' ) s1++;

    if( s2 <= s1 || s2 > end )
        return( -1 );

    ret = base64_decode( NULL, &len, (const unsigned char *) s1, s2 - s1 );
    if( ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER )
        return( ret );

    if( len > *olen )
        return( -1 );

    if( ( ret = base64_decode( output, &len, (const unsigned char *) s1,
                               s2 - s1 ) ) != 0 )
    {
        return( ret );
    }

    *olen = len;

    return( 0 );
}


static int get_file_length(const char* path)
{
        int fd, i;
        ssize_t r;
        char c;

        fd = open(path, O_RDONLY);
        if (fd < 0)
                return -1;
        printf("len=%d\n", fd);
        for(i=0; ;i++)
        {
                r = read(fd, &c, 1);
                if(r < 0) {
                        i = -1;
                        break;
                }

                if (r==0)
                        break;
        }

        close(fd);

        return i;
}


/*
 * Load all data from a file into a given buffer.
 */
int load_file( const char *path, unsigned char **buf, size_t *n )
{
        int fd;
        ssize_t r;

        int i = get_file_length(path);
        if (i < 0)
                return -1;

        *n = i;

        fd = open(path, O_RDONLY);
        if (fd < 0)
                return -1;

        *buf = malloc(*n+1);
        if(!*buf)
                return -1;

        r = read(fd, *buf, *n);
        if(r < 0)
                return -1;

        close(fd);

        return *n;
}

#endif
