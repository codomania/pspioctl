#include <stdio.h>
#include <glib.h>

#include "base64.h"

unsigned char* bin_to_base64(const unsigned char *in, size_t len)
{
	return g_base64_encode((const guchar*)in, len);
}

unsigned char* base64_to_bin(const unsigned char *in, size_t *len)
{
	return g_base64_decode(in, len);
}

