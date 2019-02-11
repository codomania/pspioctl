#ifndef _BASE64_H
#define _BASE64_H

unsigned char* bin_to_base64(const unsigned char *in, size_t len);
unsigned char* base64_to_bin(const unsigned char *in, size_t *len);

#endif
