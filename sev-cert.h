#ifndef _SEV_CERT_H
#define _SEV_CERT_H

#include <stdint.h>

typedef enum pubkey_usage_t {
	PUBKEY_ARK = 0x0,
	PUBKEY_ASK = 0x13,
	PUBKEY_INVD = 0x1000,
	PUBKEY_OCA = 0x1001,
	PUBKEY_PEK = 0x1002,
	PUBKEY_PDH = 0x1003,
	PUBKEY_CEK = 0x1004
} pubkey_usage_t;

enum pubkey_algo_t {
	PUBKEY_ALGO_INVALID = 0x0,
	PUBKEY_ALGO_RSA_SHA_256 = 0x1,
	PUBKEY_ALGO_ECDSA_SHA_256 = 0x2,
	PUBKEY_ALGO_ECDH_SHA_256 = 0x3,
	PUBKEY_ALGO_RSA_SHA_384 = 0x101,
	PUBKEY_ALGO_ECDSA_SHA_384 = 0x102,
	PUBKEY_ALGO_ECDH_SHA_384 = 0x103,
};

typedef struct rsa_sig_t {
	uint8_t		s[512];
} rsa_sig_t;

typedef struct ecdsa_sig_t {
	uint8_t		r[72];
	uint8_t		s[72];
} ecdsa_sig_t;

typedef struct rsa_key_t {
	uint32_t	modulus_sz;
	uint8_t		pubexp[512];
	uint8_t		modulus[512];
} rsa_key_t;

typedef struct ecdsa_key_t {
	uint32_t	curve;
	uint8_t		qx[72];
	uint8_t		qy[72];
} ecdsa_key_t;

typedef struct ecdh_key_t {
	uint32_t	curve;
	uint8_t		qx[72];
	uint8_t		qy[72];
} ecdh_key_t;
	
typedef struct cert_data_t {
	uint32_t	version;
	uint8_t		major;
	uint8_t		minor;
	uint16_t	reserved;
	uint32_t	pubkey_usage;
	uint32_t	pubkey_algo;
	uint8_t		pubkey[1028];
	uint32_t	sig1_usage;
	uint32_t	sig1_algo;
	uint8_t		sig1[512];
	uint32_t	sig2_usage;
	uint32_t	sig2_algo;
	uint8_t		sig2[512];
} cert_data_t;

enum {
	SIG_USAGE_NOT_PRESENT = 0x1000
};

void dump_cert_data(void *buf, int len);
char* extract_cert(const char *buf, size_t len, pubkey_usage_t type);

#endif
