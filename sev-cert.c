#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sev-cert.h"

static const char *curve_id_str[] = {
	"invalid",
	"P256",
	"P384",
};

static const int curve_id_bytes[] = {
	0, /* invalid */
	32,
	48
};

static void print_hex_dump(char *desc, void *addr, int len)
{
	int i;
	uint8_t *buf = (uint8_t *)addr;

	if (desc)
		printf("%s", desc);
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("\n   %04x  ", i);
		printf("%02hhx ", buf[i]);
	}
	printf("\n");
}

static void dump_pubkey_rsa(void *buf)
{
	rsa_key_t *h = (rsa_key_t*) buf;
	printf("   MODULES_SIZE : %d\n", h->modulus_sz);
	print_hex_dump("   PUBEXP", h->pubexp, sizeof(h->pubexp));
	print_hex_dump("   MODULUS", h->pubexp, sizeof(h->pubexp));
}

static void dump_pubkey_ecdh(void *buf)
{
	ecdh_key_t *h = (ecdh_key_t*) buf;
	printf("  CURVE : %s\n", curve_id_str[h->curve]);
	print_hex_dump("  QX", h->qx, curve_id_bytes[h->curve]);
	print_hex_dump("  QY", h->qy, curve_id_bytes[h->curve]);
}

static void dump_pubkey_ecdsa(void *buf)
{
	ecdsa_key_t *h = (ecdsa_key_t*) buf;
	printf("  CURVE : %s\n", curve_id_str[h->curve]);
	print_hex_dump("  QX", h->qx, curve_id_bytes[h->curve]);
	print_hex_dump("  QY", h->qy, curve_id_bytes[h->curve]);
}

static void dump_sig_rsa(void *buf)
{
	rsa_sig_t *h = (rsa_sig_t*) buf;
	print_hex_dump("  S", h->s, sizeof(h->s));
}

static void dump_sig_ecdsa(void *buf)
{
	ecdsa_sig_t *h = (ecdsa_sig_t*) buf;
	print_hex_dump("  R", h->r, sizeof(h->r));
	print_hex_dump("  S", h->s, sizeof(h->s));
}

char* extract_cert(const char *buf, size_t len, pubkey_usage_t type)
{
	int i;
	cert_data_t *out;

	for (i = 0; i < len; i+= sizeof(cert_data_t)) {
		cert_data_t *h = (cert_data_t*) buf;

		buf += sizeof(cert_data_t);

		if (h->version != 0x1)
			continue;

		if (h->pubkey_usage != type)
			continue;


		out = calloc(sizeof(cert_data_t), 1);
		if (!out)
			return NULL;

		memcpy(out, h, sizeof(cert_data_t));
		return (char*)out;
	}

	return NULL;
}

void dump_cert_data(void *buf, int len)
{
	int i;

	for (i = 0; i < len; i+= sizeof(cert_data_t)) {
		cert_data_t *h = (cert_data_t*) buf;

		if (h->version != 0x1) {
			fprintf(stderr, "invalid version expect 0x1 got 0x%x\n", h->version);
			continue;
		}

		printf("VERSION : %04d\n", h->version);
		printf("MAJOR   : %02d\n", h->major);
		printf("MINOR   : %02d\n", h->minor);
		switch(h->pubkey_usage) {
		case PUBKEY_ARK: printf("PUBKEY  : ARK\n"); break;
		case PUBKEY_ASK: printf("PUBKEY  : ASK\n"); break;
		case PUBKEY_INVD: printf("PUBKEY  : INVALID\n"); break;
		case PUBKEY_OCA: printf("PUBKEY  : OCA\n"); break;
		case PUBKEY_PEK: printf("PUBKEY  : PEK\n"); break;
		case PUBKEY_PDH: printf("PUBKEY  : PDH\n"); break;
		case PUBKEY_CEK: printf("PUBKEY  : CEK\n"); break;
		}

		printf("PUBKEY_ALGO :");
		fflush(stdout);
		switch(h->pubkey_algo) {
		case PUBKEY_ALGO_RSA_SHA_256: 
			printf(" RSA with SHA-256\n");
			dump_pubkey_rsa(h->pubkey);
			break;
		case PUBKEY_ALGO_ECDSA_SHA_256:
			printf(" ECDSA with SHA-256\n");
			dump_pubkey_ecdsa(h->pubkey);
			break;
		case PUBKEY_ALGO_ECDH_SHA_256:
			printf(" ECDH with SHA-256\n");
			dump_pubkey_ecdh(h->pubkey);
			break;
		case PUBKEY_ALGO_RSA_SHA_384:
			printf(" RSA with SHA-384\n");
			dump_pubkey_rsa(h->pubkey);
			break;
		case PUBKEY_ALGO_ECDSA_SHA_384:
			printf(" ECDSA with SHA-384\n");
			dump_pubkey_ecdsa(h->pubkey);
			break;
		case PUBKEY_ALGO_ECDH_SHA_384:
			printf(" ECDH with SHA-384\n");
			dump_pubkey_ecdh(h->pubkey);
			break;
		default: printf(" INVALID\n"); break;
		}

		if (h->sig1_usage != SIG_USAGE_NOT_PRESENT) {
			printf("SIG1\n");
			switch(h->sig1_algo) {
			case PUBKEY_ALGO_RSA_SHA_256: 
			case PUBKEY_ALGO_RSA_SHA_384:
				dump_sig_rsa(h->sig1);
				break;
			case PUBKEY_ALGO_ECDSA_SHA_256: 
			case PUBKEY_ALGO_ECDSA_SHA_384:
				dump_sig_ecdsa(h->sig1);
				break;
			default: break;
			}
		}

		if (len < offsetof(cert_data_t, sig2_usage))
			continue;

		if (h->sig2_usage != SIG_USAGE_NOT_PRESENT) {
			printf("SIG2\n");
			switch(h->sig2_algo) {
			case PUBKEY_ALGO_RSA_SHA_256: 
			case PUBKEY_ALGO_RSA_SHA_384:
				dump_sig_rsa(h->sig2);
				break;
			case PUBKEY_ALGO_ECDSA_SHA_256: 
			case PUBKEY_ALGO_ECDSA_SHA_384:
				dump_sig_ecdsa(h->sig2);
				break;
			default: break;
			}
		}
	
		buf += sizeof(cert_data_t);
	}
}

