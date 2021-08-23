#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "psp-sev.h"

#include "command.h"
#include "sev-cert.h"
#include "base64.h"

int verbose;

static void save_to_file(const char *file, const char *data, size_t len)
{
	FILE *fp;
	char *base64;

	fp = fopen(file, "w+");
	if (fp == NULL) {
		fprintf(stderr, "%s fopen() %s '%s'\n", __func__,
				file, strerror(errno));
		return;
	}

	base64 = bin_to_base64(data, len);
	fwrite(base64, 1, len, fp);
	fclose(fp);
	free(base64);

	printf("Saving %s\n", file);
}

static unsigned long file_size(FILE *fp)
{
	unsigned long sz;

	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);

	return sz;
}

static int load_file_blob(const char *file, char **data, int *len)
{
	FILE *fp;
	char *raw;
	int sz;
	unsigned long rawsz;

	fp = fopen(file, "r");
	if (fp == NULL) {
		fprintf(stderr, "%s fopen() %s '%s'\n", __func__,
				file, strerror(errno));
		return 1;
	}

	sz = file_size(fp);

	raw = calloc(sizeof(char), sz);
	if (!raw) {
		fclose(fp);
		perror("malloc()");
		return 1;
	}

	if (fread(raw, 1, sz, fp) != sz)
		fprintf(stderr, "failed to read %d bytes\n", sz);

	fclose(fp);
	*data = raw;
	*len = sz;

	return 0;
}

static int load_file(const char *file, char **data, int *len)
{
	FILE *fp;
	char *base64, *raw;
	int sz;
	unsigned long rawsz;

	fp = fopen(file, "r");
	if (fp == NULL) {
		fprintf(stderr, "%s fopen() %s '%s'\n", __func__,
				file, strerror(errno));
		return 1;
	}

	sz = file_size(fp);

	base64 = calloc(sizeof(char), sz);
	if (!base64) {
		fclose(fp);
		perror("malloc()");
		return 1;
	}


	if (fread(base64, 1, sz, fp) != sz)
		fprintf(stderr, "failed to read %d bytes\n", sz);

	fclose(fp);

	raw = base64_to_bin(base64, &rawsz);
	*data = calloc(sizeof(char), sz);
	if (!*data)
		return 1;
	memcpy(*data, raw, rawsz);
	*len = sz;
	free(raw);
	return 0;
}

static char* state_to_str(uint8_t state)
{
	switch(state) {
	case 0: return "uninit";
	case 1: return "init";
	case 2: return "working";
	default: return "unknown";
	}
}

static void show_snp_status(void)
{
	int ret;
	struct sev_user_data_snp_status s;

	ret = get_snp_status(&s);
	if (ret) {
		perror("snp_status()");
		fprintf(stderr, "failed to get status '0x%x'\n", ret);
		return;
	}

	printf("Status\n"); 
	printf("  major       : %d\n", s.api_major);
	printf("  minor       : %d\n", s.api_minor);
	printf("  build       : %d\n", s.build_id);
	printf("  state       : %d (%s)\n", s.state, state_to_str(s.state));
	printf("  guests      : %d\n", s.guest_count);
	printf("  tcb_version : 0x%llx\n", s.tcb_version);
}

static void show_status(void)
{
	int ret;
	struct sev_user_data_status s;

	ret = get_status(&s);
	if (ret) {
		fprintf(stderr, "failed to get status '0x%x'\n", ret);
		return;
	}

	printf("Status\n"); 
	printf("  major  : %d\n", s.api_major);
	printf("  minor  : %d\n", s.api_minor);
	printf("  build  : %d\n", s.build);
	printf("  state  : %d (%s)\n", s.state, state_to_str(s.state));
	printf("  guests : %d\n", s.guest_count);
}

static void handle_pek_csr(void)
{
	int ret;
	size_t sz;
	unsigned char *buf;
	unsigned char *base64;
	char file[] = "certs/output/csr.b64";

	mkdir("certs", 0644);
	mkdir("certs/output", 0644);

	printf("Generaring CSR ...\n");
	sz = get_pek_csr_length();
	if (sz < 0) {
		fprintf(stderr, "failed to get the CSR length code '%ld'\n", sz);
		return;
	}

	buf = malloc(sz);
	if (!buf) {
		perror("malloc()");
		return;
	}

	ret = pek_csr(buf, sz);
	if (ret != 0) {
		fprintf(stderr, "failed to get PEK_CSR err '0x%x'\n", ret);
		free(buf);
		return;
	}

	save_to_file(file, buf, sz);

	free(buf);
}

static void handle_cert_export(void)
{
	int ret;
	char *pdh = NULL, *certs = NULL;
	int expected_pdh_len, expected_certs_len;
	char pdh_file[] = "certs/output/pdh.b64";
	char pek_file[] = "certs/output/pek.b64";
	char oca_file[] = "certs/output/oca.b64";
	char cek_file[] = "certs/output/cek.b64";
	char certs_chain_file[] = "certs/output/certs_chain.b64";
	char *out;

	mkdir("certs", 0644);
	mkdir("certs/output", 0644);

	printf("Exporting certificates ...\n");
	expected_pdh_len = get_pdh_cert_length();
	expected_certs_len = get_cert_chain_length();

	pdh = malloc(expected_certs_len);
	if (!pdh)
		goto error;

	certs = malloc(expected_certs_len);
	if (!certs)
		goto error;

	ret = pdh_cert_export(pdh, expected_pdh_len, certs, expected_certs_len);
	if (ret) {
		fprintf(stderr, "PDH_EXPORT: failed error code 0x%x\n", ret);
		goto error;
	}

	save_to_file(pdh_file, pdh, expected_pdh_len);
	save_to_file(certs_chain_file, certs, expected_certs_len);
	
	/* cert chain contains PEK, OCA and CEK */
	out = extract_cert(certs, expected_certs_len, PUBKEY_PEK);
	if (out) {
		save_to_file(pek_file, out, sizeof(cert_data_t));
		free(out);
	}

	out = extract_cert(certs, expected_certs_len, PUBKEY_OCA);
	if (out) {
		save_to_file(oca_file, out, sizeof(cert_data_t));
		free(out);
	}
	out = extract_cert(certs, expected_certs_len, PUBKEY_CEK);
	if (out) {
		save_to_file(cek_file, out, sizeof(cert_data_t));
		free(out);
	}

error:
	free(pdh);
	free(certs);
}

static void handle_cert_import(void)
{
	int ret;
	int pek_sz, oca_sz;
	char *pek = NULL, *oca = NULL;
	char pek_file[] = "certs/input/pek.b64";
	char oca_file[] = "certs/input/oca.b64";

	mkdir("certs", 0644);
	mkdir("certs/input", 0644);

	printf("Import certificates\n");

	if (load_file(pek_file, &pek, &pek_sz))
		return;

	if (load_file(oca_file, &oca, &oca_sz))
		return;

	ret = pek_cert_import(pek, pek_sz, oca, oca_sz);
	if (ret) {
		fprintf(stderr, "PDH_IMPORT: failed error code 0x%x\n", ret);
		goto error;
	}

error:
	free(pek);
	free(oca);

}

static void show_id(void)
{
	int ret;
	int i;
	unsigned char *id;
	unsigned int len;

	ret = get_id(&id, &len);
	if (ret) {
		fprintf(stderr, "Error failed to get socket id\n");
		return;
	}

	for (i = 0; i < len; i++)
		printf("%02hhx", id[i]);
	printf("\n");
	free(id);
}

static void snp_set_config(const char *val)
{
	char certs_file[] = "certs/input/snp_certs.raw";
	char *certs = NULL, *p;
	unsigned long reported_tcb;
	int certs_len = 0, ret;

	reported_tcb = strtoll(val, &p, 16);

	load_file_blob(certs_file, &certs, &certs_len);

	ret = set_ext_snp_config(reported_tcb, certs, certs_len);
	if (ret) {
		fprintf(stderr, "failed to set extended config '0x%x'\n", ret);
		return;
	}
}

static void snp_get_config(void)
{
	struct sev_user_data_ext_snp_config data = {};
	struct sev_user_data_snp_config config = {};
	char certs_file[] = "certs/output/snp_certs.b64";
	char *certs, certs_len;
	int ret;

	certs = malloc(sizeof(char) * 8192);
	if (certs == NULL) {
		fprintf(stderr, "malloc()\n");
		return;
	}

	data.config_address = (unsigned long)&config;
	data.certs_address = (unsigned long)certs;
	data.certs_len = 8192;

	ret = get_ext_snp_config(&data);
	if (ret) {
		fprintf(stderr, "failed to get extended config '0x%x'\n", ret);
		return;
	}

	if (data.certs_len)
		save_to_file(certs_file, certs, data.certs_len);

	fprintf(stderr, "Reported TCB 0x%llx\n", config.reported_tcb);
}

static void print_cert(const char *fname)
{
	char *buf = NULL;
	int len;

	if (load_file(fname, &buf, &len))
		return;

	dump_cert_data(buf, len);
	free(buf);
}

static void help(void)
{
	fprintf(stderr,
		"--status                 Print the platform status\n"
		"--snp-status             Print the SNP platform status\n"
		"--pek-gen                Re-generate the PEK\n"
		"--pdh-gen                Re-generate the PDH\n"
		"--pek-csr                Re-generate the CSR\n"
		"--pdh-export             Export the PDH certificate chain\n"
		"--pek-import             Import the PEK/OCA certificate\n"
		"--get-id                 Show the ID used to get CEK public key\n"
		"--decode-cert            Decode the certificate blob\n"
		"--reset                  Perform the factory reset\n"
		"--help                   Show this help\n"
		"--verbose                Dump the command input/output buffer\n"
		"--snp-set-config	  Set the extended configuration information\n"
		"--snp-get-config	  Get the extended configuration information\n"
	       );
	exit(1);
}

int main(int argc, char **argv)
{
	int c;
	int option_index = 0;

	struct option long_options[] = {
		{"status",	no_argument,		0,'a' },
		{"pek-gen",	no_argument,		0,'b' },
		{"pdh-gen",	no_argument,		0,'c' },
		{"pek-csr",	no_argument, 		0,'d' },
		{"pdh-export",  no_argument,		0,'e' },
		{"pek-import",  no_argument,		0,'h' },
		{"get-id",	no_argument,		0,'i' },
		{"decode-cert",	required_argument,	0,'j' },
		{"reset",	no_argument,		0,'k' },
		{"help",	no_argument,		0,'l' },
		{"verbose",	no_argument,		0,'m' },
		{"snp-status",	no_argument,		0,'n' },
		{"snp-set-config", required_argument,	0,'o' },
		{"snp-get-config", no_argument,	0,'p' },
	};

	if (argc < 2)
		help();

	while(1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		
		switch(c) {
		case 'a': show_status(); break;
		case 'b': printf("PEK_GEN: %s\n",
				pek_gen() == 0 ? "success" : "failed");
			  break;
		case 'c': printf("PDH_GEN: %s\n",
				pdh_gen() == 0 ? "success" : "failed");
			  break;
		case 'd': handle_pek_csr();
			  break;
		case 'e': handle_cert_export(); break;
		case 'h': handle_cert_import(); break;
		case 'i': show_id(); break;
		case 'j': print_cert(optarg); break;
		case 'k': printf("FACTORY_RESET: %s\n",
				factory_reset() == 0 ? "success" : "failed");
			  break;
		case 'm': verbose = 1; break;
		case 'n': show_snp_status(); break;
		case 'o': snp_set_config(optarg); break;
		case 'p': snp_get_config(); break;
		default: help();
		}
	}

	return 0;
}

