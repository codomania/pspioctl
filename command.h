#ifndef _COMMAND_H_
#define _COMMAND_H_

#include "psp-sev.h"

#include <stdint.h>

int factory_reset(void);
int get_status(struct sev_user_data_status *status);
int get_snp_status(struct sev_user_data_snp_status *status);
int pek_gen(void);
int pdh_gen(void);
int factory_reset(void);
int pek_csr(const char* data, unsigned int len);
int get_pek_csr_length(void);
int get_oca_cert_length(void);
int get_pek_cert_length(void);
int get_pdh_cert_length(void);
int get_cert_chain_length(void);
int pek_cert_import(const unsigned char* pek_cert, unsigned int pek_cert_len,
		const unsigned char* oca_cert, unsigned int oca_cert_len);
int pdh_cert_export(unsigned char* pdh, unsigned int pdh_len,
		unsigned char* cert_chain, unsigned int cert_chain_len);
int get_id(unsigned char **id, unsigned int *len);
int set_ext_snp_config(unsigned long reported_tcb, char *certs, int certs_len);
int get_ext_snp_config(struct sev_user_data_ext_snp_config *data);

#endif

