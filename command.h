#ifndef _COMMAND_H_
#define _COMMAND_H_

#include <linux/psp-sev.h>
#include <stdint.h>

int factory_reset(void);
int get_status(struct sev_user_data_status *status);
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
int get_id(unsigned long *socket1, unsigned long *socket2);

#endif

