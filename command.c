#include "config.h"

#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <linux/psp-sev.h>

#include "command.h"

static int sev_ioctl(int cmd, void *data)
{
	int fd, r;
	struct sev_issue_cmd arg = { };
	
	fd = open("/dev/sev", O_RDWR);
	if (fd < 0) {
		printf("open() failed '%s'\n", strerror(errno));
		return -1;
	}

	arg.cmd = cmd;
	arg.data = (unsigned long)data;
	r = ioctl(fd, SEV_ISSUE_CMD, &arg);

	close(fd);

	if (arg.error)
		return arg.error;
	return r;
}

int get_status(struct sev_user_data_status *status)
{
	return sev_ioctl(SEV_PLATFORM_STATUS, status);
}

int pek_gen(void)
{
	return sev_ioctl(SEV_PEK_GEN, NULL);
}

int pdh_gen(void)
{
	return sev_ioctl(SEV_PDH_GEN, NULL);
}

int factory_reset(void)
{
	return sev_ioctl(SEV_FACTORY_RESET, NULL);
}

int get_pek_csr_length(void)
{
	int ret;
	struct sev_user_data_pek_csr csr = { };

	ret = sev_ioctl(SEV_PEK_CSR, &csr);
	if (ret == SEV_RET_INVALID_LEN)
		return csr.length;

	return -1;
}

int pek_csr(const char* data, unsigned int len)
{
	struct sev_user_data_pek_csr csr;

	if (!data || !len)
		return 1;

	csr.address = (unsigned long)data;
	csr.length = len;

	return sev_ioctl(SEV_PEK_CSR, &csr);
}

int get_oca_cert_length(void)
{
	int r;
	struct sev_user_data_pek_cert_import data = { };

	r = sev_ioctl(SEV_PEK_CERT_IMPORT, &data);
	if (r == SEV_RET_INVALID_LEN)
		return data.oca_cert_len;
	else
		return -1;
}

int get_pek_cert_length(void)
{
	int r;
	struct sev_user_data_pek_cert_import data = { };

	r = sev_ioctl(SEV_PEK_CERT_IMPORT, &data);
	if (r == SEV_RET_INVALID_LEN)
		return data.pek_cert_len;
	else
		return r;
}

int get_pdh_cert_length(void)
{
	int r;
	struct sev_user_data_pdh_cert_export data = { };

	r = sev_ioctl(SEV_PDH_CERT_EXPORT, &data);
	if (r == SEV_RET_INVALID_LEN)
		return data.pdh_cert_len;
	else
		return -1;
}

int get_cert_chain_length(void)
{
	int r;
	struct sev_user_data_pdh_cert_export data = { };

	r = sev_ioctl(SEV_PDH_CERT_EXPORT, &data);
	if (r == SEV_RET_INVALID_LEN)
		return data.cert_chain_len;
	else
		return -1;
}

int pek_cert_import(const unsigned char* pek_cert, unsigned int pek_cert_len,
		    const unsigned char* oca_cert, unsigned int oca_cert_len)
{
	struct sev_user_data_pek_cert_import data = { };

	if (!pek_cert || !pek_cert_len || !oca_cert || !oca_cert_len)
		return 1;

	data.pek_cert_address = (unsigned long)pek_cert;
	data.pek_cert_len = pek_cert_len;
	data.oca_cert_address = (unsigned long)oca_cert;
	data.oca_cert_len = oca_cert_len;

	return sev_ioctl(SEV_PEK_CERT_IMPORT, &data);
}

int pdh_cert_export(unsigned char* pdh, unsigned int pdh_len,
		    unsigned char* cert_chain, unsigned int cert_chain_len)
{
	struct sev_user_data_pdh_cert_export data = { };

	if (!pdh || !pdh_len || !cert_chain || !cert_chain_len)
		return 1;

	data.pdh_cert_address = (unsigned long)pdh;
	data.pdh_cert_len = pdh_len;
	data.cert_chain_address = (unsigned long)cert_chain;
	data.cert_chain_len = cert_chain_len;

	return sev_ioctl(SEV_PDH_CERT_EXPORT, &data);
}

#if HAVE_DECL_SEV_GET_ID
int get_id(unsigned char **socket1, unsigned int *socket1_len,
	   unsigned char **socket2, unsigned int *socket2_len)
{
	int r;
	struct sev_user_data_get_id data = { };

	*socket1 = calloc(sizeof(char), sizeof(data.socket1));
	if (!*socket1)
		return 1;

	*socket2 = calloc(sizeof(char), sizeof(data.socket2));
	if (!*socket2) {
		free(*socket1);
		return 1;
	}

	r = sev_ioctl(SEV_GET_ID, &data);
	if (r) {
		free(*socket1);
		free(*socket2);
		return r;
	}

	*socket1_len = sizeof(data.socket1);
	*socket2_len = sizeof(data.socket2);

	memcpy(*socket1, data.socket1, sizeof(data.socket1));
	memcpy(*socket2, data.socket2, sizeof(data.socket2));

	return 0;
}
#else
int get_id(unsigned char **socket1, unsigned int *socket1_len,
	   unsigned char **socket2, unsigned int *socket2_len)
{
	fprintf(stderr, "%s 'not supported'\n", __func__); 
	return 1; /* not supported */
}
#endif


