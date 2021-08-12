#ifndef SCTO_H
#define SCTO_H
#include "lib_sm3_phytium.h"
#include "lib_sm4_phytium.h"
#include "lib_phytium_scto.h"
#if 1
#include <tee_client_api.h>
#endif

#if 1
#define TA_SCTO_UUID { 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x2c} }

#define SCTO_SM4_INIT	0
#define SCTO_SM4_CIPHER    1
#define SCTO_SM3_INIT 2
#define SCTO_SM3_UPDATE 3
#define SCTO_SM3_FINISH 4

#endif

struct cipher_handles {
	const char *type;
	const char *name;
	int nid;
	int iv_size;
	int block_size;
    int key_size;
	unsigned long flags;
    EVP_CIPHER *_hidden;
};


struct digest_handles {
	const char *type;
	const char *name;
    int pkey_type;
    int block_size;
    int dgst_size;
    int ctx_size;
    unsigned long flags;
    EVP_MD *_hidden;
};

typedef struct cipher_handles scto_cipher_handles;
typedef struct digest_handles scto_digest_handles;

/*
 * MAGIC Number to identify correct initialisation
 * of afalg_ctx.
 */
# define MAGIC_INIT_NUM 0x1890671

struct scto_ctx_st {
    int init_done;
#if 1
	TEEC_Session sess;
	TEEC_Context ctx;
#endif
	int sm3_desc_id;
	int sm4_desc_id;
};

typedef struct scto_ctx_st scto_ctx;
#endif

