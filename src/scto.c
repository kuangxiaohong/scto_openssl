#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h> 
#include <sys/stat.h>   
#include <fcntl.h>

#include <openssl/err.h>

#include <openssl/engine.h>
#include "scto.h"



# ifndef SM3_BLOCK_SIZE
#  define SM3_BLOCK_SIZE   64
# endif

# ifndef SM3_DIGEST_LENGTH
#  define SM3_DIGEST_LENGTH   32
# endif

# ifndef SM4_KEY_SIZE
#  define SM4_KEY_SIZE   16
# endif

# ifndef SM4_BLOCK_SIZE
#  define SM4_BLOCK_SIZE   16
# endif

# ifndef SM4_IV_LEN
# define SM4_IV_LEN 16
# endif

#define SCTO_ROUND_UP(__x__, __align__) (((unsigned long)(__x__) + ((unsigned long)(__align__)-1)) & ~((unsigned long)(__align__)-1))

				
/* Engine Id and Name */
static const char *engine_scto_id = "scto";
static const char *engine_scto_name = "SCTO engine";
static uint8_t scto_in_ree_or_tee = 1;
static uint8_t first_time = 1;
static int scto_cipher_nids[] = {
	NID_sm4_ecb,
	NID_sm4_cbc,
	NID_sm4_ctr,
	NID_sm4_ofb128,
	NID_sm4_cfb128,
};

static int scto_digest_nids[] = {
	NID_sm3,
};

static scto_cipher_handles cipher_handle[] = {
	{
		.type = "skcipher",
		.name = "scto-sm4-ecb",
		.nid = NID_sm4_ecb,
		.iv_size = 0,
		.block_size = SM4_BLOCK_SIZE,
		.key_size = SM4_KEY_SIZE,
		.flags = EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,
		._hidden = NULL,
	},
	{
		.type = "skcipher",
		.name = "scto-sm4-cbc",
		.nid = NID_sm4_cbc,
		.iv_size = SM4_BLOCK_SIZE,
		.block_size = SM4_BLOCK_SIZE,
		.key_size = SM4_KEY_SIZE,
		.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,
		._hidden = NULL,
	},
	{
		.type = "skcipher",
		.name = "scto-sm4-ctr",
		.nid = NID_sm4_ctr,
		.iv_size = SM4_BLOCK_SIZE,
		.block_size = 1,
		.key_size = SM4_KEY_SIZE,
		.flags = EVP_CIPH_CTR_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,
		._hidden = NULL,
	},
	{
		.type = "skcipher",
		.name = "scto-sm4-ofb",
		.nid = NID_sm4_ofb128,
		.iv_size = SM4_BLOCK_SIZE,
		.block_size = 1,
		.key_size = SM4_KEY_SIZE,
		.flags = EVP_CIPH_OFB_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,
		._hidden = NULL,
	},
	{
		.type = "skcipher",
		.name = "scto-sm4-cfb",
		.nid = NID_sm4_cfb128,
		.iv_size = SM4_BLOCK_SIZE,
		.block_size = 1,
		.key_size = SM4_KEY_SIZE,
		.flags = EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,
		._hidden = NULL,
	},	
};

static scto_digest_handles digest_handle[] = {
	{
		.type = "hash", 			
		.name = "scto-sm3",
		.pkey_type = NID_sm3WithRSAEncryption,
		.block_size = SM3_BLOCK_SIZE,
		.dgst_size = SM3_DIGEST_LENGTH,
		.flags = EVP_MD_FLAG_DIGALGID_ABSENT,
		._hidden = NULL,
	},
};

static int scto_destroy(ENGINE *e);
static int scto_init(ENGINE *e);
static int scto_finish(ENGINE *e);
static int scto_chk_platform(void);

# ifdef OPENSSL_NO_DYNAMIC_ENGINE
void engine_load_scto_int(void);
# endif

#if 1
static void dump_meminfo(char *msg,uint8_t *data, uint64_t len)
{
#ifdef DEBUG
    if (!data)
            return ;

    uint64_t i = 0;

    printf("%s: %p len %u \n", msg, data, len);
    for (i = 0; i < len; i ++)
    {
            printf("%02x ", (uint8_t)data[i]);
            if (i%16 == 15)
                    printf("---%d\n", i+1);
    }
    printf("\n");
#endif
	return;
}
#endif

static scto_cipher_handles *get_cipher_handle(int nid)
{
	int i;
    int num = sizeof(scto_cipher_nids) / sizeof(scto_cipher_nids[0]);

    for ( i = 0; i < num; i++) {
        if (nid == cipher_handle[i].nid)
            return &cipher_handle[i];
    }
    return NULL;
}


static int scto_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
	int nid,ret,mode;
    scto_ctx *actx;
	scto_cipher_handles *handle;

    if (ctx == NULL || key == NULL) {
        printf("%s(%d): Null Parameter\n", __FILE__, __LINE__);
        return 0;
    }

    if (iv == NULL)
	    iv = EVP_CIPHER_CTX_iv(ctx);

    if (EVP_CIPHER_CTX_cipher(ctx) == NULL) {
        printf("%s(%d): Cipher object NULL\n", __FILE__, __LINE__);
        return 0;
    }

	nid = EVP_CIPHER_CTX_nid(ctx);
	if (!(handle = get_cipher_handle(nid))) {
		printf("%s(%d): Unsupported Cipher nid %d\n", __FILE__, __LINE__,nid);
		return 0;
	}

	if (nid == NID_sm4_ecb)
		mode = SM4_MODE_ECB;
	else if(nid == NID_sm4_cbc)
		mode = SM4_MODE_CBC;
	else if(nid == NID_sm4_ctr)
		mode = SM4_MODE_CTR;

    if (handle->iv_size != EVP_CIPHER_CTX_iv_length(ctx)) {
        printf("%s(%d): Unsupported IV length :%d\n", __FILE__, __LINE__,
                 EVP_CIPHER_CTX_iv_length(ctx));
        return 0;
    }
	
    actx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (actx == NULL) {
        printf("%s(%d): Cipher data NULL\n", __FILE__, __LINE__);
        return 0;
    }
	if(scto_in_ree_or_tee)
	{
		ret = phytium_sm4_init(&actx->sm4_desc_id, mode, !enc, key,	iv);
		if(ret)
		{
        		printf("%s(%d): ret:%d sm4_desc_id:%d\n", __FILE__, __LINE__,ret,actx->sm4_desc_id);
			return 0;
		}
	}
#if 1
	else
	{
		TEEC_Result res;
		TEEC_Context *tctx = &actx->ctx;
		TEEC_UUID uuid = TA_SCTO_UUID;		
		TEEC_Operation op;
		TEEC_Session *sess = &actx->sess;
		uint32_t err_origin;
		res = TEEC_InitializeContext(NULL, tctx);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_InitializeContext failed with code 0x%x\n",__FILE__, __LINE__, res);
			return 0;
		}
		res = TEEC_OpenSession(tctx, sess, &uuid,
					   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_Opensession failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,
				res, err_origin);
			return 0;
		}
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
							 TEEC_VALUE_INOUT, TEEC_NONE);
		op.params[0].tmpref.buffer = key;
		op.params[0].tmpref.size = EVP_CIPHER_CTX_key_length(ctx);
		op.params[1].tmpref.buffer = iv;
		op.params[1].tmpref.size = EVP_CIPHER_CTX_iv_length(ctx);
		op.params[2].value.a = enc ;
		op.params[2].value.b = handle->flags;
		

		dump_meminfo("afalg_cipher_init send key",key,16);
		dump_meminfo("afalg_cipher_init send iv",iv,16);

		res = TEEC_InvokeCommand(sess, SCTO_SM4_INIT, &op,&err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,
			res, err_origin);
			return 0;
		}
	}
#endif
	actx->init_done = MAGIC_INIT_NUM;
	return 1;

}

static int scto_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{	
    scto_ctx *actx;
	int nid,blk,ret;
	size_t num = 0, remainder = 0;
	scto_cipher_handles *handle;

    if (ctx == NULL || out == NULL || in == NULL) {
        printf("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (scto_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        printf("%s(%d):  %s scto ctx passed\n",__FILE__, __LINE__,
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }

	nid = EVP_CIPHER_CTX_nid(ctx);
	
	if (!(handle = get_cipher_handle(nid))) {
		printf("%s(%d): Unsupported Cipher nid %d\n", __FILE__, __LINE__,
				 nid);
		return 0;
	}


	if(scto_in_ree_or_tee)
	{	
		//printf("send data len:%d\n",inl);	
		ret =  phytium_sm4_update(actx->sm4_desc_id, in, inl, out);
		if (ret)
		{
        		printf("%s(%d): ret:%d sm4_desc_id:%d\n", __FILE__, __LINE__,ret,actx->sm4_desc_id);
			return 0;
		}
	}
#if 1
	else
	{	
		TEEC_Result res;
		TEEC_Operation op;		
		TEEC_Session *sess = &actx->sess;
		uint32_t err_origin;
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
							 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = in;
		op.params[0].tmpref.size = inl;
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = inl;
	
		dump_meminfo("afalg_do_cipher send data",in,inl);	
		res = TEEC_InvokeCommand(sess, SCTO_SM4_CIPHER, &op,&err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,res, err_origin);
			return 0;
		}
	}
#endif
	  
    return 1;
}

static int scto_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    scto_ctx *actx;

    if (ctx == NULL) {
        printf("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (scto_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        printf("%s(%d):  %s scto ctx passed\n",__FILE__, __LINE__,
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }

	if (scto_in_ree_or_tee)
	{
		if(actx->sm4_desc_id > 0)
			mem_free(actx->sm4_desc_id);
		//printf("scto cipher cleanup\n");
	}
#if 1
	else
	{
		TEEC_CloseSession(&actx->sess);
		TEEC_FinalizeContext(&actx->ctx);
	}
#endif
    return 1;
}


static const EVP_CIPHER *scto_cipher_register(int nid)
{
    scto_cipher_handles *cipher_handle = get_cipher_handle(nid);

    if(cipher_handle == NULL)
        return NULL;

    if (cipher_handle->_hidden == NULL
        && ((cipher_handle->_hidden =
         EVP_CIPHER_meth_new(nid,
                             cipher_handle->block_size,
                             cipher_handle->key_size)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(cipher_handle->_hidden,
                                          cipher_handle->iv_size)
        || !EVP_CIPHER_meth_set_flags(cipher_handle->_hidden,
                                      cipher_handle->flags)
        || !EVP_CIPHER_meth_set_init(cipher_handle->_hidden,
                                     scto_cipher_init)
        || !EVP_CIPHER_meth_set_do_cipher(cipher_handle->_hidden,
                                          scto_do_cipher)
        || !EVP_CIPHER_meth_set_cleanup(cipher_handle->_hidden,
                                        scto_cipher_cleanup)
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher_handle->_hidden,
                                              sizeof(scto_ctx)))) {
        EVP_CIPHER_meth_free(cipher_handle->_hidden);
        cipher_handle->_hidden= NULL;
    }
	
    return cipher_handle->_hidden;
}

static int scto_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid)
{
    if (cipher == NULL) {
        *nids = scto_cipher_nids;
        return (sizeof(scto_cipher_nids) / sizeof(scto_cipher_nids[0]));
    }


    if (!(*cipher = scto_cipher_register(nid)))
        return 0;

    return 1;
}

static scto_digest_handles *get_digest_handle(int nid)
{
    switch (nid) {
  		case NID_sm3:
        	return &digest_handle[0];
    	default:
        	return NULL;
    }
}

static int scto_digest_init(EVP_MD_CTX *ctx)
{
    scto_ctx *actx;
    int ret;
    if (ctx == NULL) {
        printf("%s(%d): Null Parameter\n", __FILE__, __LINE__);
        return 0;
    }

    if (EVP_MD_CTX_md(ctx) == NULL) {
        printf("%s(%d): Digest object NULL\n", __FILE__, __LINE__);
        return 0;
    }

    actx = EVP_MD_CTX_md_data(ctx);
    if (actx == NULL) {
        printf("%s(%d): Cipher data NULL\n", __FILE__, __LINE__);
        return 0;
    }

	if (scto_in_ree_or_tee)
	{
		ret = phytium_sm3_dma_init(&actx->sm3_desc_id);
		if (ret)
		{
        		printf("%s(%d): ret:%d,sm3_desc_id:%d\n", __FILE__, __LINE__,ret,actx->sm3_desc_id);
			return 0;
		}
	}
#if 1
	else
	{
		TEEC_Result res;
		TEEC_Context *tctx = &actx->ctx;
		TEEC_UUID uuid = TA_SCTO_UUID;		
		TEEC_Operation op;
		TEEC_Session *sess = &actx->sess;
		uint32_t err_origin;
		res = TEEC_InitializeContext(NULL, tctx);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_InitializeContext failed with code 0x%x\n",__FILE__, __LINE__, res);
			return 0;
		}
		res = TEEC_OpenSession(tctx, sess, &uuid,
					   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_Opensession failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,
				res, err_origin);
			return 0;
		}
		
		memset(&op, 0, sizeof(op));
		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
							 TEEC_NONE, TEEC_NONE);

		res = TEEC_InvokeCommand(sess, SCTO_SM3_INIT, &op,&err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,
			res, err_origin);
			return 0;
		}
	}
#endif
    actx->init_done = MAGIC_INIT_NUM;
    return 1;
}

static int scto_digest_update(EVP_MD_CTX *ctx, const void *in,
                                size_t inl)
{
    scto_ctx *actx;
    int ret;

    if (ctx == NULL || in == NULL) {
        printf("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (scto_ctx *) EVP_MD_CTX_md_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        printf("%s(%d): %s scto ctx passed\n",__FILE__, __LINE__,
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }

	if (scto_in_ree_or_tee )
	{
	
		ret = phytium_sm3_dma_update(actx->sm3_desc_id, in, inl);
		if (ret)
		{
        		printf("%s(%d): ret:%d sm3_desc_id:%d\n", __FILE__, __LINE__,ret,actx->sm3_desc_id);
			return 0;
		}
	}
#if 1
	else
	{
		TEEC_Result res;
		TEEC_Operation op;		
		TEEC_Session *sess = &actx->sess;
		uint32_t err_origin;
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
							 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = in;
		op.params[0].tmpref.size = inl;
	
		dump_meminfo("afalg_digest_update send input data",in,inl);	
		res = TEEC_InvokeCommand(sess, SCTO_SM3_UPDATE, &op,&err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d): TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,res, err_origin);
			return 0;
		}
	}
#endif
    return 1;
}

static int scto_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    scto_ctx *actx;
    int ret;

    if (ctx == NULL || md == NULL) {
        printf("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (scto_ctx *) EVP_MD_CTX_md_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        printf("%s(%d): %s scto ctx passed\n",__FILE__, __LINE__,
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }
	
	if (scto_in_ree_or_tee )
	{
	
		ret = phytium_sm3_dma_final(actx->sm3_desc_id, md);
		if (ret)
		{
        		printf("%s(%d): ret:%d sm3_desc_id:%d\n", __FILE__, __LINE__,ret,actx->sm3_desc_id);
			return 0;
		}
  		//printf("scto_digest_final\n");
	}
#if 1
	else
	{
		TEEC_Result res;
		TEEC_Operation op;		
		TEEC_Session *sess = &actx->sess;
		uint32_t err_origin;
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
							 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = md;
		op.params[0].tmpref.size = EVP_MD_CTX_size(ctx);
		
		res = TEEC_InvokeCommand(sess, SCTO_SM3_FINISH, &op,&err_origin);
		if (res != TEEC_SUCCESS)
		{
			printf("%s(%d):TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",__FILE__, __LINE__,res, err_origin);
			return 0;
		}
	}
#endif
    return 1;
}

static int scto_digest_cleanup(EVP_MD_CTX *ctx)
{
    scto_ctx *actx;

    if (ctx == NULL) {
        printf("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (scto_ctx *) EVP_MD_CTX_md_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        printf("%s(%d): %s scto ctx passed\n",__FILE__, __LINE__,
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }
	if (scto_in_ree_or_tee )
	{
		if(actx->sm3_desc_id > 0)
			mem_free(actx->sm3_desc_id);
    	//printf("scto_digest_cleanup\n");
	}
#if 1
	else
	{
		TEEC_CloseSession(&actx->sess);
		TEEC_FinalizeContext(&actx->ctx);
	}
#endif
    return 1;
}

static const EVP_MD *scto_digest_register(int nid)
{
    scto_digest_handles *digest_handle = get_digest_handle(nid);

    if(digest_handle == NULL)
        return NULL;
    if (digest_handle->_hidden == NULL) {
        EVP_MD *md;
        if ((md = EVP_MD_meth_new(nid, digest_handle->pkey_type)) == NULL
            || !EVP_MD_meth_set_result_size(md, digest_handle->dgst_size)
            || !EVP_MD_meth_set_input_blocksize(md, digest_handle->block_size)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(scto_ctx))
            || !EVP_MD_meth_set_flags(md, digest_handle->flags)
            || !EVP_MD_meth_set_init(md, scto_digest_init)
            || !EVP_MD_meth_set_update(md, scto_digest_update)
            || !EVP_MD_meth_set_final(md, scto_digest_final)
            || !EVP_MD_meth_set_cleanup(md,scto_digest_cleanup)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        digest_handle->_hidden = md;
    }
    return digest_handle->_hidden;
}

static int scto_digest(ENGINE *e, const EVP_MD **digest,
                         const int **nids, int nid)
{
    int r = 1;

    if (digest == NULL) {
        *nids = scto_digest_nids;
        return (sizeof(scto_digest_nids) / sizeof(scto_digest_nids[0]));
    }

    *digest = scto_digest_register(nid);

    if(*digest == NULL)
        r = 0;

    return r;
}


static int bind_scto(ENGINE *e)
{
    /* Ensure the afalg error handling is set up */
    unsigned short i;
   // ERR_load_AFALG_strings();

    if (!ENGINE_set_id(e, engine_scto_id)
        || !ENGINE_set_name(e, engine_scto_name)
        || !ENGINE_set_destroy_function(e, scto_destroy)
        || !ENGINE_set_init_function(e, scto_init)
        || !ENGINE_set_finish_function(e, scto_finish)) {
        printf("bind failed\n");
        return 0;
    }

    /*
     * 
     * now, as bind_scto can only be called by one thread at a
     * time.
     */
    for(i = 0; i < sizeof(scto_cipher_nids)/sizeof(int); i++) {
        if (scto_cipher_register(scto_cipher_nids[i]) == NULL) {
            printf("init failed\n");
            return 0;
        }
    }

    if (!ENGINE_set_ciphers(e, scto_ciphers)) {
		printf("scto_ciphers failed\n");
        return 0;
    }


    for(i = 0; i < sizeof(scto_digest_nids)/sizeof(int); i++) {
        if (scto_digest_register(scto_digest_nids[i]) == NULL) {
			printf("scto_digest_register failed\n");
            return 0;
        }
    }

    if (!ENGINE_set_digests(e, scto_digest)) {
		printf("scto_digest failed\n");
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_scto_id) != 0))
        return 0;

    if (!scto_chk_platform())
        return 0;

    if (!bind_scto(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# endif

static int scto_chk_platform(void)
{
//	printf("scto_chk_platform is ok\n");
    return 1;
}

# ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_scto(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_scto(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_scto_int(void)
{
    ENGINE *toadd;

    if (!scto_chk_platform())
        return;

    toadd = engine_scto();
    if (toadd == NULL)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
# endif

static int scto_init(ENGINE *e)
{
	if (first_time)
	{
		first_time = 0;
		int	fd = open("/dev/tee0", O_RDWR);
		if (fd < 0)
		{
			scto_in_ree_or_tee = 1;
			lib_scto_init();
		}
		else
		{
			scto_in_ree_or_tee = 0;
			close(fd);
		}
		
	}
    return 1;
}

static int scto_finish(ENGINE *e)
{
    return 1;
}

static int free_cipher(void)
{
    short unsigned int i;
    for(i = 0; i < sizeof(scto_cipher_nids)/sizeof(int); i++) {
		if (cipher_handle[i]._hidden )
		{
       		EVP_CIPHER_meth_free(cipher_handle[i]._hidden);
        	cipher_handle[i]._hidden = NULL;
		}
    }
    return 1;
}

static int free_digest(void)
{
    short unsigned int i;
    for(i = 0; i < sizeof(scto_digest_nids)/sizeof(int); i++) {
		if (digest_handle[i]._hidden)
		{
	        EVP_MD_meth_free(digest_handle[i]._hidden);
	        digest_handle[i]._hidden = NULL;
		}
    }
    return 1;
}

static int scto_destroy(ENGINE *e)
{
    //ERR_unload_AFALG_strings();
    free_cipher();
	free_digest();
    return 1;
}


