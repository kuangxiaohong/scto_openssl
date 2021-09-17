#define _GNU_SOURCE
#include <sched.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <openssl/bio.h> 
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>



#define MAX_TEST_SIZE (1024*256*1024)	
#define SM3_DIGEST_LEN (32)
#define PRINT_CNT (1024)
#define TEST_CNT (1)
#define SPEED_TEST_CNT (5)
#define NUMBER_OF_THREADS 8
#define CHECK 1
#define DEBUG
//#define SPEED 1
//#define SOFT 1

//#define GMSSL
#ifdef GMSSL
#define EVP_sm4_cbc EVP_sms4_cbc
#define EVP_sm4_ecb EVP_sms4_ecb
#define EVP_sm4_ctr EVP_sms4_ctr

#endif

static ENGINE *e;

static volatile uint8_t running = 1;

#define CIPHER_DATA_SIZE 64
unsigned char key1[] = "\x3B\xE0\x2B\xC3\x15\x76\xBC\x1E\x78\x33\x30\xAE\xB1\xAE\xEB\xC8";
unsigned char iv1[] = "\xAD\xCA\xA7\xFF\x79\xEA\x4C\xF1\x1D\x1D\x88\x4F\xED\x0B\x40\x44";
unsigned char in1[CIPHER_DATA_SIZE] = "\xC6\x2C\x09\xEE\x3B\x81\xF2\x6C\x08\x2C\xCA\x87\x32\x21\xF6\xCA\x7B\x15\x87\xF5\xF6\xB6\x12\x38\xB0\xAA\xC5\x82\xA8\x6E\x2D\xAC\xBD\xBB\x69\xC4\x78\x4F\x7A\x7C\x4F\xCA\xF0\x1F\xBD\xFC\xBE\x15\xC1\xEA\x97\x71\xD4\xDA\xD3\x92\x95\x89\xB5\x00\x82\x42\x57\x5B";
unsigned char ebuf1[CIPHER_DATA_SIZE + 32];
unsigned char dbuf1[CIPHER_DATA_SIZE + 32];
unsigned char encresult_ecb1[] = "\xB9\x85\x3C\x5A\xF2\xB5\xBA\xE9\x80\x92\xF1\xFA\x6D\x16\xA9\x18\x98\x7D\x78\xD2\x9A\x03\xF3\x27\xE9\xE0\xD7\xBF\x23\x67\x54\x6C\x2D\xC6\x3B\x2F\x2E\x83\xA6\x07\x78\x91\xA6\x38\x18\xA7\x41\x31\xDE\x78\xD2\x45\xBD\x9B\x02\x23\x6B\xD2\xEC\xEA\x55\x9E\xF4\x92";
unsigned char encresult_cbc1[] = "\xAA\x6F\xB2\x33\x39\x56\x3C\xFB\x42\xC1\x2C\xA9\xAC\x43\x93\xA3\x3F\xA1\xED\x13\xF2\x01\xA4\xD7\x17\xA7\xB7\xA5\xE0\xE0\x1B\x1F\x85\xD4\xAB\x2C\x16\x00\xE4\x57\x2B\x24\xF5\xB3\x75\x91\x8E\xE7\xFE\x02\xF0\x74\x38\x66\xB9\xB4\x8F\xAD\x3C\x91\x74\xC0\xFC\x8F";
unsigned char encresult_ctr1[] = "\xC3\x8E\x17\x16\x4C\x3E\x58\xEA\x46\xD9\x3F\xD8\x61\xE2\xC5\x22\x02\xFC\xAF\xEA\x75\xCB\xF6\xD6\x0D\x3B\x3C\x7E\x01\x0B\x95\x0D\x02\x1C\x36\x31\x97\x2E\x1E\xE2\x95\xF8\xF3\xA9\x23\x36\x26\x47\x28\xE0\xF5\xE1\xD5\xAB\x9B\xDF\x92\x71\xEF\xEC\x9D\x4E\x8E\x24";
unsigned char encresult_ofb1[] = "\xC3\x8E\x17\x16\x4C\x3E\x58\xEA\x46\xD9\x3F\xD8\x61\xE2\xC5\x22\x62\x6F\x90\x4C\xEF\x98\xFD\xDA\x7A\xF4\x0F\xA4\xB9\xEC\x73\x33\x4A\xBF\x67\x50\x12\xBC\x5E\xBC\xE2\xBD\xB9\x7B\x1C\x05\x12\x2A\xA2\x7D\xE1\x6B\xDE\x3A\x21\x41\xFB\x49\x7F\x2E\x9E\x83\x78\xE5";
unsigned char *enc_result = &encresult_cbc1[0], *piv = NULL;

static uint32_t block_sizes[] = { 16, 64, 256, 1024, 4096, 8192, 1024*16, 1024*64, 1024*128,256*1024,512*1024,1024*1024,2*1024*1024,4*1024*1024,16*1024*1024,64*1024*1024,128*1024*1024, 0 };

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

int set_thread_affinity(int n)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(n,&mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
		printf("warning: could not set CPU affinity, continuing...\n");
	return 1;
}

int cp_read_random(unsigned char *buf, uint32_t buflen)
{
	int fd = 0;
	int ret = 0;
	uint32_t len = 0;

	fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
	if(0 > fd)
		return fd;
	do {
		ret = read(fd, (buf + len), (buflen - len));
		if(0 < ret)
			len += (size_t)ret;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > len);

	close(fd);

	if(buflen == len)
		return 0;
	else
		return -1;
}

void trng_test(uint8_t *buf,uint32_t len,int id)
{
	int ret_bytes = 0;
	

	ret_bytes = RAND_bytes(buf,len);
	if (ret_bytes < len)
		printf("hardware is busy,please try again! ret_bytes:%d id:%d\n",ret_bytes,id);

		
	if (!(len % 4096))
		//dump_meminfo("trng",buf,len);
	printf("ret_bytes ok:%d id:%d\n",ret_bytes,id);
}


void sm3_test(uint8_t *buf,uint32_t len,int id)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	unsigned char *dgst_result = NULL;
	unsigned char obuf[SM3_DIGEST_LEN],check_obuf[SM3_DIGEST_LEN];
	unsigned int outlen = SM3_DIGEST_LEN;
	int ret = 0;
	uint32_t loop = 0,j;
//	struct timeval start,end;

//	gettimeofday(&start,NULL);
	ctx = EVP_MD_CTX_new();
	if (!ctx){
		printf("Can't EVP_MD_CTX_new\n");
		return ;
	}

	//遍历所有输入长度
	//for (loop = 0; loop < len; loop++)
	for (loop = len; loop < len + 1; loop++)
	{
		if (!(loop % PRINT_CNT))
			printf("SM3 test Byte:%d              -----Ok \n",loop);
#if 1	
		if (!(ret = EVP_DigestInit_ex(ctx, EVP_sm3(),NULL))
			   || !(ret = EVP_DigestUpdate(ctx, buf, loop))
			   || !(ret = EVP_DigestFinal_ex(ctx, check_obuf, &outlen)))
		{
			printf("Software: Can't EVP_DigestInit_ex id:%d\n",id);
			goto end;
		}
#endif
#if 1
		if (!(ret = EVP_DigestInit_ex(ctx, EVP_sm3(), e))
			   || !(ret = EVP_DigestUpdate(ctx, buf, loop))
			   || !(ret = EVP_DigestFinal_ex(ctx, obuf, &outlen)))
		{
			printf("Engine: Can't EVP_DigestInit_ex id:%d\n",id);
			goto end;
		}
#endif
#ifdef CHECK
		for ( j = 0; j < SM3_DIGEST_LEN; j++)
		{
			if (obuf[j] != check_obuf[j])
			{			
				printf("compare engine and soft: %s(%d):len(%d),offset(%d) id:%d\n",__func__,__LINE__,loop,j,id);
				dump_meminfo("SM3 Sofe buf",check_obuf,SM3_DIGEST_LEN);
				dump_meminfo("SM3 Engine buf",obuf,SM3_DIGEST_LEN);
				//goto end;
				break;
			}
		}	
#endif
	}
//ret = EVP_DigestFinal_ex(ctx, obuf, &outlen);
//	gettimeofday(&end,NULL);
//	long time_s =(end.tv_sec - start.tv_sec)*1000000l + (end.tv_usec - start.tv_usec);
//	printf("time:%ld us\n", time_s);
	
end:
	EVP_MD_CTX_free(ctx);
	return ;

}

void sm4_test(uint8_t *input_buf, uint32_t input_len,uint8_t *output_buf,uint32_t output_len,uint8_t *check_data_buf,uint32_t check_data_len,uint8_t *tmp_data_buf,uint32_t tmp_data_len,int id)
{
	int ret,ret1,ret2,ret0;
	EVP_CIPHER_CTX *ctx;
    	const EVP_CIPHER *cipher;
	uint32_t loop,tmp_len_final,tmp_len_update,enc_dec,i,mode,enc_len,dec_len;
	unsigned char *key= input_buf;
	unsigned char *iv = input_buf;
	unsigned char *in = input_buf;
	//unsigned char *key= key1;
	//unsigned char *iv = iv1;
	//unsigned char *in = in1;
	struct timeval start,end;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx){
		printf("Can't EVP_CIPHER_CTX_new\n");
		return ;
	}
	
	//for (loop = 64; loop < input_len; loop++)
	for (loop = input_len; loop < input_len+1; loop++)
	{
		if (!(loop % PRINT_CNT))
			printf("SM4(cbc&ecb&ctr) test Byte:%d -----Ok \n",loop);
			
		for (mode = 0; mode < 2; mode++)
		{
			if (mode == 0)
				cipher = EVP_sm4_cbc();
			else if(mode == 1)
				cipher = EVP_sm4_ecb();
			else if(mode == 2)
				cipher = EVP_sm4_ctr();
			else if(mode == 3)
				cipher = EVP_aes_128_cbc();
				//else 
					//cipher = EVP_sm4_ofb();
			enc_dec = 1; //enc

			if (!(ret = EVP_CIPHER_CTX_reset(ctx))
			        || !(ret0 = EVP_CipherInit_ex(ctx, cipher, e, key, iv, enc_dec))
				|| !(ret1 = EVP_CipherUpdate(ctx, output_buf, &tmp_len_update, in, loop))
				|| !(ret2 = EVP_CipherFinal_ex(ctx, output_buf+tmp_len_update, &tmp_len_final)))
			{
				dump_meminfo("engine enc failed",in,loop);
				printf("Err engine run enc: %s(%d):enc_dec(%d),len(%d),mode(%d) ret(%d) ret0(%d) ret1(%d) ret2(%d) id:%d\n",__func__,__LINE__,enc_dec,loop,mode,ret,ret0,ret1,ret2,id);
				goto end;;
			}
#if 0

			gettimeofday(&start,NULL);
			long i = 0;
			for(i = 0; i < 1024 * 64; i++){	
				ret1 = EVP_CipherUpdate(ctx, output_buf, &tmp_len_update, in, 64*1024);
			}
			ret2 = EVP_CipherFinal_ex(ctx, output_buf+tmp_len_update, &tmp_len_final);

			gettimeofday(&end,NULL);
			long time_s =(end.tv_sec - start.tv_sec)*1000000l + (end.tv_usec - start.tv_usec);
			printf("time:%ld us\n", time_s);
			return 0;
#endif
			int enc_len1 = tmp_len_update + tmp_len_final;
			if (!(ret = EVP_CIPHER_CTX_reset(ctx))
				|| !(ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc_dec))
				|| !(ret = EVP_CipherUpdate(ctx, check_data_buf, &tmp_len_update, in, loop))
				|| !(ret = EVP_CipherFinal_ex(ctx, check_data_buf+tmp_len_update, &tmp_len_final)))
			{
				dump_meminfo("soft enc failed",in,loop);
				printf("Err soft run enc: %s(%d):enc_dec(%d),len(%d),mode(%d) id:%d\n",__func__,__LINE__,enc_dec,loop,mode,id);
				goto end;;
			}
			enc_len = tmp_len_update + tmp_len_final;
#ifdef CHECK	
			if (enc_len1 != enc_len)
				printf("ERR enc len wrong!\n");

			//printf(" enc update:%d final:%d total_enc_len:%d\n",tmp_len_update,tmp_len_final,enc_len);
			for ( i = 0; i < loop; i++)
			{
				if(output_buf[i] != check_data_buf[i])
				{			
					printf("ERR compare engine and soft enc: %s(%d):enc_dec(%d),len(%d),mode(%d) id:%d\n",__func__,__LINE__,enc_dec,enc_len,mode,id);
					dump_meminfo("SM4 Enigne buf",output_buf,enc_len);
					dump_meminfo("SM4 Soft buf",check_data_buf,enc_len);
					//dump_meminfo("SM4 enc result",enc_result,enc_len);
					goto end;;
				}
			}
#endif
			enc_dec = 0; //dec
			if (!(ret = EVP_CIPHER_CTX_reset(ctx))
				|| !(ret0 = EVP_CipherInit_ex(ctx, cipher, e, key, iv, enc_dec))
				|| !(ret1 = EVP_CipherUpdate(ctx, tmp_data_buf, &tmp_len_update, output_buf, enc_len))
				|| !(ret2 = EVP_CipherFinal_ex(ctx, tmp_data_buf+tmp_len_update, &tmp_len_final)))
			{
				printf("ERR engine run dec: %s(%d):enc_dec(%d),len(%d),mode(%d) ret(%d) ret0(%d) ret1(%d) ret2(%d) id:%d\n",__func__,__LINE__,enc_dec,enc_len,mode,ret,ret0,ret1,ret2,id);
				dump_meminfo("Engine dec",tmp_data_buf,loop);
				dump_meminfo("ori dec",in,loop);
				goto end;;
			}
			dec_len = tmp_len_update + tmp_len_final;
			//printf("dec update:%d final:%d dec_len:%d\n",tmp_len_update,tmp_len_final,dec_len);
#ifdef CHECK
			//engine compare original
			for ( i = 0; i < dec_len; i++)
			{
				if(tmp_data_buf[i] != in[i])
				{			
					printf("Err: compare engine and ori dec: %s(%d):enc_dec(%d),len(%d),mode(%d) offset(%d) id:%d\n",__func__,__LINE__,enc_dec,dec_len,mode,i,id);
					//dump_meminfo("Ori",in,dec_len);
					//dump_meminfo("SM4 Engine buf",check_data_buf,dec_len);
					//break;
					goto end;
				}
			}
#endif
			if (!(ret = EVP_CIPHER_CTX_reset(ctx))
				|| !(ret0 = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc_dec))
				|| !(ret1 = EVP_CipherUpdate(ctx, tmp_data_buf, &tmp_len_update, check_data_buf, enc_len))
				|| !(ret2 = EVP_CipherFinal_ex(ctx, tmp_data_buf+tmp_len_update, &tmp_len_final)))
			{
				printf("Err:soft run dec: %s(%d):cipher(%p) enc_dec(%d),len(%d),mode(%d) ret(%d) ret0(%d) ret1(%d) ret2(%d) id:%d\n",__func__,__LINE__,cipher,enc_dec,enc_len,mode,ret,ret0,ret1,ret2,id);
				goto end;
				//break;
			}
			dec_len = tmp_len_update + tmp_len_final;
#ifdef CHECK
			//soft compare original
			for ( i = 0; i < dec_len; i++)
			{
				if(in[i] != tmp_data_buf[i])
				{			
					printf("Err: compare soft and ori dec: %s(%d):enc_dec(%d),len(%d),mode(%d) id:%d\n",__func__,__LINE__,enc_dec,dec_len,mode,id);
					dump_meminfo("Ori buf",in,loop);
					dump_meminfo("SM4 soft buf",check_data_buf,loop);
					goto end;;
				}
			}
#endif
			//printf("############ enc update:%d final:%d total_enc_len:%d\n",tmp_len_update,tmp_len_final,enc_len);
		}
	}
end:
    	EVP_CIPHER_CTX_free(ctx);
	return;
}

void sm3_speed_test(uint8_t *buf,uint32_t len,int id)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	unsigned char *dgst_result = NULL;
	unsigned char obuf[SM3_DIGEST_LEN],check_obuf[SM3_DIGEST_LEN];
	unsigned int outlen = SM3_DIGEST_LEN;
	int ret = 0;
	uint32_t loop = 0,j;
	struct timeval start,end;

	uint32_t block_num = sizeof(block_sizes)/sizeof(uint32_t);
	printf("block num:%d\n",block_num);
	//遍历所有输入长度
	for (loop = 0; loop < block_num; loop++)
	{
		uint32_t size = block_sizes[loop];
		if (size)
		{
			gettimeofday(&start,NULL);
			ctx = EVP_MD_CTX_new();
			if (!ctx){
				printf("Can't EVP_MD_CTX_new\n");
				return ;
			}
			
			for (j = 0; j < SPEED_TEST_CNT; j++)
			{
#ifdef SOFT
				if (!(ret = EVP_DigestInit_ex(ctx, EVP_sm3(),NULL))
						   || !(ret = EVP_DigestUpdate(ctx, buf+size, size))
						   || !(ret = EVP_DigestFinal_ex(ctx, check_obuf, &outlen)))
					{
						printf("ERR Software:  Can't EVP_DigestInit_ex id:%d\n",id);
						goto end;
					}
#else
				if (!(ret = EVP_DigestInit_ex(ctx, EVP_sm3(), e))
						   || !(ret = EVP_DigestUpdate(ctx, buf, size))
						   || !(ret = EVP_DigestFinal_ex(ctx, obuf, &outlen)))
					{
						printf("ERR Engine: Can't EVP_DigestInit_ex id:%d\n",id);
						goto end;
					}
#endif
			}
end:
			EVP_MD_CTX_free(ctx);			
			gettimeofday(&end,NULL);
			unsigned long interval = 1000ull*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000;
			unsigned long speed = (1000ull*size * SPEED_TEST_CNT)/interval;
			unsigned long operate = (1000ull*SPEED_TEST_CNT)/interval;
		
#ifdef SOFT
			printf("sm3_speed_test: software block_size:%d time:%ld(ms) speed:%ld(byte/s) Operate:%ld(operate/s) id:%d\n",size,interval,speed,operate,id);
#else
			printf("sm3_speed_test: hw engine block_size:%d time:%ld(ms) speed:%ld(byte/s) Operate:%ld(operate/s) id:%d\n",size,interval,speed,operate,id);
#endif		
		}
	}
	
	return ;
}



void sm4_speed_test(uint8_t *input_buf, uint32_t input_len,uint8_t *output_buf,uint32_t output_len,uint8_t *check_data_buf,uint32_t check_data_len,uint8_t *tmp_data_buf,uint32_t tmp_data_len,int id)
{
	int ret,ret1,ret2,ret0,j;
	EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
	uint32_t loop,tmp_len_final,tmp_len_update,enc_dec,i,mode,enc_len,dec_len;
	unsigned char *key= input_buf;
	unsigned char *iv = input_buf;
	unsigned char *in = input_buf;

	struct timeval start,end;
	uint32_t block_num = sizeof(block_sizes)/sizeof(uint32_t);
	
	for (mode = 0; mode < 3; mode++)
		for (enc_dec = 1; enc_dec < 2; enc_dec++)
			for (loop = 0; loop < block_num; loop++)
			{
				if (mode == 0)
					cipher = EVP_sm4_cbc();
				else if(mode == 1)
					cipher = EVP_sm4_ecb();
				else if(mode == 2)
					cipher = EVP_sm4_ctr();
				else if(mode == 3)
					cipher = EVP_aes_128_cbc();
					
				uint32_t size = block_sizes[loop];
				if (size)
				{		
					gettimeofday(&start,NULL);
					ctx = EVP_CIPHER_CTX_new();
					if (!ctx){
						printf("Can't EVP_CIPHER_CTX_new\n");
						return ;
					}
					
					for (j = 0; j < SPEED_TEST_CNT; j++)
					{
#ifdef SOFT
						if (!(ret = EVP_CIPHER_CTX_reset(ctx))
							|| !(ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc_dec))
							|| !(ret = EVP_CipherUpdate(ctx, check_data_buf, &tmp_len_update, in, size))
							|| !(ret = EVP_CipherFinal_ex(ctx, check_data_buf+tmp_len_update, &tmp_len_final)))
						{
							dump_meminfo("soft enc failed",in,loop);
							printf("Err soft run enc: %s(%d):enc_dec(%d),len(%d),mode(%d) id:%d\n",__func__,__LINE__,enc_dec,loop,mode,id);
							break;
						}
#else
						if (!(ret = EVP_CIPHER_CTX_reset(ctx))
							|| !(ret0 = EVP_CipherInit_ex(ctx, cipher, e, key, iv, enc_dec))
							|| !(ret1 = EVP_CipherUpdate(ctx, output_buf, &tmp_len_update, in, size))
							|| !(ret2 = EVP_CipherFinal_ex(ctx, output_buf+tmp_len_update, &tmp_len_final)))
						{
							dump_meminfo("engine enc failed",in,loop);
							printf("Err engine run enc: %s(%d):enc_dec(%d),len(%d),mode(%d) ret(%d) ret0(%d) ret1(%d) ret2(%d) id:%d\n",__func__,__LINE__,enc_dec,loop,mode,ret,ret0,ret1,ret2,id);
							break;
						}
#endif
					}
		end:
					EVP_CIPHER_CTX_free(ctx);
					gettimeofday(&end,NULL);
					unsigned long interval = 1000ull*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000;
					unsigned long speed = (1000ull*size * SPEED_TEST_CNT)/interval;
					unsigned long operate = (1000ull*SPEED_TEST_CNT)/interval;
					#ifdef SOFT
					printf("sm4_speed_test:software [0:dec 1:dec]enc_dec(%d) [0:cbc 1:ecb 2:ctr]mode(%d) block_size:%d time:%ld(ms) speed:%ld(byte/s) Operate:%ld(operate/s) id:%d\n",enc_dec,mode,size,interval,speed,operate,id);
#else
					printf("sm4_speed_test :hw engine [0:dec 1:dec]enc_dec(%d) [0:cbc 1:ecb 2:ctr]mode(%d) block_size:%d time:%ld(ms) speed:%ld(byte/s) Operate;%ld(operate/s) id:%d\n",enc_dec,mode,size,interval,speed,operate,id);
#endif	
			
				}
			}	

	return;
}


void trng_speed_test(uint8_t *input_buf, uint32_t input_len,int id)
{
	uint32_t loop,j,ret;
	struct timeval start,end;
	uint32_t block_num = sizeof(block_sizes)/sizeof(uint32_t);
	for (loop = 0; loop < block_num; loop++)
	{
		uint32_t size = block_sizes[loop];
		if (size && size <= input_len)
		{	
			gettimeofday(&start,NULL);
			for (j = 0; j < SPEED_TEST_CNT; j++)
			{
				ret = RAND_bytes(input_buf,size);
				if (ret != size)
				{
			     		printf("ret size is:%d,j:%d\n",ret,j);	
					continue;
				}
			}
			gettimeofday(&end,NULL);
			unsigned long interval = 1000ull*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000;
			unsigned long speed = (1000ull*size * SPEED_TEST_CNT)/interval;
			unsigned long operate = (1000ull*SPEED_TEST_CNT)/interval;
			printf("trng_speed_test :hw engine  block_size:%d time:%ld(ms) speed:%ld(byte/s) Operate;%ld(operate/s) id:%d\n",size,interval,speed,operate,id);

		}
	}
	return;
}

void* func_test(void *arg)
{
	int ret;
	int *a = (int *)arg;
	set_thread_affinity(*a);
	
	uint8_t *input_data_buf = malloc(MAX_TEST_SIZE);
	if (!input_data_buf){
		printf("Can't malloc data buf\n");
		return NULL;
	}
	uint32_t input_data_len = MAX_TEST_SIZE;


	uint8_t *output_data_buf = malloc(MAX_TEST_SIZE + 32);
	if (!output_data_buf){
		printf("Can't malloc output_data_buf buf\n");
		return NULL;
	}
	uint32_t output_data_len = (MAX_TEST_SIZE + 32);

	uint8_t *check_data_buf = malloc(MAX_TEST_SIZE + 32);
	if (!check_data_buf){
		printf("Can't malloc check_data_buf buf\n");
		return NULL;
	}
	uint32_t check_data_len = (MAX_TEST_SIZE + 32);

	uint8_t * tmp_data_buf = malloc(MAX_TEST_SIZE + 32);
	if (!tmp_data_buf){
		printf("Can't malloc tmp_data_buf buf\n");
		return NULL;
	}
	uint32_t tmp_data_len = (MAX_TEST_SIZE + 32);
	ret = cp_read_random(input_data_buf,input_data_len);
	if (ret){
		printf("Can't cp_read_random\n");
		return NULL;
	}

#ifdef SPEED
	sm3_speed_test(input_data_buf,input_data_len,*a);	
	sm4_speed_test(input_data_buf,input_data_len,output_data_buf,output_data_len,check_data_buf,check_data_len,tmp_data_buf,tmp_data_len,*a);
	trng_speed_test(input_data_buf,input_data_len,*a);
#else
	uint32_t loop = 64;
	uint32_t test_cnt = TEST_CNT;
	while(test_cnt--)
	{
		//for (loop = 64 ; loop < 65; loop++)
		for (loop = 64 ; loop < input_data_len; loop++)
		{
			trng_test(input_data_buf,loop,*a);
			//sm3_test(input_data_buf,loop,*a);
			//sm4_test(input_data_buf,loop,output_data_buf,output_data_len,check_data_buf,check_data_len,tmp_data_buf,tmp_data_len,*a);
			if (!running)
				return NULL;
		}
			//sm3_test(input_data_buf,input_data_len);
			//sm4_test(input_data_buf,input_data_len,output_data_buf,output_data_len);
	}
#endif
	if (input_data_buf)
		free(input_data_buf);

	if (output_data_buf)
		free(output_data_buf);
	
	if (check_data_buf)
		free(check_data_buf);
	if (tmp_data_buf)
		free(tmp_data_buf);
	return NULL;
}

static void sig_proc(int m_iSigNum)
{
   running = 0;
}


int main(int argc,char **argv)
{	
	int i,status;
	pthread_t threads[NUMBER_OF_THREADS];
	int tid[NUMBER_OF_THREADS];	
	int num = sysconf(_SC_NPROCESSORS_CONF);
	printf("system has %i processor(s). \n", num);
	if (num < NUMBER_OF_THREADS)
	{
		printf("thread > cpu_num\n");
		return 0;
	}
//	signal(SIGINT, sig_proc);
//	signal(SIGTERM, sig_proc);
	
	/* Initializing OpenSSL */     
//	ERR_load_BIO_strings(); 
	ENGINE_load_builtin_engines();	
//	OpenSSL_add_all_algorithms(); 
//	OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL);

	e = ENGINE_by_id("scto");

	//e = ENGINE_by_id("afalg");
	if ( e == NULL )
		printf("Can't load scto engine\n");

	for( i = 0; i < NUMBER_OF_THREADS; i++)
	{
		tid[i] = i;
		//printf("Main here. Creating thread %d\n",i);
		
		status = pthread_create(&threads[i],NULL,func_test,(void*)&tid[i]);
		if(status!=0)
		{
			printf("pthread_create returned error code %d\n",status);
			exit(0);
		}
	}

	for( i = 0;i < NUMBER_OF_THREADS; i++)
		pthread_join(threads[i],NULL);
	
	ENGINE_free(e);
	return 0;
}



