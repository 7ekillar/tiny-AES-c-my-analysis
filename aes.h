#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
// 将下面的宏定义为 1/0 以启用/禁用相应的工作模式
//
// CBC enables AES encryption in CBC-mode of operation.
// CBC 启用 CBC 工作模式下的 AES 加密。
// CTR enables encryption in counter-mode.
// CTR 启用计数器模式下的加密。
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.
// ECB 启用基本的 ECB 16 字节块算法。所有模式可以同时启用。

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
// #ifndef 防护使得可以在 #include 之前或在编译时进行配置。
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif


#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
                        // 块长度（字节）- AES 仅为 128 位块

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
                            // 密钥长度（字节）
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// 缓冲区大小必须正好为 AES_BLOCKLEN 字节；
// you need only AES_init_ctx as IV is not used in ECB 
// 由于 ECB 模式不使用 IV，因此只需调用 AES_init_ctx
// NB: ECB is considered insecure for most uses
// 注意：对于大多数用途，ECB 模式被认为是不安全的
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// 缓冲区大小必须是 AES_BLOCKLEN 的整数倍；
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// 建议使用 https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 作为填充方案
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
// 注意：你需要通过 AES_init_ctx_iv() 或 AES_ctx_set_iv() 在 ctx 中设置 IV
//        no IV should ever be reused with the same key
//        切勿对同一密钥重复使用 IV 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting.
// 加密和解密使用相同的函数。 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// 每处理一个块，IV 就会递增，并在加密后用作输出的异或补数
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// 建议使用 https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 作为填充方案
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
// 注意：你需要通过 AES_init_ctx_iv() 或 AES_ctx_set_iv() 在 ctx 中设置 IV
//        no IV should ever be reused with the same key
//        切勿对同一密钥重复使用 IV 
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)


#endif // _AES_H_
