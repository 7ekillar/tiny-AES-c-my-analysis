![CI](https://github.com/kokke/tiny-AES-c/actions/workflows/c-cpp.yml/badge.svg)
### Tiny AES in C

This is a small and portable implementation of the AES [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29), [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) and [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) encryption algorithms written in C.

You can override the default key-size of 128 bit with 192 or 256 bit by defining the symbols AES192 or AES256 in [`aes.h`](https://github.com/kokke/tiny-AES-c/blob/master/aes.h).

The API is very simple and looks like this (I am using C99 `<stdint.h>`-style annotated types):

```C
/* Initialize context calling one of: */
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

/* ... or reset IV at random point: */
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

/* Then start encrypting and decrypting with the functions below: */
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

/* Same function for encrypting as for decrypting in CTR mode */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
```

Important notes: 
 * No padding is provided so for CBC and ECB all buffers should be multiples of 16 bytes. For padding [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is recommendable.
 * ECB mode is considered unsafe for most uses and is not implemented in streaming mode. If you need this mode, call the function for every block of 16 bytes you need encrypted. See [wikipedia's article on ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) for more details.
 * This library is designed for small code size and simplicity, intended for cases where small binary size, low memory footprint and portability is more important than high performance. If speed is a concern, you can try more complex libraries, e.g. [Mbed TLS](https://tls.mbed.org/), [OpenSSL](https://www.openssl.org/) etc.

You can choose to use any or all of the modes-of-operations, by defining the symbols CBC, CTR or ECB in [`aes.h`](https://github.com/kokke/tiny-AES-c/blob/master/aes.h) (read the comments for clarification).

C++ users should `#include` [aes.hpp](https://github.com/kokke/tiny-AES-c/blob/master/aes.hpp) instead of [aes.h](https://github.com/kokke/tiny-AES-c/blob/master/aes.h)

There is no built-in error checking or protection from out-of-bounds memory access errors as a result of malicious input.

The module uses less than 200 bytes of RAM and 1-2K ROM when compiled for ARM, but YMMV depending on which modes are enabled.

It is one of the smallest implementations in C I've seen yet, but do contact me if you know of something smaller (or have improvements to the code here). 

I've successfully used the code on 64bit x86, 32bit ARM and 8 bit AVR platforms.


GCC size output when only CTR mode is compiled for ARM:

    $ arm-none-eabi-gcc -Os -DCBC=0 -DECB=0 -DCTR=1 -c aes.c
    $ size aes.o
       text    data     bss     dec     hex filename
       1171       0       0    1171     493 aes.o

.. and when compiling for the THUMB instruction set, we end up well below 1K in code size.

    $ arm-none-eabi-gcc -Os -mthumb -DCBC=0 -DECB=0 -DCTR=1 -c aes.c
    $ size aes.o
       text    data     bss     dec     hex filename
        903       0       0     903     387 aes.o


I am using the Free Software Foundation, ARM GCC compiler:

    $ arm-none-eabi-gcc --version
    arm-none-eabi-gcc (4.8.4-1+11-1) 4.8.4 20141219 (release)
    Copyright (C) 2013 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.  There is NO
    warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.




This implementation is verified against the data in:

[National Institute of Standards and Technology Special Publication 800-38A 2001 ED](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) Appendix F: Example Vectors for Modes of Operation of the AES.

The other appendices in the document are valuable for implementation details on e.g. padding, generation of IVs and nonces in CTR-mode etc.


A heartfelt thank-you to [all the nice people](https://github.com/kokke/tiny-AES-c/graphs/contributors) out there who have contributed to this project.


All material in this repository is in the public domain.

![CI](https://github.com/kokke/tiny-AES-c/actions/workflows/c-cpp.yml/badge.svg)
### Tiny AES in C
### 微型 AES C 语言实现

This is a small and portable implementation of the AES [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29), [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) and [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) encryption algorithms written in C.
这是一个用 C 语言编写的小型、可移植的 AES [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29)、[CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) 和 [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) 加密算法实现。

You can override the default key-size of 128 bit with 192 or 256 bit by defining the symbols AES192 or AES256 in [`aes.h`](https://github.com/kokke/tiny-AES-c/blob/master/aes.h).
你可以通过在 [`aes.h`](https://github.com/kokke/tiny-AES-c/blob/master/aes.h) 中定义 `AES192` 或 `AES256` 符号，将默认的 128 位密钥长度覆盖为 192 位或 256 位。

The API is very simple and looks like this (I am using C99 `<stdint.h>`-style annotated types):
API 非常简单，如下所示（这里使用了 C99 `<stdint.h>` 风格的注解类型）：

```C
/* Initialize context calling one of: */
/* 调用以下任一函数初始化上下文： */
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

/* ... or reset IV at random point: */
/* ... 或在任意时刻重置 IV： */
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

/* Then start encrypting and decrypting with the functions below: */
/* 然后使用以下函数开始加密和解密： */
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

/* Same function for encrypting as for decrypting in CTR mode */
/* CTR 模式下加密和解密使用同一函数 */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
```

Important notes: 
重要说明：
 * No padding is provided so for CBC and ECB all buffers should be multiples of 16 bytes. For padding [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is recommendable.
 * 本实现不提供填充，因此对于 CBC 和 ECB 模式，所有缓冲区长度应为 16 字节的整数倍。如需填充，建议使用 [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7)。
 * ECB mode is considered unsafe for most uses and is not implemented in streaming mode. If you need this mode, call the function for every block of 16 bytes you need encrypted. See [wikipedia's article on ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) for more details.
 * ECB 模式对大多数用途而言被认为不安全，且未以流模式实现。如果你需要使用此模式，请对每 16 字节的数据块分别调用加密函数。更多详情请参阅 [维基百科关于 ECB 的条目](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB))。
 * This library is designed for small code size and simplicity, intended for cases where small binary size, low memory footprint and portability is more important than high performance. If speed is a concern, you can try more complex libraries, e.g. [Mbed TLS](https://tls.mbed.org/), [OpenSSL](https://www.openssl.org/) etc.
 * 本库旨在追求代码体积小和实现简洁，适用于二进制体积小、内存占用低和可移植性比高性能更重要的场景。如果对速度有要求，可以尝试更复杂的库，例如 [Mbed TLS](https://tls.mbed.org/)、[OpenSSL](https://www.openssl.org/) 等。

You can choose to use any or all of the modes-of-operations, by defining the symbols CBC, CTR or ECB in [`aes.h`](https://github.com/kokke/tiny-AES-c/blob/master/aes.h) (read the comments for clarification).
你可以通过在 [`aes.h`](https://github.com/kokke/tiny-AES-c/blob/master/aes.h) 中定义 `CBC`、`CTR` 或 `ECB` 符号，来选择使用其中任意一种或全部工作模式（具体请参阅文件中的注释）。

C++ users should `#include` [aes.hpp](https://github.com/kokke/tiny-AES-c/blob/master/aes.hpp) instead of [aes.h](https://github.com/kokke/tiny-AES-c/blob/master/aes.h)
C++ 用户应 `#include` [aes.hpp](https://github.com/kokke/tiny-AES-c/blob/master/aes.hpp) 而非 [aes.h](https://github.com/kokke/tiny-AES-c/blob/master/aes.h)

There is no built-in error checking or protection from out-of-bounds memory access errors as a result of malicious input.
本模块未内置错误检查，也不提供针对恶意输入导致的内存越界访问错误的防护。

The module uses less than 200 bytes of RAM and 1-2K ROM when compiled for ARM, but YMMV depending on which modes are enabled.
在针对 ARM 编译时，该模块使用不到 200 字节的 RAM 和 1-2 KB 的 ROM，但实际占用会因启用的模式不同而有所差异。

It is one of the smallest implementations in C I've seen yet, but do contact me if you know of something smaller (or have improvements to the code here). 
这是我见过的最小的 C 语言实现之一，但如果你知道更小的实现（或对此处的代码有改进建议），请联系我。

I've successfully used the code on 64bit x86, 32bit ARM and 8 bit AVR platforms.
我已成功在 64 位 x86、32 位 ARM 和 8 位 AVR 平台上使用过此代码。

GCC size output when only CTR mode is compiled for ARM:
仅编译 CTR 模式时，针对 ARM 的 GCC 大小输出如下：

    $ arm-none-eabi-gcc -Os -DCBC=0 -DECB=0 -DCTR=1 -c aes.c
    $ size aes.o
       text    data     bss     dec     hex filename
       1171       0       0    1171     493 aes.o

.. and when compiling for the THUMB instruction set, we end up well below 1K in code size.
……而当为 THUMB 指令集编译时，代码大小远低于 1 KB。

    $ arm-none-eabi-gcc -Os -mthumb -DCBC=0 -DECB=0 -DCTR=1 -c aes.c
    $ size aes.o
       text    data     bss     dec     hex filename
        903       0       0     903     387 aes.o

I am using the Free Software Foundation, ARM GCC compiler:
我使用的是自由软件基金会的 ARM GCC 编译器：

    $ arm-none-eabi-gcc --version
    arm-none-eabi-gcc (4.8.4-1+11-1) 4.8.4 20141219 (release)
    Copyright (C) 2013 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.  There is NO
    warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

This implementation is verified against the data in:
本实现已根据以下文档中的数据进行验证：

[National Institute of Standards and Technology Special Publication 800-38A 2001 ED](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) Appendix F: Example Vectors for Modes of Operation of the AES.
[美国国家标准与技术研究院特别出版物 800-38A 2001 版](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) 附录 F：AES 工作模式示例向量。

The other appendices in the document are valuable for implementation details on e.g. padding, generation of IVs and nonces in CTR-mode etc.
该文档的其他附录对于实现细节（如填充、CTR 模式中 IV 和随机数的生成等）也很有价值。

A heartfelt thank-you to [all the nice people](https://github.com/kokke/tiny-AES-c/graphs/contributors) out there who have contributed to this project.
衷心感谢所有为这个项目做出贡献的[热心人士](https://github.com/kokke/tiny-AES-c/graphs/contributors)。

All material in this repository is in the public domain.
本仓库中的所有材料均属于公共领域。