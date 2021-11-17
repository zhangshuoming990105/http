#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <event2/event.h>
#include <openssl/rand.h>
#include "ssl_func.h"

SSL_CTX *ssl_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    printf("Using OpenSSL version \"%s\"\nand libevent version \"%s\"\n",
           SSLeay_version(SSLEAY_VERSION),
           event_get_version());
    //
    //根据会话协议（sslv2/sslv3等）创建会话环境，即创建CTX。  
    //创建SSL上下文环境 ，可以理解为SSL句柄 
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

    //We MUST have entropy, or else there's no point to crypto. 
    if (!RAND_poll())
        return NULL;

    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh)
        openssl_func_error_report("EC_KEY_new_by_curve_name");
    if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
        openssl_func_error_report("SSL_CTX_set_tmp_ecdh");

    //设置CTX的属性，通常的设置是指定SSL握手阶段证书的验证方式和加载自己的证书。
    //选择服务器证书和服务器私钥.
    const char *certificate_chain = "../server.cert";
    const char *private_key = "../server.key";
    //设置服务器证书和服务器私钥到CTX中
    info_report("Loading certificate chain from '%s'\n"
                "and private key from '%s'\n",
                certificate_chain, private_key);

    //为SSL会话加载用户证书
    if (SSL_CTX_use_certificate_chain_file(ctx, certificate_chain) != 1)
        openssl_func_error_report("SSL_CTX_use_certificate_chain_file");
    //为SSL会话加载用户私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM) != 1)
        openssl_func_error_report("SSL_CTX_use_PrivateKey_file");
    //验证私钥和证书是否相符
    if (SSL_CTX_check_private_key(ctx) != 1)
        openssl_func_error_report("SSL_CTX_check_private_key");
    SSL_CTX_set_options(ctx,
                        SSL_OP_SINGLE_DH_USE |
                        SSL_OP_SINGLE_ECDH_USE |
                        SSL_OP_NO_SSLv2);

    return ctx;
}

//调用openSSL提供的打印log接口
void openssl_func_error_report(const char *func) {
    fprintf(stderr, "%s failed:\n", func);
    //This is the OpenSSL function that prints the contents of the
    //error stack to the specified file handle.
    ERR_print_errors_fp(stderr);

    exit(EXIT_FAILURE);
}

void error_exit(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    exit(EXIT_FAILURE);
}
