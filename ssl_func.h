#ifndef _SSL_FUNC

#define _SSL_FUNC

SSL_CTX *ssl_init();

void openssl_func_error_report(const char *func);

void error_exit(const char *fmt, ...);


#define error_report printf
#define info_report printf

#endif