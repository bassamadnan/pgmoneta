#include <http.h>

int pgmoneta_http_curl_test(void);

int pgmoneta_http_test(void);

int pgmoneta_https_test(void);

// static int
// create_ssl_client(SSL_CTX* ctx, char* key, char* cert, char* root, int socket, SSL** ssl);
#define HTTP_GET  1
#define HTTP_POST 2
#define HTTP_PUT  3