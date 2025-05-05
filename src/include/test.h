
#ifdef __cplusplus
extern "C" {
#endif

#include <pgmoneta.h>
#include <http.h>
#include <openssl/ssl.h>

#include <stdbool.h>
#include <stdio.h>

/* HTTP method definitions */
#define HTTP_GET 0
#define HTTP_POST 1
#define HTTP_PUT 2

struct http;

/**
 * Test functions
 */
int pgmoneta_http_curl_test(void);
int pgmoneta_http_test(void);
int pgmoneta_https_test(void);
int pgmoneta_http_post_test(void);
int pgmoneta_http_put_test(void);
int pgmoneta_http_put_file_test(void);
int pgmoneta_s3_upload_test(void);
int pgmoneta_azure_upload_test(void);
// int pgmoneta_custom_read_message(SSL* ssl, int socket, char** response_text);
/**
 * Connect to an HTTP/HTTPS server
 * @param hostname The host to connect to
 * @param port The port number
 * @param secure Use SSL if true
 * @param result The resulting HTTP structure
 * @return 0 upon success, otherwise 1
 */
int pgmoneta_http_connect(const char* hostname, int port, bool secure, struct http** result);

/**
 * Disconnect and clean up HTTP resources
 * @param http The HTTP structure
 */
void pgmoneta_http_disconnect(struct http* http);

/**
 * Add a header to the HTTP request
 * @param http The HTTP structure
 * @param name The header name
 * @param value The header value
 */
void pgmoneta_http_add_header2(struct http* http, const char* name, const char* value);

/**
 * Perform HTTP GET request
 * @param http The HTTP structure
 * @param hostname The hostname for the Host header
 * @param path The path for the request
 * @return 0 upon success, otherwise 1
 */
int pgmoneta_http_get(struct http* http, const char* hostname, const char* path);

/**
 * Perform HTTP POST request
 * @param http The HTTP structure
 * @param hostname The hostname for the Host header
 * @param path The path for the request
 * @param data The data to send
 * @param length The length of the data
 * @return 0 upon success, otherwise 1
 */
int pgmoneta_http_post(struct http* http, const char* hostname, const char* path, 
                      const char* data, size_t length);

/**
 * Perform HTTP PUT request
 * @param http The HTTP structure
 * @param hostname The hostname for the Host header
 * @param path The path for the request
 * @param data The data to upload
 * @param length The length of the data
 * @return 0 upon success, otherwise 1
 */
int pgmoneta_http_put(struct http* http, const char* hostname, const char* path, 
                     const void* data, size_t length);

/**
 * Perform HTTP PUT request with a file
 * @param http The HTTP structure
 * @param hostname The hostname for the Host header
 * @param path The path for the request
 * @param file The file to upload
 * @param file_size The size of the file
 * @return 0 upon success, otherwise 1
 */
int pgmoneta_http_put_file(struct http* http, const char* hostname, const char* path, FILE* file, size_t file_size, const char* content_type); 

#ifdef __cplusplus
}
#endif
