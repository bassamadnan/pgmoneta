
#ifdef __cplusplus
extern "C" {
#endif

#include <pgmoneta.h>
#include <http.h>
#include <openssl/ssl.h>

#include <stdbool.h>
#include <stdio.h>

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

#ifdef __cplusplus
}
#endif
