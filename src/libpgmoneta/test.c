#include <test.h>
#include <stdio.h>
#include <curl/curl.h>
#include <pgmoneta.h>
#include <logging.h>
#include <network.h>
#include <security.h>
#include <http.h>
#include <message.h>
#include <utils.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <openssl/ssl.h>

int pgmoneta_http_direct_read(SSL* ssl, int socket, char** response_text);

int pgmoneta_http_curl_test(void)
{
  printf("Starting CURL test\n");
  CURL *curl;
  CURLcode res;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    printf("Got CURL handle\n");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");
    printf("Performing CURL request\n");
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    else
      printf("CURL request successful\n");
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  printf("ENDING CURL TEST\n\n");
  return 0;
}

void pgmoneta_http_add_header2(struct http* http, const char* name, const char* value)
{
   http->request_headers = pgmoneta_append(http->request_headers, name);
   http->request_headers = pgmoneta_append(http->request_headers, ": ");
   http->request_headers = pgmoneta_append(http->request_headers, value);
   http->request_headers = pgmoneta_append(http->request_headers, "\r\n");
}

static int
build_http_header(int method, const char* path, char** request)
{
   printf("Building HTTP header, method=%d, path=%s\n", method, path);
   char* r = NULL;
   *request = NULL;

   printf("Method comparison: %d vs GET=%d, POST=%d, PUT=%d\n", 
          method, HTTP_GET, HTTP_POST, HTTP_PUT);

   if (method == HTTP_GET) {
      printf("Before GET append\n");
      r = pgmoneta_append(r, "GET ");
      printf("After GET append: %s\n", r ? r : "NULL");
   } else if (method == HTTP_POST) {
      r = pgmoneta_append(r, "POST ");
   } else if (method == HTTP_PUT) {
      r = pgmoneta_append(r, "PUT ");
   } else {
      printf("Invalid HTTP method: %d\n", method);
      return 1;
   }

   r = pgmoneta_append(r, path);
   printf("Added path: %s\n", r);
   
   r = pgmoneta_append(r, " HTTP/1.1\r\n");
   printf("Added HTTP version: %s\n", r);

   *request = r;
   printf("Finished building request headers: %s\n", r);

   return 0;
}

static int
extract_headers_body(char* response, struct http* http)
{
   bool header = true;
   char* p = NULL;
   char* response_copy = NULL;

   if (response == NULL) {
      printf("ERROR: Response is NULL\n");
      return 1;
   }

   response_copy = strdup(response);
   if (response_copy == NULL) {
      printf("ERROR: Failed to duplicate response string\n");
      return 1;
   }

   printf("Tokenizing response\n");
   p = strtok(response_copy, "\n");
   while (p != NULL)
   {
      printf("Processing line: %s\n", p);
      if (*p == '\r')
      {
         printf("Found header/body separator\n");
         header = false;
      }
      else
      {
         if (!pgmoneta_is_number(p, 16))
         {
            if (header)
            {
               http->headers = pgmoneta_append(http->headers, p);
               http->headers = pgmoneta_append_char(http->headers, '\n');
            }
            else
            {
               http->body = pgmoneta_append(http->body, p);
               http->body = pgmoneta_append_char(http->body, '\n');
            }
         }
         else
         {
            printf("Skipping chunk size line: %s\n", p);
         }
      }

      p = strtok(NULL, "\n");
   }

   free(response_copy);
   printf("Finished extracting headers and body\n");
   return 0;
}

int pgmoneta_http_get(struct http* http, const char* hostname, const char* path)
{
   printf("Starting pgmoneta_http_get\n");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* full_request = NULL;
   char* response = NULL;
   const char* endpoint = path ? path : "/get";

   printf("Building HTTP header\n");
   if (build_http_header(HTTP_GET, endpoint, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header2(http, "Host", hostname);
   pgmoneta_http_add_header2(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header2(http, "Accept", "text/*");
   pgmoneta_http_add_header2(http, "Connection", "close");

   full_request = pgmoneta_append(NULL, request);
   full_request = pgmoneta_append(full_request, http->request_headers);
   full_request = pgmoneta_append(full_request, "\r\n");

   printf("HTTP request: %s\n", full_request);
   
   printf("Allocating msg_request\n");
   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      printf("Failed to allocate msg_request\n");
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   printf("Setting msg_request data\n");
   msg_request->data = full_request;
   msg_request->length = strlen(full_request) + 1;

   error = 0;
   printf("Sending request\n");
req:
   if (error < 5)
   {
      printf("Attempt %d to write message on socket: %d\n", error + 1, http->socket);
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      printf("Write status: %d\n", status);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         printf("Write failed, retrying (%d/5)\n", error);
         goto req;
      }
   }
   else
   {
      printf("Failed to write after 5 attempts\n");
      goto error;
   }

   printf("Request sent successfully, reading response\n");
   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);
   printf("Read status: %d\n", status);
   
   if (response == NULL) {
      printf("ERROR: No response data collected\n");
      goto error;
   }
   
   printf("Full response: %s\n", response);

   printf("Extracting headers and body\n");
   if (extract_headers_body(response, http))
   {
      printf("Failed to extract headers and body\n");
      goto error;
   }

   printf("HTTP Headers:\n%s\n", http->headers ? http->headers : "NULL");
   printf("HTTP Body:\n%s\n", http->body ? http->body : "NULL");

   printf("Freeing resources\n");
   free(request);
   free(full_request);
   free(response);
   free(msg_request);
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished pgmoneta_http_get successfully\n");
   return 0;

error:
   printf("Error in pgmoneta_http_get, cleaning up\n");
   if (request) free(request);
   if (full_request) free(full_request);
   if (response) free(response);
   if (msg_request) free(msg_request);
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished error cleanup\n");
   return 1;
}

int pgmoneta_http_connect(const char* hostname, int port, bool secure, struct http** result)
{
    printf("Connecting to %s:%d (secure: %d)\n", hostname, port, secure);
    struct http* h = NULL;
    int socket_fd = -1;
    SSL* ssl = NULL;
    
    h = (struct http*) malloc(sizeof(struct http));
    if(h == NULL)
    {
        pgmoneta_log_error("Failed to allocate HTTP structure");
        printf("Failed to allocate HTTP structure\n");
        return 1;
    }
    
    memset(h, 0, sizeof(struct http));
    
    if (pgmoneta_connect(hostname, port, &socket_fd))
    {
       pgmoneta_log_error("Failed to connect to %s:%d", hostname, port);
       printf("Failed to connect to %s:%d\n", hostname, port);
       free(h);
       return 1;
    }
    
    h->socket = socket_fd;
    
    if (secure)
    {
        SSL_CTX* ctx = NULL;
        
        if (pgmoneta_create_ssl_ctx(true, &ctx))
        {
            pgmoneta_log_error("Failed to create SSL context");
            printf("Failed to create SSL context\n");
            pgmoneta_disconnect(socket_fd);
            free(h);
            return 1;
        }
        
        if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0)
        {
            pgmoneta_log_error("Failed to set minimum TLS version");
            printf("Failed to set minimum TLS version\n");
            SSL_CTX_free(ctx);
            pgmoneta_disconnect(socket_fd);
            free(h);
            return 1;
        }
        
        ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            pgmoneta_log_error("Failed to create SSL structure");
            printf("Failed to create SSL structure\n");
            SSL_CTX_free(ctx);
            pgmoneta_disconnect(socket_fd);
            free(h);
            return 1;
        }
        
        if (SSL_set_fd(ssl, socket_fd) == 0)
        {
            pgmoneta_log_error("Failed to set SSL file descriptor");
            printf("Failed to set SSL file descriptor\n");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            pgmoneta_disconnect(socket_fd);
            free(h);
            return 1;
        }
        
        int connect_result;
        do
        {
            connect_result = SSL_connect(ssl);
            
            if (connect_result != 1)
            {
                int err = SSL_get_error(ssl, connect_result);
                switch (err)
                {
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                        continue;
                    default:
                        pgmoneta_log_error("SSL connection failed: %s", ERR_error_string(err, NULL));
                        printf("SSL connection failed: %s\n", ERR_error_string(err, NULL));
                        SSL_free(ssl);
                        SSL_CTX_free(ctx);
                        pgmoneta_disconnect(socket_fd);
                        free(h);
                        return 1;
                }
            }
        } while (connect_result != 1);
        
        h->ssl = ssl;
        printf("SSL connection established\n");
    }
    
    printf("Connected, socket: %d, ssl: %p\n", h->socket, (void*)h->ssl);
    *result = h;
    
    return 0;
}

void pgmoneta_http_disconnect(struct http* http)
{
    if (http != NULL)
    {
        printf("Disconnecting HTTP connection\n");
        
        if (http->ssl != NULL)
        {
            pgmoneta_close_ssl(http->ssl);
            http->ssl = NULL;
        }
        
        if (http->socket != -1)
        {
            pgmoneta_disconnect(http->socket);
            http->socket = -1;
        }
        
        if (http->headers != NULL)
        {
            free(http->headers);
            http->headers = NULL;
        }
        
        if (http->body != NULL)
        {
            free(http->body);
            http->body = NULL;
        }
        
        if (http->request_headers != NULL)
        {
            free(http->request_headers);
            http->request_headers = NULL;
        }
    }
}

int pgmoneta_http_test(void)
{
    printf("Starting pgmoneta_http_test\n");
    int status;
    struct http* h = NULL;
    
    const char* hostname = "postman-echo.com";
    int port = 80;
    bool secure = false;
    
    if (pgmoneta_http_connect(hostname, port, secure, &h))
    {
        printf("Failed to connect to %s:%d\n", hostname, port);
        return 1;
    }

    printf("Calling pgmoneta_http_get\n");
    status = pgmoneta_http_get(h, hostname, "/get");
    printf("pgmoneta_http_get returned: %d\n", status);

    pgmoneta_http_disconnect(h);
    free(h);
    
    printf("Finished pgmoneta_http_test\n");
    return 0;
}

int pgmoneta_https_test(void)
{
    printf("Starting pgmoneta_https_test\n");
    int status;
    struct http* h = NULL;
    
    const char* hostname = "postman-echo.com";
    int port = 443;
    bool secure = true;
    
    if (pgmoneta_http_connect(hostname, port, secure, &h))
    {
        printf("Failed to connect to %s:%d\n", hostname, port);
        return 1;
    }

    printf("Calling pgmoneta_http_get\n");
    status = pgmoneta_http_get(h, hostname, "/get");
    printf("pgmoneta_http_get returned: %d\n", status);

    pgmoneta_http_disconnect(h);
    free(h);
    
    printf("Finished pgmoneta_https_test\n");
    return 0;
}

int pgmoneta_http_post(struct http* http, const char* hostname, const char* path, const char* data, size_t length)
{
   printf("Starting pgmoneta_http_post\n");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* full_request = NULL;
   char* response = NULL;
   char content_length[32];

   printf("Building HTTP header\n");
   if (build_http_header(HTTP_POST, path, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header2(http, "Host", hostname);
   pgmoneta_http_add_header2(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header2(http, "Connection", "close");
   
   sprintf(content_length, "%zu", length);
   pgmoneta_http_add_header2(http, "Content-Length", content_length);
   pgmoneta_http_add_header2(http, "Content-Type", "application/x-www-form-urlencoded");
   
   full_request = pgmoneta_append(NULL, request);
   full_request = pgmoneta_append(full_request, http->request_headers);
   full_request = pgmoneta_append(full_request, "\r\n");
   
   if (data && length > 0)
   {
      full_request = pgmoneta_append(full_request, data);
   }

   printf("HTTP request: %s\n", full_request);
   
   printf("Allocating msg_request\n");
   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      printf("Failed to allocate msg_request\n");
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   printf("Setting msg_request data\n");
   msg_request->data = full_request;
   msg_request->length = strlen(full_request) + 1;

   error = 0;
   printf("Sending request\n");
req:
   if (error < 5)
   {
      printf("Attempt %d to write message on socket: %d\n", error + 1, http->socket);
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      printf("Write status: %d\n", status);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         printf("Write failed, retrying (%d/5)\n", error);
         goto req;
      }
   }
   else
   {
      printf("Failed to write after 5 attempts\n");
      goto error;
   }

   printf("Request sent successfully, reading response\n");
   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);
   printf("Read status: %d\n", status);
   
   if (response == NULL) {
      printf("ERROR: No response data collected\n");
      goto error;
   }
   
   printf("Full response: %s\n", response);

   printf("Extracting headers and body\n");
   if (extract_headers_body(response, http))
   {
      printf("Failed to extract headers and body\n");
      goto error;
   }

   printf("HTTP Headers:\n%s\n", http->headers ? http->headers : "NULL");
   printf("HTTP Body:\n%s\n", http->body ? http->body : "NULL");

   printf("Freeing resources\n");
   free(request);
   free(full_request);
   free(response);
   free(msg_request);
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished pgmoneta_http_post successfully\n");
   return 0;

error:
   printf("Error in pgmoneta_http_post, cleaning up\n");
   if (request) free(request);
   if (full_request) free(full_request);
   if (response) free(response);
   if (msg_request) free(msg_request);
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished error cleanup\n");
   return 1;
}

int pgmoneta_http_put(struct http* http, const char* hostname, const char* path, const void* data, size_t length)
{
   printf("Starting pgmoneta_http_put\n");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* full_request = NULL;
   char* response = NULL;
   char content_length[32];

   printf("Building HTTP header\n");
   if (build_http_header(HTTP_PUT, path, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header2(http, "Host", hostname);
   pgmoneta_http_add_header2(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header2(http, "Connection", "close");
   
   sprintf(content_length, "%zu", length);
   pgmoneta_http_add_header2(http, "Content-Length", content_length);
   pgmoneta_http_add_header2(http, "Content-Type", "application/octet-stream");
   
   full_request = pgmoneta_append(NULL, request);
   full_request = pgmoneta_append(full_request, http->request_headers);
   full_request = pgmoneta_append(full_request, "\r\n");
   
   size_t headers_len = strlen(full_request);
   size_t total_len = headers_len + length;
   
   char* complete_request = malloc(total_len + 1);
   if (complete_request == NULL)
   {
      printf("Failed to allocate complete request\n");
      goto error;
   }
   
   memcpy(complete_request, full_request, headers_len);
   
   if (data && length > 0)
   {
      memcpy(complete_request + headers_len, data, length);
   }
   
   complete_request[total_len] = '\0';

   printf("HTTP request headers: %s\n", full_request);
   printf("Data length: %zu\n", length);
   
   printf("Allocating msg_request\n");
   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      printf("Failed to allocate msg_request\n");
      free(complete_request);
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   printf("Setting msg_request data\n");
   msg_request->data = complete_request;
   msg_request->length = total_len + 1;

   error = 0;
   printf("Sending request\n");
req:
   if (error < 5)
   {
      printf("Attempt %d to write message on socket: %d\n", error + 1, http->socket);
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      printf("Write status: %d\n", status);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         printf("Write failed, retrying (%d/5)\n", error);
         goto req;
      }
   }
   else
   {
      printf("Failed to write after 5 attempts\n");
      goto error;
   }

   printf("Request sent successfully, reading response\n");
   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);
   printf("Read status: %d\n", status);
   
   if (response == NULL) {
      printf("ERROR: No response data collected\n");
      goto error;
   }
   
   printf("Full response: %s\n", response);

   printf("Extracting headers and body\n");
   if (extract_headers_body(response, http))
   {
      printf("Failed to extract headers and body\n");
      goto error;
   }

   printf("HTTP Headers:\n%s\n", http->headers ? http->headers : "NULL");
   printf("HTTP Body:\n%s\n", http->body ? http->body : "NULL");

   printf("Freeing resources\n");
   free(request);
   free(full_request);
   free(response);
   free(msg_request->data);
   free(msg_request);
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished pgmoneta_http_put successfully\n");
   return 0;

error:
   printf("Error in pgmoneta_http_put, cleaning up\n");
   if (request) free(request);
   if (full_request) free(full_request);
   if (response) free(response);
   if (msg_request) 
   {
      if (msg_request->data) free(msg_request->data);
      free(msg_request);
   }
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished error cleanup\n");
   return 1;
}

int pgmoneta_http_put_file(struct http* http, const char* hostname, const char* path, FILE* file, size_t file_size)
{
   printf("Starting pgmoneta_http_put_file\n");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* header_part = NULL;
   char* response = NULL;
   char content_length[32];
   void* file_buffer = NULL;

   if (file == NULL)
   {
      printf("File is NULL\n");
      goto error;
   }

   printf("Building HTTP header\n");
   if (build_http_header(HTTP_PUT, path, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header2(http, "Host", hostname);
   pgmoneta_http_add_header2(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header2(http, "Connection", "close");
   
   sprintf(content_length, "%zu", file_size);
   pgmoneta_http_add_header2(http, "Content-Length", content_length);
   pgmoneta_http_add_header2(http, "Content-Type", "application/octet-stream");
   
   header_part = pgmoneta_append(NULL, request);
   header_part = pgmoneta_append(header_part, http->request_headers);
   header_part = pgmoneta_append(header_part, "\r\n");

   printf("HTTP request headers: %s\n", header_part);
   printf("File size: %zu\n", file_size);
   
   rewind(file);
   
   file_buffer = malloc(file_size);
   if (file_buffer == NULL)
   {
      printf("Failed to allocate memory for file content: %zu bytes\n", file_size);
      goto error;
   }
   
   size_t bytes_read = fread(file_buffer, 1, file_size, file);
   if (bytes_read != file_size)
   {
      printf("Failed to read entire file. Expected %zu bytes, got %zu\n", file_size, bytes_read);
      goto error;
   }
   
   printf("Read %zu bytes from file\n", bytes_read);
   
   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      printf("Failed to allocate msg_request\n");
      goto error;
   }
   
   memset(msg_request, 0, sizeof(struct message));

   size_t header_len = strlen(header_part);
   size_t total_len = header_len + file_size;
   
   char* full_request = malloc(total_len + 1);
   if (full_request == NULL)
   {
      printf("Failed to allocate memory for full request: %zu bytes\n", total_len + 1);
      goto error;
   }
   
   memcpy(full_request, header_part, header_len);
   
   memcpy(full_request + header_len, file_buffer, file_size);
   
   full_request[total_len] = '\0';
   
   printf("Setting msg_request data, total size: %zu\n", total_len);
   msg_request->data = full_request;
   msg_request->length = total_len;

   error = 0;
   printf("Sending request\n");
req:
   if (error < 5)
   {
      printf("Attempt %d to write message on socket: %d\n", error + 1, http->socket);
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      printf("Write status: %d\n", status);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         printf("Write failed, retrying (%d/5)\n", error);
         goto req;
      }
   }
   else
   {
      printf("Failed to write after 5 attempts\n");
      goto error;
   }

   printf("Request sent successfully, reading response\n");
   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);
   printf("Read status: %d\n", status);
   
   if (response == NULL) {
      printf("ERROR: No response data collected\n");
      goto error;
   }
   
   printf("Full response: %s\n", response);

   printf("Extracting headers and body\n");
   if (extract_headers_body(response, http))
   {
      printf("Failed to extract headers and body\n");
      goto error;
   }

   int status_code = 0;
   if (http->headers && sscanf(http->headers, "HTTP/1.1 %d", &status_code) == 1) {
      printf("HTTP status code: %d\n", status_code);
      if (status_code >= 200 && status_code < 300) {
         printf("HTTP request successful\n");
      } else {
         printf("HTTP request failed with status code: %d\n", status_code);
      }
   }

   printf("HTTP Headers:\n%s\n", http->headers ? http->headers : "NULL");
   printf("HTTP Body:\n%s\n", http->body ? http->body : "NULL");

   printf("Freeing resources\n");
   free(request);
   free(header_part);
   free(response);
   free(file_buffer);
   free(full_request);
   free(msg_request);
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished pgmoneta_http_put_file with status code: %d\n", status_code);
   return (status_code >= 200 && status_code < 300) ? 0 : 1;

error:
   printf("Error in pgmoneta_http_put_file, cleaning up\n");
   if (request) free(request);
   if (header_part) free(header_part);
   if (response) free(response);
   if (file_buffer) free(file_buffer);
   if (msg_request) {
      if (msg_request->data) free(msg_request->data);
      free(msg_request);
   }
   
   free(http->request_headers);
   http->request_headers = NULL;

   printf("Finished error cleanup\n");
   return 1;
}

int pgmoneta_http_direct_read(SSL* ssl, int socket, char** response_text)
{
  char buffer[8192];
  ssize_t bytes_read;
  int total_bytes = 0;
  
  *response_text = NULL;
  
  while (1) {
     if (ssl) {
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
           int err = SSL_get_error(ssl, bytes_read);
           if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
              continue;
           }
           break;
        }
     } else {
        bytes_read = read(socket, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
           break;
        }
     }
     
     buffer[bytes_read] = '\0';
     *response_text = pgmoneta_append(*response_text, buffer);
     total_bytes += bytes_read;
     
     if (strstr(buffer, "\r\n0\r\n\r\n") || bytes_read < sizeof(buffer) - 1) {
        break;
     }
  }
  
  return total_bytes > 0 ? MESSAGE_STATUS_OK : MESSAGE_STATUS_ERROR;
}

int pgmoneta_http_post_test(void)
{
   printf("Starting pgmoneta_http_post_test\n");
   int status;
   struct http* h = NULL;
   
   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;
   const char* test_data = "name=pgmoneta&version=1.0";
   
   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
       printf("Failed to connect to %s:%d\n", hostname, port);
       return 1;
   }

   printf("Calling pgmoneta_http_post\n");
   status = pgmoneta_http_post(h, hostname, "/post", test_data, strlen(test_data));
   printf("pgmoneta_http_post returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);
   
   printf("Finished pgmoneta_http_post_test\n");
   return 0;
}

int pgmoneta_http_put_test(void)
{
   printf("Starting pgmoneta_http_put_test\n");
   int status;
   struct http* h = NULL;
   
   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;
   const char* test_data = "This is a test file content for PUT request";
   
   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
       printf("Failed to connect to %s:%d\n", hostname, port);
       return 1;
   }

   printf("Calling pgmoneta_http_put\n");
   status = pgmoneta_http_put(h, hostname, "/put", test_data, strlen(test_data));
   printf("pgmoneta_http_put returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);
   
   printf("Finished pgmoneta_http_put_test\n");
   return 0;
}

int pgmoneta_http_put_file_test(void)
{
   printf("Starting pgmoneta_http_put_file_test\n");
   int status;
   struct http* h = NULL;
   FILE* temp_file = NULL;
   
   const char* hostname = "postman-echo.com";
   int port = 443;
   bool secure = true;
   const char* test_data = "This is a test file content for PUT file request\nSecond line of test data\nThird line with some numbers: 12345";
   size_t data_len = strlen(test_data);
   
   temp_file = tmpfile();
   if (temp_file == NULL)
   {
       printf("Failed to create temporary file\n");
       return 1;
   }
   
   if (fwrite(test_data, 1, data_len, temp_file) != data_len)
   {
       printf("Failed to write to temporary file\n");
       fclose(temp_file);
       return 1;
   }
   
   rewind(temp_file);
   
   if (pgmoneta_http_connect(hostname, port, secure, &h))
   {
       printf("Failed to connect to %s:%d\n", hostname, port);
       fclose(temp_file);
       return 1;
   }

   printf("Calling pgmoneta_http_put_file\n");
   status = pgmoneta_http_put_file(h, hostname, "/put", temp_file, data_len);
   printf("pgmoneta_http_put_file returned: %d\n", status);

   pgmoneta_http_disconnect(h);
   free(h);
   fclose(temp_file);
   
   printf("Finished pgmoneta_http_put_file_test\n");
   return 0;
}

int pgmoneta_s3_upload_test(void)
{
   printf("Starting pgmoneta_s3_test\n");
   
   const char* s3_aws_region = "DO NOT TRY";
   const char* s3_access_key_id = "DO NOT TRY";
   const char* s3_secret_access_key = "DO NOT TRY";
   const char* s3_bucket = "DO NOT TRY";
   const char* s3_base_dir = "DO NOT TRY";
   
   char* temp_filename = "/tmp/pgmoneta_s3_test_file.txt";
   const char* test_content = "This is a test file for pgMoneta S3 upload functionality.\n"
                              "This file was created for testing the custom HTTP implementation.\n"
                              "The timestamp is: ";
   
   FILE* test_file = fopen(temp_filename, "w");
   if (test_file == NULL) {
       printf("Failed to create test file\n");
       return 1;
   }
   
   fputs(test_content, test_file);
   
   time_t now = time(NULL);
   char time_str[64];
   strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
   fputs(time_str, test_file);
   
   fclose(test_file);
   
   struct stat file_stat;
   if (stat(temp_filename, &file_stat) != 0) {
       printf("Failed to get file stats\n");
       return 1;
   }
   size_t file_size = file_stat.st_size;
   printf("Test file created with size: %zu bytes\n", file_size);
   
   test_file = fopen(temp_filename, "rb");
   if (test_file == NULL) {
       printf("Failed to open test file for reading\n");
       return 1;
   }
   
   char object_key[256];
   sprintf(object_key, "%s/test_%ld.txt", s3_base_dir, (long)now);
   printf("S3 object key: %s\n", object_key);
   
   struct http* h = NULL;
   char short_date[SHORT_TIME_LENGTH];
   char long_date[LONG_TIME_LENGTH];
   char* file_sha256 = NULL;
   char* s3_host = NULL;
   char* canonical_request = NULL;
   char* string_to_sign = NULL;
   char* auth_value = NULL;
   char* canonical_request_sha256 = NULL;
   
   memset(&short_date[0], 0, sizeof(short_date));
   memset(&long_date[0], 0, sizeof(long_date));
   
   if (pgmoneta_get_timestamp_ISO8601_format(short_date, long_date)) {
       printf("Failed to get timestamp\n");
       fclose(test_file);
       return 1;
   }
   
   printf("Short date: %s\n", short_date);
   printf("Long date: %s\n", long_date);
   
   pgmoneta_create_sha256_file(temp_filename, &file_sha256);
   printf("File SHA256: %s\n", file_sha256);
   
   s3_host = malloc(strlen(s3_bucket) + strlen(s3_aws_region) + 20);
   sprintf(s3_host, "%s.s3.%s.amazonaws.com", s3_bucket, s3_aws_region);
   printf("S3 host: %s\n", s3_host);
   
   if (pgmoneta_http_connect(s3_host, 443, true, &h)) {
       printf("Failed to connect to S3\n");
       fclose(test_file);
       free(s3_host);
       free(file_sha256);
       return 1;
   }
   
   canonical_request = pgmoneta_append(canonical_request, "PUT\n/");
   canonical_request = pgmoneta_append(canonical_request, object_key);
   canonical_request = pgmoneta_append(canonical_request, "\n\nhost:");
   canonical_request = pgmoneta_append(canonical_request, s3_host);
   canonical_request = pgmoneta_append(canonical_request, "\nx-amz-content-sha256:");
   canonical_request = pgmoneta_append(canonical_request, file_sha256);
   canonical_request = pgmoneta_append(canonical_request, "\nx-amz-date:");
   canonical_request = pgmoneta_append(canonical_request, long_date);
   canonical_request = pgmoneta_append(canonical_request, "\nx-amz-storage-class:REDUCED_REDUNDANCY\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n");
   canonical_request = pgmoneta_append(canonical_request, file_sha256);
   
   pgmoneta_generate_string_sha256_hash(canonical_request, &canonical_request_sha256);
   printf("Canonical request hash: %s\n", canonical_request_sha256);
   
   string_to_sign = pgmoneta_append(string_to_sign, "AWS4-HMAC-SHA256\n");
   string_to_sign = pgmoneta_append(string_to_sign, long_date);
   string_to_sign = pgmoneta_append(string_to_sign, "\n");
   string_to_sign = pgmoneta_append(string_to_sign, short_date);
   string_to_sign = pgmoneta_append(string_to_sign, "/");
   string_to_sign = pgmoneta_append(string_to_sign, s3_aws_region);
   string_to_sign = pgmoneta_append(string_to_sign, "/s3/aws4_request\n");
   string_to_sign = pgmoneta_append(string_to_sign, canonical_request_sha256);
   
   char* key = NULL;
   unsigned char* date_key_hmac = NULL;
   unsigned char* date_region_key_hmac = NULL;
   unsigned char* date_region_service_key_hmac = NULL;
   unsigned char* signing_key_hmac = NULL;
   unsigned char* signature_hmac = NULL;
   unsigned char* signature_hex = NULL;
   int hmac_length = 0;
   
   key = pgmoneta_append(key, "AWS4");
   key = pgmoneta_append(key, s3_secret_access_key);
   
   if (pgmoneta_generate_string_hmac_sha256_hash(key, strlen(key), short_date, SHORT_TIME_LENGTH - 1, 
                                            &date_key_hmac, &hmac_length)) {
       printf("Failed to generate date key\n");
       goto error;
   }
   
   if (pgmoneta_generate_string_hmac_sha256_hash((char*)date_key_hmac, hmac_length, s3_aws_region, 
                                            strlen(s3_aws_region), &date_region_key_hmac, &hmac_length)) {
       printf("Failed to generate date-region key\n");
       goto error;
   }
   
   if (pgmoneta_generate_string_hmac_sha256_hash((char*)date_region_key_hmac, hmac_length, "s3", 
                                            strlen("s3"), &date_region_service_key_hmac, &hmac_length)) {
       printf("Failed to generate date-region-service key\n");
       goto error;
   }
   
   if (pgmoneta_generate_string_hmac_sha256_hash((char*)date_region_service_key_hmac, hmac_length, 
                                            "aws4_request", strlen("aws4_request"), 
                                            &signing_key_hmac, &hmac_length)) {
       printf("Failed to generate signing key\n");
       goto error;
   }
   
   printf("Generated signing key\n");
   
   if (pgmoneta_generate_string_hmac_sha256_hash((char*)signing_key_hmac, hmac_length, string_to_sign, 
                                            strlen(string_to_sign), &signature_hmac, &hmac_length)) {
       printf("Failed to generate signature\n");
       goto error;
   }
   
   pgmoneta_convert_base32_to_hex(signature_hmac, hmac_length, &signature_hex);
   printf("Signature: %s\n", signature_hex);
   
   auth_value = pgmoneta_append(auth_value, "AWS4-HMAC-SHA256 Credential=");
   auth_value = pgmoneta_append(auth_value, s3_access_key_id);
   auth_value = pgmoneta_append(auth_value, "/");
   auth_value = pgmoneta_append(auth_value, short_date);
   auth_value = pgmoneta_append(auth_value, "/");
   auth_value = pgmoneta_append(auth_value, s3_aws_region);
   auth_value = pgmoneta_append(auth_value, "/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=");
   auth_value = pgmoneta_append(auth_value, (char*)signature_hex);
   
   printf("Authorization header generated\n");
   
   pgmoneta_http_add_header2(h, "Authorization", auth_value);
   pgmoneta_http_add_header2(h, "x-amz-content-sha256", file_sha256);
   pgmoneta_http_add_header2(h, "x-amz-date", long_date);
   pgmoneta_http_add_header2(h, "x-amz-storage-class", "REDUCED_REDUNDANCY");
   
   char s3_path[512];
   sprintf(s3_path, "/%s", object_key);
   printf("S3 path for HTTP PUT: %s\n", s3_path);
   
   printf("Uploading file to S3...\n");
   int result = pgmoneta_http_put_file(h, s3_host, s3_path, test_file, file_size);
   
   if (result == 0) {
       printf("File uploaded successfully to S3\n");
       printf("Object URL: https://%s/%s\n", s3_host, object_key);
   } else {
       printf("Failed to upload file to S3\n");
   }
   
   fclose(test_file);
   pgmoneta_http_disconnect(h);
   free(h);
   free(s3_host);
   free(file_sha256);
   free(canonical_request);
   free(canonical_request_sha256);
   free(string_to_sign);
   free(key);
   if (date_key_hmac) free(date_key_hmac);
   if (date_region_key_hmac) free(date_region_key_hmac);
   if (date_region_service_key_hmac) free(date_region_service_key_hmac);
   if (signing_key_hmac) free(signing_key_hmac);
   if (signature_hmac) free(signature_hmac);
   if (signature_hex) free(signature_hex);
   if (auth_value) free(auth_value);
   
   remove(temp_filename);
   
   printf("Finished pgmoneta_s3_test\n");
   return result;

error:
   if (test_file) fclose(test_file);
   if (h) {
       pgmoneta_http_disconnect(h);
       free(h);
   }
   if (s3_host) free(s3_host);
   if (file_sha256) free(file_sha256);
   if (canonical_request) free(canonical_request);
   if (canonical_request_sha256) free(canonical_request_sha256);
   if (string_to_sign) free(string_to_sign);
   if (key) free(key);
   if (date_key_hmac) free(date_key_hmac);
   if (date_region_key_hmac) free(date_region_key_hmac);
   if (date_region_service_key_hmac) free(date_region_service_key_hmac);
   if (signing_key_hmac) free(signing_key_hmac);
   if (signature_hmac) free(signature_hmac);
   if (signature_hex) free(signature_hex);
   if (auth_value) free(auth_value);
   
   remove(temp_filename);
   
   printf("Failed pgmoneta_s3_test with error\n");
   return 1;
}