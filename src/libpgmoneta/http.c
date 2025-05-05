/*
 * Copyright (C) 2025 The pgmoneta community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgmoneta */
#include <pgmoneta.h>
#include <http.h>
#include <utils.h>
#include <logging.h>

void pgmoneta_http_add_header(struct http* http, const char* name, const char* value)
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
          method, PGMONETA_HTTP_GET, PGMONETA_HTTP_POST, PGMONETA_HTTP_PUT);

   if (method == PGMONETA_HTTP_GET) {
      printf("Before GET append\n");
      r = pgmoneta_append(r, "GET ");
      printf("After GET append: %s\n", r ? r : "NULL");
   } else if (method == PGMONETA_HTTP_POST) {
      r = pgmoneta_append(r, "POST ");
   } else if (method == PGMONETA_HTTP_PUT) {
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
   if (build_http_header(PGMONETA_HTTP_GET, endpoint, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header(http, "Host", hostname);
   pgmoneta_http_add_header(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header(http, "Accept", "text/*");
   pgmoneta_http_add_header(http, "Connection", "close");

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
   if (build_http_header(PGMONETA_HTTP_POST, path, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header(http, "Host", hostname);
   pgmoneta_http_add_header(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header(http, "Connection", "close");
   
   sprintf(content_length, "%zu", length);
   pgmoneta_http_add_header(http, "Content-Length", content_length);
   pgmoneta_http_add_header(http, "Content-Type", "application/x-www-form-urlencoded");
   
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
   if (build_http_header(PGMONETA_HTTP_PUT, path, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header(http, "Host", hostname);
   pgmoneta_http_add_header(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header(http, "Connection", "close");
   
   sprintf(content_length, "%zu", length);
   pgmoneta_http_add_header(http, "Content-Length", content_length);
   pgmoneta_http_add_header(http, "Content-Type", "application/octet-stream");
   
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

int pgmoneta_http_put_file(struct http* http, const char* hostname, const char* path, FILE* file, size_t file_size, const char* content_type)
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
   if (build_http_header(PGMONETA_HTTP_PUT, path, &request))
   {
      printf("Failed to build HTTP header\n");
      goto error;
   }

   pgmoneta_http_add_header(http, "Host", hostname);
   pgmoneta_http_add_header(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header(http, "Connection", "close");
   
   sprintf(content_length, "%zu", file_size);
   pgmoneta_http_add_header(http, "Content-Length", content_length);

   // default to application/octet-stream if not specified
   const char* type = content_type ? content_type : "application/octet-stream";
   pgmoneta_http_add_header(http, "Content-Type", type);
   
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
