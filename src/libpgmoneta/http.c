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

void pgmoneta_http_add_header(struct http* http, const char* name, const char* value);
static int build_http_header(int method, const char* path, char** request);
static int extract_headers_body(char* response, struct http* http);
int pgmoneta_http_get(struct http* http, const char* hostname, const char* path);
int pgmoneta_http_connect(const char* hostname, int port, bool secure, struct http** result);
int pgmoneta_http_post(struct http* http, const char* hostname, const char* path, const char* data, size_t length);
int pgmoneta_http_put(struct http* http, const char* hostname, const char* path, const void* data, size_t length);
int pgmoneta_http_put_file(struct http* http, const char* hostname, const char* path, FILE* file, size_t file_size, const char* content_type);
int pgmoneta_http_direct_read(SSL* ssl, int socket, char** response_text);
void pgmoneta_http_disconnect(struct http* http);

void
pgmoneta_http_add_header(struct http* http, const char* name, const char* value)
{
   http->request_headers = pgmoneta_append(http->request_headers, name);
   http->request_headers = pgmoneta_append(http->request_headers, ": ");
   http->request_headers = pgmoneta_append(http->request_headers, value);
   http->request_headers = pgmoneta_append(http->request_headers, "\r\n");
}

static int
build_http_header(int method, const char* path, char** request)
{
   char* r = NULL;
   *request = NULL;

   if (method == PGMONETA_HTTP_GET)
   {
      r = pgmoneta_append(r, "GET ");
   }
   else if (method == PGMONETA_HTTP_POST)
   {
      r = pgmoneta_append(r, "POST ");
   }
   else if (method == PGMONETA_HTTP_PUT)
   {
      r = pgmoneta_append(r, "PUT ");
   }
   else
   {
      pgmoneta_log_error("Invalid HTTP method: %d", method);
      return 1;
   }

   r = pgmoneta_append(r, path);
   r = pgmoneta_append(r, " HTTP/1.1\r\n");

   *request = r;

   return 0;
}

static int
extract_headers_body(char* response, struct http* http)
{
   bool header = true;
   char* p = NULL;
   char* response_copy = NULL;

   if (response == NULL)
   {
      pgmoneta_log_error("Response is NULL");
      return 1;
   }

   response_copy = strdup(response);
   if (response_copy == NULL)
   {
      pgmoneta_log_error("Failed to duplicate response string");
      return 1;
   }

   p = strtok(response_copy, "\n");
   while (p != NULL)
   {
      if (*p == '\r')
      {
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
      }

      p = strtok(NULL, "\n");
   }

   free(response_copy);
   return 0;
}

int
pgmoneta_http_get(struct http* http, const char* hostname, const char* path)
{
   pgmoneta_log_debug("Starting pgmoneta_http_get");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* full_request = NULL;
   char* response = NULL;
   const char* endpoint = path ? path : "/get";

   if (build_http_header(PGMONETA_HTTP_GET, endpoint, &request))
   {
      pgmoneta_log_error("Failed to build HTTP header");
      goto error;
   }

   pgmoneta_http_add_header(http, "Host", hostname);
   pgmoneta_http_add_header(http, "User-Agent", "pgmoneta4/4");
   pgmoneta_http_add_header(http, "Accept", "text/*");
   pgmoneta_http_add_header(http, "Connection", "close");

   full_request = pgmoneta_append(NULL, request);
   full_request = pgmoneta_append(full_request, http->request_headers);
   full_request = pgmoneta_append(full_request, "\r\n");

   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      pgmoneta_log_error("Failed to allocate msg_request");
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   msg_request->data = full_request;
   msg_request->length = strlen(full_request) + 1;

   error = 0;
req:
   if (error < 5)
   {
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         pgmoneta_log_debug("Write failed, retrying (%d/5)", error);
         goto req;
      }
   }
   else
   {
      pgmoneta_log_error("Failed to write after 5 attempts");
      goto error;
   }

   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);

   if (response == NULL)
   {
      pgmoneta_log_error("No response data collected");
      goto error;
   }

   if (extract_headers_body(response, http))
   {
      pgmoneta_log_error("Failed to extract headers and body");
      goto error;
   }

   pgmoneta_log_debug("HTTP Headers: %s", http->headers ? http->headers : "NULL");
   pgmoneta_log_debug("HTTP Body: %s", http->body ? http->body : "NULL");

   free(request);
   free(full_request);
   free(response);
   free(msg_request);

   free(http->request_headers);
   http->request_headers = NULL;

   return 0;

error:
   pgmoneta_log_error("Error in pgmoneta_http_get, cleaning up");
   if (request)
   {
      free(request);
   }
   if (full_request)
   {
      free(full_request);
   }
   if (response)
   {
      free(response);
   }
   if (msg_request)
   {
      free(msg_request);
   }

   free(http->request_headers);
   http->request_headers = NULL;

   return 1;
}

int
pgmoneta_http_connect(const char* hostname, int port, bool secure, struct http** result)
{
   pgmoneta_log_debug("Connecting to %s:%d (secure: %d)", hostname, port, secure);
   struct http* h = NULL;
   int socket_fd = -1;
   SSL* ssl = NULL;

   h = (struct http*) malloc(sizeof(struct http));
   if (h == NULL)
   {
      pgmoneta_log_error("Failed to allocate HTTP structure");
      return 1;
   }

   memset(h, 0, sizeof(struct http));

   if (pgmoneta_connect(hostname, port, &socket_fd))
   {
      pgmoneta_log_error("Failed to connect to %s:%d", hostname, port);
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
         pgmoneta_disconnect(socket_fd);
         free(h);
         return 1;
      }

      if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0)
      {
         pgmoneta_log_error("Failed to set minimum TLS version");
         SSL_CTX_free(ctx);
         pgmoneta_disconnect(socket_fd);
         free(h);
         return 1;
      }

      ssl = SSL_new(ctx);
      if (ssl == NULL)
      {
         pgmoneta_log_error("Failed to create SSL structure");
         SSL_CTX_free(ctx);
         pgmoneta_disconnect(socket_fd);
         free(h);
         return 1;
      }

      if (SSL_set_fd(ssl, socket_fd) == 0)
      {
         pgmoneta_log_error("Failed to set SSL file descriptor");
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
                  SSL_free(ssl);
                  SSL_CTX_free(ctx);
                  pgmoneta_disconnect(socket_fd);
                  free(h);
                  return 1;
            }
         }
      }
      while (connect_result != 1);

      h->ssl = ssl;
   }

   *result = h;

   return 0;
}

int
pgmoneta_http_post(struct http* http, const char* hostname, const char* path, const char* data, size_t length)
{
   pgmoneta_log_debug("Starting pgmoneta_http_post");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* full_request = NULL;
   char* response = NULL;
   char content_length[32];

   if (build_http_header(PGMONETA_HTTP_POST, path, &request))
   {
      pgmoneta_log_error("Failed to build HTTP header");
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

   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      pgmoneta_log_error("Failed to allocate msg_request");
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   msg_request->data = full_request;
   msg_request->length = strlen(full_request) + 1;

   error = 0;
req:
   if (error < 5)
   {
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         pgmoneta_log_debug("Write failed, retrying (%d/5)", error);
         goto req;
      }
   }
   else
   {
      pgmoneta_log_error("Failed to write after 5 attempts");
      goto error;
   }

   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);

   if (response == NULL)
   {
      pgmoneta_log_error("No response data collected");
      goto error;
   }

   if (extract_headers_body(response, http))
   {
      pgmoneta_log_error("Failed to extract headers and body");
      goto error;
   }

   free(request);
   free(full_request);
   free(response);
   free(msg_request);

   free(http->request_headers);
   http->request_headers = NULL;

   return 0;

error:
   pgmoneta_log_error("Error in pgmoneta_http_post, cleaning up");
   if (request)
   {
      free(request);
   }
   if (full_request)
   {
      free(full_request);
   }
   if (response)
   {
      free(response);
   }
   if (msg_request)
   {
      free(msg_request);
   }

   free(http->request_headers);
   http->request_headers = NULL;

   return 1;
}

int
pgmoneta_http_put(struct http* http, const char* hostname, const char* path, const void* data, size_t length)
{
   pgmoneta_log_debug("Starting pgmoneta_http_put");
   struct message* msg_request = NULL;
   int error = 0;
   int status;
   char* request = NULL;
   char* full_request = NULL;
   char* response = NULL;
   char content_length[32];

   if (build_http_header(PGMONETA_HTTP_PUT, path, &request))
   {
      pgmoneta_log_error("Failed to build HTTP header");
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
      pgmoneta_log_error("Failed to allocate complete request");
      goto error;
   }

   memcpy(complete_request, full_request, headers_len);

   if (data && length > 0)
   {
      memcpy(complete_request + headers_len, data, length);
   }

   complete_request[total_len] = '\0';

   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      pgmoneta_log_error("Failed to allocate msg_request");
      free(complete_request);
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   msg_request->data = complete_request;
   msg_request->length = total_len + 1;

   error = 0;
req:
   if (error < 5)
   {
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         pgmoneta_log_debug("Write failed, retrying (%d/5)", error);
         goto req;
      }
   }
   else
   {
      pgmoneta_log_error("Failed to write after 5 attempts");
      goto error;
   }

   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);

   if (response == NULL)
   {
      pgmoneta_log_error("No response data collected");
      goto error;
   }

   if (extract_headers_body(response, http))
   {
      pgmoneta_log_error("Failed to extract headers and body");
      goto error;
   }

   free(request);
   free(full_request);
   free(response);
   free(msg_request->data);
   free(msg_request);

   free(http->request_headers);
   http->request_headers = NULL;

   return 0;

error:
   pgmoneta_log_error("Error in pgmoneta_http_put, cleaning up");
   if (request)
   {
      free(request);
   }
   if (full_request)
   {
      free(full_request);
   }
   if (response)
   {
      free(response);
   }
   if (msg_request)
   {
      if (msg_request->data)
      {
         free(msg_request->data);
      }
      free(msg_request);
   }

   free(http->request_headers);
   http->request_headers = NULL;

   return 1;
}

int
pgmoneta_http_put_file(struct http* http, const char* hostname, const char* path, FILE* file, size_t file_size, const char* content_type)
{
   pgmoneta_log_debug("Starting pgmoneta_http_put_file");
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
      pgmoneta_log_error("File is NULL");
      goto error;
   }

   if (build_http_header(PGMONETA_HTTP_PUT, path, &request))
   {
      pgmoneta_log_error("Failed to build HTTP header");
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

   pgmoneta_log_debug("File size: %zu", file_size);

   rewind(file);

   file_buffer = malloc(file_size);
   if (file_buffer == NULL)
   {
      pgmoneta_log_error("Failed to allocate memory for file content: %zu bytes", file_size);
      goto error;
   }

   size_t bytes_read = fread(file_buffer, 1, file_size, file);
   if (bytes_read != file_size)
   {
      pgmoneta_log_error("Failed to read entire file. Expected %zu bytes, got %zu", file_size, bytes_read);
      goto error;
   }

   pgmoneta_log_debug("Read %zu bytes from file", bytes_read);

   msg_request = (struct message*)malloc(sizeof(struct message));
   if (msg_request == NULL)
   {
      pgmoneta_log_error("Failed to allocate msg_request");
      goto error;
   }

   memset(msg_request, 0, sizeof(struct message));

   size_t header_len = strlen(header_part);
   size_t total_len = header_len + file_size;

   char* full_request = malloc(total_len + 1);
   if (full_request == NULL)
   {
      pgmoneta_log_error("Failed to allocate memory for full request: %zu bytes", total_len + 1);
      goto error;
   }

   memcpy(full_request, header_part, header_len);

   memcpy(full_request + header_len, file_buffer, file_size);

   full_request[total_len] = '\0';

   pgmoneta_log_debug("Setting msg_request data, total size: %zu", total_len);
   msg_request->data = full_request;
   msg_request->length = total_len;

   error = 0;
req:
   if (error < 5)
   {
      status = pgmoneta_write_message(http->ssl, http->socket, msg_request);
      if (status != MESSAGE_STATUS_OK)
      {
         error++;
         pgmoneta_log_debug("Write failed, retrying (%d/5)", error);
         goto req;
      }
   }
   else
   {
      pgmoneta_log_error("Failed to write after 5 attempts");
      goto error;
   }

   status = pgmoneta_http_direct_read(http->ssl, http->socket, &response);

   if (response == NULL)
   {
      pgmoneta_log_error("No response data collected");
      goto error;
   }

   if (extract_headers_body(response, http))
   {
      pgmoneta_log_error("Failed to extract headers and body");
      goto error;
   }

   int status_code = 0;
   if (http->headers && sscanf(http->headers, "HTTP/1.1 %d", &status_code) == 1)
   {
      pgmoneta_log_debug("HTTP status code: %d", status_code);
      if (status_code >= 200 && status_code < 300)
      {
         pgmoneta_log_debug("HTTP request successful");
      }
      else
      {
         pgmoneta_log_error("HTTP request failed with status code: %d", status_code);
      }
   }

   free(request);
   free(header_part);
   free(response);
   free(file_buffer);
   free(full_request);
   free(msg_request);

   free(http->request_headers);
   http->request_headers = NULL;

   return (status_code >= 200 && status_code < 300) ? 0 : 1;

error:
   pgmoneta_log_error("Error in pgmoneta_http_put_file, cleaning up");
   if (request)
   {
      free(request);
   }
   if (header_part)
   {
      free(header_part);
   }
   if (response)
   {
      free(response);
   }
   if (file_buffer)
   {
      free(file_buffer);
   }
   if (msg_request)
   {
      if (msg_request->data)
      {
         free(msg_request->data);
      }
      free(msg_request);
   }

   free(http->request_headers);
   http->request_headers = NULL;

   return 1;
}

int
pgmoneta_http_direct_read(SSL* ssl, int socket, char** response_text)
{
   char buffer[8192];
   ssize_t bytes_read;
   int total_bytes = 0;

   *response_text = NULL;

   while (1)
   {
      if (ssl)
      {
         bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
         if (bytes_read <= 0)
         {
            int err = SSL_get_error(ssl, bytes_read);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
               continue;
            }
            break;
         }
      }
      else
      {
         bytes_read = read(socket, buffer, sizeof(buffer) - 1);
         if (bytes_read <= 0)
         {
            break;
         }
      }

      buffer[bytes_read] = '\0';
      *response_text = pgmoneta_append(*response_text, buffer);
      total_bytes += bytes_read;

      if (strstr(buffer, "\r\n0\r\n\r\n") || bytes_read < sizeof(buffer) - 1)
      {
         break;
      }
   }

   return total_bytes > 0 ? MESSAGE_STATUS_OK : MESSAGE_STATUS_ERROR;
}

void
pgmoneta_http_disconnect(struct http* http)
{
   if (http != NULL)
   {
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
